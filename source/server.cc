#include "server.hpp"

#include <filesystem>
#include <optional>
#include <string>

#include <scope_guard.hpp>

#include <aws/core/auth/AWSCredentials.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/GetObjectAttributesRequest.h>
#include <aws/transfer/TransferManager.h>

#include "assertions.hpp"
#include "hashing.hpp"
#include "uuid.hpp"

namespace S3 = Aws::S3;
namespace Transfer = Aws::Transfer;
namespace fs = std::filesystem;

namespace lfs {

inline std::optional<std::string> GetEnv(const std::string_view name) {
  char* buffer{nullptr};
  std::size_t buffer_len;
  // Cleanup buffer on completion of this method:
  const auto cleanup = sg::make_scope_guard([&]() {
    if (buffer) {
      free(buffer);
      buffer = nullptr;
    }
  });

  const errno_t err = _dupenv_s(&buffer, &buffer_len, name.data());
  if (err != 0) {
    return std::nullopt;
  }
  if (!buffer) {
    // No environment variable.
    return std::nullopt;
  }
  ASSERT_GREATER(buffer_len, 0);

  if (buffer[buffer_len - 1] == 0) {
    // _dupenv_s includes the zero-terminator in the length
    --buffer_len;
  }
  std::string result{buffer, buffer_len};
  return result;
}

// Exception used to represent failure processing a request.
struct RequestError {
  template <typename... Ts>
  RequestError(int code, std::string_view fmt, Ts&&... args)
      : code_(code), message_(fmt::format(fmt, std::forward<Ts>(args)...)) {}

  int Code() const { return code_; }

  const std::string& Message() const { return message_; }

 private:
  int code_;
  std::string message_;
};

// Get S3 key from OID.
// This is the same convention that git-lfs uses to store files in `.git/lfs`.
inline std::string KeyFromOid(const std::string& oid) {
  ASSERT_EQUAL(oid.size(), 64, "OID should be a sha256 value.");
  return fmt::format("{}/{}/{}", std::string_view{oid.data(), 2},
                     std::string_view{oid.data() + 2, 2}, oid);
}

inline std::shared_ptr<S3::S3Client> CreateS3Client(const Configuration& config) {
  S3::S3ClientConfiguration client_config{};
  if (config.bucket_region) {
    client_config.region = config.bucket_region.value();
  }

  if (config.credentials) {
    auto endpoint_provider = Aws::MakeShared<S3::S3EndpointProvider>(S3::S3Client::ALLOCATION_TAG);

    Aws::Auth::AWSCredentials aws_credentials{config.credentials->access_key_id,
                                              config.credentials->secret_access_key};
    return std::make_shared<S3::S3Client>(aws_credentials, std::move(endpoint_provider),
                                          client_config);
  } else {
    // Let the SDK resolve credentials:
    return std::make_shared<S3::S3Client>(client_config);
  }
}

inline std::shared_ptr<Transfer::TransferManager> CreateTransferManager(
    const std::shared_ptr<S3::S3Client>& s3_client,
    Aws::Utils::Threading::Executor* const executor) {
  ASSERT(executor);

  Transfer::TransferManagerConfiguration transfer_config(executor);
  transfer_config.s3Client = s3_client;
  transfer_config.computeContentMD5 = true;
  transfer_config.errorCallback = [](const Transfer::TransferManager*,
                                     const std::shared_ptr<const Transfer::TransferHandle>&,
                                     const Aws::Client::AWSError<S3::S3Errors>& error) {
    // TODO: Do something more here?
    spdlog::error("Error during S3 transfer [Exception = {}]: {}", error.GetExceptionName(),
                  error.GetMessage());
  };
  return Transfer::TransferManager::Create(transfer_config);
}

Server::Server(const Configuration& config)
    : config_(config),
      s3_client_(CreateS3Client(config)),
      pooled_executor_{
          Aws::MakeShared<Aws::Utils::Threading::PooledThreadExecutor>("executor", 16)},
      transfer_manager_(CreateTransferManager(s3_client_, pooled_executor_.get())) {
  spdlog::info("Bucket: {}", config_.bucket_name);
  spdlog::info("Storage directory: {}", config_.local_storage.string());
}

void Server::Run() {
  http_server_.Post("/objects/batch", [this](const httplib::Request& req, httplib::Response& res) {
    HandleBatchPost(req, res);
  });

  http_server_.Put(R"(/objects/([a-zA-Z0-9]+))",
                   [this](const httplib::Request& req, httplib::Response& res,
                          const httplib::ContentReader& content_reader) {
                     HandleObjectPut(req, res, content_reader);
                   });

  http_server_.Get(
      R"(/objects/([a-zA-Z0-9]+))",
      [this](const httplib::Request& req, httplib::Response& res) { HandleObjectGet(req, res); });

  http_server_.set_exception_handler(
      [this](const httplib::Request& req, httplib::Response& res, std::exception_ptr ep) {
        HandleException(req, res, ep);
      });

  spdlog::info("Starting server on port {}...", config_.port);
  http_server_.listen("0.0.0.0", config_.port);
}

void Server::HandleException(const httplib::Request& req, httplib::Response& res,
                             std::exception_ptr ep) {
  res.status = 500;
  std::string response{};
  try {
    std::rethrow_exception(ep);
  } catch (std::exception& e) {
    spdlog::error("Exception thrown during request handling. Message = \"{}\", Request = {}",
                  e.what(), req.body);
    response = EncodeResponse(lfs::error_response_t{"Internal error: {}", e.what()});
  } catch (const RequestError& err) {
    response = EncodeResponse(lfs::error_response_t{"Error {}: {}", err.Code(), err.Message()});
    res.status = err.Code();  //  Customize the HTTP code.
  } catch (...) {
    spdlog::error("Unknown exception thrown during request handling. Request = {}", req.body);
    response = EncodeResponse(lfs::error_response_t{"Internal error"});
  }
  res.set_content(response, std::string(lfs::mime_type_json));
}

void Server::HandleBatchPost(const httplib::Request& req, httplib::Response& res) {
  // Decode into batch request object:
  const lfs::objects_batch_t req_converted = lfs::DecodeObjectBatch(req.body);

  lfs::response_t response{};
  for (const lfs::object_t& obj : req_converted.objects) {
    const std::string key = KeyFromOid(obj.oid);
    // Check if the object exists:
    const auto outcome = s3_client_->GetObjectAttributes(
        S3::Model::GetObjectAttributesRequest{}
            .WithBucket(config_.bucket_name)
            .WithKey(key)
            .WithObjectAttributes({S3::Model::ObjectAttributes::ObjectSize}));

    if (outcome.IsSuccess()) {
      const S3::Model::GetObjectAttributesResult& result = outcome.GetResult();

      // TODO: Handle this? Under normal operation it should never occur.
      ASSERT_EQUAL(static_cast<std::size_t>(result.GetObjectSize()), obj.size,
                   "Object {} exists on S3, but the size is incorrect.", obj.oid);

      // The object exists, so return a download URL:
      lfs::action_url_t download{fmt::format("http://localhost/objects/{}", obj.oid),
                                 {{"Accept", std::string(lfs::mime_type)}}};

      response.objects.emplace_back(lfs::object_actions_t{obj, "download", std::move(download)});
    } else {
      const auto& error = outcome.GetError();
      if (error.GetErrorType() == S3::S3Errors::NO_SUCH_KEY) {
        // Tell the client to upload this object:
        lfs::action_url_t upload{fmt::format("http://localhost/objects/{}", obj.oid),
                                 {{"Accept", std::string(lfs::mime_type_json)}}};

        response.objects.emplace_back(lfs::object_actions_t{obj, "upload", std::move(upload)});
      } else {
        // Return any other AWS error as an internal error:
        std::string message = fmt::format(
            R"(Error accessing object. Type = {}, Exception = "{}", Message = "{}")",
            static_cast<int>(error.GetErrorType()), error.GetExceptionName(), error.GetMessage());

        spdlog::error(message);
        lfs::error_t err{
            lfs::error_code::internal_error,
            std::move(message),
        };
        response.objects.emplace_back(lfs::object_error_t{obj, std::move(err)});
      }
    }
  }

  const std::string response_str = EncodeResponse(response);
  res.set_content(response_str, std::string(lfs::mime_type_json));
  res.status = 200;
}

void Server::HandleObjectPut(const httplib::Request& req, httplib::Response& res,
                             const httplib::ContentReader& content_reader) {
  // Pull the Content-Size field from the header:
  const std::string content_len_str = req.get_header_value("Content-Length");
  ASSERT(!content_len_str.empty(), "Missing the Content-Length header");

  // The OID was parsed by the regex matcher:
  ASSERT_GREATER_OR_EQ(req.matches.size(), 2);
  const lfs::object_t obj{req.matches[1].str(), std::stoull(content_len_str)};

  // Create a unique sub-folder to place this file into:
  const std::string uuid = GenerateUuidString();
  const fs::path storage_path = config_.local_storage / uuid;
  fs::create_directories(storage_path);

  // On completion, we will remove this directory:
  const auto cleanup_local_path = sg::make_scope_guard([&] {
    // Don't throw here, since an exception might already be in flight:
    std::error_code err_code{};
    if (!fs::remove_all(storage_path, err_code)) {
      spdlog::error("Failed to remove temporary file: {} (code = {}, message = {})",
                    storage_path.string(), err_code.value(), err_code.message());
    }
  });

  const fs::space_info space = fs::space(storage_path);
  if (space.available < obj.size) {
    FillWithError(res, lfs::error_code::internal_error,
                  "Insufficient space to receive file: oid = {}, required = {}, available = {}",
                  obj.oid, obj.size, space.available);
    return;
  }

  const fs::path filename = storage_path / obj.oid;
  std::ofstream output_stream{filename, std::ios::out | std::ios::binary};
  std::size_t bytes_written = 0;

  // Receive the object body:
  lfs::Hasher hasher{};
  content_reader([&](const char* data, size_t data_length) {
    output_stream.write(data, static_cast<std::streamsize>(data_length));
    if (!output_stream) {
      return false;
    }
    hasher.Update({data, data_length});
    bytes_written += data_length;
    return bytes_written < obj.size;  //  Don't read past the declared size.
  });

  output_stream.flush();

  // Check that the size matches our expectations:
  if (bytes_written != obj.size) {
    FillWithError(res, lfs::error_code::validation_error,
                  "Object size does not match. expected = {}, actual = {}", obj.size,
                  bytes_written);
    return;
  }

  // Compute the hash:
  lfs::Sha256 final_hash = hasher.GetHash();

  // Check the hash:
  const std::string final_hash_string = lfs::StringFromSha256(final_hash);
  if (final_hash_string != obj.oid) {
    FillWithError(res, lfs::error_code::validation_error,
                  "Object hash does not match. expected = {}, actual = {}", obj.oid,
                  final_hash_string);
    return;
  }

  // Transfer to S3:
  std::shared_ptr<Aws::Transfer::TransferHandle> handle = transfer_manager_->UploadFile(
      filename.string(), config_.bucket_name, KeyFromOid(obj.oid), "application/octet-stream", {});
  ASSERT(handle);
  handle->WaitUntilFinished();

  if (handle->GetStatus() != Transfer::TransferStatus::COMPLETED) {
    spdlog::error("Failed to transfer object: oid = {}, size = {}, status: {}", obj.oid, obj.size,
                  handle->GetStatus());
  } else {
    spdlog::info("Transfer successful: oid = {}, size = {}", obj.oid, obj.size);
  }

  // Create a response w/ a download URL to indicate success.
  lfs::response_t response{};
  lfs::action_url_t download{fmt::format("http://localhost/objects/{}", obj.oid),
                             {{"Accept", std::string(lfs::mime_type)}}};
  response.objects.emplace_back(lfs::object_actions_t{obj, "download", std::move(download)});

  std::string response_str = EncodeResponse(response);
  res.set_content(response_str, std::string(lfs::mime_type_json));
  res.status = 200;
}

void Server::HandleObjectGet(const httplib::Request& req, httplib::Response& res) {
  // Pull the oid from the URL:
  ASSERT_GREATER_OR_EQ(req.matches.size(), 2);
  const std::string oid = req.matches[1].str();

  // See whether client is requesting meta-data, or the object itself:
  const std::string accept = req.get_header_value("Accept");
  if (accept == lfs::mime_type_json) {
    // Client is requesting meta-data about an object:
    // todo
  } else if (accept == lfs::mime_type) {
    // Create a directory to download the object to:
    const std::string uuid = GenerateUuidString();
    const fs::path storage_path = config_.local_storage / uuid;
    fs::create_directories(storage_path);

    // Where the file will be saved:
    const fs::path download_path = storage_path / oid;

    // Query the size:
    const std::string object_key = KeyFromOid(oid);
    const auto outcome = s3_client_->GetObjectAttributes(
        S3::Model::GetObjectAttributesRequest{}
            .WithBucket(config_.bucket_name)
            .WithKey(object_key)
            .WithObjectAttributes({S3::Model::ObjectAttributes::ObjectSize}));

    std::size_t object_size;
    if (outcome.IsSuccess()) {
      object_size = outcome.GetResult().GetObjectSize();
    } else {
      FillWithError(res, error_code::object_does_not_exist, "Object {} does not exist.", oid);
      return;
    }

    const fs::space_info space = fs::space(storage_path);
    if (space.available < object_size) {
      FillWithError(res, lfs::error_code::internal_error,
                    "Insufficient space to transfer file from S3: required = {}, available = {}",
                    object_size, space.available);
      return;
    }

    std::shared_ptr<Aws::Transfer::TransferHandle> handle = transfer_manager_->DownloadFile(
        config_.bucket_name, object_key, download_path.string(), {});
    ASSERT(handle);
    handle->WaitUntilFinished();

    if (handle->GetStatus() != Transfer::TransferStatus::COMPLETED) {
      FillWithError(res, error_code::internal_error,
                    "Failed to transfer object: oid = {}, size = {}, status = {}", oid, object_size,
                    handle->GetStatus());
      return;
    } else {
      spdlog::debug("Transfer from S3 successful: oid = {}, size = {}", oid, object_size);
    }

    ASSERT(fs::exists(download_path), "File not found at expected path: {}",
           download_path.string());

    const std::uintmax_t actual_size = fs::file_size(download_path);
    if (actual_size != object_size) {
      FillWithError(res, error_code::internal_error,
                    "S3 download was truncated. expected = {} bytes, actual = {} bytes",
                    object_size, actual_size);
      return;
    }

    // Compare the hash
    const auto actual_hash = ComputeFileHash(download_path, object_size);
    if (actual_hash != oid) {
      FillWithError(res, error_code::internal_error,
                    "S3 object has incorrect sha-256: expected = {}, actual = {}", oid,
                    actual_hash);
      return;
    }

    // Now send the object back to the client:
    auto input_stream =
        std::make_shared<std::ifstream>(download_path, std::ios::in | std::ios::binary);
    ASSERT(input_stream->good(), "Failed opening file: {}", download_path.string());

    // set_content_provider returns immediately, and our lambda is executed later:
    res.status = 200;
    res.set_content_provider(
        object_size, std::string{lfs::mime_type},
        [input_stream = std::move(input_stream), download_path](
            std::size_t offset, std::size_t length, httplib::DataSink& sink) -> bool {
          constexpr std::size_t max_read_size = 1024 * 1024 * 8;
          const std::size_t actual_len = std::min(length, max_read_size);
          std::vector<char> buffer(actual_len);
          input_stream->seekg(static_cast<std::streamsize>(offset), std::ios::beg);
          input_stream->read(buffer.data(), static_cast<std::streamsize>(actual_len));
          if (!input_stream->operator bool()) {
            return false;
          }
          sink.write(buffer.data(), actual_len);
          return true;
        },
        [storage_path, oid, object_size](bool success) {
          // Once writing is done we clean up:
          if (success) {
            spdlog::info("Successfully served: oid = {}, size = {}", oid, object_size);
          } else {
            spdlog::error("Error occurred serving file from: \"{}\", oid = {}, size = {}",
                          storage_path.string(), oid, object_size);
          }
          std::error_code err_code{};
          if (!fs::remove_all(storage_path, err_code)) {
            spdlog::error("Failed to remove temporary file: {} (code = {}, message = {})",
                          storage_path.string(), err_code.value(), err_code.message());
          }
        });
  } else {
    FillWithError(res, error_code::validation_error, "Invalid MIME type requested: \"{}\"", accept);
    return;
  }
}

std::string Server::ComputeFileHash(const std::filesystem::path& path, std::size_t expected_size) {
  // Compute hash:
  std::ifstream input_stream{path, std::ios::in | std::ios::binary};
  ASSERT(input_stream.is_open(), "Failed to open file: {}", path.string());

  // Space for temporary data used while hashing
  std::vector<char> buffer{};
  buffer.resize(1024 * 1024);

  lfs::Hasher hasher{};
  for (std::size_t bytes_read = 0; bytes_read < expected_size;) {
    const std::size_t bytes_remaining = expected_size - bytes_read;
    const auto bytes_to_read = std::min(buffer.size(), bytes_remaining);
    const auto bytes_to_read_signed = static_cast<std::streamsize>(bytes_to_read);

    // We know the file size in advance, so this should not fail:
    input_stream.read(buffer.data(), bytes_to_read_signed);
    ASSERT(input_stream, "Read failed (bytes read = {} of {})", bytes_read, expected_size);

    hasher.Update(std::string_view{buffer.data(), bytes_to_read});
    bytes_read += bytes_to_read;
  }
  return StringFromSha256(hasher.GetHash());
}

template <typename... Ts>
void Server::FillWithError(httplib::Response& res, lfs::error_code code,
                           Ts&&... format_args) const {
  const lfs::error_response_t error_response{std::forward<Ts>(format_args)...};
  const std::string message = lfs::EncodeResponse(error_response);
  spdlog::error(message);
  res.status = static_cast<int>(code);
  res.set_content(message, std::string(lfs::mime_type_json));
}

}  // namespace lfs

template <>
struct fmt::formatter<Aws::Transfer::TransferStatus> {
  constexpr auto parse(format_parse_context& ctx) -> format_parse_context::iterator {
    return ctx.begin();
  }

  auto format(const Aws::Transfer::TransferStatus& status, format_context& ctx) const
      -> format_context::iterator {
    std::stringstream stream;
    stream << status;
    return fmt::format_to(ctx.out(), "{}", stream.str());
  }
};
