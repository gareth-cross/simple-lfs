#include "server.hpp"

#include <optional>
#include <string>

#include <scope_guard.hpp>

#include <aws/core/auth/AWSCredentials.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/GetObjectAttributesRequest.h>
#include <aws/transfer/TransferManager.h>

#include "assertions.hpp"
#include "hashing.hpp"

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
inline std::string KeyFromOid(const std::string& oid) {
  ASSERT_EQUAL(oid.size(), 64, "OID should be a sha256 value.");
  return fmt::format("{}/{}/{}", std::string_view{oid.data(), 2},
                     std::string_view{oid.data() + 2, 2},
                     std::string_view{oid.data() + 4, oid.size() - 4});
}

Server::Server() {
  // Create s3 client:
  const std::string access_id = GetEnv("ACCESS_KEY").value();
  const std::string access_key = GetEnv("ACCESS_SECRET").value();
  Aws::Auth::AWSCredentials credentials{access_id, access_key};

  S3::S3ClientConfiguration config{};
  config.region = "us-west-1";

  auto endpoint_provider = Aws::MakeShared<S3::S3EndpointProvider>(S3::S3Client::ALLOCATION_TAG);
  s3_client_ = std::make_shared<S3::S3Client>(credentials, endpoint_provider, config);

  pooled_executor_ = Aws::MakeShared<Aws::Utils::Threading::PooledThreadExecutor>("executor", 16);

  Transfer::TransferManagerConfiguration transfer_config(pooled_executor_.get());
  transfer_config.s3Client = s3_client_;
  transfer_config.computeContentMD5 = true;
  transfer_config.errorCallback = [](const Transfer::TransferManager*,
                                     const std::shared_ptr<const Transfer::TransferHandle>&,
                                     const Aws::Client::AWSError<S3::S3Errors>& error) {
    spdlog::error("Error during S3 transfer [Exception = {}]: {}", error.GetExceptionName(),
                  error.GetMessage());
  };

  transfer_manager_ = Transfer::TransferManager::Create(transfer_config);
}

void Server::Run() {
  spdlog::info("Starting server...");
  //
  //  http_server_.Put(
  //      R"(/objects/([a-zA-Z0-9]+)/([0-9]+))",
  //      [&](const httplib::Request& req, httplib::Response& res,
  //          const httplib::ContentReader& content_reader) {
  //        ASSERT_GREATER_OR_EQ(req.matches.size(), 3);
  //        const lfs::object_t obj{req.matches[1].str(), std::stoull(req.matches[2].str())};
  //
  //        lfs::Hasher hasher{};
  //
  //        // create temporary directory
  //        UUID uuid;
  //        const auto uuid_status = UuidCreate(&uuid);
  //        ASSERT_EQUAL(RPC_S_OK, uuid_status);
  //
  //        RPC_CSTR uuid_str = nullptr;
  //        const auto uuid_convert_result = UuidToString(&uuid, &uuid_str);
  //        const auto cleanup = sg::make_scope_guard([&] { RpcStringFree(&uuid_str); });
  //        ASSERT_EQUAL(RPC_S_OK, uuid_convert_result);
  //
  //        std::string uuid_str_converted{reinterpret_cast<const char*>(uuid_str)};
  //        uuid_str_converted.erase(
  //            std::remove(uuid_str_converted.begin(), uuid_str_converted.end(), '-'),
  //            uuid_str_converted.end());
  //
  //        const fs::path local_path = tmp / uuid_str_converted;
  //        fs::create_directories(local_path);
  //        const auto cleanup_local_path = sg::make_scope_guard([&] {
  //          // Don't throw here, since an exception might already be in flight:
  //          std::error_code err_code{};
  //          if (!fs::remove_all(local_path, err_code)) {
  //            spdlog::error("Failed to remove temporary file: {} (code = {}, message = {})",
  //                          local_path.string(), err_code.value(), err_code.message());
  //          }
  //        });
  //
  //        // todo: check space
  //        const auto space = fs::space(local_path);
  //
  //        spdlog::info("Local path: {}", local_path.string());
  //
  //        const fs::path filename = local_path / obj.oid;
  //        std::ofstream output_stream{filename, std::ios::out | std::ios::binary};
  //        std::size_t bytes_written = 0;
  //
  //        // Receive the object body:
  //        content_reader([&](const char* data, size_t data_length) {
  //          output_stream.write(data, static_cast<std::streamsize>(data_length));
  //          if (!output_stream) {
  //            return false;
  //          }
  //          hasher.Update({data, data_length});
  //          bytes_written += data_length;
  //          return bytes_written < obj.size;  //  Don't read past the declared size.
  //        });
  //
  //        output_stream.flush();
  //
  //        // Check that the size matches our expectations:
  //        if (bytes_written != obj.size) {
  //          const lfs::error_response_t error_response{
  //              "Object size does not match. expected = {}, actual = {}", obj.size,
  //              bytes_written};
  //          res.set_content(lfs::EncodeResponse(error_response),
  //          std::string(lfs::mime_type_json)); res.status =
  //          static_cast<int>(lfs::error_code::validation_error); return;
  //        }
  //
  //        // Compute the hash:
  //        lfs::Sha256 final_hash = hasher.GetHash();
  //        spdlog::info("Computed SHA256 hash: {} (expected = {})",
  //        lfs::StringFromSha256(final_hash),
  //                     obj.oid);
  //
  //        //        if (!final_hash) {
  //        //          const lfs::error_response_t error_response{"Failed to compute SHA256
  //        hash."};
  //        //          res.set_content(lfs::EncodeResponse(error_response),
  //        //          std::string(lfs::mime_type_json)); res.status =
  //        //          static_cast<int>(lfs::error_code::internal_error); return;
  //        //        } else {
  //
  //        //        }
  //
  //        std::shared_ptr<Aws::Transfer::TransferHandle> handle = transfer_manager_->UploadFile(
  //            filename.string(), "ortho-fs", obj.oid, "application/octet-stream", {});
  //        handle->WaitUntilFinished();
  //
  //        if (handle->GetStatus() != Transfer::TransferStatus::COMPLETED) {
  //          spdlog::error("Failed to transfer object (oid = {}, size = {}), status is {}",
  //          obj.oid,
  //                        obj.size, handle->GetStatus());
  //        } else {
  //          spdlog::info("Transfer successful: oid = {}, size = {}", obj.oid, obj.size);
  //        }
  //
  //        lfs::response_t response{};
  //        response.objects.emplace_back(CreateActionResponse(obj, "download"));
  //
  //        std::string response_str = EncodeResponse(response);
  //        res.set_content(response_str, std::string(lfs::mime_type_json));
  //        res.status = 200;
  //      });

  http_server_.Post("/objects/batch", [&](const httplib::Request& req, httplib::Response& res) {
    HandleBatchPost(req, res);
  });

  http_server_.set_exception_handler(
      [this](const httplib::Request& req, httplib::Response& res, std::exception_ptr ep) {
        HandleException(req, res, ep);
      });

  http_server_.listen("0.0.0.0", 80);
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
            .WithBucket("ortho-fs")
            .WithKey(key)
            .WithObjectAttributes({S3::Model::ObjectAttributes::ObjectSize}));

    if (outcome.IsSuccess()) {
      const S3::Model::GetObjectAttributesResult& result = outcome.GetResult();
      const auto size = static_cast<std::size_t>(result.GetObjectSize());

      if (size == obj.size) {
        // The object exists and the size is correct:
      } else {
        // Object exists, but size is mismatched...
      }
    } else {
      const auto& error = outcome.GetError();
      if (error.GetErrorType() == S3::S3Errors::NO_SUCH_KEY) {
        // Tell the client to upload this object:
        lfs::action_url_t upload{fmt::format("http://localhost/objects/{}/{}", obj.oid, obj.size),
                                 {{"Accept", std::string(lfs::mime_type)}}};

        response.objects.emplace_back(lfs::object_actions_t{obj, {{"upload", std::move(upload)}}});
      } else {
        // Return any other AWS error as an internal error:
        std::string message = fmt::format(
            R"(Internal error accessing object. Type = {}, Exception = "{}", Message = "{}")",
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
