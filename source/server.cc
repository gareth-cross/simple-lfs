#include "server.hpp"

#include <filesystem>
#include <regex>
#include <string>

#include <scope_guard.hpp>

#include <aws/core/auth/AWSCredentials.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/GetObjectAttributesRequest.h>
#include <aws/s3/model/ListObjectsRequest.h>
#include <aws/transfer/TransferManager.h>

#include "assertions.hpp"
#include "error_type.hpp"
#include "hashing.hpp"
#include "uuid.hpp"

namespace S3 = Aws::S3;
namespace Transfer = Aws::Transfer;
namespace fs = std::filesystem;

namespace lfs {

Server::Server(std::shared_ptr<const Configuration> config)
    : config_(std::move(config)), storage_(config_) {
  // Configure the http server to allow large uploads:
  http_server_.set_read_timeout(std::chrono::seconds(3600));
  http_server_.set_write_timeout(std::chrono::seconds(3600));
}

tl::expected<void, Error> Server::Run() {
  // Itemize contents of the S3 bucket and start the uploader:
  if (auto maybe_init = storage_.Initialize(); !maybe_init) {
    return maybe_init;
  }

  // Make sure the upload directory exists:
  std::error_code ec{};
  if (!fs::exists(config_->upload_location) &&
      !fs::create_directories(config_->upload_location, ec)) {
    return tl::unexpected<Error>("Failed while creating path \"{}\": {}",
                                 config_->upload_location.string(), ec.message());
  }

  SetupRoutes();
  spdlog::info("Starting server on port {}...", config_->port);
  if (!http_server_.listen("0.0.0.0", config_->port)) {
    return tl::unexpected<Error>("Unable to start HTTP server (port probably already in use).");
  }
  return {};
}

void Server::Stop() {
  http_server_.stop();
  storage_.OnExit();
}

void Server::SetupRoutes() {
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
}

void Server::HandleException(const httplib::Request& req, httplib::Response& res,
                             std::exception_ptr ep) const {
  res.status = 500;
  std::string response{};
  try {
    std::rethrow_exception(ep);
  } catch (std::exception& e) {
    spdlog::error("Exception thrown during request handling. Message = \"{}\", Request = {} {}",
                  e.what(), req.method, req.path);
    response = EncodeResponse(lfs::error_response_t{"Internal error: {}", e.what()});
  } catch (...) {
    spdlog::error("Unknown exception thrown during request handling. Request = {} {}", req.method,
                  req.path);
    throw;
  }
  res.set_content(response, std::string(lfs::mime_type_json));
}

void Server::HandleBatchPost(const httplib::Request& req, httplib::Response& res) {
  // Decode into batch request object:
  const lfs::objects_batch_t batch = lfs::DecodeObjectBatch(req.body);
  if (batch.hash_algo != lfs::sha256) {
    // Client does not use the same hash function as we do:
    FillWithError(res, lfs::error_code::invalid_hash_algorithm,
                  "The server does not support hash algorithm: \"{}\"", batch.hash_algo);
    return;
  }

  lfs::response_t response{};
  std::size_t num_downloads = 0;
  for (const lfs::object_t& obj : batch.objects) {
    // Query the object size:
    const auto maybe_size = storage_.ObjectSize(obj.oid);
    if (maybe_size) {
      ASSERT_EQUAL(obj.size, maybe_size.value(), "Requested size does not match server value.");

      // The object exists, so return a download URL:
      lfs::action_url_t download{fmt::format("http://{}/objects/{}", config_->hostname, obj.oid),
                                 {{"Accept", std::string(lfs::mime_type)}}};
      ++num_downloads;
      response.objects.emplace_back(lfs::object_actions_t{obj, "download", std::move(download)});
    } else {
      // Tell the client how to upload this object:
      lfs::action_url_t upload{fmt::format("http://{}/objects/{}", config_->hostname, obj.oid),
                               {{"Accept", std::string(lfs::mime_type_json)}}};
      response.objects.emplace_back(lfs::object_actions_t{obj, "upload", std::move(upload)});
    }
  }

  spdlog::info("Handling batch request from \"{}\": total = {}, down = {}, up = {}",
               req.remote_addr, batch.objects.size(), num_downloads,
               batch.objects.size() - num_downloads);

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
  const fs::path upload_filename =
      config_->upload_location / fmt::format("{}.{}", obj.oid, GenerateUuidString());

  // On completion, we will remove this directory.
  const auto cleanup = sg::make_scope_guard([&] {
    if (fs::exists(upload_filename)) {
      std::error_code ec{};
      fs::remove(upload_filename, ec);
    }
  });

  if (const fs::space_info space = fs::space(config_->upload_location);
      space.available < obj.size) {
    FillWithError(res, lfs::error_code::internal_error,
                  "Insufficient space to receive file: oid = {}, required = {}, available = {}",
                  obj.oid, obj.size, space.available);
    return;
  }

  std::ofstream output_stream{upload_filename, std::ios::out | std::ios::binary};
  output_stream.exceptions(std::ios::failbit | std::ios::badbit);

  // Receive the object body:
  lfs::Hasher hasher{};
  std::size_t bytes_written = 0;
  content_reader([&](const char* data, size_t data_length) {
    try {
      output_stream.write(data, static_cast<std::streamsize>(data_length));
    } catch (const std::ios_base::failure& failure) {
      spdlog::error("Failure while writing: \"{}\", error = {}", failure.what());
      return false;
    }
    if (!output_stream) {
      return false;
    }
    hasher.Update({data, data_length});
    bytes_written += data_length;
    return bytes_written < obj.size;  //  Don't read past the declared size.
  });
  output_stream.flush();
  output_stream.close();

  // Check that the size matches our expectations:
  if (bytes_written != obj.size) {
    FillWithError(res, lfs::error_code::validation_error,
                  "Object size does not match. oid = {}, expected = {}, actual = {}", obj.oid,
                  obj.size, bytes_written);
    return;
  }

  // Compute the hash:
  lfs::Sha256 final_hash = hasher.GetHash();

  // Check the hash:
  if (const std::string final_hash_string = lfs::StringFromSha256(final_hash);
      final_hash_string != obj.oid) {
    FillWithError(res, lfs::error_code::validation_error,
                  "Object hash does not match. expected = {}, actual = {}", obj.oid,
                  final_hash_string);
    return;
  }

  spdlog::info("Received object: oid = {}, size = {}", obj.oid, obj.size);

  // Move the object to storage location:
  auto maybe_put = storage_.PutObject(obj, upload_filename);
  if (!maybe_put) {
    FillWithError(res, maybe_put.error());
    return;
  }

  // Create a response w/ a download URL to indicate success.
  lfs::response_t response{};
  lfs::action_url_t download{fmt::format("http://{}/objects/{}", config_->hostname, obj.oid),
                             {{"Accept", std::string(lfs::mime_type)}}};
  response.objects.emplace_back(lfs::object_actions_t{obj, "download", std::move(download)});

  std::string response_str = EncodeResponse(response);
  res.set_content(response_str, std::string(lfs::mime_type_json));
  res.status = 201;
}

void Server::HandleObjectGet(const httplib::Request& req, httplib::Response& res) {
  // Pull the oid from the URL:
  ASSERT_GREATER_OR_EQ(req.matches.size(), 2);
  const std::string oid = req.matches[1].str();

  // Does the object exist:
  const auto maybe_size = storage_.ObjectSize(oid);
  if (!maybe_size) {
    FillWithError(res, error_code::object_does_not_exist, "Object {} does not exist.", oid);
    return;
  }

  // See whether client is requesting meta-data, or the object itself:
  const std::string accept = req.get_header_value("Accept");
  if (accept == lfs::mime_type_json) {
    // Client is requesting meta-data about an object:
    lfs::response_t response{};
    lfs::action_url_t download{fmt::format("http://{}/objects/{}", config_->hostname, oid),
                               {{"Accept", std::string(lfs::mime_type)}}};
    response.objects.emplace_back(lfs::object_actions_t{lfs::object_t{oid, maybe_size.value()},
                                                        "download", std::move(download)});

    const std::string response_str = EncodeResponse(response);
    res.set_content(response_str, std::string(lfs::mime_type_json));
    res.status = 200;
  } else if (accept == lfs::mime_type) {
    // Client is requesting the object data itself:
    DownloadAndSendObject(oid, maybe_size.value(), res);
  } else {
    FillWithError(res, error_code::validation_error, "Invalid content type requested: \"{}\"",
                  accept);
  }
}

void Server::DownloadAndSendObject(const std::string& oid, const std::size_t object_size,
                                   httplib::Response& res) {
  tl::expected maybe_getter = storage_.GetObject(lfs::object_t{oid, object_size});
  if (!maybe_getter) {
    FillWithError(res, error_code::internal_error, "Internal error: {}", maybe_getter.error());
    return;
  }

  ObjectGetter::shared_ptr getter = maybe_getter.value();
  ASSERT(getter);

  // set_content_provider returns immediately, and our lambda is executed later:
  res.status = 200;
  res.set_content_provider(
      object_size, std::string{lfs::mime_type},
      [getter](std::size_t offset, std::size_t length, httplib::DataSink& sink) -> bool {
        // httplib does not catch exceptions in the content provider, so we do it
        try {
          std::vector<char> buffer(length);
          const tl::expected<std::size_t, Error> maybe_actual_length =
              getter->Read(offset, length, buffer.data());
          if (maybe_actual_length) {
            sink.write(buffer.data(), maybe_actual_length.value());
          } else {
            spdlog::error(maybe_actual_length.error());
            return false;
          }
          return true;
        } catch (std::exception& exception) {
          spdlog::error("Exception while sending content: {}", exception.what());
          return false;
        }
      },
      [getter](bool success) { getter->Finalize(success); });
}

template <typename... Ts>
void Server::FillWithError(httplib::Response& res, lfs::error_code code,
                           Ts&&... format_args) const {
  std::string message = fmt::format(std::forward<Ts>(format_args)...);
  spdlog::error(message);

  const lfs::error_response_t error_response{std::move(message)};
  res.status = static_cast<int>(code);
  res.set_content(lfs::EncodeResponse(error_response), std::string(lfs::mime_type_json));
}

void Server::FillWithError(httplib::Response& res, const Error& error) const {
  spdlog::error(error.Message());

  const lfs::error_response_t error_response{error.Message()};
  res.status = static_cast<int>(lfs::error_code::internal_error);
  res.set_content(lfs::EncodeResponse(error_response), std::string(lfs::mime_type_json));
}

}  // namespace lfs
