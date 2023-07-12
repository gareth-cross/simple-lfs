#pragma once
#include <filesystem>

#include <httplib.h>

#include "configuration.hpp"
#include "storage.hpp"
#include "structs.hpp"

namespace Aws::S3 {
class S3Client;
}  // namespace Aws::S3

namespace Aws::Transfer {
class TransferManager;
}  // namespace Aws::Transfer

namespace Aws::Utils::Threading {
class PooledThreadExecutor;
}  // namespace Aws::Utils::Threading

namespace lfs {

// Main server object that handles HTTP requests.
struct Server {
 public:
  // Construct w/ configuration parameters.
  explicit Server(std::shared_ptr<const Configuration> config);

  // Run the server. Returns unexpected if we could not start the server.
  [[nodiscard]] tl::expected<void, Error> Run();

  // Stop the server (called from interrupt handler).
  void Stop();

 private:
  std::shared_ptr<const Configuration> config_;

  // HTTP server - we register POST/GET/PUT routes on this object.
  httplib::Server http_server_{};

  // Manages uploads and downloads from S3.
  lfs::Storage storage_;

  // Configure routes on the http server.
  void SetupRoutes();

  // Convert exception to HTTP response.
  // This is called if any code in the HTTP handler unexpectedly throws. We convert the exception
  // into a 500 "internal error" response.
  void HandleException(const httplib::Request& req, httplib::Response& res,
                       std::exception_ptr ep) const;

  // Handle a batch POST. Client uses this method to query the status of multiple (typically ~100)
  // objects at a time. For each object we check if it exists on the server and reply accordingly.
  void HandleBatchPost(const httplib::Request& req, httplib::Response& res);

  // Handle a PUT request to upload a file.
  void HandleObjectPut(const httplib::Request& req, httplib::Response& res,
                       const httplib::ContentReader& content_reader);

  // Handle a GET request to download a file.
  void HandleObjectGet(const httplib::Request& req, httplib::Response& res);

  // Download an object from bucket and stream it as part of response.
  void DownloadAndSendObject(const std::string& oid, std::size_t object_size,
                             httplib::Response& res);

  // Fill response w/ an error.
  template <typename... Ts>
  void FillWithError(httplib::Response& res, lfs::error_code code, Ts&&... format_args) const;

  // Fill response w/ message from `Error` object:
  void FillWithError(httplib::Response& res, const Error& error) const;
};

}  // namespace lfs
