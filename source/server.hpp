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
  explicit Server(const Configuration& config);

  // Run the server. Returns unexpected if we could not start the server.
  [[nodiscard]] tl::expected<void, Error> Run();

 private:
  Configuration config_;

  httplib::Server http_server_{};

  // Manages uploads and downloads from S3.
  lfs::Storage storage_;

  std::atomic_int64_t num_active_uploads_{0};

  // Configure routes on the http server.
  void SetupRoutes();

  // Convert exception to HTTP response.
  void HandleException(const httplib::Request& req, httplib::Response& res, std::exception_ptr ep);

  // Handle a batch POST.
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
