#pragma once
#include <filesystem>

#include <httplib.h>

#include "configuration.hpp"
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
  explicit Server(const Configuration& config);

  // Run the HTTP server.
  void Run();

 private:
  Configuration config_;

  httplib::Server http_server_{};

  std::shared_ptr<Aws::S3::S3Client> s3_client_;
  std::shared_ptr<Aws::Utils::Threading::PooledThreadExecutor> pooled_executor_;
  std::shared_ptr<Aws::Transfer::TransferManager> transfer_manager_;

  // Convert exception to HTTP response.
  void HandleException(const httplib::Request& req, httplib::Response& res, std::exception_ptr ep);

  // Handle a batch POST.
  void HandleBatchPost(const httplib::Request& req, httplib::Response& res);

  // Handle a PUT request to upload a file.
  void HandleObjectPut(const httplib::Request& req, httplib::Response& res,
                       const httplib::ContentReader& content_reader);

  // Handle a GET request to download a file.
  void HandleObjectGet(const httplib::Request& req, httplib::Response& res);

  // Compute the hash of the specified file.
  static std::string ComputeFileHash(const std::filesystem::path& path, std::size_t expected_size);

  // Fill response w/ an error.
  template <typename... Ts>
  void FillWithError(httplib::Response& res, lfs::error_code code, Ts&&... format_args) const;
};

}  // namespace lfs
