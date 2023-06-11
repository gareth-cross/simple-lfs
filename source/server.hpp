#pragma once
#include <httplib.h>

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
  Server();

  // Run the HTTP server.
  void Run();

 private:
  httplib::Server http_server_{};

  std::shared_ptr<Aws::S3::S3Client> s3_client_;
  std::shared_ptr<Aws::Transfer::TransferManager> transfer_manager_;
  std::shared_ptr<Aws::Utils::Threading::PooledThreadExecutor> pooled_executor_;

  // Convert exception to HTTP response.
  void HandleException(const httplib::Request& req, httplib::Response& res, std::exception_ptr ep);

  // Handle a batch POST (uploading files).
  void HandleBatchPost(const httplib::Request& req, httplib::Response& res);

  lfs::object_actions_t CreateActionResponse(const lfs::object_t& obj, const std::string& action);
};

}  // namespace lfs
