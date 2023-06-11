#include <filesystem>
#include <fstream>
#include <optional>

#include <fmt/format.h>
#include <httplib.h>
#include <spdlog/spdlog.h>
#include <scope_guard.hpp>

#include <aws/core/auth/AWSCredentials.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/GetObjectAttributesRequest.h>
#include <aws/transfer/TransferManager.h>

#include "assertions.hpp"
#include "aws/core/Aws.h"

#include "hashing.hpp"
#include "server.hpp"
#include "structs.hpp"

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

namespace S3 = Aws::S3;
namespace Transfer = Aws::Transfer;

lfs::object_actions_t CreateActionResponse(const lfs::object_t& obj, const std::string& action) {
  lfs::object_actions_t res{};
  res.oid = obj.oid;
  res.size = obj.size;

  std::map<std::string, std::string> header = {{"Accept", std::string(lfs::mime_type)}};
  lfs::action_url_t upload{fmt::format("http://localhost/objects/{}/{}", res.oid, res.size),
                           std::move(header)};
  res.actions.emplace(action, std::move(upload));
  return res;
}

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

int main(int, char**) {
  //  httplib::Server server;

  namespace fs = std::filesystem;

  fs::path tmp = fs::temp_directory_path();
  spdlog::info("Temp directory: {}", tmp.string());

  Aws::SDKOptions options{};
  Aws::InitAPI(options);
  const auto api_exit = sg::make_scope_guard([&] { Aws::ShutdownAPI(options); });

  lfs::Server server;
  server.Run();

  // Create s3 client:
  //  const std::string access_id = GetEnv("ACCESS_KEY").value();
  //  const std::string access_key = GetEnv("ACCESS_SECRET").value();
  //  Aws::Auth::AWSCredentials credentials{access_id, access_key};
  //
  //  S3::S3ClientConfiguration config{};
  //  config.region = "us-west-1";
  //
  //  auto endpoint_provider =
  //      Aws::MakeShared<Aws::S3::S3EndpointProvider>(S3::S3Client::ALLOCATION_TAG);
  //  std::shared_ptr<S3::S3Client> client =
  //      std::make_shared<S3::S3Client>(credentials, endpoint_provider, config);
  //
  //  auto aws_executor = Aws::MakeShared<Aws::Utils::Threading::PooledThreadExecutor>("executor",
  //  16);
  //
  //  Transfer::TransferManagerConfiguration transfer_config(aws_executor.get());
  //  transfer_config.s3Client = client;
  //  transfer_config.computeContentMD5 = true;
  //  transfer_config.errorCallback = [](const Transfer::TransferManager*,
  //                                     const std::shared_ptr<const Transfer::TransferHandle>&,
  //                                     const Aws::Client::AWSError<Aws::S3::S3Errors>& error) {
  //    spdlog::error("Error during S3 transfer [Exception = {}]: {}", error.GetExceptionName(),
  //                  error.GetMessage());
  //  };
  //
  //  std::shared_ptr<Transfer::TransferManager> transfer_manager =
  //      Transfer::TransferManager::Create(transfer_config);
  //
  //  //  const auto outcome = client->GetObjectAttributes(
  //  //      S3::Model::GetObjectAttributesRequest{}
  //  //          .WithBucket("ortho-fs")
  //  //          .WithKey("49/bc/"
  //  //                   "20df15e412a64472421e13fe86ff1c5165e18b2afccf160d4dc19fe68a14")
  //  //          .WithObjectAttributes({S3::Model::ObjectAttributes::ObjectSize}));
  //  //
  //  //  if (!outcome.IsSuccess()) {
  //  //    const S3::S3Error& err = outcome.GetError();
  //  //    spdlog::error("Error: GetObject [Exception = {}]: {}", err.GetExceptionName(),
  //  //                  err.GetMessage());
  //  //  }
  //
  //  server.Put(
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
  //        std::shared_ptr<Aws::Transfer::TransferHandle> handle = transfer_manager->UploadFile(
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
  //
  //  server.Post("/objects/batch", [&](const httplib::Request& req, httplib::Response& res) {
  //    // Decode into batch request object:
  //    const lfs::objects_batch_t req_converted = lfs::DecodeObjectBatch(req.body);
  //
  //    lfs::response_t response{};
  //    if (req_converted.operation == lfs::operation::upload) {
  //      std::transform(req_converted.objects.begin(), req_converted.objects.end(),
  //                     std::back_inserter(response.objects),
  //                     [](const lfs::object_t& obj) { return CreateActionResponse(obj, "upload");
  //                     });
  //    }
  //
  //    std::string response_str = EncodeResponse(response);
  //    res.set_content(response_str, std::string(lfs::mime_type_json));
  //    res.status = 200;
  //  });
  //
  //  server.set_exception_handler(
  //      [](const httplib::Request& req, httplib::Response& res, std::exception_ptr ep) {
  //        std::string exception_string{};
  //        try {
  //          std::rethrow_exception(ep);
  //        } catch (std::exception& e) {
  //          exception_string = e.what();
  //        } catch (...) {
  //          exception_string = "<Unknown exception>";
  //        }
  //        spdlog::error("Exception thrown during request handling. Failure = {}, Request = {}",
  //                      exception_string, req.body);
  //
  //        const std::string response = fmt::format("<h1>Error 500</h1><p>{}</p>",
  //        exception_string); res.set_content(response, "text/plain"); res.status = 500;
  //      });
  //
  //  spdlog::info("Starting server...");
  //  server.listen("0.0.0.0", 80);

  return 0;
}
