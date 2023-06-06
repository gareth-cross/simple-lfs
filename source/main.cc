#include <optional>

#include <fmt/format.h>
#include <httplib.h>
#include <spdlog/spdlog.h>
#include <scope_guard.hpp>

#include <aws/core/auth/AWSCredentials.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/GetObjectAttributesRequest.h>

#include "assertions.hpp"
#include "aws/core/Aws.h"
#include "structs.hpp"

lfs::object_response_t CreateUploadResponse(const lfs::object_t& obj) {
  lfs::object_response_t res{};
  res.oid = obj.oid;
  res.size = obj.size;

  std::map<std::string, std::string> header = {{"Accept", std::string(lfs::mime_type)}};
  lfs::action_url_t upload{fmt::format("http://localhost/objects/{}/{}", res.oid, res.size),
                           std::move(header)};
  res.actions.emplace("upload", std::move(upload));
  return res;
}

std::optional<std::string> GetEnv(const std::string_view name) {
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
  httplib::Server server;
  //  server.Get("/info/lfs", [&](const httplib::Request& req, httplib::Response&) {
  //    fmt::print("Got request (info lfs):\n{}\n", req.body);
  //    //    res.set_content(, "text/plain");
  //  });

  //  server.Get("/objects/batch", [&](const httplib::Request& req, httplib::Response&) {
  //    fmt::print("Got request:\n{}\n", req.body);
  //    //    res.set_content(, "text/plain");
  //  });

  //  server.Put(R"(/objects/([a-zA-Z0-9]+))", [&](const httplib::Request& req, httplib::Response&)
  //  {
  ////    fmt::print("Got request:\n{}\n", req.body);
  //    fmt::print("match: {}\n", req.matches[1].str());
  //    //    res.set_content(, "text/plain");
  //  });

  Aws::SDKOptions options{};
  Aws::InitAPI(options);

  // Create s3 client:
  const std::string access_id = GetEnv("ACCESS_KEY").value();
  const std::string access_key = GetEnv("ACCESS_SECRET").value();
  Aws::Auth::AWSCredentials credentials{access_id, access_key};

  Aws::S3::S3ClientConfiguration config{};
  config.region = "us-west-1";

  auto endpoint_provider =
      Aws::MakeShared<Aws::S3::S3EndpointProvider>(Aws::S3::S3Client::ALLOCATION_TAG);
  std::unique_ptr<Aws::S3::S3Client> client =
      std::make_unique<Aws::S3::S3Client>(credentials, endpoint_provider, config);

  const auto outcome = client->GetObjectAttributes(
      Aws::S3::Model::GetObjectAttributesRequest{}
          .WithBucket("ortho-fs")
          .WithKey("49/bc/"
                   "20df15e412a64472421e13fe86ff1c5165e18b2afccf160d4dc19fe68a14")
          .WithObjectAttributes({Aws::S3::Model::ObjectAttributes::ObjectSize}));

  if (!outcome.IsSuccess()) {
    const Aws::S3::S3Error& err = outcome.GetError();
    spdlog::error("Error: GetObject [Exception = {}]: {}", err.GetExceptionName(),
                  err.GetMessage());
  }

  server.Put(R"(/objects/([a-zA-Z0-9]+)/([0-9]+))",
             [&](const httplib::Request& req, httplib::Response&, const httplib::ContentReader&) {
               ASSERT_GREATER_OR_EQ(req.matches.size(), 3);

               const lfs::object_t obj{req.matches[1].str(), std::stoull(req.matches[2].str())};

               fmt::print("match: {}, {}\n", req.matches[1].str(), req.is_multipart_form_data());
               //    res.set_content(, "text/plain");
             });

  server.Post("/objects/batch", [&](const httplib::Request& req, httplib::Response& res) {
    // Decode into batch request object:
    const lfs::objects_batch_t req_converted = lfs::DecodeObjectBatch(req.body);

    lfs::response_t response{};
    if (req_converted.operation == lfs::operation::upload) {
      std::transform(req_converted.objects.begin(), req_converted.objects.end(),
                     std::back_inserter(response.objects),
                     [](const lfs::object_t& obj) { return CreateUploadResponse(obj); });
    }

    std::string response_str = EncodeResponse(response);
    res.set_content(response_str, std::string(lfs::mime_type_json));
  });

  server.set_exception_handler(
      [](const httplib::Request& req, httplib::Response& res, std::exception_ptr ep) {
        std::string exception_string{};
        try {
          std::rethrow_exception(ep);
        } catch (std::exception& e) {
          exception_string = e.what();
        } catch (...) {
          exception_string = "<Unknown exception>";
        }
        spdlog::error("Exception thrown during request handling. Failure = {}, Request = {}",
                      exception_string, req.body);

        const std::string response = fmt::format("<h1>Error 500</h1><p>{}</p>", exception_string);
        res.set_content(response, "text/plain");
        res.status = 500;
      });

  spdlog::info("Starting server...");
  server.listen("0.0.0.0", 80);

  Aws::ShutdownAPI(options);
  return 0;
}
