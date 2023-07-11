#include <spdlog/spdlog.h>
#include <CLI/App.hpp>
#include <CLI/Config.hpp>     //  Required for linking.
#include <CLI/Formatter.hpp>  //  Required for linking.
#include <scope_guard.hpp>

#include <aws/core/Aws.h>

#include "configuration.hpp"
#include "server.hpp"

int main() {
  CLI::App app{"A simple S3-backed git-lfs server."};

  std::string config_file{};
  app.add_option("-c,--config", config_file, "Path to the config file")->required(true);
  CLI11_PARSE(app)

  // Load the configuration file
  auto config_expected = lfs::LoadConfig(config_file);
  if (!config_expected) {
    spdlog::error("Error encountered while parsing configuration file: {}",
                  config_expected.error());
    return 1;
  }

  Aws::SDKOptions options{};
  Aws::InitAPI(options);
  const auto api_exit = sg::make_scope_guard([&] { Aws::ShutdownAPI(options); });

  lfs::Server server{config_expected.value()};
  try {
    if (auto maybe_error = server.Run(); !maybe_error) {
      spdlog::error("{}", maybe_error.error());
      return 1;
    }
  } catch (std::exception& e) {
    // Log unhandled exceptions to stdout before throwing.
    spdlog::error("Unhandled error: {}", e.what());
    throw;
  }
  return 0;
}
