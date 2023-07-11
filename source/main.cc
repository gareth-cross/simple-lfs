#include <spdlog/spdlog.h>
#include <CLI/App.hpp>
#include <CLI/Config.hpp>     //  Required for linking.
#include <CLI/Formatter.hpp>  //  Required for linking.
#include <scope_guard.hpp>

#include <aws/core/Aws.h>

#include "configuration.hpp"
#include "server.hpp"

// Global: Called on exit when the user interrupts the server.
// This is global so the signal handler can access it.
std::function<void(void)> exit_handler_global;

#ifdef _WIN32
#include <windows.h>

// Signal handler on windows:
BOOL WINAPI CtrlHandler(DWORD fdw_ctrl_type) {
  switch (fdw_ctrl_type) {
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT: {
      spdlog::warn("Received Ctrl-C (control type: {})",
                   fdw_ctrl_type == CTRL_C_EVENT ? "CTRL_C_EVENT" : "CTRL_CLOSE_EVENT");
      if (exit_handler_global) {
        exit_handler_global();
      }
      return TRUE;
    }
    default:
      return FALSE;
  }
}
#else  //  _WIN32
#include <signal.h>
#include <string.h>

// Signal handler on *nix.
void SigHandler(int signum) {
  switch (signum) {
    case SIGINT:
    case SIGQUIT: {
      spdlog::warn(R"(Received signal: "{}")", strsignal(signum));
      if (exit_handler_global) {
        exit_handler_global();
      }
      break;
    }
    default:
      break;
  }
}
#endif

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

  // Initialize AWS SDK
  Aws::SDKOptions options{};
  Aws::InitAPI(options);
  const auto api_exit = sg::make_scope_guard([&] { Aws::ShutdownAPI(options); });

  // Construct the server w/ our values loaded from the config.
  lfs::Server server{config_expected.value()};

  // Configure handler for Ctrl-C/termination:
  exit_handler_global = [&]() { server.Stop(); };

#ifdef _WIN32
  SetConsoleCtrlHandler(CtrlHandler, TRUE);
#else  //  _WIN32
  signal(SIGINT, SigHandler);
  signal(SIGQUIT, SigHandler);
#endif

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
