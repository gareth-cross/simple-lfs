#include "configuration.hpp"

#include <fmt/core.h>

#define TOML_EXCEPTIONS 0
#include <toml++/toml.h>

namespace lfs {

namespace fs = std::filesystem;

tl::expected<Configuration, std::string> LoadConfig(const std::filesystem::path& path) {
  if (!fs::exists(path)) {
    return tl::unexpected(fmt::format("Configuration file does not exist: {}", path.string()));
  }

  auto table = toml::parse_file(path.string());
  if (!table) {
    const toml::parse_error& err = table.error();
    std::string message = fmt::format("Failed while parsing configuration TOML. Error:\n{}", err);
    return tl::unexpected(std::move(message));
  }

  Configuration config{};
  auto credentials = table["credentials"];
  if (credentials && credentials.is_table()) {
    // Check that both fields were provided:
    auto access_key_id = credentials["access_key_id"].value<std::string>();
    auto secret_access_key = credentials["secret_access_key"].value<std::string>();
    if (!access_key_id || !secret_access_key) {
      return tl::unexpected(fmt::format("Missing access_key_id or secret_access_key."));
    }
    config.credentials = Credentials{*access_key_id, *secret_access_key};
  }

  auto bucket_name = table["bucket_name"].value<std::string>();
  if (!bucket_name) {
    return tl::unexpected("The field bucket_name is missing from the configuration file.");
  }
  config.bucket_name = bucket_name.value();

  // Bucket region can be left at the default value:
  auto bucket_region = table["bucket_region"].value<std::string>();
  if (bucket_region) {
    config.bucket_region = bucket_region.value();
  }

  auto local_storage = table["local_storage"].value<std::string>();
  if (local_storage) {
    config.local_storage = local_storage.value();
  } else {
    config.local_storage = fs::temp_directory_path();
  }

  auto port = table["port"].value<int>();
  if (port) {
    config.port = port.value();
    constexpr auto port_max = std::numeric_limits<int16_t>::max();
    if (config.port < 1 || config.port > port_max) {
      return tl::unexpected(
          fmt::format("Port value must be in range [1, {}], invalid value specified: {}", port_max,
                      config.port));
    }
  }
  return config;
}

}  // namespace lfs

template <>
struct fmt::formatter<toml::parse_error> {
  constexpr auto parse(format_parse_context& ctx) -> format_parse_context::iterator {
    return ctx.begin();
  }

  auto format(const toml::parse_error& err, format_context& ctx) const -> format_context::iterator {
    std::stringstream stream;
    stream << err;
    return fmt::format_to(ctx.out(), "{}", stream.str());
  }
};
