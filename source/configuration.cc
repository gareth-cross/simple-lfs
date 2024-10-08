#include "configuration.hpp"

#include <fmt/core.h>
#include <fmt/ostream.h>

#define TOML_EXCEPTIONS 0
#include <toml++/toml.h>

namespace lfs {

namespace fs = std::filesystem;

tl::expected<std::shared_ptr<const Configuration>, std::string> LoadConfig(
    const std::filesystem::path& path) {
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
  if (auto credentials = table["credentials"]; credentials && credentials.is_table()) {
    // Check that both fields were provided:
    auto access_key_id = credentials["access_key_id"].value<std::string>();
    auto secret_access_key = credentials["secret_access_key"].value<std::string>();
    if (!access_key_id || !secret_access_key) {
      return tl::unexpected(fmt::format("Missing access_key_id or secret_access_key."));
    }
    config.credentials = Credentials{*access_key_id, *secret_access_key};
  }

  // Bucket name must be specified, since there is no reasonable default for this:
  auto bucket_name = table["bucket_name"].value<std::string>();
  if (!bucket_name) {
    return tl::unexpected("The field bucket_name is missing from the configuration file.");
  }
  config.bucket_name = bucket_name.value();

  // Bucket region can be left at the default value:
  config.bucket_region = table["bucket_region"].value<std::string>().value_or("");

  // endpoint is optional, we don't need to assign a default here:
  config.endpoint = table["endpoint"].value<std::string>();

  if (auto storage_location = table["storage_location"].value<std::string>(); storage_location) {
    config.storage_location = storage_location.value();
  } else {
    return tl::unexpected("Parameter `storage_location` must be specified.");
  }

  if (auto upload_location = table["upload_location"].value<std::string>(); upload_location) {
    config.upload_location = upload_location.value();
  } else {
    // If unspecified, default to /tmp (or whatever Windows selects, which is usually AppData).
    config.upload_location = fs::temp_directory_path() / "lfs";
  }

  config.hostname = table["hostname"].value<std::string>().value_or("localhost");

  if (auto port = table["port"].value<int>(); port) {
    config.port = port.value();
    constexpr auto port_max = std::numeric_limits<int16_t>::max();
    if (config.port < 1 || config.port > port_max) {
      return tl::unexpected(
          fmt::format("Port value must be in range [1, {}], invalid value specified: {}", port_max,
                      config.port));
    }
  }
  return std::make_shared<const Configuration>(std::move(config));
}

}  // namespace lfs

template <>
struct fmt::formatter<toml::parse_error> : fmt::ostream_formatter {};
