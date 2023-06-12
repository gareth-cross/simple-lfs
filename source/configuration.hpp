#pragma once
#include <filesystem>
#include <optional>
#include <string>

#include <tl/expected.hpp>

namespace lfs {

struct Credentials {
  std::string access_key_id;
  std::string secret_access_key;
};

// Server configuration parameters.
struct Configuration {
  // AWS access credentials.
  std::optional<Credentials> credentials{};

  // Bucket name to store LFS files in.
  std::string bucket_name;

  // Bucket region.
  std::optional<std::string> bucket_region;

  // Local storage directory for uploaded files.
  std::filesystem::path local_storage;

  // Network port to serve HTTP request on.
  int port{80};
};

// Load configuration TOML file from the specified path.
// On failure, returns a string message indicating the failure.
tl::expected<Configuration, std::string> LoadConfig(const std::filesystem::path& path);

}  // namespace lfs
