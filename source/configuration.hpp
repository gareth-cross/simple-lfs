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
  // If unspecified, the AWS SDK resolves the credentials itself.
  std::optional<Credentials> credentials{};

  // Bucket name to store LFS files in.
  std::string bucket_name;

  // Bucket region.
  // If unspecified, this is left at whatever default the AWS SDK chooses.
  std::optional<std::string> bucket_region;

  // End-point override.
  // Can be used to specify an alternative bucket provider.
  std::optional<std::string> endpoint;

  // Local storage directory for cache of objects.
  std::filesystem::path storage_location;

  // Local temporary storage for uploads.
  std::filesystem::path upload_location;

  // Hostname for the server. Defaults to `localhost`.
  std::string hostname;

  // Network port to serve HTTP request on.
  int port{6000};
};

// Load configuration TOML file from the specified path.
// On failure, returns a string message indicating the failure.
tl::expected<std::shared_ptr<const Configuration>, std::string> LoadConfig(
    const std::filesystem::path& path);

}  // namespace lfs
