#include "storage.hpp"

#include <fstream>
#include <numeric>
#include <regex>

#include <aws/core/auth/AWSCredentials.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/GetObjectAttributesRequest.h>
#include <aws/s3/model/ListObjectsRequest.h>
#include <aws/transfer/TransferManager.h>

#include "assertions.hpp"
#include "exception.hpp"
#include "hashing.hpp"
#include "uuid.hpp"

namespace S3 = Aws::S3;
namespace Transfer = Aws::Transfer;
namespace fs = std::filesystem;

#ifdef _WIN32
#pragma push_macro("GetMessage")  //  Stop leaking from windows unicode header...
#pragma push_macro("GetObject")
#undef GetMessage
#undef GetObject
#endif  //  _WIN32

namespace lfs {

struct SizePrinter {
  explicit SizePrinter(std::size_t bytes) : bytes(bytes) {}

  std::size_t bytes;
};

// Get the directory prefix for an OID. Per LFS convention, this is just the first 4 characters
// of the hash in two directory levels. Ie: a0b2c91x... --> a0/b2/a0b2c91x...
inline std::string KeyPrefixFromOid(const std::string& oid) {
  ASSERT_EQUAL(oid.size(), 64, "OID should be a sha256 value.");
  return fmt::format("{}/{}", std::string_view{oid.data(), 2}, std::string_view{oid.data() + 2, 2});
}

// `KeyPrefixFromOid`, but as a path.
inline fs::path DirectoryPrefixFromOid(const std::string& oid) {
  std::string prefix_str = KeyPrefixFromOid(oid);
#ifdef _WIN32
  // We could use fs::path::preferred_separator here, but it is wchar_t, which makes everything
  // painful.
  std::replace(prefix_str.begin(), prefix_str.end(), '/', '\\');
#endif
  return {prefix_str};
}

inline std::string KeyFromOid(const std::string& oid) {
  std::string prefix = KeyPrefixFromOid(oid);
  return fmt::format("{}/{}", prefix, oid);
}

// Extract OID from a key. Because other objects might be in the bucket, we look for the specific
// pattern that we upload with.
inline std::optional<std::string> OidFromKey(const std::string& key) {
  constexpr std::string_view key_pattern = "[a-z0-9]{2}\\/[a-z0-9]{2}\\/([a-z0-9]{64})$";
  static const std::regex re{key_pattern.data(), key_pattern.size(),
                             std::regex::ECMAScript | std::regex::icase};

  std::sregex_iterator it(key.begin(), key.end(), re), it_end;
  if (it == it_end || it->size() != 2) {
    return std::nullopt;
  } else {
    // Second match is the oid:
    std::string match = it->operator[](1);
    ASSERT_EQUAL(64, match.size());
    return {std::move(match)};
  }
}

inline std::shared_ptr<S3::S3Client> CreateS3Client(const Configuration& config) {
  S3::S3ClientConfiguration client_config{};
  if (config.bucket_region) {
    client_config.region = config.bucket_region.value();
  }
  if (config.endpoint) {
    client_config.endpointOverride = config.endpoint.value();
  }

  if (config.credentials) {
    auto endpoint_provider = Aws::MakeShared<S3::S3EndpointProvider>(S3::S3Client::ALLOCATION_TAG);

    Aws::Auth::AWSCredentials aws_credentials{config.credentials->access_key_id,
                                              config.credentials->secret_access_key};
    return std::make_shared<S3::S3Client>(aws_credentials, std::move(endpoint_provider),
                                          client_config);
  } else {
    // Let the SDK resolve credentials:
    return std::make_shared<S3::S3Client>(client_config);
  }
}

inline std::shared_ptr<Transfer::TransferManager> CreateTransferManager(
    const std::shared_ptr<S3::S3Client>& s3_client, Aws::Utils::Threading::Executor* const executor,
    Transfer::TransferStatusUpdatedCallback&& transfer_updated_callback) {
  ASSERT(executor);

  Transfer::TransferManagerConfiguration transfer_config(executor);
  transfer_config.s3Client = s3_client;
  transfer_config.computeContentMD5 = true;
  transfer_config.errorCallback = [](const Transfer::TransferManager*,
                                     const std::shared_ptr<const Transfer::TransferHandle>&,
                                     const Aws::Client::AWSError<S3::S3Errors>& error) {
    spdlog::error("Error during S3 transfer [Exception = {}]: {}", error.GetExceptionName(),
                  error.GetMessage());
  };
  transfer_config.transferStatusUpdatedCallback = std::move(transfer_updated_callback);
  return Transfer::TransferManager::Create(transfer_config);
}

Storage::Storage(lfs::Configuration config)
    : config_(std::move(config)),
      s3_client_(CreateS3Client(config_)),
      pooled_executor_{
          Aws::MakeShared<Aws::Utils::Threading::PooledThreadExecutor>("executor", 16)},
      transfer_manager_(CreateTransferManager(
          s3_client_, pooled_executor_.get(),
          [this](const Transfer::TransferManager*,
                 const std::shared_ptr<const Transfer::TransferHandle>& handle) {
            TransferStatusUpdatedCallback(handle);
          })) {}

tl::expected<void, Error> Storage::Initialize() {
  // enumerate objects in our bucket
  S3::Model::ListObjectsRequest request =
      S3::Model::ListObjectsRequest{}.WithBucket(config_.bucket_name);

  for (;;) {
    const auto outcome = s3_client_->ListObjects(request);
    if (!outcome.IsSuccess()) {
      const auto& error = outcome.GetError();
      return tl::unexpected<Error>("Failed while listing objects in bucket [Exception = {}]: {}",
                                   error.GetExceptionName(), error.GetMessage());
    }

    const auto& success = outcome.GetResult();
    const auto& contents = success.GetContents();
    if (contents.empty()) {
      // Done.
      break;
    }
    for (const S3::Model::Object& obj : contents) {
      // See if this object is one of ours:
      if (std::optional<std::string> oid = OidFromKey(obj.GetKey()); oid) {
        const auto size = static_cast<std::size_t>(obj.GetSize());
        s3_objects_.emplace(std::move(*oid), size);
      }
    }

    // Request the next batch, starting from the end of this one:
    request.WithMarker(contents.back().GetKey());
  }

  std::error_code ec{};
  if (!fs::exists(config_.storage_location) &&
      !fs::create_directories(config_.storage_location, ec)) {
    return tl::unexpected<Error>("Failed while creating path \"{}\": {}",
                                 config_.storage_location.string(), ec.message());
  }

  // Compute total size of objects in bucket:
  const std::size_t size_in_bucket =
      std::accumulate(s3_objects_.begin(), s3_objects_.end(), static_cast<std::size_t>(0),
                      [](std::size_t total, const auto& pair) { return total + pair.second; });

  spdlog::info("Bucket: {} ({} objects, {})", config_.bucket_name, s3_objects_.size(),
               SizePrinter(size_in_bucket));
  spdlog::info("Storage directory: \"{}\"", config_.storage_location.string());

  // enumerate the storage directory and queue uploads:
  std::size_t upload_size = 0;
  for (auto it = fs::recursive_directory_iterator(config_.storage_location);
       it != fs::recursive_directory_iterator(); ++it) {
    if (it.depth() != 2 || it->is_directory()) {
      continue;
    }

    std::string entry_path = fs::relative(it->path(), config_.storage_location).string();
#ifdef _WIN32
    std::replace(entry_path.begin(), entry_path.end(), '\\', '/');
#endif
    const auto oid = OidFromKey(entry_path);
    if (!oid || s3_objects_.count(*oid)) {
      continue;
    }

    auto transfer = transfer_manager_->UploadFile(it->path().string(), config_.bucket_name,
                                                  KeyFromOid(*oid), "application/octet-stream", {});
    ASSERT(transfer);
    pending_transfers_.insert(std::move(transfer));
    upload_size += fs::file_size(it->path());
  }

  if (!pending_transfers_.empty()) {
    spdlog::info("Queued {} ({}) uploads to the bucket from local storage.",
                 pending_transfers_.size(), SizePrinter(upload_size));
  }
  return {};
}

std::optional<std::size_t> Storage::ObjectSize(const std::string& oid) {
  // Lock to check the bucket first:
  {
    std::lock_guard lock{mutex_};
    auto it = s3_objects_.find(oid);
    if (it != s3_objects_.end()) {
      return it->second;
    }
  }

  // It may not be in the bucket, but we might have it locally:
  const fs::path local_path = config_.storage_location / DirectoryPrefixFromOid(oid) / oid;
  if (fs::exists(local_path)) {
    return fs::file_size(local_path);
  }
  return std::nullopt;
}

tl::expected<void, Error> Storage::PutObject(const lfs::object_t& obj,
                                             const std::filesystem::path& upload_path) {
  // Construct the path to the object:
  const fs::path local_dir = config_.storage_location / DirectoryPrefixFromOid(obj.oid);
  const fs::path local_path = local_dir / obj.oid;

  if (fs::exists(local_path)) {
    // The target already exists. These files must be identical because the sha matches.
    ASSERT_EQUAL(fs::file_size(local_path), obj.size);
    return {};
  }

  std::error_code ec{};
  if (!fs::exists(local_dir) && !fs::create_directories(local_dir, ec)) {
    return tl::unexpected<Error>(R"(Failed to create directory: "{}", reason = "{}")",
                                 local_dir.string(), ec.message());
  }

  // Move the file from the upload location to our target path:
  ec.clear();
  fs::rename(upload_path, local_path, ec);
  if (ec && !fs::exists(local_path)) {
    // Failed for some reason other than the target already existing:
    return tl::unexpected<Error>(R"(Failed while moving file "{}" -> "{}: {}")",
                                 upload_path.string(), local_path.string(), ec.message());
  }

  // Queue an upload:
  auto transfer =
      transfer_manager_->UploadFile(local_path.string(), config_.bucket_name, KeyFromOid(obj.oid),
                                    "application/octet-stream", {});

  spdlog::info("Queuing object upload: oid = {}, size = {}", obj.oid, obj.size);

  std::lock_guard<std::mutex> lock{mutex_};
  pending_transfers_.emplace(std::move(transfer));
  return {};
}

// LocalObjectGetter returns a file from our local storage.
class LocalObjectGetter : public ObjectGetter {
 public:
  explicit LocalObjectGetter(fs::path path) : path_(std::move(path)) {}

  tl::expected<std::size_t, Error> Read(std::size_t offset, std::size_t length,
                                        char* data) override {
    // On first call, open the stream:
    if (!stream_.is_open()) {
      stream_.open(path_, std::ios::binary | std::ios::in);
      if (!stream_.good()) {
        return tl::unexpected<Error>("Failed opening path for reading: \"{}\"", path_.string());
      }
      stream_.exceptions(std::ios::failbit | std::ios::badbit);
    }

    try {
      stream_.seekg(static_cast<std::streamsize>(offset), std::ios::beg);
      stream_.read(data, static_cast<std::streamsize>(length));
      return static_cast<std::size_t>(stream_.gcount());
    } catch (std::ios_base::failure& failure) {
      const std::error_code& ec = failure.code();
      return tl::unexpected<Error>(
          R"(Failed reading object: offset = {}, length = {}, category = "{}", reason = "{}")",
          offset, length, ec.category().name(), ec.message());
    }
  }

  void Finalize(bool) override {
    if (stream_.is_open()) {
      stream_.close();
    }
  }

 private:
  fs::path path_;
  std::ifstream stream_{};
};

// BucketObjectGetter returns an object from S3. This is designed to allow for a streaming
// response. As parts are fetched from S3, we return them to the client.
class BucketObjectGetter : public ObjectGetter {
 public:
  static constexpr std::size_t ChunkSize = 1024 * 1024;

  BucketObjectGetter(lfs::object_t object, fs::path download_path,
                     std::shared_ptr<const Configuration> config,
                     std::shared_ptr<S3::S3Client> client)
      : object_(std::move(object)),
        download_path_(std::move(download_path)),
        config_(std::move(config)),
        client_(std::move(client)) {}

  tl::expected<std::size_t, Error> Read(std::size_t offset, std::size_t length,
                                        char* data) override {
    if (!stream_.is_open()) {
      const auto parent = download_path_.parent_path();
      std::error_code ec{};
      if (!fs::exists(parent) && !fs::create_directories(parent, ec)) {
        return tl::unexpected<Error>(R"(Failed to create directory: "{}", reason = "{}")",
                                     parent.string(), ec.message());
      }

      stream_.open(download_path_,
                   std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc);
      if (!stream_.good()) {
        return tl::unexpected<Error>("Failed opening path for writing: \"{}\"",
                                     download_path_.string());
      }
      stream_.exceptions(std::ios::failbit | std::ios::badbit);
    }

    if (position_ < offset + length) {
      if (auto maybe_fetch = FetchNextPart(); !maybe_fetch) {
        return tl::unexpected(std::move(maybe_fetch.error()));
      }
    }

    // Somewhat lazy here - we just use the fstream as our buffer and read back what we wrote.
    const std::size_t amount_to_read = std::min(length, position_ - offset);
    try {
      stream_.seekg(static_cast<std::streamsize>(offset), std::ios::beg);
      stream_.read(data, static_cast<std::streamsize>(amount_to_read));
      const std::size_t amount_read = stream_.gcount();
      return amount_read;
    } catch (std::ios_base::failure& failure) {
      const auto& ec = failure.code();
      return tl::unexpected<Error>(
          R"(Failed reading object: offset = {}, length = {}, category = "{}", reason = "{}")",
          offset, amount_to_read, ec.category().name(), ec.message());
    }
  }

  void Finalize(bool success) override {
    // Close the file and move it to the final destination:
    if (stream_.is_open()) {
      stream_.close();
    }
    if (success && fs::exists(download_path_)) {
      const fs::path final_path = config_->storage_location / KeyFromOid(object_.oid);

      std::error_code ec{};
      fs::rename(download_path_, final_path, ec);
      if (ec && !fs::exists(final_path)) {
        // Failed for some other reason than the destination exists.
        spdlog::warn(R"(Failed moving to final path: "{}" -> "{}")", download_path_.string(),
                     final_path.string());
      }
    }
  }

  tl::expected<void, Error> FetchNextPart() {
    // The last byte we will read, inclusive:
    const std::size_t range_end = std::min(position_ + ChunkSize, object_.size) - 1;
    const std::size_t range_len = range_end - position_ + 1;

    S3::Model::GetObjectRequest request =
        S3::Model::GetObjectRequest{}
            .WithBucket(config_->bucket_name)
            .WithKey(KeyFromOid(object_.oid))
            .WithRange(fmt::format("bytes={}-{}", position_, range_end));

    constexpr std::size_t max_attempts = 3;
    for (std::size_t attempt = 0; attempt < max_attempts; ++attempt) {
      const auto outcome = client_->GetObject(request);
      if (outcome.IsSuccess()) {
        const S3::Model::GetObjectResult& result = outcome.GetResult();
        if (static_cast<std::size_t>(result.GetContentLength()) < range_len) {
          return tl::unexpected<Error>(
              "Returned content has incorrect length: oid = {}, range = {}-{}, expected={}, "
              "actual={}",
              object_.oid, position_, range_end, range_len, result.GetContentLength());
        }

        // Copy the result from in-memory stream to disk:
        Aws::IOStream& input_stream = result.GetBody();
        if (auto hash_result = UpdateHash(input_stream); !hash_result) {
          return tl::unexpected(std::move(hash_result.error()));
        }

        // Write it to our output stream:
        input_stream.seekg(0, std::ios::beg);
        try {
          stream_.seekg(0, std::ios::end);
          stream_ << input_stream.rdbuf();
        } catch (std::ios_base::failure& failure) {
          const auto& ec = failure.code();
          return tl::unexpected<Error>(R"(Failed writing object: category = "{}", reason = "{}")",
                                       ec.category().name(), ec.message());
        }
        position_ = range_end + 1;
        break;
      }

      const auto& err = outcome.GetError();
      if (err.ShouldRetry() && attempt + 1 < max_attempts) {
        continue;
      } else {
        // No more attempts allowed:
        return tl::unexpected<Error>(R"(Failed S3 download: oid = {}, name = "{}", message = "{}")",
                                     object_.oid, err.GetExceptionName(), err.GetMessage());
      }
    }
    return {};  // Success.
  }

  [[nodiscard]] tl::expected<void, Error> UpdateHash(Aws::IOStream& input_stream) {
    input_stream.seekg(0, std::ios::beg);

    // Update the hash.
    std::vector<char> copy{std::istreambuf_iterator<char>(input_stream),
                           std::istreambuf_iterator<char>()};
    ASSERT(input_stream.good());
    hasher_.Update(std::string_view{copy.data(), copy.size()});

    if (position_ + copy.size() == object_.size) {
      // Downloaded the entire object, now check the hash:
      const Sha256 hash = hasher_.GetHash();
      const auto hash_str = StringFromSha256(hash);
      if (hash_str != object_.oid) {
        return tl::unexpected<Error>("Downloaded object has invalid hash: oid = {}, actual = {}",
                                     object_.oid, hash_str);  //  Failed hash comparison.
      }
    }
    return {};
  }

 private:
  lfs::object_t object_;

  // Where the object is written to, and
  fs::path download_path_;
  std::fstream stream_{};

  // Position in the file we have read to so far;
  std::size_t position_{0};

  // Parameters that may influence our requests
  std::shared_ptr<const Configuration> config_;

  // Hash computed so far
  Hasher hasher_{};

  // AWS Client
  std::shared_ptr<S3::S3Client> client_;
};

tl::expected<ObjectGetter::shared_ptr, Error> Storage::GetObject(const lfs::object_t& obj) {
  // Check if object exists in local cache already:
  const fs::path local_dir = config_.storage_location / DirectoryPrefixFromOid(obj.oid);
  const fs::path local_path = local_dir / obj.oid;
  if (fs::exists(local_path)) {
    // The file exists in local storage:
    spdlog::info("Serving object from local storage: oid = {}, size = {}", obj.oid, obj.size);
    return std::make_shared<LocalObjectGetter>(local_path);
  }

  const fs::space_info space = fs::space(config_.storage_location);
  if (space.available < obj.size) {
    return tl::unexpected(Error{
        "Insufficient space to transfer file from S3: oid = {}, required = {}, available = {}",
        obj.oid, obj.size, space.available});
  }

  // Start a download of the object:
  const fs::path download_path =
      local_dir / fmt::format("{}.download-{}", obj.oid, GenerateUuidString());

  spdlog::info("Serving object from S3: oid = {}, size = {}", obj.oid, obj.size);
  return std::make_shared<BucketObjectGetter>(obj, download_path,
                                              std::make_shared<Configuration>(config_), s3_client_);
}

void Storage::TransferStatusUpdatedCallback(
    const std::shared_ptr<const Transfer::TransferHandle>& handle) {
  switch (handle->GetStatus()) {
    case Transfer::TransferStatus::ABORTED:
    case Transfer::TransferStatus::CANCELED:
    case Transfer::TransferStatus::COMPLETED:
    case Transfer::TransferStatus::FAILED:
      HandleTransferEnd(handle);
      break;
    default:
      // Don't care about other cases.
      return;
  }
}

void Storage::HandleTransferEnd(
    const std::shared_ptr<const Aws::Transfer::TransferHandle>& handle) {
  const std::string oid = OidFromKey(handle->GetKey()).value();
  const auto size = handle->GetBytesTotalSize();

  // Lock before modifying shared state:
  std::lock_guard<std::mutex> lock{mutex_};
  pending_transfers_.erase(handle);

  if (handle->GetStatus() == Transfer::TransferStatus::COMPLETED) {
    // Update internal map:
    s3_objects_.emplace(oid, size);
    spdlog::info("Completed object upload: oid = {}, size = {}", oid, size);
  } else if (handle->GetStatus() == Transfer::TransferStatus::CANCELED) {
    // Cancelled, maybe because we are shutting down.
    spdlog::info("Cancelled object upload: oid = {}, size = {}", oid, size);
  } else if (handle->GetStatus() == Transfer::TransferStatus::FAILED) {
    // Failed:
    auto error = handle->GetLastError();
    spdlog::warn(R"(Object upload failed: oid = {}, size = {}, exception = "{}", message = "{}")",
                 oid, size, error.GetExceptionName(), error.GetMessage());
  }
}

}  // namespace lfs

// Pretty-printing for disk sizes.
template <>
struct fmt::formatter<lfs::SizePrinter> {
  constexpr auto parse(format_parse_context& ctx) -> format_parse_context::iterator {
    return ctx.begin();
  }

  auto format(const lfs::SizePrinter& sz, format_context& ctx) const -> format_context::iterator {
    constexpr auto gig = static_cast<std::size_t>(1073741824);
    constexpr auto meg = static_cast<std::size_t>(1048576);
    if (sz.bytes >= gig) {
      return fmt::format_to(ctx.out(), "{:.3f}GB",
                            static_cast<double>(sz.bytes) / static_cast<double>(gig));
    } else if (sz.bytes >= meg) {
      return fmt::format_to(ctx.out(), "{:.3f}MB",
                            static_cast<double>(sz.bytes) / static_cast<double>(meg));
    } else {
      return fmt::format_to(ctx.out(), "{}bytes", sz.bytes);
    }
  }
};

#ifdef _WIN32
#pragma pop_macro("GetMessage")
#pragma pop_macro("GetObject")
#endif  //  _WIN32
