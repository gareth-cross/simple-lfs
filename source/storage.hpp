#pragma once
#include <memory>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

#include <tl/expected.hpp>

#include "configuration.hpp"
#include "exception.hpp"
#include "structs.hpp"

namespace Aws::S3 {
class S3Client;
}  // namespace Aws::S3

namespace Aws::Transfer {
class TransferManager;
class TransferHandle;
}  // namespace Aws::Transfer

namespace Aws::Utils::Threading {
class PooledThreadExecutor;
}  // namespace Aws::Utils::Threading

#ifdef _WIN32
#pragma push_macro("GetMessage")  //  Stop leaking from windows unicode header...
#pragma push_macro("GetObject")
#undef GetMessage
#undef GetObject
#endif  //  _WIN32

namespace lfs {

// Represents an active download initiated by `GetObject`.
struct ObjectGetter {
 public:
  using shared_ptr = std::shared_ptr<ObjectGetter>;

  virtual ~ObjectGetter() = default;

  // Try to read `length` bytes at position `offset` into the buffer pointed to by `data`.
  // Returns the # of bytes read, or throws if an error occurs.
  [[nodiscard]] virtual tl::expected<std::size_t, Error> Read(std::size_t offset,
                                                              std::size_t length, char* data) = 0;

  // Indicate that we are finished reading the object.
  virtual void Finalize(bool success) = 0;
};

// Manage local storage of objects and synchronization w/ bucket.
struct Storage {
 public:
  explicit Storage(Configuration config);

  // Query all the objects in the bucket to build our initial list. Assuming that succeeds, start
  // the uploader thread.
  [[nodiscard]] tl::expected<void, Error> Initialize();

  // Given an `object_t` from a batch API POST request, determine if that object exists in our
  // local cache or in the bucket. Return the size, or nullopt if it does not exist.
  std::optional<std::size_t> ObjectSize(const std::string& oid);

  // Move object to the storage directory, and queue upload to S3 if appropriate.
  [[nodiscard]] tl::expected<void, Error> PutObject(const lfs::object_t& obj,
                                                    const std::filesystem::path& upload_path);

  //
  [[nodiscard]] tl::expected<ObjectGetter::shared_ptr, Error> GetObject(const lfs::object_t& obj);

 private:
  Configuration config_;

  std::shared_ptr<Aws::S3::S3Client> s3_client_;
  std::shared_ptr<Aws::Utils::Threading::PooledThreadExecutor> pooled_executor_;
  std::shared_ptr<Aws::Transfer::TransferManager> transfer_manager_;

  // Map from oid -> size of the object.
  std::unordered_map<std::string, std::size_t> s3_objects_;

  // Pending uploads:
  std::unordered_set<std::shared_ptr<const Aws::Transfer::TransferHandle>> pending_transfers_;

  // Lock for touching internal states.
  std::mutex mutex_{};

  // Callback from the AWS SDK when a download updates progress.
  void TransferStatusUpdatedCallback(
      const std::shared_ptr<const Aws::Transfer::TransferHandle>& handle);

  void HandleTransferEnd(const std::shared_ptr<const Aws::Transfer::TransferHandle>& handle);
};

}  // namespace lfs

#ifdef _WIN32
#pragma pop_macro("GetMessage")
#pragma pop_macro("GetObject")
#endif  //  _WIN32
