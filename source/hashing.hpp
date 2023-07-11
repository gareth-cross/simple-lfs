#pragma once
#include <array>
#include <cstdint>
#include <memory>
#include <string>

#include <openssl/evp.h>

namespace lfs {

using Sha256 = std::array<uint8_t, 32>;

// Struct for building sha-256 hash from streaming data.
struct Hasher {
 public:
  // Initialize the EVP context, or throw if we fail.
  Hasher();

  // Update the hash w/ a stream of bytes.
  void Update(std::string_view data);

  // Get the resulting hash.
  Sha256 GetHash() const;

 private:
  std::unique_ptr<EVP_MD_CTX, void (*)(EVP_MD_CTX*)> context_;
};

// Print a hash as a string of hex characters.
std::string StringFromSha256(const Sha256& sha);

}  // namespace lfs
