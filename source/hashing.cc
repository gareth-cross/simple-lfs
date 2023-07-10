#include "hashing.hpp"

#include <openssl/evp.h>

#include "assertions.hpp"

namespace lfs {

Hasher::Hasher() : context_(EVP_MD_CTX_new(), &EVP_MD_CTX_free) {
  ASSERT(context_, "Failed to create EVP context.");

  const int init_result = EVP_DigestInit_ex(context_.get(), EVP_sha256(), nullptr);
  ASSERT_EQUAL(1, init_result, "Failed to initialize EVP digest.");
}

void Hasher::Update(std::string_view data) {
  const int updated_result =
      EVP_DigestUpdate(context_.get(), static_cast<const void*>(data.data()), data.size());
  ASSERT_EQUAL(1, updated_result, "Failed to update digest (data length = {}).", data.size());
}

Sha256 Hasher::GetHash() const {
  Sha256 digest{};
  ASSERT_EQUAL(EVP_MD_size(EVP_sha256()), digest.size());

  unsigned int digest_size{0};
  const int read_result = EVP_DigestFinal_ex(context_.get(), &digest[0], &digest_size);
  ASSERT_EQUAL(1, read_result, "Failed reading final digest.");
  ASSERT_EQUAL(digest.size(), digest_size, "Digest is the wrong size (should be {} bytes).",
               digest.size());
  return digest;
}

std::string StringFromSha256(const Sha256& sha) {
  return fmt::format("{:02x}", fmt::join(sha, ""));
}

std::string Base64FromSha256(const Sha256& sha) {
  // Expected size of the hashed data:
  // (32 * 4 / 3), rounded up to nearest 4, plus one for null terminator.
  constexpr std::size_t expected_size = 45;
  std::array<uint8_t, expected_size> encoded{};
  const std::size_t sha_size = sha.size();
  const int encoded_len = EVP_EncodeBlock(encoded.data(), sha.data(), static_cast<int>(sha_size));
  ASSERT_EQUAL(expected_size, static_cast<std::size_t>(encoded_len) + 1,
               "Wrong size for base-64 encoded sha-256.");
  return std::string{encoded.begin(), encoded.end()};
}

}  // namespace lfs
