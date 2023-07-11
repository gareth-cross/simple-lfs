#include "uuid.hpp"

#ifdef _WIN32
#include <windows.h>
#else
#include <uuid/uuid.h>
#endif

#include <scope_guard.hpp>

#include "assertions.hpp"

namespace lfs {

std::string GenerateUuidString() {
#ifdef _WIN32
  UUID uuid;
  const auto uuid_status = UuidCreate(&uuid);
  ASSERT_EQUAL(RPC_S_OK, uuid_status);

  RPC_CSTR uuid_str = nullptr;
  const auto uuid_convert_result = UuidToString(&uuid, &uuid_str);
  const auto cleanup = sg::make_scope_guard([&] { RpcStringFree(&uuid_str); });
  ASSERT_EQUAL(RPC_S_OK, uuid_convert_result);
  std::string uuid_str_converted{reinterpret_cast<const char*>(uuid_str)};
#else
  uuid_t uuid;
  static_assert(sizeof(uuid) == 16, "UUID is supposed to be 16 bytes");
  uuid_generate(uuid);

  char buffer[37];  //  36 bytes plus trailing zero
  uuid_unparse(uuid, &buffer[0]);
  std::string uuid_str_converted{buffer};
#endif
  uuid_str_converted.erase(std::remove(uuid_str_converted.begin(), uuid_str_converted.end(), '-'),
                           uuid_str_converted.end());
  return uuid_str_converted;
}

}  // namespace lfs
