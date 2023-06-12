#include "uuid.hpp"

#ifdef _WIN32
#include "windows.h"
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
  uuid_str_converted.erase(std::remove(uuid_str_converted.begin(), uuid_str_converted.end(), '-'),
                           uuid_str_converted.end());
  return uuid_str_converted;
#else
#error "Implement me"
#endif
}

}  // namespace lfs
