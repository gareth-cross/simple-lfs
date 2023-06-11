#include "structs.hpp"

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace lfs {

NLOHMANN_JSON_SERIALIZE_ENUM(operation, {{operation::invalid, nullptr},
                                         {operation::upload, "upload"},
                                         {operation::download, "download"}})

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(object_t, oid, size)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(ref_t, name)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(objects_batch_t, operation, objects, transfers, ref, hash_algo)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(action_url_t, href, header)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(object_actions_t, oid, size, actions)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(error_t, code, message)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(object_error_t, oid, size, error)

// Custom decoding to support variant.
void to_json(json& j, const std::variant<std::monostate, object_actions_t, object_error_t>& x) {
  std::visit(
      [&j](const auto& x) {
        using T = std::decay_t<decltype(x)>;
        if constexpr (!std::is_same_v<T, std::monostate>) {
          to_json(j, x);
        }
      },
      x);
}

// We define this for the benefit of the macro, but it isn't actually required.
void from_json(const json& j, std::variant<std::monostate, object_actions_t, object_error_t>& x) {
  if (j.contains("error")) {
    x = j.get<object_error_t>();
  } else {
    x = j.get<object_actions_t>();
  }
}

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(response_t, transfer, objects, hash_algo)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(error_response_t, message, documentation_url)

objects_batch_t DecodeObjectBatch(const std::string_view& str) {
  json j = json::parse(str);
  spdlog::debug("Received object match: {}", j.dump(2));
  return j.get<objects_batch_t>();
}

std::string EncodeResponse(const response_t& response) {
  json j = response;
  std::string str = j.dump(2);
  spdlog::debug("Created response: {}", str);
  return str;
}

std::string EncodeResponse(const error_response_t& response) {
  json j = response;
  std::string str = j.dump(2);
  spdlog::debug("Created error response: {}", str);
  return str;
}

}  // namespace lfs
