#pragma once
#include <map>
#include <string>
#include <variant>
#include <vector>

#include <fmt/format.h>

namespace lfs {

// MIME type for actual data:
constexpr std::string_view mime_type = "application/vnd.git-lfs";

// MIME type for JSON communication to/from the lfs server.
constexpr std::string_view mime_type_json = "application/vnd.git-lfs+json";

// Hash algorithm.
constexpr std::string_view sha256 = "sha256";

// Error codes we can return in `object_error_t`.
enum class error_code {
  success = 200,
  validation_error = 422,
  internal_error = 500,
};

// Types of operations we can instruct the client to do.
enum operation {
  invalid,
  upload,
  download,
};

struct object_t {
  std::string oid;
  std::size_t size{0};
};

struct ref_t {
  std::string name;
};

struct objects_batch_t {
  operation operation{operation::invalid};
  std::vector<object_t> objects;
  std::vector<std::string> transfers;
  ref_t ref;
  std::string hash_algo{sha256};
};

struct action_url_t {
  std::string href;
  std::map<std::string, std::string> header;

  action_url_t() = default;

  action_url_t(std::string href,
               std::initializer_list<std::pair<const std::string, std::string>> header)
      : href(std::move(href)), header(header) {}

  action_url_t(std::string href, std::map<std::string, std::string> header)
      : href(std::move(href)), header(std::move(header)) {}
};

struct object_actions_t {
  std::string oid;
  std::size_t size{0};
  std::map<std::string, action_url_t> actions;

  object_actions_t() = default;

  explicit object_actions_t(const object_t& object) : oid(object.oid), size(object.size) {}

  object_actions_t(const object_t& object,
                   std::initializer_list<std::pair<const std::string, action_url_t>> actions)
      : oid(object.oid), size(object.size), actions(actions) {}
};

// Pair together an error code w/ a message.
// LFS error codes are supposed to roughly match HTTP error codes.
struct error_t {
  int code{0};
  std::string message;

  error_t() = default;

  // Construct w/ error code and message w/ formatting.
  template <typename... Ts>
  error_t(error_code code, std::string_view fmt, Ts&&... args)
      : code(static_cast<int>(code)), message(fmt::format(fmt, std::forward<Ts>(args)...)) {}

  // Construct w/ error code and message.
  error_t(error_code code, std::string message)
      : code(static_cast<int>(code)), message(std::move(message)) {}
};

struct object_error_t {
  std::string oid;
  std::size_t size{0};
  error_t error;

  object_error_t() = default;
  object_error_t(const object_t& obj, error_t err)
      : oid(obj.oid), size(obj.size), error(std::move(err)) {}
};

struct response_t {
  std::string transfer{"basic"};
  std::vector<std::variant<std::monostate, object_actions_t, object_error_t>> objects;
  std::string hash_algo{sha256};
};

// Response returned when an error occurs.
struct error_response_t {
  std::string message;
  std::string documentation_url{"https://github.com/git-lfs/git-lfs/tree/main/docs/api"};

  error_response_t() = default;

  // Construct w/ message.
  template <typename... Ts>
  explicit error_response_t(std::string_view fmt, Ts&&... args)
      : message(fmt::format(fmt, std::forward<Ts>(args)...)) {}
};

// Create a `response_t` object that indicates an error.
// template <typename... Ts>
// response_t CreateErrorResponse(const object_t& obj, error_code code, std::string_view fmt,
//                               Ts&&... args) {
//  response_t response{};
//  error_t err{code, fmt, std::forward<Ts>(args)...};
//  response.objects.emplace_back(object_error_t{obj.oid, obj.size, std::move(err)});
//  return response;
//}

// Decode `objects_batch_t` from json.
objects_batch_t DecodeObjectBatch(const std::string_view& str);

// Encode `response_t` to json.
std::string EncodeResponse(const response_t& response);

// Encode `error_response_t` to json.
std::string EncodeResponse(const error_response_t& response);

}  // namespace lfs
