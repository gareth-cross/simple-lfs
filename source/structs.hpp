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
  object_does_not_exist = 404,
  // git-lfs spec recommends using HTTP 409 for "invalid hash algorithm".
  invalid_hash_algorithm = 409,
  validation_error = 422,
  internal_error = 500,
};

// Types of operations we can instruct the client to do.
enum op {
  invalid,
  upload,
  download,
};

// Pair together an OID (sha-256 hash) and the size in bytes of the object.
struct object_t {
  std::string oid;
  std::size_t size{0};
};

// Stores a git Refspec: https://git-scm.com/book/en/v2/Git-Internals-The-Refspec
struct ref_t {
  std::string name;
};

// Struct the client sends when making a PUT operation on the /batch API.
struct objects_batch_t {
  // Either `upload` or `download`.
  op operation{op::invalid};
  // Objects the client is requesting.
  std::vector<object_t> objects;
  // Types of transfer that the client can support. We ignore this and assume basic.
  std::vector<std::string> transfers;
  // Optional object describing the server ref that the objects belong to.
  ref_t ref;
  // Only SHA256 is supported.
  std::string hash_algo{sha256};
};

// Specify a URL the client should hit, w/ corresponding HTTP headers.
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

// Return a dict of actions the client can perform for a specific object.
struct object_actions_t {
  std::string oid;
  std::size_t size{0};
  std::map<std::string, action_url_t> actions;

  object_actions_t() = default;

  explicit object_actions_t(const object_t& object) : oid(object.oid), size(object.size) {}

  // Construct w/ a single action URL (the most common case).
  object_actions_t(const object_t& object, std::string_view action, action_url_t action_url)
      : object_actions_t(object) {
    actions.emplace(action, std::move(action_url));
  }
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

// Indicate an error occurred processing a request for a specific object.
struct object_error_t {
  std::string oid;
  std::size_t size{0};
  error_t error;

  object_error_t() = default;
  object_error_t(const object_t& obj, error_t err)
      : oid(obj.oid), size(obj.size), error(std::move(err)) {}
};

// Top level response object for the batch API.
struct response_t {
  // We only support `basic` transfer.
  std::string transfer{"basic"};
  // List of either `object_actions_t` or `object_error_t`.
  std::vector<std::variant<std::monostate, object_actions_t, object_error_t>> objects;
  // The only hash we support is sha256.
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

  explicit error_response_t(std::string message) : message(std::move(message)) {}
};

// Decode `objects_batch_t` from json.
objects_batch_t DecodeObjectBatch(const std::string_view& str);

// Encode `response_t` to json.
std::string EncodeResponse(const response_t& response);

// Encode `error_response_t` to json.
std::string EncodeResponse(const error_response_t& response);

}  // namespace lfs
