#pragma once
#include <map>
#include <string>
#include <variant>
#include <vector>

namespace lfs {

// MIME type for actual data:
constexpr std::string_view mime_type = "application/vnd.git-lfs";

// MIME type for JSON communication to/from the lfs server.
constexpr std::string_view mime_type_json = "application/vnd.git-lfs+json";

// Hash algorithm.
constexpr std::string_view sha256 = "sha256";

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
};

struct object_response_t {
  std::string oid;
  std::size_t size{0};
  std::map<std::string, action_url_t> actions;
};

struct object_error_t {
  int code{0};
  std::string message;
};

struct response_t {
  std::string transfer{"basic"};
  std::vector<std::variant<std::monostate, object_response_t, object_error_t>> objects;
  std::string hash_algo{sha256};
};

// Decode `objects_batch_t` from json.
objects_batch_t DecodeObjectBatch(const std::string_view& str);

// Encode `response_t` to json.
std::string EncodeResponse(const response_t& response);

}  // namespace lfs
