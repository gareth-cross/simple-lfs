#pragma once
#include <exception>

#include <fmt/core.h>

namespace lfs {

// Exception that supports fmt-style args.
struct Exception : public std::exception {
 public:
  // Create w/ format string.
  template <typename... Ts>
  explicit Exception(fmt::string_view fmt, Ts&&... args)
      : str_(fmt::format(fmt, std::forward<Ts>(args)...)) {}

  [[nodiscard]] const char* what() const final { return str_.c_str(); }

 private:
  std::string str_;
};

}  // namespace lfs
