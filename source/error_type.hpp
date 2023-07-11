#pragma once
#include <exception>

#include <fmt/core.h>

namespace lfs {

// Exception or error type that supports fmt-style args.
// TODO: We could return typed errors in a variant (or at least preserve more type information).
// That said, everything will just be converted to HTTP 500, so the specific cause of error is
// often not that relevant (yet).
struct Error {
 public:
  // Create w/ format string.
  template <typename... Ts>
  explicit Error(fmt::string_view fmt, Ts&&... args)
      : str_(fmt::format(fmt, std::forward<Ts>(args)...)) {}

  const std::string& Message() const { return str_; }

 private:
  std::string str_;
};

}  // namespace lfs

// Supporting printing of `Error` type directly in fmt::format calls.
template <>
struct fmt::formatter<lfs::Error> {
  constexpr auto parse(format_parse_context& ctx) -> format_parse_context::iterator {
    return ctx.begin();
  }

  auto format(const lfs::Error& err, format_context& ctx) const -> format_context::iterator {
    return fmt::format_to(ctx.out(), "{}", err.Message());
  }
};
