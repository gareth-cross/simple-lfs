// Copyright 2023 Gareth Cross
#pragma once
#ifdef _MSC_VER
// Silence some warnings that libfmt can trigger w/ msvc.
#pragma warning(push)
#pragma warning(disable : 4583)
#pragma warning(disable : 4582)
#endif  // _MSC_VER
#include <fmt/ostream.h>
#ifdef _MSC_VER
#pragma warning(pop)
#endif  // _MSC_VER

#include <spdlog/spdlog.h>

class AssertionError : public std::exception {
 public:
  explicit AssertionError(std::string&& str) : str_(std::move(str)) {}

  [[nodiscard]] const char* what() const override { return str_.c_str(); }

 private:
  std::string str_;
};

namespace detail {

// Generates an exception w/ a formatted string.
template <typename... Ts>
void RaiseAssert(std::string_view condition, std::string_view file, const int line, Ts&&... args) {
  std::string err = fmt::format("Assertion failed: {}\nFile: {}\nLine: {}", condition, file, line);
  if constexpr (sizeof...(args) > 0) {
    err += "\nMessage: ";
    fmt::format_to(std::back_inserter(err), std::forward<Ts>(args)...);
  }
  spdlog::error("Encountered assertion: {}", err);
  throw AssertionError(std::move(err));
}

// Version that prints args A & B as well. For binary comparisons.
template <typename A, typename B, typename... Ts>
void RaiseAssertBinaryOp(std::string_view condition, std::string_view file, const int line,
                         std::string_view a_name, A&& a, std::string_view b_name, B&& b,
                         Ts&&... args) {
  std::string err = fmt::format(
      "Assertion failed: {}\n"
      "Operands are: {} = {}, {} = {}\n"
      "File: {}\nLine: {}",
      condition, a_name, std::forward<A>(a), b_name, std::forward<B>(b), file, line);
  if constexpr (sizeof...(args) > 0) {
    err += "\nMessage: ";
    fmt::format_to(std::back_inserter(err), std::forward<Ts>(args)...);
  }
  spdlog::error("Encountered assertion: {}", err);
  throw AssertionError(std::move(err));
}

}  // namespace detail

// Assertion macros.
// Based on: http://cnicholson.net/2009/02/stupid-c-tricks-adventures-in-assert
#define ASSERT_IMPL(cond, file, line, handler, ...) \
  do {                                              \
    if (!static_cast<bool>(cond)) {                 \
      handler(#cond, file, line, ##__VA_ARGS__);    \
    }                                               \
  } while (false)

// Macro to use when defining an assertion.
#define ASSERT(cond, ...) ASSERT_IMPL(cond, __FILE__, __LINE__, detail::RaiseAssert, ##__VA_ARGS__)
#define ASSERT_EQUAL(a, b, ...)                                                          \
  ASSERT_IMPL((a) == (b), __FILE__, __LINE__, detail::RaiseAssertBinaryOp, #a, a, #b, b, \
              ##__VA_ARGS__)
#define ASSERT_NOT_EQUAL(a, b, ...)                                                      \
  ASSERT_IMPL((a) != (b), __FILE__, __LINE__, detail::RaiseAssertBinaryOp, #a, a, #b, b, \
              ##__VA_ARGS__)
#define ASSERT_LESS(a, b, ...)                                                          \
  ASSERT_IMPL((a) < (b), __FILE__, __LINE__, detail::RaiseAssertBinaryOp, #a, a, #b, b, \
              ##__VA_ARGS__)
#define ASSERT_GREATER(a, b, ...)                                                       \
  ASSERT_IMPL((a) > (b), __FILE__, __LINE__, detail::RaiseAssertBinaryOp, #a, a, #b, b, \
              ##__VA_ARGS__)
#define ASSERT_LESS_OR_EQ(a, b, ...)                                                     \
  ASSERT_IMPL((a) <= (b), __FILE__, __LINE__, detail::RaiseAssertBinaryOp, #a, a, #b, b, \
              ##__VA_ARGS__)
#define ASSERT_GREATER_OR_EQ(a, b, ...)                                                  \
  ASSERT_IMPL((a) >= (b), __FILE__, __LINE__, detail::RaiseAssertBinaryOp, #a, a, #b, b, \
              ##__VA_ARGS__)
