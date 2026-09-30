// Copyright 2026 Summon Software Labs
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef TENANT_REGISTRY_TESTS_SUPPORT_TEST_HARNESS_HPP
#define TENANT_REGISTRY_TESTS_SUPPORT_TEST_HARNESS_HPP

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace treg_test {

/// Thrown by TREG_REQUIRE to abandon the current test without abandoning the
/// run. Exceptions are used only inside the harness; the library itself never
/// throws for control flow.
class TestAbort {};

using TestFunction = void (*)();

/// Registers one test. Tests are grouped by suite so that a failure names the
/// area it belongs to.
struct Registrar {
  Registrar(const char* suite, const char* name, TestFunction function);
};

/// Registers a handler for a child mode, used by the tests that need a real
/// second operating system process.
void register_child_mode(std::string_view mode, std::function<int(const std::vector<std::string>&)> handler);

/// Runs the child handler for mode. Returns 64 when no handler is registered,
/// which the parent reports as a harness failure rather than as a test result.
int dispatch_child(const std::string& mode, const std::vector<std::string>& arguments);

/// Runs every registered test, or the ones whose name contains a filter.
int run_all(const std::vector<std::string>& arguments);

// -- reporting ---------------------------------------------------------------

void report_failure(const char* file, int line, const std::string& message);
[[nodiscard]] bool current_test_has_failed() noexcept;

/// Compares two values through a function call rather than inline. Real tests
/// compare compile time constants, and a direct comparison of constants is
/// diagnosed as a constant conditional expression by MSVC (C4127); routing the
/// comparison through here keeps the check honest without suppressing it.
template <class Left, class Right>
[[nodiscard]] bool same(const Left& lhs, const Right& rhs) {
  return lhs == rhs;
}

/// The absolute path of the running test executable. Set once by test_main.
[[nodiscard]] const std::filesystem::path& executable_path();
void set_executable_path(const std::filesystem::path& path);

/// A unique, empty temporary directory for one test. Removed by remove_tree,
/// which the test is expected to call.
[[nodiscard]] std::filesystem::path make_temp_directory(std::string_view label);
void remove_tree(const std::filesystem::path& path) noexcept;

/// Renders any value that has a to_text() or is streamable, for diagnostics.
template <class T>
std::string render(const T& value);

std::string render(std::string_view value);
std::string render(const std::string& value);
std::string render(bool value);
std::string render(const char* value);

template <class T>
std::string render(const T& value) {
  if constexpr (requires { value.to_text(); }) {
    return value.to_text();
  } else if constexpr (requires { value.to_canonical(); }) {
    return value.to_canonical();
  } else if constexpr (std::is_enum_v<T>) {
    return std::to_string(static_cast<long long>(value));
  } else if constexpr (std::is_integral_v<T>) {
    return std::to_string(value);
  } else {
    return "<value>";
  }
}

}  // namespace treg_test

#define TREG_TEST(suite_name, test_name)                                                   \
  static void treg_test_##suite_name##_##test_name();                                      \
  static const ::treg_test::Registrar treg_registrar_##suite_name##_##test_name{           \
      #suite_name, #test_name, &treg_test_##suite_name##_##test_name};                     \
  static void treg_test_##suite_name##_##test_name()

#define TREG_CHECK(condition)                                                              \
  do {                                                                                     \
    if (!(condition)) {                                                                    \
      ::treg_test::report_failure(__FILE__, __LINE__, "check failed: " #condition);        \
    }                                                                                      \
  } while (false)

#define TREG_CHECK_EQ(actual, expected)                                                    \
  do {                                                                                     \
    const auto treg_actual = (actual);                                                     \
    const auto treg_expected = (expected);                                                 \
    if (!::treg_test::same(treg_actual, treg_expected)) {                                   \
      ::treg_test::report_failure(                                                         \
          __FILE__, __LINE__,                                                              \
          std::string{"expected "} + ::treg_test::render(treg_expected) + " but found " +   \
              ::treg_test::render(treg_actual) + " (" #actual " == " #expected ")");        \
    }                                                                                      \
  } while (false)

#define TREG_CHECK_CODE(result, expected_code)                                             \
  do {                                                                                     \
    const auto& treg_result = (result);                                                    \
    if (treg_result.has_value()) {                                                         \
      ::treg_test::report_failure(__FILE__, __LINE__,                                      \
                                  "expected the operation to fail with " #expected_code     \
                                  " but it succeeded");                                     \
    } else if (treg_result.error().code() != (expected_code)) {                             \
      ::treg_test::report_failure(__FILE__, __LINE__,                                       \
                                  std::string{"expected " #expected_code " but found "} +    \
                                      std::string{::tenant_registry::to_token(              \
                                          treg_result.error().code())} +                     \
                                      ": " + treg_result.error().detail());                  \
    }                                                                                        \
  } while (false)

#define TREG_CHECK_STATUS(status, expected_code)                                           \
  do {                                                                                     \
    const auto& treg_status = (status);                                                    \
    if (treg_status.ok()) {                                                                \
      ::treg_test::report_failure(__FILE__, __LINE__,                                      \
                                  "expected the operation to fail with " #expected_code     \
                                  " but it succeeded");                                     \
    } else if (treg_status.code() != (expected_code)) {                                     \
      ::treg_test::report_failure(__FILE__, __LINE__,                                       \
                                  std::string{"expected " #expected_code " but found "} +    \
                                      std::string{::tenant_registry::to_token(              \
                                          treg_status.code())} +                             \
                                      ": " + treg_status.error().detail());                  \
    }                                                                                        \
  } while (false)

#define TREG_REQUIRE(condition)                                                             \
  do {                                                                                      \
    if (!(condition)) {                                                                     \
      ::treg_test::report_failure(__FILE__, __LINE__, "requirement failed: " #condition);   \
      throw ::treg_test::TestAbort{};                                                       \
    }                                                                                       \
  } while (false)

#define TREG_REQUIRE_CODE(result, expected_code)                                            \
  do {                                                                                      \
    const auto& treg_result = (result);                                                     \
    if (!treg_result.has_value() || treg_result.error().code() != (expected_code)) {        \
      ::treg_test::report_failure(                                                          \
          __FILE__, __LINE__, "expected failure " #expected_code " from " #result);         \
      throw ::treg_test::TestAbort{};                                                       \
    }                                                                                       \
  } while (false)

#define TREG_REQUIRE_OK(result)                                                             \
  do {                                                                                      \
    const auto& treg_result = (result);                                                     \
    if (!treg_result.has_value()) {                                                         \
      ::treg_test::report_failure(__FILE__, __LINE__,                                       \
                                  std::string{"expected success from " #result " but found "} + \
                                      std::string{::tenant_registry::to_token(              \
                                          treg_result.error().code())} +                    \
                                      ": " + treg_result.error().detail());                 \
      throw ::treg_test::TestAbort{};                                                       \
    }                                                                                       \
  } while (false)

#endif  // TENANT_REGISTRY_TESTS_SUPPORT_TEST_HARNESS_HPP
