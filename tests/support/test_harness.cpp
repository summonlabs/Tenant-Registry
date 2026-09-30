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

#include "test_harness.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include "tenant_registry/tenant_registry.hpp"

namespace treg_test {
namespace {

struct TestCase {
  std::string suite;
  std::string name;
  TestFunction function;
  bool failed = false;
};

std::vector<TestCase>& cases() {
  static std::vector<TestCase> registry;
  return registry;
}

std::map<std::string, std::function<int(const std::vector<std::string>&)>>& child_modes() {
  static std::map<std::string, std::function<int(const std::vector<std::string>&)>> handlers;
  return handlers;
}

bool& current_failed() {
  static bool failed = false;
  return failed;
}

std::string& current_name() {
  static std::string name;
  return name;
}

std::filesystem::path& executable() {
  static std::filesystem::path path;
  return path;
}

std::string unique_token() {
  static std::uint64_t counter = 0;
  ++counter;
  const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
  std::mt19937_64 generator{static_cast<std::uint64_t>(now) ^ (counter * 0x9E3779B97F4A7C15ull)};
  return std::to_string(generator() % 1000000000ull) + "-" + std::to_string(counter);
}

}  // namespace

Registrar::Registrar(const char* suite, const char* name, TestFunction function) {
  cases().push_back(TestCase{suite, name, function, false});
}

void register_child_mode(std::string_view mode, std::function<int(const std::vector<std::string>&)> handler) {
  child_modes()[std::string{mode}] = std::move(handler);
}

int dispatch_child(const std::string& mode, const std::vector<std::string>& arguments) {
  const auto found = child_modes().find(mode);
  if (found == child_modes().end()) {
    std::fprintf(stderr, "treg_tests: no child mode is registered for '%s'\n", mode.c_str());
    return 64;
  }
  return found->second(arguments);
}

void report_failure(const char* file, int line, const std::string& message) {
  current_failed() = true;
  std::fprintf(stderr, "  FAIL %s:%d: %s\n", file, line, message.c_str());
  std::fflush(stderr);
}

bool current_test_has_failed() noexcept { return current_failed(); }

const std::filesystem::path& executable_path() { return executable(); }

void set_executable_path(const std::filesystem::path& path) { executable() = path; }

std::filesystem::path make_temp_directory(std::string_view label) {
  const auto base = std::filesystem::temp_directory_path();
  std::filesystem::path candidate = base / ("treg-test-" + std::string{label} + "-" + unique_token());
  std::error_code error;
  std::filesystem::create_directories(candidate, error);
  if (error) {
    std::fprintf(stderr, "treg_tests: could not create %s\n", candidate.string().c_str());
    std::abort();
  }
  return candidate;
}

void remove_tree(const std::filesystem::path& path) noexcept {
  std::error_code error;
  std::filesystem::remove_all(path, error);
}

std::string render(std::string_view value) { return std::string{value}; }
std::string render(const std::string& value) { return value; }
std::string render(bool value) { return value ? "true" : "false"; }
std::string render(const char* value) { return std::string{value}; }

int run_all(const std::vector<std::string>& arguments) {
  std::vector<std::string> filters;
  for (std::size_t index = 0; index < arguments.size(); ++index) {
    const std::string& argument = arguments[index];
    if (argument == "--child" && index + 1 < arguments.size()) {
      const std::string mode = arguments[index + 1];
      std::vector<std::string> rest;
      for (std::size_t other = index + 2; other < arguments.size(); ++other) {
        rest.push_back(arguments[other]);
      }
      return dispatch_child(mode, rest);
    }
    if (argument == "--filter" && index + 1 < arguments.size()) {
      filters.push_back(arguments[index + 1]);
      ++index;
      continue;
    }
    if (!argument.empty() && argument[0] != '-') {
      filters.push_back(argument);
    }
  }

  std::size_t passed = 0;
  std::size_t failed = 0;
  std::vector<std::string> failures;

  for (auto& test : cases()) {
    if (!filters.empty()) {
      bool matches = false;
      for (const auto& filter : filters) {
        if (test.suite.find(filter) != std::string::npos || test.name.find(filter) != std::string::npos) {
          matches = true;
          break;
        }
      }
      if (!matches) {
        continue;
      }
    }
    current_failed() = false;
    current_name() = test.suite + "." + test.name;
    std::printf("RUN  %s\n", current_name().c_str());
    std::fflush(stdout);
    try {
      test.function();
    } catch (const TestAbort&) {
      current_failed() = true;
    } catch (const std::exception& error) {
      report_failure(__FILE__, __LINE__, std::string{"unexpected exception: "} + error.what());
    } catch (...) {
      report_failure(__FILE__, __LINE__, "unexpected non standard exception");
    }
    if (current_failed()) {
      ++failed;
      failures.push_back(current_name());
      std::printf("FAIL %s\n", current_name().c_str());
    } else {
      ++passed;
      std::printf("PASS %s\n", current_name().c_str());
    }
    std::fflush(stdout);
  }

  std::printf("\n%zu passed, %zu failed\n", passed, failed);
  for (const auto& name : failures) {
    std::printf("  failed: %s\n", name.c_str());
  }
  std::fflush(stdout);
  return failed == 0 ? 0 : 1;
}

}  // namespace treg_test
