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

#ifndef TENANT_REGISTRY_TESTS_SUPPORT_TEST_PROCESS_HPP
#define TENANT_REGISTRY_TESTS_SUPPORT_TEST_PROCESS_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace treg_test {

/// A real, independent operating system process running this same executable.
///
/// These exist so that every claim this repository makes about a second writer,
/// about a restart, and about an abrupt death is proved against the operating
/// system rather than argued about in one address space.
class ChildProcess {
 public:
  ChildProcess() = default;
  ~ChildProcess();

  ChildProcess(ChildProcess&& other) noexcept;
  ChildProcess& operator=(ChildProcess&& other) noexcept;
  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;

  /// Starts this executable again with the given arguments. The child inherits
  /// this process's standard streams, so nothing here needs a pipe.
  [[nodiscard]] static ChildProcess start(const std::vector<std::string>& arguments, std::string& error);

  [[nodiscard]] bool started() const noexcept;
  [[nodiscard]] std::uint64_t id() const noexcept { return id_; }

  /// Waits for the child and returns its exit code. Returns -1 when the child
  /// was never started.
  int wait();

  /// Terminates the child abruptly, without giving it a chance to run any
  /// cleanup. This is how kernel released lock behaviour is proved.
  void terminate();

 private:
  void release() noexcept;

  void* process_ = nullptr;
  void* thread_ = nullptr;
  std::uint64_t id_ = 0;
};

/// Runs this executable again with the given arguments, waits for it, and
/// returns its exit code.
int run_child(const std::vector<std::string>& arguments);

/// Blocks until a sentinel file appears, or the deadline passes. Returns false
/// on timeout. Used to sequence a test against a child that must first reach a
/// known state.
[[nodiscard]] bool wait_for_file(const std::string& path, std::uint64_t timeout_milliseconds);

}  // namespace treg_test

#endif  // TENANT_REGISTRY_TESTS_SUPPORT_TEST_PROCESS_HPP
