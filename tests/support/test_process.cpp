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

#include "test_process.hpp"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#include "test_harness.hpp"

#if defined(_WIN32)
#include <windows.h>
#else
#include <csignal>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace treg_test {

#if defined(_WIN32)

ChildProcess::~ChildProcess() { release(); }

ChildProcess::ChildProcess(ChildProcess&& other) noexcept
    : process_(other.process_), thread_(other.thread_), id_(other.id_) {
  other.process_ = nullptr;
  other.thread_ = nullptr;
  other.id_ = 0;
}

ChildProcess& ChildProcess::operator=(ChildProcess&& other) noexcept {
  if (this != &other) {
    release();
    process_ = other.process_;
    thread_ = other.thread_;
    id_ = other.id_;
    other.process_ = nullptr;
    other.thread_ = nullptr;
    other.id_ = 0;
  }
  return *this;
}

void ChildProcess::release() noexcept {
  if (process_ != nullptr) {
    CloseHandle(static_cast<HANDLE>(process_));
    process_ = nullptr;
  }
  if (thread_ != nullptr) {
    CloseHandle(static_cast<HANDLE>(thread_));
    thread_ = nullptr;
  }
  id_ = 0;
}

bool ChildProcess::started() const noexcept { return process_ != nullptr; }

ChildProcess ChildProcess::start(const std::vector<std::string>& arguments, std::string& error) {
  std::string command_line = "\"" + executable_path().string() + "\"";
  for (const auto& argument : arguments) {
    command_line.append(" \"");
    command_line.append(argument);
    command_line.append("\"");
  }

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION information{};
  std::wstring wide(command_line.begin(), command_line.end());
  std::vector<wchar_t> buffer(wide.begin(), wide.end());
  buffer.push_back(L'\0');

  if (CreateProcessW(nullptr, buffer.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &startup,
                     &information) == 0) {
    error = "CreateProcessW failed with error " + std::to_string(GetLastError());
    return ChildProcess{};
  }

  ChildProcess child;
  child.process_ = information.hProcess;
  child.thread_ = information.hThread;
  child.id_ = information.dwProcessId;
  return child;
}

int ChildProcess::wait() {
  if (process_ == nullptr) {
    return -1;
  }
  const DWORD status = WaitForSingleObject(static_cast<HANDLE>(process_), INFINITE);
  if (status != WAIT_OBJECT_0) {
    return -1;
  }
  DWORD code = 0;
  if (GetExitCodeProcess(static_cast<HANDLE>(process_), &code) == 0) {
    return -1;
  }
  return static_cast<int>(code);
}

void ChildProcess::terminate() {
  if (process_ == nullptr) {
    return;
  }
  TerminateProcess(static_cast<HANDLE>(process_), 3);
  WaitForSingleObject(static_cast<HANDLE>(process_), INFINITE);
}

#else  // POSIX

ChildProcess::~ChildProcess() { release(); }

ChildProcess::ChildProcess(ChildProcess&& other) noexcept
    : process_(other.process_), thread_(other.thread_), id_(other.id_) {
  other.process_ = nullptr;
  other.id_ = 0;
}

ChildProcess& ChildProcess::operator=(ChildProcess&& other) noexcept {
  if (this != &other) {
    release();
    process_ = other.process_;
    id_ = other.id_;
    other.process_ = nullptr;
    other.id_ = 0;
  }
  return *this;
}

void ChildProcess::release() noexcept {
  process_ = nullptr;
  id_ = 0;
}

bool ChildProcess::started() const noexcept { return process_ != nullptr; }

ChildProcess ChildProcess::start(const std::vector<std::string>& arguments, std::string& error) {
  std::vector<std::string> storage;
  storage.push_back(executable_path().string());
  for (const auto& argument : arguments) {
    storage.push_back(argument);
  }
  std::vector<char*> argv;
  for (auto& entry : storage) {
    argv.push_back(entry.data());
  }
  argv.push_back(nullptr);

  const pid_t pid = ::fork();
  if (pid < 0) {
    error = "fork failed";
    return ChildProcess{};
  }
  if (pid == 0) {
    ::execv(storage[0].c_str(), argv.data());
    ::_exit(127);
  }
  ChildProcess child;
  child.process_ = reinterpret_cast<void*>(static_cast<std::intptr_t>(pid));
  child.id_ = static_cast<std::uint64_t>(pid);
  return child;
}

int ChildProcess::wait() {
  if (process_ == nullptr) {
    return -1;
  }
  int status = 0;
  const pid_t pid = static_cast<pid_t>(reinterpret_cast<std::intptr_t>(process_));
  if (::waitpid(pid, &status, 0) < 0) {
    return -1;
  }
  process_ = nullptr;
  id_ = 0;
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  return 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
}

void ChildProcess::terminate() {
  if (process_ == nullptr) {
    return;
  }
  const pid_t pid = static_cast<pid_t>(reinterpret_cast<std::intptr_t>(process_));
  ::kill(pid, SIGKILL);
  int status = 0;
  ::waitpid(pid, &status, 0);
  process_ = nullptr;
  id_ = 0;
}

#endif

int run_child(const std::vector<std::string>& arguments) {
  std::string error;
  ChildProcess child = ChildProcess::start(arguments, error);
  if (!child.started()) {
    std::fprintf(stderr, "treg_tests: could not start a child process: %s\n", error.c_str());
    return -1;
  }
  return child.wait();
}

bool wait_for_file(const std::string& path, std::uint64_t timeout_milliseconds) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_milliseconds);
  while (std::chrono::steady_clock::now() < deadline) {
    std::error_code error;
    if (std::filesystem::exists(std::filesystem::path{path}, error)) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  return false;
}

}  // namespace treg_test
