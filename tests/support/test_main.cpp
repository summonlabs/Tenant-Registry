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

#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "test_harness.hpp"

#if defined(_WIN32)
#include <windows.h>
#endif

int main(int argc, char** argv) {
#if defined(_WIN32)
  // A test that wants to prove what happens when a process dies abruptly must
  // be able to die abruptly without Windows putting a dialog in front of it.
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
#endif

  std::vector<std::string> arguments;
  arguments.reserve(static_cast<std::size_t>(argc > 0 ? argc - 1 : 0));
  for (int index = 1; index < argc; ++index) {
    arguments.emplace_back(argv[index]);
  }

  if (argc > 0) {
    std::error_code error;
    const auto absolute = std::filesystem::absolute(std::filesystem::path{argv[0]}, error);
    treg_test::set_executable_path(error ? std::filesystem::path{argv[0]} : absolute);
  }

  return treg_test::run_all(arguments);
}
