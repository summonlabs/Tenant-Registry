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

#ifndef TENANT_REGISTRY_SRC_FILE_LOCK_HPP
#define TENANT_REGISTRY_SRC_FILE_LOCK_HPP

#include <filesystem>
#include <string>
#include <string_view>

#include "tenant_registry/errors.hpp"

namespace tenant_registry {
namespace detail {

/// An exclusive, operating-system backed lock on a file.
///
/// This is the mechanism that makes a durable store single-writer. It is held
/// for the whole lifetime of a read-write session and is released by the
/// operating system even when the process dies without running any cleanup, so
/// a crashed writer can never block or authorize a later one.
///
/// The lock is advisory in the sense that a process which never calls acquire
/// is free to read the file; it is mandatory in the sense that a second acquire
/// of the same path fails while the first is held.
class FileLock {
 public:
  FileLock() = default;
  ~FileLock();

  FileLock(FileLock&& other) noexcept;
  FileLock& operator=(FileLock&& other) noexcept;
  FileLock(const FileLock&) = delete;
  FileLock& operator=(const FileLock&) = delete;

  /// Takes the lock without blocking. Fails with StoreLocked when another
  /// process holds it, and with StoreIoError for anything else. On success the
  /// file is truncated and record is written into it, so an operator can see
  /// who holds it.
  [[nodiscard]] static Result<FileLock> acquire(const std::filesystem::path& path, std::string_view record);

  [[nodiscard]] bool held() const noexcept;
  void release() noexcept;

 private:
  void* handle_ = nullptr;
};

/// Reads the record left in a lock file, without taking the lock. Used by
/// read-only inspection to report who currently holds the store.
[[nodiscard]] Result<std::string> read_lock_record(const std::filesystem::path& path);

}  // namespace detail
}  // namespace tenant_registry

#endif  // TENANT_REGISTRY_SRC_FILE_LOCK_HPP
