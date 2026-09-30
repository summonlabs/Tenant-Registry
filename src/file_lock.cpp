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

#include "file_lock.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "file_ops.hpp"

#if defined(_WIN32)
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace tenant_registry {
namespace detail {

namespace {

/// The longest lock record this file writes, and the longest it reads back. A
/// lock file is evidence for an operator, never a data channel, so it is small
/// and it is bounded.
constexpr std::size_t kMaxLockRecordBytes = 512;

/// Replaces every byte outside the printable ASCII range with '.', and truncates
/// to max_bytes. A lock record is read back by operators and echoed into
/// diagnostics, so it must not be able to carry a control byte anywhere.
[[nodiscard]] std::string sanitize_record(std::string_view text, std::size_t max_bytes) {
  const std::size_t length = text.size() < max_bytes ? text.size() : max_bytes;
  std::string clean;
  clean.reserve(length);
  for (std::size_t index = 0; index < length; ++index) {
    const char character = text[index];
    const bool printable = character >= 0x20 && character <= 0x7E;
    clean.push_back(printable ? character : '.');
  }
  return clean;
}

#if defined(_WIN32)

/// Opens the lock file, withholding write sharing. That is the whole mechanism:
/// a second acquire asks for write access, this sharing mode does not grant it,
/// so the second open fails with a sharing violation and no second writer can
/// exist.
[[nodiscard]] void* open_lock_handle(const std::filesystem::path& path, Error& error) {
  HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    const DWORD code = GetLastError();
    if (code == ERROR_SHARING_VIOLATION || code == ERROR_LOCK_VIOLATION) {
      error = Error{ErrorCode::StoreLocked, "another writer already holds this store lock"};
      return nullptr;
    }
    error = Error{ErrorCode::StoreIoError, "the writer lock file could not be opened (Win32 error " +
                                               std::to_string(static_cast<unsigned long>(code)) + ")"};
    return nullptr;
  }
  return handle;
}

[[nodiscard]] Status write_record(void* handle, std::string_view record) {
  LARGE_INTEGER start{};
  start.QuadPart = 0;
  if (SetFilePointerEx(static_cast<HANDLE>(handle), start, nullptr, FILE_BEGIN) == FALSE) {
    return Status::failure(ErrorCode::StoreIoError, "the lock file could not be repositioned");
  }
  if (SetEndOfFile(static_cast<HANDLE>(handle)) == FALSE) {
    return Status::failure(ErrorCode::StoreIoError, "the lock file could not be truncated");
  }
  std::size_t written = 0;
  while (written < record.size()) {
    const DWORD chunk = static_cast<DWORD>(record.size() - written);
    DWORD progressed = 0;
    if (WriteFile(static_cast<HANDLE>(handle), record.data() + written, chunk, &progressed, nullptr) == FALSE) {
      return Status::failure(ErrorCode::StoreIoError, "the lock record could not be written");
    }
    if (progressed == 0) {
      return Status::failure(ErrorCode::StoreIoError, "the lock record write made no progress");
    }
    written += static_cast<std::size_t>(progressed);
  }
  if (FlushFileBuffers(static_cast<HANDLE>(handle)) == FALSE) {
    return Status::failure(ErrorCode::StoreIoError, "the lock record could not be flushed");
  }
  return Status::success();
}

void close_handle(void* handle) noexcept { (void)CloseHandle(static_cast<HANDLE>(handle)); }

#else  // POSIX

/// The frozen header stores one opaque pointer, so a descriptor is carried as a
/// pointer sized integer biased by one: descriptor zero is valid and a null
/// handle has to keep meaning "no lock".
[[nodiscard]] void* handle_from_fd(int descriptor) noexcept {
  return reinterpret_cast<void*>(static_cast<std::uintptr_t>(descriptor) + 1u);
}

[[nodiscard]] int fd_from_handle(void* handle) noexcept {
  return static_cast<int>(reinterpret_cast<std::uintptr_t>(handle) - 1u);
}

[[nodiscard]] void* open_lock_handle(const std::filesystem::path& path, Error& error) {
  const int descriptor = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  if (descriptor < 0) {
    const int code = errno;
    error = Error{ErrorCode::StoreIoError,
                  "the writer lock file could not be opened (errno " + std::to_string(code) + ")"};
    return nullptr;
  }
  struct flock exclusive{};
  exclusive.l_type = F_WRLCK;
  exclusive.l_whence = SEEK_SET;
  exclusive.l_start = 0;
  exclusive.l_len = 0;
  if (::fcntl(descriptor, F_SETLK, &exclusive) != 0) {
    const int code = errno;
    (void)::close(descriptor);
    if (code == EACCES || code == EAGAIN) {
      error = Error{ErrorCode::StoreLocked, "another writer already holds this store lock"};
    } else {
      error = Error{ErrorCode::StoreIoError,
                    "the writer lock could not be taken (errno " + std::to_string(code) + ")"};
    }
    return nullptr;
  }
  return handle_from_fd(descriptor);
}

[[nodiscard]] Status write_record(void* handle, std::string_view record) {
  const int descriptor = fd_from_handle(handle);
  if (::ftruncate(descriptor, 0) != 0) {
    return Status::failure(ErrorCode::StoreIoError, "the lock file could not be truncated");
  }
  if (::lseek(descriptor, 0, SEEK_SET) < 0) {
    return Status::failure(ErrorCode::StoreIoError, "the lock file could not be repositioned");
  }
  std::size_t written = 0;
  while (written < record.size()) {
    const ssize_t progressed = ::write(descriptor, record.data() + written, record.size() - written);
    if (progressed < 0) {
      if (errno == EINTR) {
        continue;
      }
      return Status::failure(ErrorCode::StoreIoError, "the lock record could not be written");
    }
    if (progressed == 0) {
      return Status::failure(ErrorCode::StoreIoError, "the lock record write made no progress");
    }
    written += static_cast<std::size_t>(progressed);
  }
  if (::fsync(descriptor) != 0) {
    return Status::failure(ErrorCode::StoreIoError, "the lock record could not be flushed");
  }
  return Status::success();
}

void close_handle(void* handle) noexcept { (void)::close(fd_from_handle(handle)); }

#endif

}  // namespace

FileLock::~FileLock() { release(); }

FileLock::FileLock(FileLock&& other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }

FileLock& FileLock::operator=(FileLock&& other) noexcept {
  if (this != &other) {
    release();
    handle_ = other.handle_;
    other.handle_ = nullptr;
  }
  return *this;
}

Result<FileLock> FileLock::acquire(const std::filesystem::path& path, std::string_view record) {
  const std::string clean = sanitize_record(record, kMaxLockRecordBytes);
  Error refusal{ErrorCode::Unspecified};
  void* handle = open_lock_handle(path, refusal);
  if (handle == nullptr) {
    return refusal;
  }
  const Status written = write_record(handle, clean);
  if (!written.ok()) {
    close_handle(handle);
    return written.error();
  }
  FileLock lock;
  lock.handle_ = handle;
  return lock;
}

bool FileLock::held() const noexcept { return handle_ != nullptr; }

void FileLock::release() noexcept {
  if (handle_ != nullptr) {
    close_handle(handle_);
    handle_ = nullptr;
  }
}

Result<std::string> read_lock_record(const std::filesystem::path& path) {
  const Result<std::vector<std::byte>> bytes = read_file_bounded(path, kMaxLockRecordBytes);
  if (!bytes) {
    return bytes.error();
  }
  std::string text;
  text.reserve(bytes.value().size());
  for (const std::byte byte : bytes.value()) {
    const unsigned int value = std::to_integer<unsigned int>(byte);
    text.push_back(value >= 0x20u && value <= 0x7Eu ? static_cast<char>(value) : '.');
  }
  return text;
}

}  // namespace detail
}  // namespace tenant_registry
