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

#if defined(_WIN32)
// rand_s, the CRT's cryptographically strong random source, is declared by
// <stdlib.h> only when this macro is defined before that header is first
// included, which is why it stands before every other include in this file.
#define _CRT_RAND_S
#endif

#include "file_ops.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "sha256.hpp"

#if defined(_WIN32)
#include <stdlib.h>
#include <windows.h>
#else
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace tenant_registry {
namespace detail {

namespace {

/// The largest block handed to one operating system read or write call. Larger
/// requests are split so that a single call is never given a length the platform
/// cannot express.
constexpr std::size_t kMaxTransferChunk = 16u * 1024u * 1024u;

/// The largest file this process will read in one call. It bounds what a single
/// untrusted file can make this process allocate for, before any reservation.
constexpr std::uint64_t kMaxSingleRead = 512ull * 1024ull * 1024ull;

/// How many directory entries a listing may return before it is refused instead
/// of truncated: a truncated listing would hide durable state.
constexpr std::size_t kMaxDirectoryEntries = 4096;

/// How many missing directories one call will create. A longer chain is refused
/// rather than walked without end.
constexpr std::size_t kMaxCreatedDirectories = 256;

/// Counts every token this process mints, so two tokens minted in the same
/// microsecond still differ.
std::atomic<std::uint64_t> g_token_counter{0};

[[nodiscard]] constexpr char hex_digit(unsigned int value) noexcept {
  return value < 10u ? static_cast<char>('0' + value) : static_cast<char>('a' + (value - 10u));
}

[[nodiscard]] std::string hex_encode(std::span<const std::uint8_t> bytes) {
  std::string text;
  text.reserve(bytes.size() * 2);
  for (const std::uint8_t byte : bytes) {
    text.push_back(hex_digit(static_cast<unsigned int>(byte >> 4)));
    text.push_back(hex_digit(static_cast<unsigned int>(byte & 0x0Fu)));
  }
  return text;
}

#if defined(_WIN32)

[[nodiscard]] ErrorCode classify_win32(DWORD code) noexcept {
  switch (code) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
    case ERROR_INVALID_NAME:
    case ERROR_BAD_PATHNAME:
      return ErrorCode::StoreNotFound;
    case ERROR_SHARING_VIOLATION:
    case ERROR_LOCK_VIOLATION:
      return ErrorCode::StoreLocked;
    default:
      return ErrorCode::StoreIoError;
  }
}

[[nodiscard]] Error win32_error(const char* what, DWORD code) {
  std::string detail =
      std::string{what} + " failed with Win32 error " + std::to_string(static_cast<unsigned long>(code));
  return Error{classify_win32(code), std::move(detail)};
}

[[nodiscard]] Status win32_status(const char* what, DWORD code) { return Status::failure(win32_error(what, code)); }

/// Writes every byte or reports why it could not.
[[nodiscard]] Status write_all(HANDLE handle, std::span<const std::byte> bytes) {
  std::size_t written = 0;
  while (written < bytes.size()) {
    const std::size_t remaining = bytes.size() - written;
    const DWORD chunk = static_cast<DWORD>(remaining < kMaxTransferChunk ? remaining : kMaxTransferChunk);
    DWORD progressed = 0;
    if (WriteFile(handle, bytes.data() + written, chunk, &progressed, nullptr) == FALSE) {
      return win32_status("write", GetLastError());
    }
    if (progressed == 0) {
      return Status::failure(ErrorCode::StoreIoError, "write made no progress");
    }
    written += static_cast<std::size_t>(progressed);
  }
  return Status::success();
}

/// Reads exactly buffer.size() bytes from offset, or reports why it could not.
[[nodiscard]] Status read_at(HANDLE handle, std::uint64_t offset, std::span<std::byte> buffer) {
  LARGE_INTEGER position{};
  position.QuadPart = static_cast<LONGLONG>(offset);
  if (SetFilePointerEx(handle, position, nullptr, FILE_BEGIN) == FALSE) {
    return win32_status("seek", GetLastError());
  }
  std::size_t filled = 0;
  while (filled < buffer.size()) {
    const std::size_t remaining = buffer.size() - filled;
    const DWORD chunk = static_cast<DWORD>(remaining < kMaxTransferChunk ? remaining : kMaxTransferChunk);
    DWORD progressed = 0;
    if (ReadFile(handle, buffer.data() + filled, chunk, &progressed, nullptr) == FALSE) {
      const DWORD code = GetLastError();
      if (code == ERROR_HANDLE_EOF) {
        break;
      }
      return win32_status("read", code);
    }
    if (progressed == 0) {
      break;
    }
    filled += static_cast<std::size_t>(progressed);
  }
  if (filled != buffer.size()) {
    return Status::failure(ErrorCode::StoreIoError, "read reached the end of the file before the requested length");
  }
  return Status::success();
}

[[nodiscard]] Status create_directory_one(const std::filesystem::path& path) {
  if (CreateDirectoryW(path.c_str(), nullptr) != FALSE) {
    return Status::success();
  }
  const DWORD code = GetLastError();
  if (code == ERROR_ALREADY_EXISTS) {
    if (tenant_registry::detail::is_directory(path)) {
      return Status::success();
    }
    return Status::failure(ErrorCode::StoreIoError, "a path component exists and is not a directory");
  }
  return win32_status("create directory", code);
}

#else  // POSIX

[[nodiscard]] Error errno_error(const char* what, int code) {
  const ErrorCode mapped = code == ENOENT ? ErrorCode::StoreNotFound : ErrorCode::StoreIoError;
  std::string detail = std::string{what} + " failed with errno " + std::to_string(code);
  return Error{mapped, std::move(detail)};
}

[[nodiscard]] Status errno_status(const char* what, int code) { return Status::failure(errno_error(what, code)); }

/// The frozen header stores one opaque pointer, so a POSIX descriptor is carried
/// as a pointer sized integer biased by one: descriptor zero is a valid
/// descriptor, and a null handle has to keep meaning "no file".
[[nodiscard]] void* handle_from_fd(int descriptor) noexcept {
  return reinterpret_cast<void*>(static_cast<std::uintptr_t>(descriptor) + 1u);
}

[[nodiscard]] int fd_from_handle(void* handle) noexcept {
  return static_cast<int>(reinterpret_cast<std::uintptr_t>(handle) - 1u);
}

[[nodiscard]] Status write_all(int descriptor, std::span<const std::byte> bytes) {
  std::size_t written = 0;
  while (written < bytes.size()) {
    const std::size_t remaining = bytes.size() - written;
    const std::size_t chunk = remaining < kMaxTransferChunk ? remaining : kMaxTransferChunk;
    const ssize_t progressed = ::write(descriptor, bytes.data() + written, chunk);
    if (progressed < 0) {
      if (errno == EINTR) {
        continue;
      }
      return errno_status("write", errno);
    }
    if (progressed == 0) {
      return Status::failure(ErrorCode::StoreIoError, "write made no progress");
    }
    written += static_cast<std::size_t>(progressed);
  }
  return Status::success();
}

[[nodiscard]] Status read_at(int descriptor, std::uint64_t offset, std::span<std::byte> buffer) {
  std::size_t filled = 0;
  while (filled < buffer.size()) {
    const std::size_t remaining = buffer.size() - filled;
    const std::size_t chunk = remaining < kMaxTransferChunk ? remaining : kMaxTransferChunk;
    const ssize_t progressed = ::pread(descriptor, buffer.data() + filled, chunk, static_cast<off_t>(offset + filled));
    if (progressed < 0) {
      if (errno == EINTR) {
        continue;
      }
      return errno_status("read", errno);
    }
    if (progressed == 0) {
      break;
    }
    filled += static_cast<std::size_t>(progressed);
  }
  if (filled != buffer.size()) {
    return Status::failure(ErrorCode::StoreIoError, "read reached the end of the file before the requested length");
  }
  return Status::success();
}

[[nodiscard]] Status create_directory_one(const std::filesystem::path& path) {
  if (::mkdir(path.c_str(), 0700) == 0) {
    return Status::success();
  }
  if (errno == EEXIST) {
    if (tenant_registry::detail::is_directory(path)) {
      return Status::success();
    }
    return Status::failure(ErrorCode::StoreIoError, "a path component exists and is not a directory");
  }
  return errno_status("create directory", errno);
}

#endif

[[nodiscard]] bool readable_length(std::uint64_t length, std::uint64_t max_bytes, Error& error) {
  if (length > max_bytes) {
    error = Error{ErrorCode::PayloadTooLarge,
                  "the file is " + std::to_string(length) + " bytes, above the bound of " +
                      std::to_string(max_bytes) + " bytes"};
    return false;
  }
  if (length > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
    error = Error{ErrorCode::PayloadTooLarge, "the file is larger than this process can address"};
    return false;
  }
  return true;
}

}  // namespace

AppendFile::~AppendFile() { (void)close(); }

AppendFile::AppendFile(AppendFile&& other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }

AppendFile& AppendFile::operator=(AppendFile&& other) noexcept {
  if (this != &other) {
    (void)close();
    handle_ = other.handle_;
    other.handle_ = nullptr;
  }
  return *this;
}

Result<AppendFile> AppendFile::open_existing(const std::filesystem::path& path) {
#if defined(_WIN32)
  HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    return win32_error("open", GetLastError());
  }
#else
  const int descriptor = ::open(path.c_str(), O_RDWR | O_CLOEXEC);
  if (descriptor < 0) {
    return errno_error("open", errno);
  }
  void* handle = handle_from_fd(descriptor);
#endif
  AppendFile file;
  file.handle_ = handle;
  return file;
}

Result<AppendFile> AppendFile::create_new(const std::filesystem::path& path) {
#if defined(_WIN32)
  HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    const DWORD code = GetLastError();
    if (code == ERROR_FILE_EXISTS || code == ERROR_ALREADY_EXISTS) {
      return Error{ErrorCode::StoreIoError, "the file already exists, so the exclusive create was refused"};
    }
    return win32_error("create", code);
  }
#else
  const int descriptor = ::open(path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (descriptor < 0) {
    if (errno == EEXIST) {
      return Error{ErrorCode::StoreIoError, "the file already exists, so the exclusive create was refused"};
    }
    return errno_error("create", errno);
  }
  void* handle = handle_from_fd(descriptor);
#endif
  AppendFile file;
  file.handle_ = handle;
  return file;
}

Status AppendFile::append(std::span<const std::byte> bytes) {
  if (handle_ == nullptr) {
    return Status::failure(ErrorCode::StoreIoError, "append refused because no file is open");
  }
  if (bytes.empty()) {
    return Status::success();
  }
#if defined(_WIN32)
  LARGE_INTEGER end{};
  end.QuadPart = 0;
  if (SetFilePointerEx(static_cast<HANDLE>(handle_), end, nullptr, FILE_END) == FALSE) {
    return win32_status("seek to end", GetLastError());
  }
  return write_all(static_cast<HANDLE>(handle_), bytes);
#else
  if (::lseek(fd_from_handle(handle_), 0, SEEK_END) < 0) {
    return errno_status("seek to end", errno);
  }
  return write_all(fd_from_handle(handle_), bytes);
#endif
}

Status AppendFile::flush() {
  if (handle_ == nullptr) {
    return Status::failure(ErrorCode::StoreIoError, "flush refused because no file is open");
  }
#if defined(_WIN32)
  if (FlushFileBuffers(static_cast<HANDLE>(handle_)) == FALSE) {
    return win32_status("flush", GetLastError());
  }
  return Status::success();
#else
  if (::fsync(fd_from_handle(handle_)) != 0) {
    return errno_status("flush", errno);
  }
  return Status::success();
#endif
}

Result<std::vector<std::byte>> AppendFile::read_back(std::uint64_t offset, std::size_t count) const {
  if (handle_ == nullptr) {
    return Error{ErrorCode::StoreIoError, "read back refused because no file is open"};
  }
  Error refusal{ErrorCode::Unspecified};
  if (!readable_length(static_cast<std::uint64_t>(count), kMaxSingleRead, refusal)) {
    return refusal;
  }
  std::vector<std::byte> buffer(count);
  if (!buffer.empty()) {
#if defined(_WIN32)
    const Status read = read_at(static_cast<HANDLE>(handle_), offset, buffer);
#else
    const Status read = read_at(fd_from_handle(handle_), offset, buffer);
#endif
    if (!read.ok()) {
      return read.error();
    }
  }
  return buffer;
}

Result<std::uint64_t> AppendFile::size() const {
  if (handle_ == nullptr) {
    return Error{ErrorCode::StoreIoError, "size refused because no file is open"};
  }
#if defined(_WIN32)
  LARGE_INTEGER length{};
  if (GetFileSizeEx(static_cast<HANDLE>(handle_), &length) == FALSE) {
    return win32_error("size", GetLastError());
  }
  if (length.QuadPart < 0) {
    return Error{ErrorCode::StoreCorrupt, "the file reports a negative length"};
  }
  return static_cast<std::uint64_t>(length.QuadPart);
#else
  struct stat info{};
  if (::fstat(fd_from_handle(handle_), &info) != 0) {
    return errno_error("size", errno);
  }
  if (info.st_size < 0) {
    return Error{ErrorCode::StoreCorrupt, "the file reports a negative length"};
  }
  return static_cast<std::uint64_t>(info.st_size);
#endif
}

Status AppendFile::truncate(std::uint64_t length) {
  if (handle_ == nullptr) {
    return Status::failure(ErrorCode::StoreIoError, "truncate refused because no file is open");
  }
#if defined(_WIN32)
  LARGE_INTEGER position{};
  position.QuadPart = static_cast<LONGLONG>(length);
  if (SetFilePointerEx(static_cast<HANDLE>(handle_), position, nullptr, FILE_BEGIN) == FALSE) {
    return win32_status("seek for truncate", GetLastError());
  }
  if (SetEndOfFile(static_cast<HANDLE>(handle_)) == FALSE) {
    return win32_status("truncate", GetLastError());
  }
  if (FlushFileBuffers(static_cast<HANDLE>(handle_)) == FALSE) {
    return win32_status("flush after truncate", GetLastError());
  }
  return Status::success();
#else
  if (::ftruncate(fd_from_handle(handle_), static_cast<off_t>(length)) != 0) {
    return errno_status("truncate", errno);
  }
  if (::fsync(fd_from_handle(handle_)) != 0) {
    return errno_status("flush after truncate", errno);
  }
  return Status::success();
#endif
}

Status AppendFile::close() {
  if (handle_ == nullptr) {
    return Status::success();
  }
#if defined(_WIN32)
  const HANDLE handle = static_cast<HANDLE>(handle_);
  handle_ = nullptr;
  if (CloseHandle(handle) == FALSE) {
    return win32_status("close", GetLastError());
  }
  return Status::success();
#else
  const int descriptor = fd_from_handle(handle_);
  handle_ = nullptr;
  if (::close(descriptor) != 0) {
    return errno_status("close", errno);
  }
  return Status::success();
#endif
}

Result<std::vector<std::byte>> read_file_bounded(const std::filesystem::path& path, std::uint64_t max_bytes) {
#if defined(_WIN32)
  HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    return win32_error("open", GetLastError());
  }
  LARGE_INTEGER length{};
  if (GetFileSizeEx(handle, &length) == FALSE) {
    const DWORD code = GetLastError();
    (void)CloseHandle(handle);
    return win32_error("size", code);
  }
  if (length.QuadPart < 0) {
    (void)CloseHandle(handle);
    return Error{ErrorCode::StoreCorrupt, "the file reports a negative length"};
  }
  const std::uint64_t file_bytes = static_cast<std::uint64_t>(length.QuadPart);
#else
  const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) {
    return errno_error("open", errno);
  }
  struct stat info{};
  if (::fstat(descriptor, &info) != 0) {
    const int code = errno;
    (void)::close(descriptor);
    return errno_error("size", code);
  }
  if (S_ISDIR(info.st_mode)) {
    (void)::close(descriptor);
    return Error{ErrorCode::StoreIoError, "the path names a directory, not a file"};
  }
  if (info.st_size < 0) {
    (void)::close(descriptor);
    return Error{ErrorCode::StoreCorrupt, "the file reports a negative length"};
  }
  const std::uint64_t file_bytes = static_cast<std::uint64_t>(info.st_size);
  void* handle = handle_from_fd(descriptor);
#endif
  Error refusal{ErrorCode::Unspecified};
  if (!readable_length(file_bytes, max_bytes, refusal)) {
#if defined(_WIN32)
    (void)CloseHandle(handle);
#else
    (void)::close(fd_from_handle(handle));
#endif
    return refusal;
  }
  std::vector<std::byte> buffer(static_cast<std::size_t>(file_bytes));
  if (!buffer.empty()) {
#if defined(_WIN32)
    const Status read = read_at(handle, 0, buffer);
#else
    const Status read = read_at(fd_from_handle(handle), 0, buffer);
#endif
    if (!read.ok()) {
#if defined(_WIN32)
      (void)CloseHandle(handle);
#else
      (void)::close(fd_from_handle(handle));
#endif
      return read.error();
    }
  }
#if defined(_WIN32)
  (void)CloseHandle(handle);
#else
  (void)::close(fd_from_handle(handle));
#endif
  return buffer;
}

Status write_new_file(const std::filesystem::path& path, std::span<const std::byte> bytes) {
#if defined(_WIN32)
  HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    const DWORD code = GetLastError();
    if (code == ERROR_FILE_EXISTS || code == ERROR_ALREADY_EXISTS) {
      return Status::failure(ErrorCode::StoreIoError, "create refused because the file already exists");
    }
    return win32_status("create", code);
  }
#else
  const int descriptor = ::open(path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (descriptor < 0) {
    if (errno == EEXIST) {
      return Status::failure(ErrorCode::StoreIoError, "create refused because the file already exists");
    }
    return errno_status("create", errno);
  }
  void* handle = handle_from_fd(descriptor);
#endif
#if defined(_WIN32)
  Status outcome = write_all(handle, bytes);
  if (outcome.ok() && FlushFileBuffers(handle) == FALSE) {
    outcome = win32_status("flush", GetLastError());
  }
  if (CloseHandle(handle) == FALSE && outcome.ok()) {
    outcome = win32_status("close", GetLastError());
  }
#else
  Status outcome = write_all(fd_from_handle(handle), bytes);
  if (outcome.ok() && ::fsync(fd_from_handle(handle)) != 0) {
    outcome = errno_status("flush", errno);
  }
  if (::close(fd_from_handle(handle)) != 0 && outcome.ok()) {
    outcome = errno_status("close", errno);
  }
#endif
  if (!outcome.ok()) {
    // A partially written file is not left behind: the caller asked for an
    // exclusive create, and half a file is worse than none.
    const Status removed = remove_file(path);
    if (!removed.ok()) {
      Error error = outcome.error();
      error.add_suppressed("the partially written file could not be removed");
      return Status::failure(std::move(error));
    }
    return outcome;
  }
  return Status::success();
}

Status sync_file(const std::filesystem::path& path) {
#if defined(_WIN32)
  HANDLE handle = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    return win32_status("open for flush", GetLastError());
  }
  const BOOL flushed = FlushFileBuffers(handle);
  const DWORD code = flushed != FALSE ? ERROR_SUCCESS : GetLastError();
  (void)CloseHandle(handle);
  if (flushed == FALSE) {
    return win32_status("flush", code);
  }
  return Status::success();
#else
  const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) {
    return errno_status("open for flush", errno);
  }
  const int flushed = ::fsync(descriptor);
  const int code = errno;
  (void)::close(descriptor);
  if (flushed != 0) {
    return errno_status("flush", code);
  }
  return Status::success();
#endif
}

Status replace_file(const std::filesystem::path& source, const std::filesystem::path& destination) {
#if defined(_WIN32)
  if (MoveFileExW(source.c_str(), destination.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == FALSE) {
    return win32_status("replace", GetLastError());
  }
  return Status::success();
#else
  if (::rename(source.c_str(), destination.c_str()) != 0) {
    return errno_status("replace", errno);
  }
  const std::filesystem::path parent = destination.parent_path();
  return sync_directory(parent.empty() ? std::filesystem::path{"."} : parent);
#endif
}

Status sync_directory(const std::filesystem::path& path) {
#if defined(_WIN32)
  // Windows has no directory flush this code can rely on, and the durability of
  // a replacement comes from MOVEFILE_WRITE_THROUGH plus FlushFileBuffers on the
  // file itself. Reporting success here is a documented difference, not a claim
  // that something was flushed.
  (void)path;
  return Status::success();
#else
#if defined(O_DIRECTORY)
  const int flags = O_RDONLY | O_CLOEXEC | O_DIRECTORY;
#else
  const int flags = O_RDONLY | O_CLOEXEC;
#endif
  const int descriptor = ::open(path.c_str(), flags);
  if (descriptor < 0) {
    return errno_status("open directory", errno);
  }
  const int flushed = ::fsync(descriptor);
  const int code = errno;
  (void)::close(descriptor);
  if (flushed != 0) {
    return errno_status("flush directory", code);
  }
  return Status::success();
#endif
}

Result<std::uint64_t> file_size(const std::filesystem::path& path) {
#if defined(_WIN32)
  WIN32_FILE_ATTRIBUTE_DATA data{};
  if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data) == FALSE) {
    return win32_error("size", GetLastError());
  }
  if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
    return Error{ErrorCode::StoreIoError, "the path names a directory, not a file"};
  }
  const std::uint64_t length = (static_cast<std::uint64_t>(data.nFileSizeHigh) << 32) |
                               static_cast<std::uint64_t>(data.nFileSizeLow);
  return length;
#else
  struct stat info{};
  if (::stat(path.c_str(), &info) != 0) {
    return errno_error("size", errno);
  }
  if (S_ISDIR(info.st_mode)) {
    return Error{ErrorCode::StoreIoError, "the path names a directory, not a file"};
  }
  if (info.st_size < 0) {
    return Error{ErrorCode::StoreCorrupt, "the file reports a negative length"};
  }
  return static_cast<std::uint64_t>(info.st_size);
#endif
}

bool path_exists(const std::filesystem::path& path) {
#if defined(_WIN32)
  return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
#else
  struct stat info{};
  return ::stat(path.c_str(), &info) == 0;
#endif
}

bool is_directory(const std::filesystem::path& path) {
#if defined(_WIN32)
  const DWORD attributes = GetFileAttributesW(path.c_str());
  return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
#else
  struct stat info{};
  return ::stat(path.c_str(), &info) == 0 && S_ISDIR(info.st_mode);
#endif
}

Status remove_file(const std::filesystem::path& path) noexcept {
#if defined(_WIN32)
  if (DeleteFileW(path.c_str()) != FALSE) {
    return Status::success();
  }
  const DWORD code = GetLastError();
  if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND) {
    // The postcondition "this path names no file" already holds.
    return Status::success();
  }
  return Status::failure(Error{ErrorCode::StoreIoError});
#else
  if (::unlink(path.c_str()) == 0) {
    return Status::success();
  }
  if (errno == ENOENT) {
    return Status::success();
  }
  return Status::failure(Error{ErrorCode::StoreIoError});
#endif
}

Status ensure_directory(const std::filesystem::path& path) {
  if (path.empty()) {
    return Status::failure(ErrorCode::InvalidArgument, "ensure_directory: the path is empty");
  }
  std::vector<std::filesystem::path> missing;
  std::filesystem::path current = path;
  for (;;) {
    if (tenant_registry::detail::is_directory(current)) {
      break;
    }
    if (path_exists(current)) {
      return Status::failure(ErrorCode::StoreIoError,
                             "ensure_directory: '" + to_utf8(current) + "' exists and is not a directory");
    }
    if (missing.size() >= kMaxCreatedDirectories) {
      return Status::failure(ErrorCode::StoreIoError,
                             "ensure_directory: the path has more components than this build will create");
    }
    missing.push_back(current);
    const std::filesystem::path parent = current.parent_path();
    if (parent.empty()) {
      // The current directory is the nearest ancestor that exists.
      break;
    }
    if (parent == current) {
      return Status::failure(ErrorCode::StoreIoError,
                             "ensure_directory: no existing ancestor directory for '" + to_utf8(path) + "'");
    }
    current = parent;
  }
  for (auto entry = missing.rbegin(); entry != missing.rend(); ++entry) {
    const Status created = create_directory_one(*entry);
    if (!created.ok()) {
      return created;
    }
  }
  return Status::success();
}

Result<std::vector<std::string>> list_directory_names(const std::filesystem::path& path, std::size_t max_entries) {
  std::vector<std::string> names;
#if defined(_WIN32)
  std::filesystem::path pattern = path;
  pattern /= L"*";
  WIN32_FIND_DATAW entry{};
  HANDLE search = FindFirstFileW(pattern.c_str(), &entry);
  if (search == INVALID_HANDLE_VALUE) {
    const DWORD code = GetLastError();
    if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND) {
      return names;
    }
    return win32_error("list directory", code);
  }
  bool more = true;
  while (more) {
    const std::wstring_view name{entry.cFileName};
    if (name != L"." && name != L"..") {
      if (names.size() >= max_entries) {
        (void)FindClose(search);
        return Error{ErrorCode::ListingLimitExceeded,
                     "the directory holds more entries than the listing bound allows"};
      }
      names.push_back(to_utf8(std::filesystem::path{entry.cFileName}));
    }
    if (FindNextFileW(search, &entry) == FALSE) {
      const DWORD code = GetLastError();
      if (code != ERROR_NO_MORE_FILES) {
        (void)FindClose(search);
        return win32_error("list directory", code);
      }
      more = false;
    }
  }
  (void)FindClose(search);
#else
  DIR* directory = ::opendir(path.c_str());
  if (directory == nullptr) {
    return errno_error("list directory", errno);
  }
  for (;;) {
    errno = 0;
    const dirent* entry = ::readdir(directory);
    if (entry == nullptr) {
      if (errno != 0) {
        const int code = errno;
        (void)::closedir(directory);
        return errno_error("list directory", code);
      }
      break;
    }
    const std::string_view name{entry->d_name};
    if (name == "." || name == "..") {
      continue;
    }
    if (names.size() >= max_entries) {
      (void)::closedir(directory);
      return Error{ErrorCode::ListingLimitExceeded, "the directory holds more entries than the listing bound allows"};
    }
    names.push_back(std::string{name});
  }
  (void)::closedir(directory);
#endif
  std::sort(names.begin(), names.end());
  return names;
}

std::string random_token() {
  std::array<std::uint8_t, 32> pool{};
#if defined(_WIN32)
  for (std::size_t index = 0; index < pool.size(); index += 4) {
    unsigned int value = 0;
    if (rand_s(&value) != 0) {
      break;
    }
    pool[index + 0] = static_cast<std::uint8_t>(value & 0xFFu);
    pool[index + 1] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
    pool[index + 2] = static_cast<std::uint8_t>((value >> 16) & 0xFFu);
    pool[index + 3] = static_cast<std::uint8_t>((value >> 24) & 0xFFu);
  }
#else
  const int descriptor = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
  if (descriptor >= 0) {
    std::size_t filled = 0;
    while (filled < pool.size()) {
      const ssize_t progressed = ::read(descriptor, pool.data() + filled, pool.size() - filled);
      if (progressed > 0) {
        filled += static_cast<std::size_t>(progressed);
        continue;
      }
      if (progressed < 0 && errno == EINTR) {
        continue;
      }
      break;
    }
    (void)::close(descriptor);
  }
#endif
  // Whatever the operating system supplied is mixed with values that differ
  // between two processes even when no system source is available, and the mix
  // is hashed, so a token exposes nothing about the values it was built from.
  const std::uint64_t counter = g_token_counter.fetch_add(1, std::memory_order_relaxed);
  const std::uint64_t steady = static_cast<std::uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
  const std::uint64_t wall = static_cast<std::uint64_t>(std::chrono::system_clock::now().time_since_epoch().count());
  const std::uint64_t thread = static_cast<std::uint64_t>(std::hash<std::thread::id>{}(std::this_thread::get_id()));
  const std::uint64_t process = current_process_id();
  const std::uint64_t address = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(&counter));
  const std::array<std::uint64_t, 6> extra{counter, steady, wall, thread, process, address};
  Sha256 hasher;
  hasher.update(std::span<const std::byte>{reinterpret_cast<const std::byte*>(pool.data()), pool.size()});
  hasher.update(std::span<const std::byte>{reinterpret_cast<const std::byte*>(extra.data()),
                                           extra.size() * sizeof(std::uint64_t)});
  const ContentDigest digest = hasher.finish();
  return hex_encode(std::span<const std::uint8_t>{digest.bytes().data(), 16});
}

std::uint64_t current_process_id() noexcept {
#if defined(_WIN32)
  return static_cast<std::uint64_t>(GetCurrentProcessId());
#else
  return static_cast<std::uint64_t>(::getpid());
#endif
}

std::string to_utf8(const std::filesystem::path& path) {
#if defined(_WIN32)
  const std::u8string text = path.u8string();
  if (text.empty()) {
    return std::string{};
  }
  return std::string{reinterpret_cast<const char*>(text.data()), text.size()};
#else
  return path.native();
#endif
}

}  // namespace detail
}  // namespace tenant_registry
