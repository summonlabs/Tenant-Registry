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

#ifndef TENANT_REGISTRY_SRC_BYTE_CODEC_HPP
#define TENANT_REGISTRY_SRC_BYTE_CODEC_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "tenant_registry/digest.hpp"
#include "tenant_registry/errors.hpp"

namespace tenant_registry {
namespace detail {

/// A bounded, canonical little-endian encoder.
///
/// Every multi byte field is little-endian, every length is a 32 bit unsigned
/// count of bytes, and no value is ever encoded through its in-memory
/// representation. Two builds on two machines therefore produce identical bytes
/// for the same value, which is what makes a digest over those bytes mean
/// anything.
///
/// The writer is additionally bounded: every append is refused once the buffer
/// has reached the writer's limit, so an encoder cannot be used to allocate
/// without end from untrusted input.
class ByteWriter {
 public:
  explicit ByteWriter(std::size_t limit = 64u * 1024u * 1024u) noexcept : limit_(limit) {}

  /// Appends an unsigned 8 bit value.
  void u8(std::uint8_t value);
  void u16(std::uint16_t value);
  void u32(std::uint32_t value);
  void u64(std::uint64_t value);
  void i64(std::int64_t value);

  /// Appends raw bytes with no length prefix.
  void raw(std::span<const std::byte> value);
  void raw(std::string_view value);

  /// Appends a 32 bit byte count followed by that many bytes.
  void length_prefixed(std::span<const std::byte> value);
  void length_prefixed(std::string_view value);

  /// Appends a 32 byte digest.
  void digest(const ContentDigest& value);

  /// Appends an explicit presence flag followed by the value when present. An
  /// absent optional encodes as a zero flag and nothing else: it can never be
  /// confused with a present value that happens to be zero or empty.
  template <class T, class Encode>
  void optional(const std::optional<T>& value, Encode&& encode) {
    if (value.has_value()) {
      u8(1);
      encode(*value);
    } else {
      u8(0);
    }
  }

  [[nodiscard]] std::size_t size() const noexcept { return bytes_.size(); }
  [[nodiscard]] bool overflowed() const noexcept { return overflowed_; }
  [[nodiscard]] const std::vector<std::byte>& bytes() const noexcept { return bytes_; }
  [[nodiscard]] std::vector<std::byte> take() && noexcept { return std::move(bytes_); }
  [[nodiscard]] std::span<const std::byte> view() const noexcept {
    return std::span<const std::byte>{bytes_.data(), bytes_.size()};
  }
  [[nodiscard]] std::string as_text() const;

 private:
  [[nodiscard]] bool reserve(std::size_t count) noexcept;

  std::vector<std::byte> bytes_;
  std::size_t limit_;
  bool overflowed_ = false;
};

/// A bounded, canonical little-endian decoder.
///
/// Every read returns nothing when the input is exhausted or malformed. There
/// is no overload that returns zero on failure, because a decoder that turns a
/// missing field into zero is a decoder that turns a truncated record into a
/// valid one.
class ByteReader {
 public:
  explicit ByteReader(std::span<const std::byte> data) noexcept : data_(data) {}

  [[nodiscard]] std::size_t remaining() const noexcept { return data_.size() - position_; }
  [[nodiscard]] std::size_t position() const noexcept { return position_; }
  [[nodiscard]] bool at_end() const noexcept { return position_ == data_.size(); }

  [[nodiscard]] std::optional<std::uint8_t> u8() noexcept;
  [[nodiscard]] std::optional<std::uint16_t> u16() noexcept;
  [[nodiscard]] std::optional<std::uint32_t> u32() noexcept;
  [[nodiscard]] std::optional<std::uint64_t> u64() noexcept;
  [[nodiscard]] std::optional<std::int64_t> i64() noexcept;

  [[nodiscard]] std::optional<std::span<const std::byte>> raw(std::size_t count) noexcept;
  [[nodiscard]] std::optional<std::span<const std::byte>> length_prefixed(std::size_t max_bytes) noexcept;
  [[nodiscard]] std::optional<std::string> length_prefixed_text(std::size_t max_bytes);
  [[nodiscard]] std::optional<ContentDigest> digest() noexcept;
  [[nodiscard]] std::optional<std::string> remaining_text(std::size_t max_bytes);

  /// Reads a presence flag. Nothing when absent, a value when present.
  [[nodiscard]] std::optional<bool> optional_present() noexcept;

  /// True when every byte has been consumed. A decoder must call this before it
  /// believes a record: trailing bytes are a malformed record, not a bonus.
  [[nodiscard]] bool require_end() const noexcept { return at_end(); }

 private:
  std::span<const std::byte> data_;
  std::size_t position_ = 0;
};

/// A canonical domain separated preimage: domain bytes, a zero byte, then the
/// value. The zero byte cannot occur inside a canonical identity token, so no
/// two (domain, value) pairs can collide.
[[nodiscard]] std::string canonical_preimage(std::string_view domain, std::string_view value);

}  // namespace detail
}  // namespace tenant_registry

#endif  // TENANT_REGISTRY_SRC_BYTE_CODEC_HPP
