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

#include "byte_codec.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "tenant_registry/digest.hpp"
#include "tenant_registry/errors.hpp"

namespace tenant_registry {
namespace detail {

namespace {

constexpr char kHexDigits[] = "0123456789abcdef";

std::string hex_of(std::span<const std::byte> bytes) {
  std::string out;
  for (const std::byte value : bytes) {
    const std::uint8_t byte = static_cast<std::uint8_t>(value);
    out += kHexDigits[byte >> 4];
    out += kHexDigits[byte & 0x0Fu];
  }
  return out;
}

}  // namespace

bool ByteWriter::reserve(std::size_t count) noexcept {
  if (overflowed_) {
    return false;
  }
  // No addition is performed here: bytes_.size() never exceeds limit_, so the
  // subtraction below cannot wrap and the comparison cannot either.
  if (count > limit_ - bytes_.size()) {
    overflowed_ = true;
    return false;
  }
  return true;
}

void ByteWriter::u8(std::uint8_t value) {
  if (!reserve(1)) {
    return;
  }
  bytes_.push_back(static_cast<std::byte>(value));
}

void ByteWriter::u16(std::uint16_t value) {
  if (!reserve(2)) {
    return;
  }
  bytes_.push_back(static_cast<std::byte>(value & 0xFFu));
  bytes_.push_back(static_cast<std::byte>((value >> 8) & 0xFFu));
}

void ByteWriter::u32(std::uint32_t value) {
  if (!reserve(4)) {
    return;
  }
  for (unsigned shift = 0; shift < 32u; shift += 8u) {
    bytes_.push_back(static_cast<std::byte>((value >> shift) & 0xFFu));
  }
}

void ByteWriter::u64(std::uint64_t value) {
  if (!reserve(8)) {
    return;
  }
  for (unsigned shift = 0; shift < 64u; shift += 8u) {
    bytes_.push_back(static_cast<std::byte>((value >> shift) & 0xFFu));
  }
}

void ByteWriter::i64(std::int64_t value) {
  // The two's complement bit pattern is written, so -1 and UINT64_MAX have the
  // same bytes; the field's declared type is what tells them apart.
  u64(std::bit_cast<std::uint64_t>(value));
}

void ByteWriter::raw(std::span<const std::byte> value) {
  if (!reserve(value.size())) {
    return;
  }
  bytes_.insert(bytes_.end(), value.begin(), value.end());
}

void ByteWriter::raw(std::string_view value) {
  raw(std::span<const std::byte>{reinterpret_cast<const std::byte*>(value.data()), value.size()});
}

void ByteWriter::length_prefixed(std::span<const std::byte> value) {
  if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
    // A length that does not fit its own field is refused rather than wrapped.
    overflowed_ = true;
    return;
  }
  if (!reserve(value.size() + 4)) {
    return;
  }
  u32(static_cast<std::uint32_t>(value.size()));
  raw(value);
}

void ByteWriter::length_prefixed(std::string_view value) {
  length_prefixed(std::span<const std::byte>{reinterpret_cast<const std::byte*>(value.data()), value.size()});
}

void ByteWriter::digest(const ContentDigest& value) {
  const std::array<std::uint8_t, 32>& bytes = value.bytes();
  raw(std::span<const std::byte>{reinterpret_cast<const std::byte*>(bytes.data()), bytes.size()});
}

std::string ByteWriter::as_text() const {
  // A diagnostic rendering, not a canonical encoding: lowercase hexadecimal so
  // that it is printable, unambiguous and identical on every platform. The
  // canonical bytes are what bytes() and take() carry.
  return hex_of(view());
}

std::optional<std::uint8_t> ByteReader::u8() noexcept {
  if (data_.size() - position_ < 1) {
    return std::nullopt;
  }
  const std::uint8_t value = static_cast<std::uint8_t>(data_[position_]);
  ++position_;
  return value;
}

std::optional<std::uint16_t> ByteReader::u16() noexcept {
  if (data_.size() - position_ < 2) {
    return std::nullopt;
  }
  std::uint16_t value = 0;
  for (unsigned index = 0; index < 2; ++index) {
    value = static_cast<std::uint16_t>(value | static_cast<std::uint16_t>(
                                                   static_cast<std::uint16_t>(data_[position_ + index]) << (8u * index)));
  }
  position_ += 2;
  return value;
}

std::optional<std::uint32_t> ByteReader::u32() noexcept {
  if (data_.size() - position_ < 4) {
    return std::nullopt;
  }
  std::uint32_t value = 0;
  for (unsigned index = 0; index < 4; ++index) {
    value |= static_cast<std::uint32_t>(data_[position_ + index]) << (8u * index);
  }
  position_ += 4;
  return value;
}

std::optional<std::uint64_t> ByteReader::u64() noexcept {
  if (data_.size() - position_ < 8) {
    return std::nullopt;
  }
  std::uint64_t value = 0;
  for (unsigned index = 0; index < 8; ++index) {
    value |= static_cast<std::uint64_t>(data_[position_ + index]) << (8u * index);
  }
  position_ += 8;
  return value;
}

std::optional<std::int64_t> ByteReader::i64() noexcept {
  const std::optional<std::uint64_t> value = u64();
  if (!value.has_value()) {
    return std::nullopt;
  }
  return std::bit_cast<std::int64_t>(*value);
}

std::optional<std::span<const std::byte>> ByteReader::raw(std::size_t count) noexcept {
  if (count > data_.size() - position_) {
    return std::nullopt;
  }
  const std::span<const std::byte> value = data_.subspan(position_, count);
  position_ += count;
  return value;
}

std::optional<std::span<const std::byte>> ByteReader::length_prefixed(std::size_t max_bytes) noexcept {
  const std::size_t start = position_;
  const std::optional<std::uint32_t> length = u32();
  if (!length.has_value()) {
    return std::nullopt;
  }
  if (static_cast<std::size_t>(*length) > max_bytes) {
    position_ = start;
    return std::nullopt;
  }
  const std::optional<std::span<const std::byte>> value = raw(static_cast<std::size_t>(*length));
  if (!value.has_value()) {
    position_ = start;
    return std::nullopt;
  }
  return value;
}

std::optional<std::string> ByteReader::length_prefixed_text(std::size_t max_bytes) {
  const std::optional<std::span<const std::byte>> value = length_prefixed(max_bytes);
  if (!value.has_value()) {
    return std::nullopt;
  }
  if (value->empty()) {
    return std::string{};
  }
  // The bytes are returned as they were encoded. Whether they are legal text
  // for the field that owns them is decided by the record layer, which knows
  // that field's rules.
  return std::string{reinterpret_cast<const char*>(value->data()), value->size()};
}

std::optional<ContentDigest> ByteReader::digest() noexcept {
  const std::size_t start = position_;
  const std::optional<std::span<const std::byte>> value = raw(32);
  if (!value.has_value()) {
    return std::nullopt;
  }
  const std::string hex = hex_of(*value);
  ContentDigest out;
  if (!ContentDigest::parse(hex, out)) {
    position_ = start;
    return std::nullopt;
  }
  return out;
}

std::optional<std::string> ByteReader::remaining_text(std::size_t max_bytes) {
  if (remaining() > max_bytes) {
    return std::nullopt;
  }
  const std::optional<std::span<const std::byte>> value = raw(remaining());
  if (!value.has_value()) {
    return std::nullopt;
  }
  if (value->empty()) {
    return std::string{};
  }
  return std::string{reinterpret_cast<const char*>(value->data()), value->size()};
}

std::optional<bool> ByteReader::optional_present() noexcept {
  const std::size_t start = position_;
  const std::optional<std::uint8_t> flag = u8();
  if (!flag.has_value()) {
    return std::nullopt;
  }
  if (*flag == 0u) {
    return false;
  }
  if (*flag == 1u) {
    return true;
  }
  // Any other byte is a malformed flag, not a truthy one.
  position_ = start;
  return std::nullopt;
}

std::string canonical_preimage(std::string_view domain, std::string_view value) {
  return domain_separated(domain, value);
}

}  // namespace detail
}  // namespace tenant_registry
