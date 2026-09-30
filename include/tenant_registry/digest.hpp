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

#ifndef TENANT_REGISTRY_DIGEST_HPP
#define TENANT_REGISTRY_DIGEST_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace tenant_registry {

/// A 32 byte SHA-256 digest.
///
/// Digests in this repository exist only where they protect a meaningful
/// binding: the exact identity of a record, the exact bytes of a commit, the
/// exact content of a snapshot, the exact shape of a request. They are never
/// used as decoration.
class ContentDigest {
 public:
  ContentDigest() = default;

  /// The all zero digest. It is deliberately *not* the digest of the empty
  /// byte sequence: an unset digest must not be confusable with a real one.
  [[nodiscard]] static ContentDigest zero() noexcept;

  [[nodiscard]] static ContentDigest of(std::span<const std::byte> bytes) noexcept;
  [[nodiscard]] static ContentDigest of(std::string_view text) noexcept;

  /// Parses exactly 64 lower case hexadecimal characters. Upper case input is
  /// refused rather than normalized, so a digest has exactly one textual form.
  [[nodiscard]] static bool parse(std::string_view text, ContentDigest& out) noexcept;

  [[nodiscard]] const std::array<std::uint8_t, 32>& bytes() const noexcept { return bytes_; }
  [[nodiscard]] bool is_zero() const noexcept;

  /// The lower case hexadecimal form, always 64 characters.
  [[nodiscard]] std::string to_text() const;

  /// The first 16 hexadecimal characters, for diagnostics only. This is not an
  /// identity and must never be compared for equality.
  [[nodiscard]] std::string to_short_text() const;

  friend bool operator==(const ContentDigest& lhs, const ContentDigest& rhs) noexcept {
    return lhs.bytes_ == rhs.bytes_;
  }
  friend bool operator!=(const ContentDigest& lhs, const ContentDigest& rhs) noexcept { return !(lhs == rhs); }
  friend bool operator<(const ContentDigest& lhs, const ContentDigest& rhs) noexcept {
    return lhs.bytes_ < rhs.bytes_;
  }

 private:
  std::array<std::uint8_t, 32> bytes_{};
};

/// CRC-32 (IEEE 802.3, reflected, polynomial 0xEDB88320). It is used only as a
/// fast first-line check inside durable frames, never as the integrity
/// guarantee; SHA-256 is the integrity guarantee.
[[nodiscard]] std::uint32_t crc32(std::span<const std::byte> bytes) noexcept;
[[nodiscard]] std::uint32_t crc32(std::string_view text) noexcept;

/// Builds the canonical domain separated digest preimage for one component, so
/// that two different kinds of identity can never produce the same preimage.
[[nodiscard]] std::string domain_separated(std::string_view domain, std::string_view value);

}  // namespace tenant_registry

#endif  // TENANT_REGISTRY_DIGEST_HPP
