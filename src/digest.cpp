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

#include "tenant_registry/digest.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include "sha256.hpp"

namespace tenant_registry {

namespace {

constexpr char kHexDigits[] = "0123456789abcdef";

/// The value of one lower case hexadecimal digit, or 0xFF for anything else.
/// Upper case is deliberately not accepted: a digest has exactly one textual
/// form, and accepting a second one would make "the same digest" ambiguous.
constexpr std::uint8_t hex_value(char character) noexcept {
  if (character >= '0' && character <= '9') {
    return static_cast<std::uint8_t>(character - '0');
  }
  if (character >= 'a' && character <= 'f') {
    return static_cast<std::uint8_t>(character - 'a' + 10);
  }
  return 0xFFu;
}

}  // namespace

ContentDigest ContentDigest::zero() noexcept { return ContentDigest{}; }

ContentDigest ContentDigest::of(std::span<const std::byte> bytes) noexcept { return detail::sha256(bytes); }

ContentDigest ContentDigest::of(std::string_view text) noexcept { return detail::sha256(text); }

bool ContentDigest::parse(std::string_view text, ContentDigest& out) noexcept {
  if (text.size() != 64) {
    return false;
  }
  std::array<std::uint8_t, 32> parsed{};
  for (std::size_t index = 0; index < parsed.size(); ++index) {
    const std::uint8_t high = hex_value(text[index * 2]);
    const std::uint8_t low = hex_value(text[index * 2 + 1]);
    if (high == 0xFFu || low == 0xFFu) {
      return false;
    }
    parsed[index] = static_cast<std::uint8_t>((high << 4) | low);
  }
  out.bytes_ = parsed;
  return true;
}

bool ContentDigest::is_zero() const noexcept {
  for (const std::uint8_t byte : bytes_) {
    if (byte != 0u) {
      return false;
    }
  }
  return true;
}

std::string ContentDigest::to_text() const {
  std::string out;
  out.reserve(64);
  for (const std::uint8_t byte : bytes_) {
    out += kHexDigits[byte >> 4];
    out += kHexDigits[byte & 0x0Fu];
  }
  return out;
}

std::string ContentDigest::to_short_text() const {
  std::string out;
  out.reserve(16);
  for (std::size_t index = 0; index < 8; ++index) {
    out += kHexDigits[bytes_[index] >> 4];
    out += kHexDigits[bytes_[index] & 0x0Fu];
  }
  return out;
}

std::string domain_separated(std::string_view domain, std::string_view value) {
  std::string out;
  out.reserve(domain.size());
  out.append(domain);
  out.push_back('\0');
  out.append(value);
  return out;
}

}  // namespace tenant_registry
