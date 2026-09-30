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

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "tenant_registry/digest.hpp"

namespace tenant_registry {

namespace {

/// The reflected lookup table for polynomial 0xEDB88320, built at compile time
/// so that no initialization order and no lazy state is involved.
constexpr std::array<std::uint32_t, 256> make_crc32_table() noexcept {
  std::array<std::uint32_t, 256> table{};
  for (std::size_t index = 0; index < table.size(); ++index) {
    std::uint32_t value = static_cast<std::uint32_t>(index);
    for (unsigned bit = 0; bit < 8u; ++bit) {
      value = (value & 1u) != 0u ? (0xEDB88320u ^ (value >> 1)) : (value >> 1);
    }
    table[index] = value;
  }
  return table;
}

constexpr std::array<std::uint32_t, 256> kCrc32Table = make_crc32_table();

std::uint32_t crc32_impl(std::span<const std::byte> bytes) noexcept {
  std::uint32_t crc = 0xFFFFFFFFu;
  for (const std::byte value : bytes) {
    const std::uint8_t byte = static_cast<std::uint8_t>(value);
    crc = kCrc32Table[(crc ^ byte) & 0xFFu] ^ (crc >> 8);
  }
  return crc ^ 0xFFFFFFFFu;
}

}  // namespace

std::uint32_t crc32(std::span<const std::byte> bytes) noexcept { return crc32_impl(bytes); }

std::uint32_t crc32(std::string_view text) noexcept {
  return crc32_impl(std::span<const std::byte>{reinterpret_cast<const std::byte*>(text.data()), text.size()});
}

}  // namespace tenant_registry
