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

#ifndef TENANT_REGISTRY_SRC_SHA256_HPP
#define TENANT_REGISTRY_SRC_SHA256_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "tenant_registry/digest.hpp"

namespace tenant_registry {
namespace detail {

/// Incremental SHA-256 (FIPS 180-4).
///
/// This exists so that a large durable payload can be hashed while it is being
/// written and verified without holding a second copy of it in memory, and so
/// that the journal's hash chain can be advanced by one step per commit instead
/// of re-hashing the whole journal.
class Sha256 {
 public:
  Sha256() noexcept;

  void update(std::span<const std::byte> bytes) noexcept;
  void update(std::string_view text) noexcept;

  /// Finalizes and returns the digest. The instance must not be updated after
  /// this call; a second call returns the same digest.
  [[nodiscard]] ContentDigest finish() noexcept;

 private:
  void compress(const std::uint8_t* block) noexcept;

  std::array<std::uint32_t, 8> state_;
  std::array<std::uint8_t, 64> buffer_{};
  std::size_t buffered_ = 0;
  std::uint64_t total_bytes_ = 0;
  ContentDigest digest_{};
  bool finished_ = false;
};

/// One shot SHA-256 over a byte range.
[[nodiscard]] ContentDigest sha256(std::span<const std::byte> bytes) noexcept;
[[nodiscard]] ContentDigest sha256(std::string_view text) noexcept;

/// The known answer test vector result for the empty input, used by the test
/// suite to prove this implementation rather than to trust it.
inline constexpr std::string_view kSha256EmptyHex =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// The known answer test vector result for "abc".
inline constexpr std::string_view kSha256AbcHex =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

}  // namespace detail
}  // namespace tenant_registry

#endif  // TENANT_REGISTRY_SRC_SHA256_HPP
