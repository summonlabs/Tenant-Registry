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

#include "sha256.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>

#include "tenant_registry/digest.hpp"

namespace tenant_registry {
namespace detail {

namespace {

// FIPS 180-4 section 4.2.2.
constexpr std::array<std::uint32_t, 64> kRoundConstants = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

// FIPS 180-4 section 5.3.3.
constexpr std::array<std::uint32_t, 8> kInitialState = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                                                        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

constexpr std::uint32_t rotate_right(std::uint32_t value, unsigned count) noexcept {
  return (value >> count) | (value << (32u - count));
}

constexpr std::uint32_t choose(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept {
  return (x & y) ^ (~x & z);
}

constexpr std::uint32_t majority(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept {
  return (x & y) ^ (x & z) ^ (y & z);
}

constexpr std::uint32_t big_sigma0(std::uint32_t value) noexcept {
  return rotate_right(value, 2) ^ rotate_right(value, 13) ^ rotate_right(value, 22);
}

constexpr std::uint32_t big_sigma1(std::uint32_t value) noexcept {
  return rotate_right(value, 6) ^ rotate_right(value, 11) ^ rotate_right(value, 25);
}

constexpr std::uint32_t small_sigma0(std::uint32_t value) noexcept {
  return rotate_right(value, 7) ^ rotate_right(value, 18) ^ (value >> 3);
}

constexpr std::uint32_t small_sigma1(std::uint32_t value) noexcept {
  return rotate_right(value, 17) ^ rotate_right(value, 19) ^ (value >> 10);
}

constexpr char kHexDigits[] = "0123456789abcdef";

}  // namespace

Sha256::Sha256() noexcept : state_(kInitialState) {}

void Sha256::compress(const std::uint8_t* block) noexcept {
  std::array<std::uint32_t, 64> schedule{};
  for (std::size_t index = 0; index < 16; ++index) {
    const std::size_t base = index * 4;
    schedule[index] = (static_cast<std::uint32_t>(block[base]) << 24) |
                      (static_cast<std::uint32_t>(block[base + 1]) << 16) |
                      (static_cast<std::uint32_t>(block[base + 2]) << 8) |
                      static_cast<std::uint32_t>(block[base + 3]);
  }
  for (std::size_t index = 16; index < 64; ++index) {
    schedule[index] = small_sigma1(schedule[index - 2]) + schedule[index - 7] +
                      small_sigma0(schedule[index - 15]) + schedule[index - 16];
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t index = 0; index < 64; ++index) {
    const std::uint32_t t1 = h + big_sigma1(e) + choose(e, f, g) + kRoundConstants[index] + schedule[index];
    const std::uint32_t t2 = big_sigma0(a) + majority(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::update(std::span<const std::byte> bytes) noexcept {
  if (finished_) {
    return;
  }
  total_bytes_ += static_cast<std::uint64_t>(bytes.size());
  const std::uint8_t* data = reinterpret_cast<const std::uint8_t*>(bytes.data());
  std::size_t remaining = bytes.size();
  while (remaining > 0) {
    const std::size_t free_space = buffer_.size() - buffered_;
    const std::size_t take = remaining < free_space ? remaining : free_space;
    std::memcpy(buffer_.data() + buffered_, data, take);
    buffered_ += take;
    data += take;
    remaining -= take;
    if (buffered_ == buffer_.size()) {
      compress(buffer_.data());
      buffered_ = 0;
    }
  }
}

void Sha256::update(std::string_view text) noexcept {
  update(std::span<const std::byte>{reinterpret_cast<const std::byte*>(text.data()), text.size()});
}

ContentDigest Sha256::finish() noexcept {
  if (finished_) {
    return digest_;
  }

  // The message length in bits is fixed *before* the padding is hashed, per
  // FIPS 180-4 section 5.1.1.
  const std::uint64_t bit_length = total_bytes_ * 8u;
  std::array<std::uint8_t, 8> length_bytes{};
  for (std::size_t index = 0; index < length_bytes.size(); ++index) {
    length_bytes[index] = static_cast<std::uint8_t>((bit_length >> (56u - 8u * index)) & 0xFFu);
  }

  const std::uint8_t marker = 0x80u;
  update(std::span<const std::byte>{reinterpret_cast<const std::byte*>(&marker), 1});
  const std::uint8_t zero = 0x00u;
  while (buffered_ != 56) {
    update(std::span<const std::byte>{reinterpret_cast<const std::byte*>(&zero), 1});
  }
  update(std::span<const std::byte>{reinterpret_cast<const std::byte*>(length_bytes.data()), length_bytes.size()});

  // The state is written out big-endian, then converted through the public
  // hexadecimal form so that no private access to ContentDigest is needed. The
  // conversion cannot fail; a failure would yield the deliberately unusable
  // zero digest rather than a plausible wrong one.
  std::array<char, 64> hex{};
  for (std::size_t index = 0; index < 8; ++index) {
    const std::uint32_t word = state_[index];
    for (std::size_t byte = 0; byte < 4; ++byte) {
      const std::uint8_t value = static_cast<std::uint8_t>((word >> (24u - 8u * byte)) & 0xFFu);
      hex[index * 8 + byte * 2] = kHexDigits[value >> 4];
      hex[index * 8 + byte * 2 + 1] = kHexDigits[value & 0x0Fu];
    }
  }

  ContentDigest result;
  if (!ContentDigest::parse(std::string_view{hex.data(), hex.size()}, result)) {
    result = ContentDigest::zero();
  }
  digest_ = result;
  finished_ = true;
  return digest_;
}

ContentDigest sha256(std::span<const std::byte> bytes) noexcept {
  Sha256 hasher;
  hasher.update(bytes);
  return hasher.finish();
}

ContentDigest sha256(std::string_view text) noexcept {
  Sha256 hasher;
  hasher.update(text);
  return hasher.finish();
}

}  // namespace detail
}  // namespace tenant_registry
