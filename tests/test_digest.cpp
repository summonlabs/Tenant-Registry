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

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "sha256.hpp"
#include "test_support.hpp"

namespace treg_test {
namespace {

using tenant_registry::ContentDigest;
using tenant_registry::crc32;
using tenant_registry::domain_separated;

std::string unprefixed_preimage(std::string_view domain, std::string_view value) {
  std::string out{domain};
  out.push_back('\0');
  out.append(value);
  return out;
}

}  // namespace

TREG_TEST(digest, sha256_known_answer_vectors) {
  TREG_CHECK_EQ(ContentDigest::of(std::string_view{}).to_text(), std::string{tenant_registry::detail::kSha256EmptyHex});
  TREG_CHECK_EQ(ContentDigest::of(std::string_view{"abc"}).to_text(),
                std::string{tenant_registry::detail::kSha256AbcHex});
  TREG_CHECK_EQ(tenant_registry::detail::sha256(std::string_view{"abc"}).to_text(),
                std::string{tenant_registry::detail::kSha256AbcHex});
  TREG_CHECK_EQ(tenant_registry::detail::sha256(std::string_view{}).to_text(),
                std::string{tenant_registry::detail::kSha256EmptyHex});

  // The empty answer is a real digest of a real input, and it is not the digest
  // of no input at all.
  TREG_CHECK(ContentDigest::of(std::string_view{}) != ContentDigest::zero());

  // Chunking must not change the answer: the incremental hasher exists so a
  // large payload can be hashed as it is written.
  tenant_registry::detail::Sha256 chunked;
  chunked.update(std::string_view{"a"});
  chunked.update(std::string_view{"b"});
  chunked.update(std::string_view{"c"});
  const ContentDigest first_finish = chunked.finish();
  TREG_CHECK_EQ(first_finish.to_text(), std::string{tenant_registry::detail::kSha256AbcHex});
  // Finalizing twice returns the same digest rather than a changed one.
  TREG_CHECK_EQ(chunked.finish().to_text(), first_finish.to_text());

  tenant_registry::detail::Sha256 byte_wise;
  const std::string alphabet = "abc";
  for (const char character : alphabet) {
    byte_wise.update(std::span<const std::byte>{reinterpret_cast<const std::byte*>(&character), 1});
  }
  TREG_CHECK(byte_wise.finish() == first_finish);

  // A longer input crosses the 64 byte compression block, so the padding path
  // is exercised too.
  const std::string longer(1000, 'a');
  TREG_CHECK(ContentDigest::of(std::string_view{longer}) == tenant_registry::detail::sha256(std::string_view{longer}));
  TREG_CHECK(ContentDigest::of(std::string_view{longer}) != ContentDigest::of(std::string_view{"a"}));
}

TREG_TEST(digest, parse_accepts_exactly_sixty_four_lower_case_hex_characters) {
  const ContentDigest digest = ContentDigest::of(std::string_view{"abc"});
  const std::string text = digest.to_text();
  TREG_CHECK_EQ(text.size(), static_cast<std::size_t>(64));

  ContentDigest parsed;
  TREG_CHECK(ContentDigest::parse(text, parsed));
  TREG_CHECK(parsed == digest);
  TREG_CHECK_EQ(parsed.to_text(), text);

  // The all zero digest is a legal 64 character string and parses to zero().
  const ContentDigest zero = ContentDigest::zero();
  TREG_CHECK(ContentDigest::parse(zero.to_text(), parsed));
  TREG_CHECK(parsed == ContentDigest::zero());
  TREG_CHECK(parsed.is_zero());

  // Upper case is refused rather than normalized: a digest has exactly one
  // textual form.
  std::string upper = text;
  upper[0] = 'A';
  TREG_CHECK(!ContentDigest::parse(upper, parsed));
  std::string upper_tail = text;
  upper_tail[63] = 'F';
  upper_tail[62] = '0';
  TREG_CHECK(!ContentDigest::parse(upper_tail, parsed));
  TREG_CHECK(!ContentDigest::parse(upper, parsed));

  // Wrong lengths are refused.
  TREG_CHECK(!ContentDigest::parse("", parsed));
  TREG_CHECK(!ContentDigest::parse(text.substr(0, 63), parsed));
  TREG_CHECK(!ContentDigest::parse(text + "0", parsed));
  TREG_CHECK(!ContentDigest::parse(text + text, parsed));

  // Non hexadecimal characters are refused wherever they appear.
  const std::string_view bad_characters[] = {"g", "G", "z", " ", "-", "_", ":", "\n", "\t"};
  for (const std::string_view bad : bad_characters) {
    std::string candidate = text;
    candidate.replace(0, bad.size(), bad);
    TREG_CHECK(!ContentDigest::parse(candidate, parsed));
    std::string at_tail = text;
    at_tail.replace(64 - bad.size(), bad.size(), bad);
    TREG_CHECK(!ContentDigest::parse(at_tail, parsed));
  }

  // A failed parse leaves the output untouched instead of writing a default.
  ContentDigest untouched = ContentDigest::of(std::string_view{"abc"});
  TREG_CHECK(!ContentDigest::parse("not a digest", untouched));
  TREG_CHECK(untouched == digest);
}

TREG_TEST(digest, zero_is_not_the_digest_of_the_empty_input) {
  const ContentDigest zero = ContentDigest::zero();
  const ContentDigest empty = ContentDigest::of(std::string_view{});

  TREG_CHECK(zero.is_zero());
  TREG_CHECK(!empty.is_zero());
  TREG_CHECK(zero != empty);
  TREG_CHECK_EQ(zero.to_text(), std::string(64, '0'));
  TREG_CHECK_EQ(zero.to_short_text(), std::string(16, '0'));
  TREG_CHECK_EQ(empty.to_text(), std::string{tenant_registry::detail::kSha256EmptyHex});
  TREG_CHECK_EQ(empty.to_short_text(), std::string{tenant_registry::detail::kSha256EmptyHex}.substr(0, 16));

  // A default constructed digest is the zero digest, not a digest of anything.
  const ContentDigest unset;
  TREG_CHECK(unset.is_zero());
  TREG_CHECK(unset == zero);

  // The short form is a prefix of the long form and nothing else.
  TREG_CHECK_EQ(empty.to_text().substr(0, 16), empty.to_short_text());
  TREG_CHECK_EQ(empty.to_short_text().size(), static_cast<std::size_t>(16));
  TREG_CHECK(ContentDigest::of(std::string_view{"abc"}).to_short_text() !=
             ContentDigest::of(std::string_view{"abd"}).to_short_text());
}

TREG_TEST(digest, crc32_known_answer_vectors) {
  TREG_CHECK_EQ(crc32(std::string_view{}), static_cast<std::uint32_t>(0x00000000u));
  TREG_CHECK_EQ(crc32(std::string_view{"a"}), static_cast<std::uint32_t>(0xE8B7BE43u));
  TREG_CHECK_EQ(crc32(std::string_view{"abc"}), static_cast<std::uint32_t>(0x352441C2u));
  TREG_CHECK_EQ(crc32(std::string_view{"123456789"}), static_cast<std::uint32_t>(0xCBF43926u));
  TREG_CHECK_EQ(crc32(std::string_view{"The quick brown fox jumps over the lazy dog"}),
                static_cast<std::uint32_t>(0x414FA339u));

  // The byte overload and the text overload are the same function.
  std::vector<char> buffer{'1', '2', '3', '4', '5', '6', '7', '8', '9'};
  const std::span<const std::byte> bytes = std::as_bytes(std::span<char>{buffer});
  TREG_CHECK_EQ(crc32(bytes), crc32(std::string_view{"123456789"}));

  // Stability and sensitivity: the check value moves when the input does.
  TREG_CHECK_EQ(crc32(std::string_view{"abc"}), crc32(std::string_view{"abc"}));
  TREG_CHECK(crc32(std::string_view{"abc"}) != crc32(std::string_view{"abd"}));
  TREG_CHECK(crc32(std::string_view{"abc"}) != crc32(std::string_view{"acb"}));
  TREG_CHECK(crc32(std::string_view{}) != crc32(std::string_view{"\0", 1}));
}

TREG_TEST(digest, domain_separation_keeps_domains_and_values_apart) {
  // The preimage is the domain, one zero byte, then the value. The literals
  // carry an explicit length because a std::string built from a pointer stops
  // at the first zero byte, which is exactly the byte being asserted here.
  const std::string expected = unprefixed_preimage("tenant", "acme");
  TREG_CHECK_EQ(domain_separated("tenant", "acme"), expected);
  TREG_CHECK_EQ(domain_separated("tenant", "acme").size(), static_cast<std::size_t>(11));
  TREG_CHECK_EQ(domain_separated("tenant", "acme")[6], '\0');
  TREG_CHECK_EQ(domain_separated("", ""), (std::string{"\0", 1}));
  TREG_CHECK_EQ(domain_separated("", "value"), (std::string{"\0value", 6}));

  // Without the separator, ("ab", "c") and ("a", "bc") would be the same
  // preimage; with it they are not.
  TREG_CHECK(domain_separated("ab", "c") != domain_separated("a", "bc"));
  TREG_CHECK(domain_separated("tenant", "acme") != domain_separated("service", "acme"));
  TREG_CHECK(domain_separated("tenant", "acme") != domain_separated("tenant", "acme2"));
  TREG_CHECK(domain_separated("tenant", "acme") != domain_separated("tenan", "tacme"));

  // The same text under two domains digests differently, and the same pair
  // digests identically every time.
  const ContentDigest as_tenant = ContentDigest::of(domain_separated("tenant", "shared"));
  const ContentDigest as_service = ContentDigest::of(domain_separated("service", "shared"));
  TREG_CHECK(as_tenant != as_service);
  TREG_CHECK(as_tenant == ContentDigest::of(domain_separated("tenant", "shared")));

  // An identity digest is exactly the domain separated preimage of its own kind
  // and bytes, which is why the same text under two kinds can never collide.
  TREG_CHECK(tenant_id("shared").digest() == as_tenant);
  TREG_CHECK(service_id("shared").digest() == as_service);
  TREG_CHECK(tenant_id("acme").digest() == ContentDigest::of(domain_separated("tenant", "acme")));
  TREG_CHECK(service_id("acme").digest() == ContentDigest::of(domain_separated("service", "acme")));
  TREG_CHECK(tenant_id("shared").digest() != service_id("shared").digest());
}

}  // namespace treg_test