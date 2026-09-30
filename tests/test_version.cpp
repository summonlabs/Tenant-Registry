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

#include <cstdint>
#include <limits>
#include <string>

#include "test_support.hpp"

namespace treg_test {
namespace {

using tenant_registry::can_read_canonical_encoding;
using tenant_registry::can_read_store_format;
using tenant_registry::kCanonicalEncodingVersion;
using tenant_registry::kExportFormatVersion;
using tenant_registry::kStoreFormatVersion;
using tenant_registry::kVersionMajor;
using tenant_registry::kVersionMinor;
using tenant_registry::kVersionPatch;
using tenant_registry::kVersionString;
using tenant_registry::version_string;
using tenant_registry::version_text;

}  // namespace

TREG_TEST(version, constants_are_the_declared_release) {
  TREG_CHECK_EQ(kVersionMajor, 1);
  TREG_CHECK_EQ(kVersionMinor, 0);
  TREG_CHECK_EQ(kVersionPatch, 0);
  TREG_CHECK_EQ(kVersionString, std::string_view{"1.0.0"});
  TREG_CHECK_EQ(kStoreFormatVersion, static_cast<std::uint16_t>(1));
  TREG_CHECK_EQ(kCanonicalEncodingVersion, static_cast<std::uint16_t>(1));
  TREG_CHECK_EQ(kExportFormatVersion, static_cast<std::uint16_t>(1));

  TREG_CHECK_EQ(version_string(), kVersionString);
  TREG_CHECK_EQ(version_text(), std::string{"1.0.0"});
  // The rendered text must agree with the constant: a caller that compares the
  // two must never see a build that claims two different versions.
  TREG_CHECK_EQ(version_text(), std::string{version_string()});
}

TREG_TEST(version, store_format_readability_is_exact) {
  TREG_CHECK(can_read_store_format(kStoreFormatVersion));
  // Zero is not a version any container was written in, and it must never be
  // treated as the current one.
  TREG_CHECK(!can_read_store_format(0));
  // An older format is refused rather than guessed at: forward and backward
  // compatibility are both claims this build does not make.
  TREG_CHECK(!can_read_store_format(static_cast<std::uint16_t>(kStoreFormatVersion - 1)));
  TREG_CHECK(!can_read_store_format(static_cast<std::uint16_t>(kStoreFormatVersion + 1)));
  TREG_CHECK(!can_read_store_format(std::numeric_limits<std::uint16_t>::max()));
}

TREG_TEST(version, canonical_encoding_readability_is_exact) {
  TREG_CHECK(can_read_canonical_encoding(kCanonicalEncodingVersion));
  TREG_CHECK(!can_read_canonical_encoding(0));
  TREG_CHECK(!can_read_canonical_encoding(static_cast<std::uint16_t>(kCanonicalEncodingVersion - 1)));
  TREG_CHECK(!can_read_canonical_encoding(static_cast<std::uint16_t>(kCanonicalEncodingVersion + 1)));
  TREG_CHECK(!can_read_canonical_encoding(std::numeric_limits<std::uint16_t>::max()));
}

}  // namespace treg_test
