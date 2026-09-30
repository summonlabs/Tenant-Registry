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
#include <string>
#include <string_view>
#include <vector>

#include "test_support.hpp"

namespace treg_test {
namespace {

using tenant_registry::ErrorCode;
using tenant_registry::MetadataKind;
using tenant_registry::TenancyMetadata;
using tenant_registry::parse_metadata_kind;
using tenant_registry::to_token;

MetadataValue text_value(std::string_view text) {
  return unwrap(MetadataValue::text(std::string{text}, 512), "MetadataValue::text");
}

MetadataValue token_value(std::string_view text) {
  return unwrap(MetadataValue::token(std::string{text}, 512), "MetadataValue::token");
}

MetadataEntry text_entry(std::string_view key, std::string_view value) {
  return MetadataEntry{metadata_key(key), text_value(value)};
}

TenancyMetadata metadata_of(std::vector<MetadataEntry> entries, std::size_t max_entries = 64) {
  return unwrap(TenancyMetadata::create(std::move(entries), max_entries, 512), "TenancyMetadata::create");
}

}  // namespace

TREG_TEST(metadata, duplicate_keys_are_refused_never_last_wins) {
  TREG_CHECK_CODE((TenancyMetadata::create({text_entry("zone", "one"), text_entry("zone", "two")}, 64, 512)),
                  ErrorCode::InvalidMetadata);
  // The duplicate is found even when the two copies are not adjacent, because
  // the set is ordered before it is checked.
  TREG_CHECK_CODE(
      TenancyMetadata::create({text_entry("a", "1"), text_entry("b", "2"), text_entry("a", "3")}, 64, 512),
      ErrorCode::InvalidMetadata);
  // Keys that differ only in case are different keys, and both survive.
  const TenancyMetadata case_sensitive = metadata_of({text_entry("Zone", "one"), text_entry("zone", "two")});
  TREG_CHECK_EQ(case_sensitive.size(), static_cast<std::size_t>(2));

  // A duplicate that carries a different kind is still a duplicate.
  const MetadataEntry same_key_other_kind{metadata_key("k"), MetadataValue::integer(7)};
  TREG_CHECK_CODE((TenancyMetadata::create({text_entry("k", "seven"), same_key_other_kind}, 64, 512)),
                  ErrorCode::InvalidMetadata);
}

TREG_TEST(metadata, canonical_order_is_independent_of_insertion_order) {
  const TenancyMetadata forward =
      metadata_of({text_entry("alpha", "1"), text_entry("beta", "2"), text_entry("gamma", "3")});
  const TenancyMetadata backward =
      metadata_of({text_entry("gamma", "3"), text_entry("beta", "2"), text_entry("alpha", "1")});
  const TenancyMetadata scrambled =
      metadata_of({text_entry("beta", "2"), text_entry("gamma", "3"), text_entry("alpha", "1")});

  TREG_CHECK(forward == backward);
  TREG_CHECK(forward == scrambled);
  TREG_CHECK_EQ(forward.to_canonical(), backward.to_canonical());
  TREG_CHECK_EQ(forward.to_canonical(), scrambled.to_canonical());

  // The order is byte order, not locale collation: "M" and "Z" sort before "a".
  const TenancyMetadata bytes_order = metadata_of({text_entry("a", "1"), text_entry("Z", "2"), text_entry("M", "3")});
  TREG_REQUIRE(bytes_order.size() == 3);
  TREG_CHECK_EQ(bytes_order.entries()[0].key.value(), std::string{"M"});
  TREG_CHECK_EQ(bytes_order.entries()[1].key.value(), std::string{"Z"});
  TREG_CHECK_EQ(bytes_order.entries()[2].key.value(), std::string{"a"});

  // Two sets that differ in a value are different, and their canonical forms
  // differ too.
  const TenancyMetadata other = metadata_of({text_entry("alpha", "1"), text_entry("beta", "9"), text_entry("gamma", "3")});
  TREG_CHECK(forward != other);
  TREG_CHECK(forward.to_canonical() != other.to_canonical());
}

TREG_TEST(metadata, entry_and_value_length_limits) {
  const std::vector<MetadataEntry> three = {text_entry("a", "1"), text_entry("b", "2"), text_entry("c", "3")};
  TREG_CHECK(TenancyMetadata::create(three, 3, 512).has_value());
  TREG_CHECK_CODE(TenancyMetadata::create(three, 2, 512), ErrorCode::LimitExceeded);

  const std::vector<MetadataEntry> five_byte_value = {text_entry("k", "abcde")};
  TREG_CHECK(TenancyMetadata::create(five_byte_value, 64, 5).has_value());
  TREG_CHECK_CODE(TenancyMetadata::create(five_byte_value, 64, 4), ErrorCode::InvalidMetadata);
  const std::vector<MetadataEntry> five_byte_token = {MetadataEntry{metadata_key("k"), token_value("abcde")}};
  TREG_CHECK_CODE(TenancyMetadata::create(five_byte_token, 64, 4), ErrorCode::InvalidMetadata);
  // Values that carry no bytes are never refused for length.
  const std::vector<MetadataEntry> scalars = {MetadataEntry{metadata_key("i"), MetadataValue::integer(1)},
                                              MetadataEntry{metadata_key("b"), MetadataValue::boolean(true)},
                                              MetadataEntry{metadata_key("u"), MetadataValue::unknown()}};
  TREG_CHECK(TenancyMetadata::create(scalars, 3, 1).has_value());

  // The value factory applies the same bound before the set ever sees it.
  TREG_CHECK_CODE(MetadataValue::text(std::string{"abcdef"}, 5), ErrorCode::InvalidTextForm);
  TREG_CHECK_CODE(MetadataValue::token(std::string{"abcdef"}, 5), ErrorCode::InvalidTextForm);
  TREG_CHECK_CODE(MetadataValue::text(std::string{}, 5), ErrorCode::InvalidTextForm);
  TREG_CHECK(MetadataValue::text(std::string{"abcde"}, 5).has_value());
}

TREG_TEST(metadata, kinds_are_distinct_and_never_interconvert) {
  const MetadataValue unknown = MetadataValue::unknown();
  const MetadataValue text = text_value("1");
  const MetadataValue token = token_value("1");
  const MetadataValue integer = MetadataValue::integer(1);
  const MetadataValue zero = MetadataValue::integer(0);
  const MetadataValue boolean_true = MetadataValue::boolean(true);
  const MetadataValue boolean_false = MetadataValue::boolean(false);

  TREG_CHECK_EQ(unknown.kind(), MetadataKind::Unknown);
  TREG_CHECK_EQ(text.kind(), MetadataKind::Text);
  TREG_CHECK_EQ(token.kind(), MetadataKind::Token);
  TREG_CHECK_EQ(integer.kind(), MetadataKind::Integer);
  TREG_CHECK_EQ(boolean_true.kind(), MetadataKind::Boolean);

  // Each value answers only for its own kind.
  TREG_REQUIRE(text.text_if() != nullptr);
  TREG_CHECK_EQ(*text.text_if(), std::string{"1"});
  TREG_CHECK(text.token_if() == nullptr);
  TREG_CHECK(text.integer_if() == nullptr);
  TREG_CHECK(text.boolean_if() == nullptr);
  TREG_REQUIRE(token.token_if() != nullptr);
  TREG_CHECK_EQ(*token.token_if(), std::string{"1"});
  TREG_CHECK(token.text_if() == nullptr);
  TREG_REQUIRE(integer.integer_if() != nullptr);
  TREG_CHECK_EQ(*integer.integer_if(), static_cast<std::int64_t>(1));
  TREG_CHECK(integer.boolean_if() == nullptr);
  TREG_CHECK(integer.text_if() == nullptr);
  TREG_REQUIRE(boolean_true.boolean_if() != nullptr);
  TREG_CHECK(*boolean_true.boolean_if());
  TREG_CHECK(boolean_true.integer_if() == nullptr);
  TREG_CHECK(unknown.text_if() == nullptr);
  TREG_CHECK(unknown.token_if() == nullptr);
  TREG_CHECK(unknown.integer_if() == nullptr);
  TREG_CHECK(unknown.boolean_if() == nullptr);
  TREG_CHECK(!unknown.is_known());
  TREG_CHECK(text.is_known());
  TREG_CHECK(token.is_known());
  TREG_CHECK(integer.is_known());
  TREG_CHECK(boolean_true.is_known());

  // "1" the text, "1" the token, 1 the integer and true the boolean are four
  // different values, and the canonical forms keep them apart.
  TREG_CHECK(text != token);
  TREG_CHECK(text != integer);
  TREG_CHECK(token != integer);
  TREG_CHECK(integer != boolean_true);
  TREG_CHECK(boolean_true != boolean_false);
  TREG_CHECK(integer != zero);
  TREG_CHECK(zero != MetadataValue::unknown());
  TREG_CHECK(zero != boolean_false);
  TREG_CHECK_EQ(unknown.to_canonical(), std::string{"unknown"});
  TREG_CHECK_EQ(text.to_canonical(), std::string{"text:1:1"});
  TREG_CHECK_EQ(token.to_canonical(), std::string{"token:1:1"});
  TREG_CHECK_EQ(integer.to_canonical(), std::string{"integer:1"});
  TREG_CHECK_EQ(zero.to_canonical(), std::string{"integer:0"});
  TREG_CHECK_EQ(boolean_true.to_canonical(), std::string{"boolean:true"});
  TREG_CHECK_EQ(boolean_false.to_canonical(), std::string{"boolean:false"});
  TREG_CHECK(text.to_canonical() != token.to_canonical());
  TREG_CHECK_EQ(MetadataValue::integer(-3).to_canonical(), std::string{"integer:-3"});

  // Canonical rendering is stable.
  TREG_CHECK_EQ(text.to_canonical(), text.to_canonical());

  // Kind order dominates value order, and the kind order is the declaration
  // order: Unknown, Text, Integer, Boolean, Token.
  TREG_CHECK(unknown < text);
  TREG_CHECK(text < integer);
  TREG_CHECK(integer < boolean_true);
  TREG_CHECK(boolean_true < token);
  TREG_CHECK(token < token_value("z"));
  TREG_CHECK(text_value("a") < text_value("b"));
  TREG_CHECK(zero < integer);
  TREG_CHECK(boolean_false < boolean_true);

  struct KindTokenRow {
    MetadataKind kind;
    std::string_view token;
  };
  constexpr KindTokenRow kTokens[] = {
      {MetadataKind::Unspecified, "unspecified"}, {MetadataKind::Unknown, "unknown"},
      {MetadataKind::Text, "text"},               {MetadataKind::Integer, "integer"},
      {MetadataKind::Boolean, "boolean"},         {MetadataKind::Token, "token"},
  };
  for (const KindTokenRow& row : kTokens) {
    TREG_CHECK_EQ(to_token(row.kind), row.token);
    MetadataKind parsed = MetadataKind::Unspecified;
    TREG_CHECK(parse_metadata_kind(row.token, parsed));
    TREG_CHECK_EQ(parsed, row.kind);
  }
  MetadataKind ignored = MetadataKind::Integer;
  TREG_CHECK(!parse_metadata_kind("", ignored));
  TREG_CHECK(!parse_metadata_kind("Text", ignored));
  TREG_CHECK(!parse_metadata_kind("integer ", ignored));
  TREG_CHECK(!parse_metadata_kind("number", ignored));
  TREG_CHECK_EQ(ignored, MetadataKind::Integer);
  TREG_CHECK_EQ(to_token(static_cast<MetadataKind>(99)), std::string_view{});
}

TREG_TEST(metadata, absent_key_is_explicitly_unknown_never_a_default) {
  const TenancyMetadata present = metadata_of({text_entry("zone", "west")});
  const MetadataKey absent_key = metadata_key("absent");
  const MetadataValue found = present.find(absent_key);

  TREG_CHECK(!present.contains(absent_key));
  TREG_CHECK_EQ(found.kind(), MetadataKind::Unknown);
  TREG_CHECK(!found.is_known());
  TREG_CHECK(found.text_if() == nullptr);
  TREG_CHECK(found.token_if() == nullptr);
  TREG_CHECK(found.integer_if() == nullptr);
  TREG_CHECK(found.boolean_if() == nullptr);
  // An absent key is not zero, not false and not an empty string.
  TREG_CHECK(found != MetadataValue::integer(0));
  TREG_CHECK(found != MetadataValue::boolean(false));
  TREG_CHECK(found != text_value("west"));
  // A text or token payload is never empty, so "absent" and "empty" cannot even
  // both be represented.
  TREG_CHECK_CODE(MetadataValue::text(std::string{}, 512), ErrorCode::InvalidTextForm);
  TREG_CHECK_CODE(MetadataValue::token(std::string{}, 512), ErrorCode::InvalidTextForm);
  TREG_CHECK_EQ(found.to_canonical(), MetadataValue::unknown().to_canonical());

  // The present key answers with its own value; presence and absence are
  // distinguishable without a second lookup.
  const MetadataValue zone = present.find(metadata_key("zone"));
  TREG_REQUIRE(zone.text_if() != nullptr);
  TREG_CHECK_EQ(*zone.text_if(), std::string{"west"});
  TREG_CHECK(present.contains(metadata_key("zone")));

  // An empty set finds nothing and says so explicitly.
  const TenancyMetadata empty;
  TREG_CHECK(empty.empty());
  TREG_CHECK_EQ(empty.size(), static_cast<std::size_t>(0));
  TREG_CHECK_EQ(empty.find(absent_key).kind(), MetadataKind::Unknown);
}

TREG_TEST(metadata, put_and_erase_semantics) {
  TenancyMetadata set;
  TREG_CHECK(set.empty());

  require_ok(set.put(metadata_key("b"), text_value("two"), 4), "put b");
  require_ok(set.put(metadata_key("a"), text_value("one"), 4), "put a");
  TREG_CHECK_EQ(set.size(), static_cast<std::size_t>(2));
  // Canonical order is maintained by put, not repaired later.
  TREG_CHECK_EQ(set.entries()[0].key.value(), std::string{"a"});
  TREG_CHECK_EQ(set.entries()[1].key.value(), std::string{"b"});

  // put replaces in place: the size does not grow and the new value wins.
  require_ok(set.put(metadata_key("a"), text_value("ONE"), 4), "replace a");
  TREG_CHECK_EQ(set.size(), static_cast<std::size_t>(2));
  const MetadataValue replaced = set.find(metadata_key("a"));
  TREG_REQUIRE(replaced.text_if() != nullptr);
  TREG_CHECK_EQ(*replaced.text_if(), std::string{"ONE"});

  // Replacing is allowed at the limit; adding is not.
  require_ok(set.put(metadata_key("c"), text_value("three"), 3), "put c at the limit");
  TREG_CHECK_EQ(set.size(), static_cast<std::size_t>(3));
  TREG_CHECK_STATUS(set.put(metadata_key("d"), text_value("four"), 3), ErrorCode::LimitExceeded);
  TREG_CHECK_EQ(set.size(), static_cast<std::size_t>(3));
  TREG_CHECK(!set.contains(metadata_key("d")));
  require_ok(set.put(metadata_key("c"), text_value("THREE"), 3), "replace c at the limit");
  TREG_CHECK_EQ(set.size(), static_cast<std::size_t>(3));

  TREG_CHECK(set.erase(metadata_key("b")));
  TREG_CHECK_EQ(set.size(), static_cast<std::size_t>(2));
  TREG_CHECK(!set.contains(metadata_key("b")));
  TREG_CHECK_EQ(set.find(metadata_key("b")).kind(), MetadataKind::Unknown);
  TREG_CHECK(!set.erase(metadata_key("b")));
  TREG_CHECK(!set.erase(metadata_key("never-there")));

  // The canonical form follows put and erase, and stays stable.
  const std::string before = set.to_canonical();
  TREG_CHECK_EQ(before, set.to_canonical());
  require_ok(set.put(metadata_key("d"), MetadataValue::integer(4), 4), "put d");
  TREG_CHECK(set.to_canonical() != before);
  const std::string after = set.to_canonical();
  TREG_CHECK(set.erase(metadata_key("d")));
  TREG_CHECK_EQ(set.to_canonical(), before);
  TREG_CHECK(after != before);

  const TenancyMetadata rebuilt = metadata_of({text_entry("a", "ONE"), text_entry("c", "THREE")});
  TREG_CHECK(set == rebuilt);
  TREG_CHECK_EQ(set.to_canonical(), rebuilt.to_canonical());
}

}  // namespace treg_test
