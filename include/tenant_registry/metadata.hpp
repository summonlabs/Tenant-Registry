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

#ifndef TENANT_REGISTRY_METADATA_HPP
#define TENANT_REGISTRY_METADATA_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <string_view>
#include <vector>

#include "tenant_registry/digest.hpp"
#include "tenant_registry/errors.hpp"
#include "tenant_registry/ids.hpp"

namespace tenant_registry {

/// The kind of a metadata value.
///
/// The kinds exist so that "no value was ever recorded" and "a value was
/// recorded and it is literally the number zero" are different answers. They
/// must stay different all the way out to a caller.
enum class MetadataKind : std::uint8_t {
  Unspecified = 0,
  /// The key is known to exist and its value is explicitly not known. This is
  /// a statement an operator can make, and it is preserved as such.
  Unknown = 1,
  Text = 2,
  Integer = 3,
  Boolean = 4,
  /// A single canonical token, for values drawn from an enumeration whose
  /// members this repository does not own.
  Token = 5,
};

[[nodiscard]] std::string_view to_token(MetadataKind kind) noexcept;
[[nodiscard]] bool parse_metadata_kind(std::string_view token, MetadataKind& out) noexcept;

/// One typed metadata value.
///
/// There is no implicit conversion to a scalar anywhere in this type. A caller
/// that wants an integer must ask for an integer and must handle the answer
/// "that is not an integer" and the answer "nothing was recorded".
class MetadataValue {
 public:
  MetadataValue() = delete;

  /// A key that exists and whose value is explicitly not known.
  [[nodiscard]] static MetadataValue unknown() noexcept;
  [[nodiscard]] static Result<MetadataValue> text(std::string value, std::size_t max_bytes);
  [[nodiscard]] static MetadataValue integer(std::int64_t value) noexcept;
  [[nodiscard]] static MetadataValue boolean(bool value) noexcept;
  [[nodiscard]] static Result<MetadataValue> token(std::string value, std::size_t max_bytes);

  [[nodiscard]] MetadataKind kind() const noexcept { return kind_; }

  /// True when the value is explicitly known. An Unknown value is not known.
  [[nodiscard]] bool is_known() const noexcept;

  /// The payload of a Text or Token value, or nothing when this is not one.
  [[nodiscard]] const std::string* text_if() const noexcept;
  [[nodiscard]] const std::string* token_if() const noexcept;
  [[nodiscard]] const std::int64_t* integer_if() const noexcept;
  [[nodiscard]] const bool* boolean_if() const noexcept;

  /// The canonical encoding of this value, stable across builds and platforms.
  [[nodiscard]] std::string to_canonical() const;

  friend bool operator==(const MetadataValue& lhs, const MetadataValue& rhs) noexcept;
  friend bool operator<(const MetadataValue& lhs, const MetadataValue& rhs) noexcept;

 private:
  MetadataValue(MetadataKind kind, std::string payload, std::int64_t integer, bool boolean) noexcept
      : kind_(kind), payload_(std::move(payload)), integer_(integer), boolean_(boolean) {}

  MetadataKind kind_ = MetadataKind::Unspecified;
  std::string payload_;
  std::int64_t integer_ = 0;
  bool boolean_ = false;
};

/// One key/value pair in canonical key order.
struct MetadataEntry {
  MetadataKey key;
  MetadataValue value;
};

/// A bounded, canonically ordered set of metadata attached to one record.
///
/// The set is ordered by key bytes, so its canonical encoding and therefore its
/// digest do not depend on the order a caller supplied the entries in, nor on
/// any hash iteration order. Duplicate keys are refused rather than resolved:
/// silently keeping the last one would make the meaning of a declaration depend
/// on its textual order.
class TenancyMetadata {
 public:
  TenancyMetadata() = default;

  [[nodiscard]] static Result<TenancyMetadata> create(std::vector<MetadataEntry> entries,
                                                      std::size_t max_entries, std::size_t max_value_bytes);

  /// Puts or replaces one entry, keeping canonical order. Refuses when the
  /// resulting set would exceed max_entries.
  [[nodiscard]] Status put(const MetadataKey& key, MetadataValue value, std::size_t max_entries);

  /// Removes one entry. Returns false when the key was not present.
  [[nodiscard]] bool erase(const MetadataKey& key);

  /// The value recorded for a key. When the key is not present this returns an
  /// explicitly Unknown value, so an absent key can never be read as zero,
  /// false or an empty string.
  [[nodiscard]] MetadataValue find(const MetadataKey& key) const;

  [[nodiscard]] bool contains(const MetadataKey& key) const noexcept;
  [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }
  [[nodiscard]] bool empty() const noexcept { return entries_.empty(); }
  [[nodiscard]] const std::vector<MetadataEntry>& entries() const noexcept { return entries_; }

  [[nodiscard]] std::string to_canonical() const;
  [[nodiscard]] std::string to_json() const;

  friend bool operator==(const TenancyMetadata& lhs, const TenancyMetadata& rhs) noexcept;
  friend bool operator<(const TenancyMetadata& lhs, const TenancyMetadata& rhs) noexcept;

 private:
  std::vector<MetadataEntry> entries_;
};

}  // namespace tenant_registry

#endif  // TENANT_REGISTRY_METADATA_HPP
