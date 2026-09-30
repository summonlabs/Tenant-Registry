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

#include "tenant_registry/metadata.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "tenant_registry/digest.hpp"
#include "tenant_registry/errors.hpp"
#include "tenant_registry/ids.hpp"
#include "utf8.hpp"

namespace tenant_registry {

namespace {

struct MetadataKindToken {
  MetadataKind kind;
  std::string_view token;
};

constexpr MetadataKindToken kMetadataKindTokens[] = {
    {MetadataKind::Unspecified, "unspecified"},
    {MetadataKind::Unknown, "unknown"},
    {MetadataKind::Text, "text"},
    {MetadataKind::Integer, "integer"},
    {MetadataKind::Boolean, "boolean"},
    {MetadataKind::Token, "token"},
};

/// The payload of a value when it has one, or nullptr. Only Text and Token
/// carry bytes, so only they can exceed a byte bound.
const std::string* payload_of(const MetadataValue& value) noexcept {
  const std::string* payload = value.text_if();
  return payload != nullptr ? payload : value.token_if();
}

}  // namespace

std::string_view to_token(MetadataKind kind) noexcept {
  for (const MetadataKindToken& entry : kMetadataKindTokens) {
    if (entry.kind == kind) {
      return entry.token;
    }
  }
  return std::string_view{};
}

bool parse_metadata_kind(std::string_view token, MetadataKind& out) noexcept {
  for (const MetadataKindToken& entry : kMetadataKindTokens) {
    if (entry.token == token) {
      out = entry.kind;
      return true;
    }
  }
  return false;
}

MetadataValue MetadataValue::unknown() noexcept {
  return MetadataValue{MetadataKind::Unknown, std::string{}, 0, false};
}

Result<MetadataValue> MetadataValue::text(std::string value, std::size_t max_bytes) {
  Result<std::string> validated = validate_text_field(value, max_bytes, "metadata text value");
  if (!validated) {
    return validated.error();
  }
  return MetadataValue{MetadataKind::Text, std::move(validated).value(), 0, false};
}

MetadataValue MetadataValue::integer(std::int64_t value) noexcept {
  return MetadataValue{MetadataKind::Integer, std::string{}, value, false};
}

MetadataValue MetadataValue::boolean(bool value) noexcept {
  return MetadataValue{MetadataKind::Boolean, std::string{}, 0, value};
}

Result<MetadataValue> MetadataValue::token(std::string value, std::size_t max_bytes) {
  Result<std::string> validated = validate_text_field(value, max_bytes, "metadata token value");
  if (!validated) {
    return validated.error();
  }
  return MetadataValue{MetadataKind::Token, std::move(validated).value(), 0, false};
}

bool MetadataValue::is_known() const noexcept {
  return kind_ != MetadataKind::Unknown && kind_ != MetadataKind::Unspecified;
}

const std::string* MetadataValue::text_if() const noexcept {
  return kind_ == MetadataKind::Text ? &payload_ : nullptr;
}

const std::string* MetadataValue::token_if() const noexcept {
  return kind_ == MetadataKind::Token ? &payload_ : nullptr;
}

const std::int64_t* MetadataValue::integer_if() const noexcept {
  return kind_ == MetadataKind::Integer ? &integer_ : nullptr;
}

const bool* MetadataValue::boolean_if() const noexcept {
  return kind_ == MetadataKind::Boolean ? &boolean_ : nullptr;
}

std::string MetadataValue::to_canonical() const {
  // Every kind owns a prefix no other kind can produce, and Text and Token are
  // never confusable: the length makes a payload that contains a colon or a
  // digit unambiguous.
  switch (kind_) {
    case MetadataKind::Unspecified:
      return "unspecified";
    case MetadataKind::Unknown:
      return "unknown";
    case MetadataKind::Text:
      return "text:" + std::to_string(payload_.size()) + ":" + payload_;
    case MetadataKind::Integer:
      return "integer:" + std::to_string(integer_);
    case MetadataKind::Boolean:
      return boolean_ ? "boolean:true" : "boolean:false";
    case MetadataKind::Token:
      return "token:" + std::to_string(payload_.size()) + ":" + payload_;
  }
  return "unspecified";
}

bool operator==(const MetadataValue& lhs, const MetadataValue& rhs) noexcept {
  return lhs.kind_ == rhs.kind_ && lhs.payload_ == rhs.payload_ && lhs.integer_ == rhs.integer_ &&
         lhs.boolean_ == rhs.boolean_;
}

bool operator<(const MetadataValue& lhs, const MetadataValue& rhs) noexcept {
  if (lhs.kind_ != rhs.kind_) {
    return static_cast<std::uint8_t>(lhs.kind_) < static_cast<std::uint8_t>(rhs.kind_);
  }
  if (lhs.payload_ != rhs.payload_) {
    return lhs.payload_ < rhs.payload_;
  }
  if (lhs.integer_ != rhs.integer_) {
    return lhs.integer_ < rhs.integer_;
  }
  return static_cast<int>(lhs.boolean_) < static_cast<int>(rhs.boolean_);
}

Result<TenancyMetadata> TenancyMetadata::create(std::vector<MetadataEntry> entries, std::size_t max_entries,
                                                std::size_t max_value_bytes) {
  if (entries.size() > max_entries) {
    return Error{ErrorCode::LimitExceeded, "metadata has " + std::to_string(entries.size()) +
                                               " entries and the maximum is " + std::to_string(max_entries)};
  }
  for (const MetadataEntry& entry : entries) {
    const std::string* payload = payload_of(entry.value);
    if (payload != nullptr && payload->size() > max_value_bytes) {
      return Error{ErrorCode::InvalidMetadata, "the value of metadata key " + std::string{entry.key.value()} +
                                                   " is " + std::to_string(payload->size()) +
                                                   " bytes and the maximum is " +
                                                   std::to_string(max_value_bytes)};
    }
  }
  std::sort(entries.begin(), entries.end(), [](const MetadataEntry& left, const MetadataEntry& right) {
    // Key bytes, not locale collation: the order must not depend on the host.
    return left.key.value() < right.key.value();
  });
  for (std::size_t index = 1; index < entries.size(); ++index) {
    if (entries[index - 1].key == entries[index].key) {
      // Keeping the last one would make the meaning of a declaration depend on
      // the order it was written in, so the duplicate is refused instead.
      return Error{ErrorCode::InvalidMetadata,
                   "metadata key " + std::string{entries[index].key.value()} + " appears more than once"};
    }
  }
  TenancyMetadata result;
  result.entries_ = std::move(entries);
  return result;
}

Status TenancyMetadata::put(const MetadataKey& key, MetadataValue value, std::size_t max_entries) {
  const auto position =
      std::lower_bound(entries_.begin(), entries_.end(), key,
                       [](const MetadataEntry& entry, const MetadataKey& candidate) {
                         return entry.key.value() < candidate.value();
                       });
  if (position != entries_.end() && position->key == key) {
    position->value = std::move(value);
    return Status::success();
  }
  if (entries_.size() >= max_entries) {
    return Status::failure(ErrorCode::LimitExceeded,
                           "metadata would have " + std::to_string(entries_.size() + 1) +
                               " entries and the maximum is " + std::to_string(max_entries));
  }
  entries_.insert(position, MetadataEntry{key, std::move(value)});
  return Status::success();
}

bool TenancyMetadata::erase(const MetadataKey& key) {
  const auto position =
      std::lower_bound(entries_.begin(), entries_.end(), key,
                       [](const MetadataEntry& entry, const MetadataKey& candidate) {
                         return entry.key.value() < candidate.value();
                       });
  if (position == entries_.end() || !(position->key == key)) {
    return false;
  }
  entries_.erase(position);
  return true;
}

MetadataValue TenancyMetadata::find(const MetadataKey& key) const {
  const auto position =
      std::lower_bound(entries_.begin(), entries_.end(), key,
                       [](const MetadataEntry& entry, const MetadataKey& candidate) {
                         return entry.key.value() < candidate.value();
                       });
  if (position == entries_.end() || !(position->key == key)) {
    // An absent key is explicitly unknown, never a default constructed value.
    return MetadataValue::unknown();
  }
  return position->value;
}

bool TenancyMetadata::contains(const MetadataKey& key) const noexcept {
  const auto position =
      std::lower_bound(entries_.begin(), entries_.end(), key,
                       [](const MetadataEntry& entry, const MetadataKey& candidate) {
                         return entry.key.value() < candidate.value();
                       });
  return position != entries_.end() && position->key == key;
}

std::string TenancyMetadata::to_canonical() const {
  // The entries are already in canonical key order, so this rendering is the
  // same for every insertion order. Each key is length prefixed, so a key that
  // contains the separator cannot be read as two keys.
  std::string out;
  for (const MetadataEntry& entry : entries_) {
    out += std::to_string(entry.key.value().size());
    out += ':';
    out += entry.key.value();
    out += '=';
    out += entry.value.to_canonical();
    out += '\n';
  }
  return out;
}

std::string TenancyMetadata::to_json() const {
  std::string out;
  out += '{';
  bool first = true;
  for (const MetadataEntry& entry : entries_) {
    if (!first) {
      out += ',';
    }
    first = false;
    out += '"';
    detail::json_escape(out, entry.key.value());
    out += '"';
    out += ':';
    switch (entry.value.kind()) {
      case MetadataKind::Unspecified:
      case MetadataKind::Unknown:
        out += "null";
        break;
      case MetadataKind::Text:
      case MetadataKind::Token: {
        const std::string* payload = payload_of(entry.value);
        out += '"';
        detail::json_escape(out, payload != nullptr ? std::string_view{*payload} : std::string_view{});
        out += '"';
        break;
      }
      case MetadataKind::Integer: {
        const std::int64_t* number = entry.value.integer_if();
        out += std::to_string(number != nullptr ? *number : 0);
        break;
      }
      case MetadataKind::Boolean: {
        const bool* flag = entry.value.boolean_if();
        out += (flag != nullptr && *flag) ? "true" : "false";
        break;
      }
    }
  }
  out += '}';
  return out;
}

bool operator==(const TenancyMetadata& lhs, const TenancyMetadata& rhs) noexcept {
  if (lhs.entries_.size() != rhs.entries_.size()) {
    return false;
  }
  for (std::size_t index = 0; index < lhs.entries_.size(); ++index) {
    if (!(lhs.entries_[index].key == rhs.entries_[index].key)) {
      return false;
    }
    if (!(lhs.entries_[index].value == rhs.entries_[index].value)) {
      return false;
    }
  }
  return true;
}

bool operator<(const TenancyMetadata& lhs, const TenancyMetadata& rhs) noexcept {
  return std::lexicographical_compare(
      lhs.entries_.begin(), lhs.entries_.end(), rhs.entries_.begin(), rhs.entries_.end(),
      [](const MetadataEntry& left, const MetadataEntry& right) {
        if (!(left.key == right.key)) {
          return left.key < right.key;
        }
        return left.value < right.value;
      });
}

}  // namespace tenant_registry
