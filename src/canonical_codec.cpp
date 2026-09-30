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

#include "canonical_codec.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "sha256.hpp"
#include "tenant_registry/query.hpp"

namespace tenant_registry {
namespace detail {

namespace {

// ---------------------------------------------------------------------------
// Shared bounds and preimage parts
// ---------------------------------------------------------------------------

/// The single zero byte that separates the parts of a digest preimage. It can
/// never occur inside a canonical identity token, so no two (domain, token,
/// value) triples can produce the same preimage.
constexpr std::string_view kSeparator{"\0", 1};

/// The byte bound of a canonical record key. A key is built from at most two
/// 128 byte identities, their kind tokens and two separators, so no canonical
/// key can reach this bound; the bound exists so that reading one out of
/// untrusted bytes is bounded before the key's shape is even considered.
constexpr std::size_t kMaxCanonicalKeyBytes = 512;

/// The absence of a byte bound. It is used only where the field's own type
/// carries the bound, so the codec never invents a limit the type does not
/// have.
constexpr std::size_t kNoByteLimit = std::numeric_limits<std::size_t>::max();

/// The one token table for RecordKind. The token is part of the record digest
/// preimage, so each kind has exactly one spelling.
constexpr std::size_t kRecordKindCount = 8;
constexpr std::string_view kRecordKindTokens[kRecordKindCount] = {"unspecified",
                                                                 "tenant",
                                                                 "service",
                                                                 "isolation_domain",
                                                                 "ownership_edge",
                                                                 "service_binding",
                                                                 "isolation_membership",
                                                                 "tombstone"};

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// Every refusal a decoder produces names the field that failed and the byte
/// offset that field starts at. "The input was malformed" is not an answer an
/// operator can act on; an offset is what turns a corrupt frame into a range
/// someone can look at.
[[nodiscard]] Error field_error(ErrorCode code, std::string_view field, std::size_t offset,
                                std::string_view reason) {
  return Error{code, "field '" + std::string{field} + "' at byte " + std::to_string(offset) + ": " +
                         std::string{reason}};
}

// ---------------------------------------------------------------------------
// Bounded primitive readers
// ---------------------------------------------------------------------------

[[nodiscard]] Result<std::uint32_t> read_u32(ByteReader& reader, const char* field) {
  const std::size_t offset = reader.position();
  const auto value = reader.u32();
  if (!value.has_value()) {
    return field_error(ErrorCode::DecodeFailed, field, offset, "truncated 32 bit unsigned value");
  }
  return value.value();
}

[[nodiscard]] Result<std::uint64_t> read_u64(ByteReader& reader, const char* field) {
  const std::size_t offset = reader.position();
  const auto value = reader.u64();
  if (!value.has_value()) {
    return field_error(ErrorCode::DecodeFailed, field, offset, "truncated 64 bit unsigned value");
  }
  return value.value();
}

[[nodiscard]] Result<std::int64_t> read_i64(ByteReader& reader, const char* field) {
  const std::size_t offset = reader.position();
  const auto value = reader.i64();
  if (!value.has_value()) {
    return field_error(ErrorCode::DecodeFailed, field, offset, "truncated 64 bit signed value");
  }
  return value.value();
}

[[nodiscard]] Result<ContentDigest> read_digest(ByteReader& reader, const char* field) {
  const std::size_t offset = reader.position();
  const auto value = reader.digest();
  if (!value.has_value()) {
    return field_error(ErrorCode::DecodeFailed, field, offset, "truncated 32 byte digest");
  }
  return value.value();
}

[[nodiscard]] Result<bool> read_bool(ByteReader& reader, const char* field) {
  const std::size_t offset = reader.position();
  const auto value = reader.u8();
  if (!value.has_value()) {
    return field_error(ErrorCode::DecodeFailed, field, offset, "truncated boolean byte");
  }
  if (value.value() > 1) {
    return field_error(ErrorCode::DecodeFailed, field, offset,
                       "boolean byte is " + std::to_string(value.value()) + ", only 0 and 1 are canonical");
  }
  return value.value() == 1;
}

/// Reads the presence flag of an optional field. A flag that is neither 0 nor 1
/// states neither absence nor presence, so it is refused rather than
/// interpreted as one of them.
[[nodiscard]] Result<bool> read_presence(ByteReader& reader, const char* field) {
  const std::size_t offset = reader.position();
  const auto flag = reader.u8();
  if (!flag.has_value()) {
    return field_error(ErrorCode::DecodeFailed, field, offset, "truncated presence flag");
  }
  if (flag.value() == 0) {
    return false;
  }
  if (flag.value() == 1) {
    return true;
  }
  return field_error(ErrorCode::DecodeFailed, field, offset,
                     "presence flag is " + std::to_string(flag.value()) +
                         ", only 0 (absent) and 1 (present) are canonical");
}

/// Reads one enum encoded as a single byte. Zero (Unspecified) and every value
/// the enum does not define are refused: a decoder never maps an unknown byte
/// onto a default, because that would turn an unrecognized durable value into a
/// recognized one.
template <class Enum>
[[nodiscard]] Result<Enum> read_enum(ByteReader& reader, const char* field, std::uint8_t highest) {
  const std::size_t offset = reader.position();
  const auto raw = reader.u8();
  if (!raw.has_value()) {
    return field_error(ErrorCode::DecodeFailed, field, offset, "truncated enum byte");
  }
  if (raw.value() == 0) {
    return field_error(ErrorCode::InvalidEnumValue, field, offset, "value 0 (Unspecified) is never a legal value");
  }
  if (raw.value() > highest) {
    return field_error(ErrorCode::InvalidEnumValue, field, offset,
                       "value " + std::to_string(raw.value()) + " is not defined by this enum");
  }
  return static_cast<Enum>(raw.value());
}

/// OperationKind is the one enum wider than a byte.
[[nodiscard]] Result<OperationKind> read_operation_kind(ByteReader& reader, const char* field) {
  const std::size_t offset = reader.position();
  const auto raw = reader.u16();
  if (!raw.has_value()) {
    return field_error(ErrorCode::DecodeFailed, field, offset, "truncated 16 bit operation value");
  }
  if (raw.value() == 0) {
    return field_error(ErrorCode::InvalidEnumValue, field, offset, "value 0 (Unspecified) is never a legal operation");
  }
  if (raw.value() > static_cast<std::uint16_t>(OperationKind::Tombstone)) {
    return field_error(ErrorCode::InvalidEnumValue, field, offset,
                       "value " + std::to_string(raw.value()) + " is not an operation this build defines");
  }
  return static_cast<OperationKind>(raw.value());
}

template <class Enum>
[[nodiscard]] bool decode_enum_u8(ByteReader& reader, Enum& out, std::uint8_t highest) noexcept {
  const auto raw = reader.u8();
  if (!raw.has_value() || raw.value() == 0 || raw.value() > highest) {
    return false;
  }
  out = static_cast<Enum>(raw.value());
  return true;
}

template <class Enum>
[[nodiscard]] bool decode_enum_u16(ByteReader& reader, Enum& out, std::uint16_t highest) noexcept {
  const auto raw = reader.u16();
  if (!raw.has_value() || raw.value() == 0 || raw.value() > highest) {
    return false;
  }
  out = static_cast<Enum>(raw.value());
  return true;
}

/// Reads a 32 bit byte count followed by that many bytes. The count is checked
/// against the caller's bound before a single byte is copied, so a declared
/// count can never make this process allocate more than the bound allows.
[[nodiscard]] Result<std::string> read_text(ByteReader& reader, std::size_t max_bytes, const char* field) {
  const std::size_t offset = reader.position();
  const auto length = reader.u32();
  if (!length.has_value()) {
    return field_error(ErrorCode::DecodeFailed, field, offset, "truncated 32 bit byte count");
  }
  if (length.value() > max_bytes) {
    return field_error(ErrorCode::LimitExceeded, field, offset,
                       "declares " + std::to_string(length.value()) + " bytes, the limit is " +
                           std::to_string(max_bytes));
  }
  const auto bytes = reader.raw(length.value());
  if (!bytes.has_value()) {
    return field_error(ErrorCode::DecodeFailed, field, offset,
                       "declares " + std::to_string(length.value()) + " bytes but only " +
                           std::to_string(reader.remaining()) + " remain");
  }
  if (bytes->empty()) {
    return std::string{};
  }
  return std::string{reinterpret_cast<const char*>(bytes->data()), bytes->size()};
}

/// Reads one opaque text field and re-validates it against the same rules the
/// encoder used. A field that is not well formed UTF-8, that carries a control
/// byte, or that exceeds its bound is malformed, not close enough.
[[nodiscard]] Result<std::string> read_text_field(ByteReader& reader, std::size_t max_bytes, const char* field,
                                                  bool allow_empty = false) {
  const std::size_t offset = reader.position();
  auto text = read_text(reader, max_bytes, field);
  if (!text.has_value()) {
    return text.error();
  }
  if (!is_valid_utf8(text.value())) {
    return field_error(ErrorCode::InvalidUtf8, field, offset, "text is not well formed UTF-8");
  }
  if (text.value().empty()) {
    // A note is allowed to be empty and must stay empty. Refusing it here would
    // make a record the registry accepted impossible to read back, which is a
    // durability defect rather than a validation one.
    if (allow_empty) {
      return std::string{};
    }
    return field_error(ErrorCode::InvalidTextForm, field, offset, "text must not be empty");
  }
  auto validated = validate_text_field(text.value(), max_bytes, field);
  if (!validated.has_value()) {
    const ErrorCode code =
        validated.error().code() == ErrorCode::Unspecified ? ErrorCode::DecodeFailed : validated.error().code();
    return field_error(code, field, offset, validated.error().detail());
  }
  return std::move(validated).value();
}

[[nodiscard]] Result<std::vector<std::byte>> read_payload(ByteReader& reader, std::size_t max_bytes,
                                                          const char* field) {
  const std::size_t offset = reader.position();
  const auto length = reader.u32();
  if (!length.has_value()) {
    return field_error(ErrorCode::DecodeFailed, field, offset, "truncated 32 bit byte count");
  }
  if (length.value() > max_bytes) {
    return field_error(ErrorCode::PayloadTooLarge, field, offset,
                       "declares " + std::to_string(length.value()) + " bytes, the limit is " +
                           std::to_string(max_bytes));
  }
  const auto bytes = reader.raw(length.value());
  if (!bytes.has_value()) {
    return field_error(ErrorCode::DecodeFailed, field, offset,
                       "declares " + std::to_string(length.value()) + " bytes but only " +
                           std::to_string(reader.remaining()) + " remain");
  }
  return std::vector<std::byte>{bytes->begin(), bytes->end()};
}

[[nodiscard]] Result<std::optional<std::uint64_t>> read_optional_u64(ByteReader& reader, const char* field) {
  const auto present = read_presence(reader, field);
  if (!present.has_value()) {
    return present.error();
  }
  if (!present.value()) {
    return std::optional<std::uint64_t>{};
  }
  auto value = read_u64(reader, field);
  if (!value.has_value()) {
    return value.error();
  }
  return std::optional<std::uint64_t>{value.value()};
}

[[nodiscard]] Result<std::optional<std::string>> read_optional_text_field(ByteReader& reader, std::size_t max_bytes,
                                                                          const char* field) {
  const auto present = read_presence(reader, field);
  if (!present.has_value()) {
    return present.error();
  }
  if (!present.value()) {
    return std::optional<std::string>{};
  }
  auto text = read_text_field(reader, max_bytes, field);
  if (!text.has_value()) {
    return text.error();
  }
  return std::optional<std::string>{std::move(text).value()};
}

[[nodiscard]] std::optional<RegistryGeneration> to_generation(std::optional<std::uint64_t> value) {
  if (!value.has_value()) {
    return std::nullopt;
  }
  return RegistryGeneration::from_value(value.value());
}

template <class T, class DecodeOne>
[[nodiscard]] Result<std::optional<T>> read_optional(ByteReader& reader, const char* field, DecodeOne&& decode_one) {
  const auto present = read_presence(reader, field);
  if (!present.has_value()) {
    return present.error();
  }
  if (!present.value()) {
    return std::optional<T>{};
  }
  auto value = decode_one(reader);
  if (!value.has_value()) {
    return value.error();
  }
  return std::optional<T>{std::move(value).value()};
}

// ---------------------------------------------------------------------------
// Bounded identity readers
// ---------------------------------------------------------------------------

/// Reads an identity token and re-validates it with the strong type that owns
/// those rules. A record whose identity does not satisfy the identity rules is
/// malformed: there is no such thing as a nearly valid tenant.
template <class Id>
[[nodiscard]] Result<Id> read_identity(ByteReader& reader, std::size_t max_bytes, const char* field) {
  const std::size_t offset = reader.position();
  auto text = read_text(reader, max_bytes, field);
  if (!text.has_value()) {
    return text.error();
  }
  auto id = Id::create(text.value());
  if (!id.has_value()) {
    return field_error(ErrorCode::InvalidIdentity, field, offset,
                       "identity does not satisfy its rules: " + id.error().detail());
  }
  return std::move(id).value();
}

template <class Id>
[[nodiscard]] Result<std::optional<Id>> read_optional_identity(ByteReader& reader, std::size_t max_bytes,
                                                               const char* field) {
  const auto present = read_presence(reader, field);
  if (!present.has_value()) {
    return present.error();
  }
  if (!present.value()) {
    return std::optional<Id>{};
  }
  auto id = read_identity<Id>(reader, max_bytes, field);
  if (!id.has_value()) {
    return id.error();
  }
  return std::optional<Id>{std::move(id).value()};
}

/// Reads an identity token whose kind is a value of the encoding rather than a
/// static type, and validates it against the rules of that kind.
[[nodiscard]] Result<std::string> read_kind_identity(ByteReader& reader, SubjectKind kind, std::size_t max_bytes,
                                                     const char* field) {
  const std::size_t offset = reader.position();
  auto text = read_text(reader, max_bytes, field);
  if (!text.has_value()) {
    return text.error();
  }
  const IdentityRules* rules = nullptr;
  switch (kind) {
    case SubjectKind::Tenant:
      rules = &TenantId::rules();
      break;
    case SubjectKind::Service:
      rules = &ServiceId::rules();
      break;
    case SubjectKind::IsolationDomain:
      rules = &IsolationDomainId::rules();
      break;
    default:
      return field_error(ErrorCode::InvalidEnumValue, field, offset,
                         "subject kind 0 (Unspecified) names no identity rules");
  }
  auto validated = validate_identity(text.value(), *rules);
  if (!validated.has_value()) {
    return field_error(ErrorCode::InvalidIdentity, field, offset,
                       "identity does not satisfy its rules: " + validated.error().detail());
  }
  return std::move(validated).value();
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

void write_metadata_value(ByteWriter& writer, const MetadataValue& value) {
  encode(writer, value.kind());
  switch (value.kind()) {
    case MetadataKind::Unknown:
      break;
    case MetadataKind::Text:
      if (const std::string* text = value.text_if()) {
        writer.length_prefixed(*text);
      }
      break;
    case MetadataKind::Token:
      if (const std::string* token = value.token_if()) {
        writer.length_prefixed(*token);
      }
      break;
    case MetadataKind::Integer:
      if (const std::int64_t* number = value.integer_if()) {
        writer.i64(*number);
      }
      break;
    case MetadataKind::Boolean:
      if (const bool* flag = value.boolean_if()) {
        writer.u8(static_cast<std::uint8_t>(*flag ? 1 : 0));
      }
      break;
    default:
      break;
  }
}

[[nodiscard]] Result<MetadataValue> read_metadata_value(ByteReader& reader, const RegistryLimits& limits) {
  const std::size_t offset = reader.position();
  auto kind = read_enum<MetadataKind>(reader, "Metadata.value.kind", static_cast<std::uint8_t>(MetadataKind::Token));
  if (!kind.has_value()) {
    return kind.error();
  }
  switch (kind.value()) {
    case MetadataKind::Unknown:
      return MetadataValue::unknown();
    case MetadataKind::Text: {
      auto text = read_text_field(reader, limits.max_metadata_value_bytes, "Metadata.value.text");
      if (!text.has_value()) {
        return text.error();
      }
      auto value = MetadataValue::text(std::move(text).value(), limits.max_metadata_value_bytes);
      if (!value.has_value()) {
        return field_error(ErrorCode::InvalidMetadata, "Metadata.value", offset, value.error().detail());
      }
      return std::move(value).value();
    }
    case MetadataKind::Token: {
      auto token = read_text_field(reader, limits.max_metadata_value_bytes, "Metadata.value.token");
      if (!token.has_value()) {
        return token.error();
      }
      auto value = MetadataValue::token(std::move(token).value(), limits.max_metadata_value_bytes);
      if (!value.has_value()) {
        return field_error(ErrorCode::InvalidMetadata, "Metadata.value", offset, value.error().detail());
      }
      return std::move(value).value();
    }
    case MetadataKind::Integer: {
      auto number = read_i64(reader, "Metadata.value.integer");
      if (!number.has_value()) {
        return number.error();
      }
      return MetadataValue::integer(number.value());
    }
    case MetadataKind::Boolean: {
      auto flag = read_bool(reader, "Metadata.value.boolean");
      if (!flag.has_value()) {
        return flag.error();
      }
      return MetadataValue::boolean(flag.value());
    }
    default:
      return field_error(ErrorCode::InvalidEnumValue, "Metadata.value.kind", offset,
                         "value 0 (Unspecified) is never a legal metadata kind");
  }
}

// ---------------------------------------------------------------------------
// Bounded lists
// ---------------------------------------------------------------------------

template <class T, class DecodeOne>
[[nodiscard]] Result<std::vector<T>> read_list(ByteReader& reader, const char* field, std::uint64_t max_entries,
                                               DecodeOne&& decode_one) {
  const std::size_t offset = reader.position();
  auto count = read_u32(reader, field);
  if (!count.has_value()) {
    return count.error();
  }
  if (count.value() > max_entries) {
    return field_error(ErrorCode::LimitExceeded, field, offset,
                       "declares " + std::to_string(count.value()) + " entries, the limit is " +
                           std::to_string(max_entries));
  }
  std::vector<T> items;
  for (std::uint32_t index = 0; index < count.value(); ++index) {
    auto item = decode_one(reader);
    if (!item.has_value()) {
      return item.error();
    }
    items.push_back(std::move(item).value());
  }
  return items;
}

/// The record count limit that corresponds to one record kind.
[[nodiscard]] std::uint64_t record_limit(RecordKind kind, const RegistryLimits& limits) {
  switch (kind) {
    case RecordKind::Tenant:
      return limits.max_tenants;
    case RecordKind::Service:
      return limits.max_services;
    case RecordKind::IsolationDomain:
      return limits.max_isolation_domains;
    case RecordKind::OwnershipEdge:
      return limits.max_ownership_edges;
    case RecordKind::ServiceBinding:
      return limits.max_service_bindings;
    case RecordKind::IsolationMembership:
      return limits.max_isolation_memberships;
    case RecordKind::Tombstone:
      return limits.max_tenants + limits.max_services + limits.max_isolation_domains;
    default:
      return 0;
  }
}

/// The total number of records one payload may carry. It is the sum of the per
/// kind limits: a set of records whose kinds are not known until each element
/// has been read has no other bound that can be checked before the first read.
[[nodiscard]] std::uint64_t total_record_limit(const RegistryLimits& limits) {
  return limits.max_tenants + limits.max_services + limits.max_isolation_domains + limits.max_ownership_edges +
         limits.max_service_bindings + limits.max_isolation_memberships +
         (limits.max_tenants + limits.max_services + limits.max_isolation_domains);
}

/// Reads an upsert set, enforcing each record kind's own limit as it goes. The
/// kinds in one set are not known before the set is read, so the bound that can
/// actually be enforced is the per kind bound.
[[nodiscard]] Result<std::vector<AnyRecord>> read_upserts(ByteReader& reader, const RegistryLimits& limits) {
  const char* const field = "CommitRecord.upserts";
  const std::size_t offset = reader.position();
  auto count = read_u32(reader, field);
  if (!count.has_value()) {
    return count.error();
  }
  const std::uint64_t limit = total_record_limit(limits);
  if (count.value() > limit) {
    return field_error(ErrorCode::LimitExceeded, field, offset,
                       "declares " + std::to_string(count.value()) + " records, the limit is " + std::to_string(limit));
  }
  std::array<std::uint64_t, kRecordKindCount> seen{};
  std::vector<AnyRecord> records;
  for (std::uint32_t index = 0; index < count.value(); ++index) {
    auto record = decode_any(reader, limits);
    if (!record.has_value()) {
      return record.error();
    }
    const RecordKind kind = kind_of(record.value());
    std::uint64_t& seen_for_kind = seen[static_cast<std::size_t>(kind)];
    ++seen_for_kind;
    const std::uint64_t kind_limit = record_limit(kind, limits);
    if (seen_for_kind > kind_limit) {
      return field_error(ErrorCode::LimitExceeded, field, offset,
                         "record " + std::to_string(index) + " is " + std::string{to_token(kind)} + " number " +
                             std::to_string(seen_for_kind) + ", the limit is " + std::to_string(kind_limit));
    }
    records.push_back(std::move(record).value());
  }
  return records;
}

/// Reads a delete set. A canonical delete set holds no empty key and no key
/// twice: the encoder can produce neither, so either one means these bytes are
/// not a canonical encoding.
[[nodiscard]] Result<std::vector<std::string>> read_deletes(ByteReader& reader, const RegistryLimits& limits) {
  const char* const field = "CommitRecord.deletes";
  const std::size_t offset = reader.position();
  auto count = read_u32(reader, field);
  if (!count.has_value()) {
    return count.error();
  }
  const std::uint64_t limit = total_record_limit(limits);
  if (count.value() > limit) {
    return field_error(ErrorCode::LimitExceeded, field, offset,
                       "declares " + std::to_string(count.value()) + " keys, the limit is " + std::to_string(limit));
  }
  std::vector<std::string> keys;
  for (std::uint32_t index = 0; index < count.value(); ++index) {
    const std::size_t key_offset = reader.position();
    auto key = read_text_field(reader, kMaxCanonicalKeyBytes, field);
    if (!key.has_value()) {
      return key.error();
    }
    if (key.value().empty()) {
      return field_error(ErrorCode::DecodeFailed, field, key_offset, "key " + std::to_string(index) + " is empty");
    }
    for (const std::string& existing : keys) {
      if (existing == key.value()) {
        return field_error(ErrorCode::DecodeFailed, field, key_offset,
                           "key " + std::to_string(index) + " repeats '" + key.value() + "'");
      }
    }
    keys.push_back(std::move(key).value());
  }
  return keys;
}

[[nodiscard]] Result<std::vector<std::pair<IsolationDomainId, DomainGeneration>>> read_domain_generations(
    ByteReader& reader, const RegistryLimits& limits, const char* field, std::uint64_t max_entries) {
  const std::size_t offset = reader.position();
  auto count = read_u32(reader, field);
  if (!count.has_value()) {
    return count.error();
  }
  if (count.value() > max_entries) {
    return field_error(ErrorCode::LimitExceeded, field, offset,
                       "declares " + std::to_string(count.value()) + " entries, the limit is " +
                           std::to_string(max_entries));
  }
  std::vector<std::pair<IsolationDomainId, DomainGeneration>> entries;
  for (std::uint32_t index = 0; index < count.value(); ++index) {
    auto id = read_identity<IsolationDomainId>(reader, limits.max_identity_bytes, field);
    if (!id.has_value()) {
      return id.error();
    }
    auto generation = read_u64(reader, field);
    if (!generation.has_value()) {
      return generation.error();
    }
    entries.emplace_back(std::move(id).value(), DomainGeneration::from_value(generation.value()));
  }
  return entries;
}

// ---------------------------------------------------------------------------
// Digest preimages
// ---------------------------------------------------------------------------

void write_context(ByteWriter& writer, const MutationContext& context) {
  writer.u64(context.expected_generation.value());
  writer.optional(context.idempotency_key, [&writer](const IdempotencyKey& key) { encode(writer, key); });
  encode(writer, context.actor);
}

[[nodiscard]] ContentDigest record_digest_of(RecordKind kind, const ByteWriter& body) {
  Sha256 hasher;
  hasher.update(kRecordDigestDomain);
  hasher.update(kSeparator);
  hasher.update(to_token(kind));
  hasher.update(kSeparator);
  hasher.update(body.view());
  return hasher.finish();
}

[[nodiscard]] ContentDigest request_digest_of(OperationKind kind, const ByteWriter& body) {
  Sha256 hasher;
  hasher.update(kRequestDigestDomain);
  hasher.update(kSeparator);
  hasher.update(to_token(kind));
  hasher.update(kSeparator);
  hasher.update(body.view());
  return hasher.finish();
}

template <class T>
void write_record_list(ByteWriter& writer, const std::vector<T>& records) {
  writer.u32(static_cast<std::uint32_t>(records.size()));
  for (const T& record : records) {
    encode(writer, record);
  }
}

void write_domain_generations(ByteWriter& writer,
                              const std::vector<std::pair<IsolationDomainId, DomainGeneration>>& entries) {
  writer.u32(static_cast<std::uint32_t>(entries.size()));
  for (const std::pair<IsolationDomainId, DomainGeneration>& entry : entries) {
    writer.length_prefixed(entry.first.value());
    writer.u64(entry.second.value());
  }
}

[[nodiscard]] std::string text_of(std::span<const std::byte> bytes) {
  if (bytes.empty()) {
    return std::string{};
  }
  return std::string{reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

}  // namespace

// ---------------------------------------------------------------------------
// Record kinds and canonical keys
// ---------------------------------------------------------------------------

std::string_view to_token(RecordKind kind) noexcept {
  const auto index = static_cast<std::size_t>(kind);
  if (index < kRecordKindCount) {
    return kRecordKindTokens[index];
  }
  return kRecordKindTokens[0];
}

bool parse_record_kind(std::string_view token, RecordKind& out) noexcept {
  for (std::size_t index = 0; index < kRecordKindCount; ++index) {
    if (token == kRecordKindTokens[index]) {
      out = static_cast<RecordKind>(index);
      return true;
    }
  }
  return false;
}

RecordKind kind_of(const AnyRecord& record) noexcept {
  return std::visit(
      [](const auto& value) noexcept -> RecordKind {
        using Value = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<Value, TenantRecord>) {
          return RecordKind::Tenant;
        } else if constexpr (std::is_same_v<Value, ServiceRecord>) {
          return RecordKind::Service;
        } else if constexpr (std::is_same_v<Value, IsolationDomainRecord>) {
          return RecordKind::IsolationDomain;
        } else if constexpr (std::is_same_v<Value, OwnershipEdge>) {
          return RecordKind::OwnershipEdge;
        } else if constexpr (std::is_same_v<Value, ServiceBinding>) {
          return RecordKind::ServiceBinding;
        } else if constexpr (std::is_same_v<Value, IsolationMembership>) {
          return RecordKind::IsolationMembership;
        } else {
          static_assert(std::is_same_v<Value, TombstoneRecord>,
                        "AnyRecord gained an alternative that has no RecordKind");
          return RecordKind::Tombstone;
        }
      },
      record);
}

bool is_identity_record(const AnyRecord& record) noexcept {
  return std::visit(
      [](const auto& value) noexcept {
        using Value = std::decay_t<decltype(value)>;
        return std::is_same_v<Value, TenantRecord> || std::is_same_v<Value, ServiceRecord> ||
               std::is_same_v<Value, IsolationDomainRecord>;
      },
      record);
}

std::string canonical_key(const TenantRecord& record) {
  std::string key(record.id.kind_token());
  key += ':';
  key += record.id.to_text();
  return key;
}

std::string canonical_key(const ServiceRecord& record) {
  std::string key(record.id.kind_token());
  key += ':';
  key += record.id.to_text();
  return key;
}

std::string canonical_key(const IsolationDomainRecord& record) {
  std::string key(record.id.kind_token());
  key += ':';
  key += record.id.to_text();
  return key;
}

std::string canonical_key(const OwnershipEdge& record) {
  std::string key{"ownership:"};
  key += record.child.to_text();
  key += '|';
  key += record.parent.to_text();
  return key;
}

std::string canonical_key(const ServiceBinding& record) {
  std::string key{"binding:"};
  key += record.service.to_text();
  key += '|';
  key += record.tenant.to_text();
  key += '|';
  key += to_token(record.kind);
  return key;
}

std::string canonical_key(const IsolationMembership& record) {
  std::string key{"membership:"};
  key += record.subject.to_text();
  key += '|';
  key += record.domain.to_text();
  return key;
}

std::string canonical_key(const TombstoneRecord& record) {
  std::string key{"tombstone:"};
  key += to_token(record.kind);
  key += ':';
  key += record.identity;
  return key;
}

std::string canonical_key(const AnyRecord& record) {
  return std::visit([](const auto& value) { return canonical_key(value); }, record);
}

// ---------------------------------------------------------------------------
// Primitive encoders
// ---------------------------------------------------------------------------

void encode(ByteWriter& writer, LifecycleState value) { writer.u8(static_cast<std::uint8_t>(value)); }
void encode(ByteWriter& writer, MembershipState value) { writer.u8(static_cast<std::uint8_t>(value)); }
void encode(ByteWriter& writer, OwnershipKind value) { writer.u8(static_cast<std::uint8_t>(value)); }
void encode(ByteWriter& writer, BindingKind value) { writer.u8(static_cast<std::uint8_t>(value)); }
void encode(ByteWriter& writer, MembershipRole value) { writer.u8(static_cast<std::uint8_t>(value)); }
void encode(ByteWriter& writer, IsolationClass value) { writer.u8(static_cast<std::uint8_t>(value)); }
void encode(ByteWriter& writer, ProvenanceSource value) { writer.u8(static_cast<std::uint8_t>(value)); }
void encode(ByteWriter& writer, SubjectKind value) { writer.u8(static_cast<std::uint8_t>(value)); }
void encode(ByteWriter& writer, MetadataKind value) { writer.u8(static_cast<std::uint8_t>(value)); }
void encode(ByteWriter& writer, OperationKind value) { writer.u16(static_cast<std::uint16_t>(value)); }
void encode(ByteWriter& writer, RecordKind value) { writer.u8(static_cast<std::uint8_t>(value)); }
void encode(ByteWriter& writer, TraversalDirection value) { writer.u8(static_cast<std::uint8_t>(value)); }

void encode(ByteWriter& writer, const TenancySubject& value) {
  encode(writer, value.kind());
  writer.length_prefixed(value.identity_value());
}

void encode(ByteWriter& writer, const ProvenanceRecord& value) {
  encode(writer, value.source());
  writer.length_prefixed(value.source_id().value());
  writer.length_prefixed(value.principal().value());
  writer.optional(value.declared_at(),
                  [&writer](const Timestamp& declared_at) { writer.i64(declared_at.unix_milliseconds); });
  writer.length_prefixed(value.note());
}

void encode(ByteWriter& writer, const TenancyMetadata& value) {
  const std::vector<MetadataEntry>& entries = value.entries();
  writer.u32(static_cast<std::uint32_t>(entries.size()));
  for (const MetadataEntry& entry : entries) {
    writer.length_prefixed(entry.key.value());
    write_metadata_value(writer, entry.value);
  }
}

void encode(ByteWriter& writer, const RebindPermit& value) {
  encode(writer, value.successor_kind());
  writer.length_prefixed(value.successor_text());
  writer.u64(value.issued_generation().value());
  writer.optional(value.consumed_generation(),
                  [&writer](const RegistryGeneration& consumed) { writer.u64(consumed.value()); });
  writer.length_prefixed(value.note());
}

void encode(ByteWriter& writer, const Tombstone& value) {
  writer.u64(value.retired_generation().value());
  writer.u64(value.tombstoned_generation().value());
  writer.optional(value.rebind_permit(), [&writer](const RebindPermit& permit) { encode(writer, permit); });
  writer.length_prefixed(value.note());
}

void encode(ByteWriter& writer, const IdempotencyKey& value) { writer.length_prefixed(value.value()); }

// ---------------------------------------------------------------------------
// Primitive decoders
// ---------------------------------------------------------------------------

bool decode(ByteReader& reader, LifecycleState& out) noexcept {
  return decode_enum_u8(reader, out, static_cast<std::uint8_t>(LifecycleState::Tombstoned));
}

bool decode(ByteReader& reader, MembershipState& out) noexcept {
  return decode_enum_u8(reader, out, static_cast<std::uint8_t>(MembershipState::Withdrawn));
}

bool decode(ByteReader& reader, OwnershipKind& out) noexcept {
  return decode_enum_u8(reader, out, static_cast<std::uint8_t>(OwnershipKind::DataResidency));
}

bool decode(ByteReader& reader, BindingKind& out) noexcept {
  return decode_enum_u8(reader, out, static_cast<std::uint8_t>(BindingKind::ConsumedBy));
}

bool decode(ByteReader& reader, MembershipRole& out) noexcept {
  return decode_enum_u8(reader, out, static_cast<std::uint8_t>(MembershipRole::Fallback));
}

bool decode(ByteReader& reader, IsolationClass& out) noexcept {
  return decode_enum_u8(reader, out, static_cast<std::uint8_t>(IsolationClass::TenantPrivate));
}

bool decode(ByteReader& reader, ProvenanceSource& out) noexcept {
  return decode_enum_u8(reader, out, static_cast<std::uint8_t>(ProvenanceSource::TestFixture));
}

bool decode(ByteReader& reader, SubjectKind& out) noexcept {
  return decode_enum_u8(reader, out, static_cast<std::uint8_t>(SubjectKind::IsolationDomain));
}

bool decode(ByteReader& reader, MetadataKind& out) noexcept {
  return decode_enum_u8(reader, out, static_cast<std::uint8_t>(MetadataKind::Token));
}

bool decode(ByteReader& reader, OperationKind& out) noexcept {
  return decode_enum_u16(reader, out, static_cast<std::uint16_t>(OperationKind::Tombstone));
}

bool decode(ByteReader& reader, RecordKind& out) noexcept {
  return decode_enum_u8(reader, out, static_cast<std::uint8_t>(RecordKind::Tombstone));
}

bool decode(ByteReader& reader, TraversalDirection& out) noexcept {
  return decode_enum_u8(reader, out, static_cast<std::uint8_t>(TraversalDirection::Descendants));
}

// ---------------------------------------------------------------------------
// Composite decoders
// ---------------------------------------------------------------------------

Result<TenancySubject> decode_subject(ByteReader& reader, const RegistryLimits& limits) {
  const std::size_t offset = reader.position();
  auto kind = read_enum<SubjectKind>(reader, "TenancySubject.kind",
                                     static_cast<std::uint8_t>(SubjectKind::IsolationDomain));
  if (!kind.has_value()) {
    return kind.error();
  }
  switch (kind.value()) {
    case SubjectKind::Tenant: {
      auto id = read_identity<TenantId>(reader, limits.max_identity_bytes, "TenancySubject.tenant");
      if (!id.has_value()) {
        return id.error();
      }
      return TenancySubject::of_tenant(std::move(id).value());
    }
    case SubjectKind::Service: {
      auto id = read_identity<ServiceId>(reader, limits.max_identity_bytes, "TenancySubject.service");
      if (!id.has_value()) {
        return id.error();
      }
      return TenancySubject::of_service(std::move(id).value());
    }
    case SubjectKind::IsolationDomain: {
      auto id = read_identity<IsolationDomainId>(reader, limits.max_identity_bytes, "TenancySubject.isolation_domain");
      if (!id.has_value()) {
        return id.error();
      }
      return TenancySubject::of_isolation_domain(std::move(id).value());
    }
    default:
      return field_error(ErrorCode::InvalidEnumValue, "TenancySubject.kind", offset,
                         "value 0 (Unspecified) names no subject kind");
  }
}

Result<ProvenanceRecord> decode_provenance(ByteReader& reader, const RegistryLimits& limits) {
  const std::size_t offset = reader.position();
  auto source = read_enum<ProvenanceSource>(reader, "Provenance.source",
                                            static_cast<std::uint8_t>(ProvenanceSource::TestFixture));
  if (!source.has_value()) {
    return source.error();
  }
  auto source_id = read_identity<SourceId>(reader, limits.max_source_bytes, "Provenance.source_id");
  if (!source_id.has_value()) {
    return source_id.error();
  }
  auto principal = read_identity<PrincipalId>(reader, limits.max_principal_bytes, "Provenance.principal");
  if (!principal.has_value()) {
    return principal.error();
  }
  auto declared_at = read_optional<std::int64_t>(reader, "Provenance.declared_at", [](ByteReader& source_reader) {
    return read_i64(source_reader, "Provenance.declared_at");
  });
  if (!declared_at.has_value()) {
    return declared_at.error();
  }
  auto note = read_text_field(reader, limits.max_provenance_note_bytes, "Provenance.note", true);
  if (!note.has_value()) {
    return note.error();
  }
  std::optional<Timestamp> timestamp;
  if (declared_at.value().has_value()) {
    timestamp = Timestamp{declared_at.value().value()};
  }
  auto provenance = ProvenanceRecord::create(source.value(), std::move(source_id).value(),
                                             std::move(principal).value(), timestamp, std::move(note).value(),
                                             limits.max_provenance_note_bytes);
  if (!provenance.has_value()) {
    return field_error(ErrorCode::DecodeFailed, "Provenance", offset, provenance.error().detail());
  }
  return std::move(provenance).value();
}

Result<TenancyMetadata> decode_metadata(ByteReader& reader, const RegistryLimits& limits) {
  const std::size_t offset = reader.position();
  auto count = read_u32(reader, "Metadata.entries");
  if (!count.has_value()) {
    return count.error();
  }
  if (count.value() > limits.max_metadata_entries_per_record) {
    return field_error(ErrorCode::LimitExceeded, "Metadata.entries", offset,
                       "declares " + std::to_string(count.value()) + " entries, the limit is " +
                           std::to_string(limits.max_metadata_entries_per_record));
  }
  std::vector<MetadataEntry> entries;
  for (std::uint32_t index = 0; index < count.value(); ++index) {
    const std::size_t key_offset = reader.position();
    auto key = read_identity<MetadataKey>(reader, limits.max_metadata_key_bytes, "Metadata.key");
    if (!key.has_value()) {
      return key.error();
    }
    for (const MetadataEntry& existing : entries) {
      if (existing.key == key.value()) {
        return field_error(ErrorCode::InvalidMetadata, "Metadata.key", key_offset,
                           "key '" + std::string{key.value().value()} +
                               "' appears more than once; a canonical encoding holds one entry per key");
      }
    }
    auto value = read_metadata_value(reader, limits);
    if (!value.has_value()) {
      return value.error();
    }
    entries.push_back(MetadataEntry{std::move(key).value(), std::move(value).value()});
  }
  auto metadata = TenancyMetadata::create(std::move(entries), limits.max_metadata_entries_per_record,
                                          limits.max_metadata_value_bytes);
  if (!metadata.has_value()) {
    return field_error(ErrorCode::InvalidMetadata, "Metadata", offset, metadata.error().detail());
  }
  return std::move(metadata).value();
}

Result<RebindPermit> decode_rebind_permit(ByteReader& reader, const RegistryLimits& limits) {
  const std::size_t offset = reader.position();
  auto successor_kind = read_enum<SubjectKind>(reader, "RebindPermit.successor_kind",
                                               static_cast<std::uint8_t>(SubjectKind::IsolationDomain));
  if (!successor_kind.has_value()) {
    return successor_kind.error();
  }
  auto successor_text =
      read_kind_identity(reader, successor_kind.value(), limits.max_identity_bytes, "RebindPermit.successor_text");
  if (!successor_text.has_value()) {
    return successor_text.error();
  }
  auto issued_generation = read_u64(reader, "RebindPermit.issued_generation");
  if (!issued_generation.has_value()) {
    return issued_generation.error();
  }
  auto consumed_generation = read_optional_u64(reader, "RebindPermit.consumed_generation");
  if (!consumed_generation.has_value()) {
    return consumed_generation.error();
  }
  auto note = read_text_field(reader, limits.max_provenance_note_bytes, "RebindPermit.note", true);
  if (!note.has_value()) {
    return note.error();
  }
  auto permit = RebindPermit::issue(successor_kind.value(), std::move(successor_text).value(),
                                    RegistryGeneration::from_value(issued_generation.value()),
                                    std::move(note).value(), limits.max_identity_bytes,
                                    limits.max_provenance_note_bytes);
  if (!permit.has_value()) {
    return field_error(ErrorCode::DecodeFailed, "RebindPermit", offset, permit.error().detail());
  }
  if (consumed_generation.value().has_value()) {
    // A permit that was consumed when it was written must come back consumed.
    // Dropping this field would make a consumed permit indistinguishable from an
    // outstanding one, which is a difference that decides whether an identity
    // may still be taken over.
    return permit.value().consumed_at(RegistryGeneration::from_value(consumed_generation.value().value()));
  }
  return std::move(permit).value();
}

Result<Tombstone> decode_tombstone(ByteReader& reader, const RegistryLimits& limits) {
  const std::size_t offset = reader.position();
  auto retired_generation = read_u64(reader, "Tombstone.retired_generation");
  if (!retired_generation.has_value()) {
    return retired_generation.error();
  }
  auto tombstoned_generation = read_u64(reader, "Tombstone.tombstoned_generation");
  if (!tombstoned_generation.has_value()) {
    return tombstoned_generation.error();
  }
  auto permit = read_optional<RebindPermit>(reader, "Tombstone.permit", [&limits](ByteReader& source) {
    return decode_rebind_permit(source, limits);
  });
  if (!permit.has_value()) {
    return permit.error();
  }
  auto note = read_text_field(reader, limits.max_provenance_note_bytes, "Tombstone.note", true);
  if (!note.has_value()) {
    return note.error();
  }
  auto tombstone = Tombstone::create(RegistryGeneration::from_value(retired_generation.value()),
                                     RegistryGeneration::from_value(tombstoned_generation.value()),
                                     std::move(permit).value(), std::move(note).value(),
                                     limits.max_provenance_note_bytes);
  if (!tombstone.has_value()) {
    return field_error(ErrorCode::DecodeFailed, "Tombstone", offset, tombstone.error().detail());
  }
  return std::move(tombstone).value();
}

Result<IdempotencyKey> decode_idempotency_key(ByteReader& reader) {
  const std::size_t offset = reader.position();
  auto text = read_text(reader, kNoByteLimit, "IdempotencyKey");
  if (!text.has_value()) {
    return text.error();
  }
  auto key = IdempotencyKey::create(text.value());
  if (!key.has_value()) {
    return field_error(ErrorCode::DecodeFailed, "IdempotencyKey", offset,
                       "text is not a canonical idempotency key: " + key.error().detail());
  }
  return std::move(key).value();
}


// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

void encode(ByteWriter& writer, const TenantRecord& record) {
  writer.length_prefixed(record.id.value());
  writer.optional(record.display_name, [&writer](const std::string& name) { writer.length_prefixed(name); });
  encode(writer, record.state);
  writer.u64(record.revision.value());
  writer.u64(record.created_generation.value());
  writer.u64(record.updated_generation.value());
  writer.optional(record.retired_generation,
                  [&writer](const RegistryGeneration& retired) { writer.u64(retired.value()); });
  writer.optional(record.tombstone, [&writer](const Tombstone& tombstone) { encode(writer, tombstone); });
  writer.optional(record.owner, [&writer](const PrincipalId& owner) { writer.length_prefixed(owner.value()); });
  encode(writer, record.metadata);
  encode(writer, record.provenance);
  writer.digest(record.origin_digest);
}

void encode(ByteWriter& writer, const ServiceRecord& record) {
  writer.length_prefixed(record.id.value());
  writer.optional(record.display_name, [&writer](const std::string& name) { writer.length_prefixed(name); });
  encode(writer, record.state);
  writer.u64(record.revision.value());
  writer.u64(record.created_generation.value());
  writer.u64(record.updated_generation.value());
  writer.optional(record.retired_generation,
                  [&writer](const RegistryGeneration& retired) { writer.u64(retired.value()); });
  writer.optional(record.tombstone, [&writer](const Tombstone& tombstone) { encode(writer, tombstone); });
  encode(writer, record.metadata);
  encode(writer, record.provenance);
  writer.digest(record.origin_digest);
}

void encode(ByteWriter& writer, const IsolationDomainRecord& record) {
  writer.length_prefixed(record.id.value());
  writer.optional(record.display_name, [&writer](const std::string& name) { writer.length_prefixed(name); });
  encode(writer, record.isolation_class);
  encode(writer, record.state);
  writer.u64(record.revision.value());
  writer.u64(record.membership_generation.value());
  writer.u64(record.created_generation.value());
  writer.u64(record.updated_generation.value());
  writer.optional(record.retired_generation,
                  [&writer](const RegistryGeneration& retired) { writer.u64(retired.value()); });
  writer.optional(record.tombstone, [&writer](const Tombstone& tombstone) { encode(writer, tombstone); });
  encode(writer, record.metadata);
  encode(writer, record.provenance);
  writer.digest(record.origin_digest);
}

void encode(ByteWriter& writer, const OwnershipEdge& record) {
  writer.length_prefixed(record.child.value());
  writer.length_prefixed(record.parent.value());
  encode(writer, record.kind);
  encode(writer, record.state);
  writer.u64(record.revision.value());
  writer.u64(record.created_generation.value());
  writer.u64(record.updated_generation.value());
  encode(writer, record.provenance);
  writer.digest(record.origin_digest);
}

void encode(ByteWriter& writer, const ServiceBinding& record) {
  writer.length_prefixed(record.service.value());
  writer.length_prefixed(record.tenant.value());
  encode(writer, record.kind);
  encode(writer, record.state);
  writer.u64(record.revision.value());
  writer.u64(record.created_generation.value());
  writer.u64(record.updated_generation.value());
  encode(writer, record.provenance);
  writer.digest(record.origin_digest);
}

void encode(ByteWriter& writer, const IsolationMembership& record) {
  encode(writer, record.subject);
  writer.length_prefixed(record.domain.value());
  encode(writer, record.role);
  encode(writer, record.state);
  writer.u64(record.revision.value());
  writer.u64(record.created_generation.value());
  writer.u64(record.updated_generation.value());
  encode(writer, record.provenance);
  writer.digest(record.origin_digest);
}

void encode(ByteWriter& writer, const TombstoneRecord& record) {
  encode(writer, record.kind);
  writer.length_prefixed(record.identity);
  encode(writer, record.state);
  writer.u64(record.revision.value());
  writer.u64(record.retired_generation.value());
  writer.u64(record.tombstoned_generation.value());
  writer.optional(record.permit, [&writer](const RebindPermit& permit) { encode(writer, permit); });
  writer.length_prefixed(record.note);
  encode(writer, record.provenance);
  writer.digest(record.origin_digest);
}

void encode(ByteWriter& writer, const AnyRecord& record) {
  encode(writer, kind_of(record));
  std::visit([&writer](const auto& value) { encode(writer, value); }, record);
}

Result<TenantRecord> decode_tenant(ByteReader& reader, const RegistryLimits& limits) {
  auto id = read_identity<TenantId>(reader, limits.max_identity_bytes, "TenantRecord.id");
  if (!id.has_value()) {
    return id.error();
  }
  auto display_name = read_optional_text_field(reader, limits.max_display_name_bytes, "TenantRecord.display_name");
  if (!display_name.has_value()) {
    return display_name.error();
  }
  auto state =
      read_enum<LifecycleState>(reader, "TenantRecord.state", static_cast<std::uint8_t>(LifecycleState::Tombstoned));
  if (!state.has_value()) {
    return state.error();
  }
  auto revision = read_u64(reader, "TenantRecord.revision");
  if (!revision.has_value()) {
    return revision.error();
  }
  auto created_generation = read_u64(reader, "TenantRecord.created_generation");
  if (!created_generation.has_value()) {
    return created_generation.error();
  }
  auto updated_generation = read_u64(reader, "TenantRecord.updated_generation");
  if (!updated_generation.has_value()) {
    return updated_generation.error();
  }
  auto retired_generation = read_optional_u64(reader, "TenantRecord.retired_generation");
  if (!retired_generation.has_value()) {
    return retired_generation.error();
  }
  auto tombstone = read_optional<Tombstone>(reader, "TenantRecord.tombstone",
                                            [&limits](ByteReader& source) { return decode_tombstone(source, limits); });
  if (!tombstone.has_value()) {
    return tombstone.error();
  }
  auto owner = read_optional_identity<PrincipalId>(reader, limits.max_principal_bytes, "TenantRecord.owner");
  if (!owner.has_value()) {
    return owner.error();
  }
  auto metadata = decode_metadata(reader, limits);
  if (!metadata.has_value()) {
    return metadata.error();
  }
  auto provenance = decode_provenance(reader, limits);
  if (!provenance.has_value()) {
    return provenance.error();
  }
  auto origin_digest = read_digest(reader, "TenantRecord.origin_digest");
  if (!origin_digest.has_value()) {
    return origin_digest.error();
  }
  return TenantRecord{.id = std::move(id).value(),
                      .display_name = std::move(display_name).value(),
                      .state = state.value(),
                      .revision = RecordRevision::from_value(revision.value()),
                      .created_generation = RegistryGeneration::from_value(created_generation.value()),
                      .updated_generation = RegistryGeneration::from_value(updated_generation.value()),
                      .retired_generation = to_generation(std::move(retired_generation).value()),
                      .tombstone = std::move(tombstone).value(),
                      .owner = std::move(owner).value(),
                      .metadata = std::move(metadata).value(),
                      .provenance = std::move(provenance).value(),
                      .origin_digest = origin_digest.value()};
}

Result<ServiceRecord> decode_service(ByteReader& reader, const RegistryLimits& limits) {
  auto id = read_identity<ServiceId>(reader, limits.max_identity_bytes, "ServiceRecord.id");
  if (!id.has_value()) {
    return id.error();
  }
  auto display_name = read_optional_text_field(reader, limits.max_display_name_bytes, "ServiceRecord.display_name");
  if (!display_name.has_value()) {
    return display_name.error();
  }
  auto state =
      read_enum<LifecycleState>(reader, "ServiceRecord.state", static_cast<std::uint8_t>(LifecycleState::Tombstoned));
  if (!state.has_value()) {
    return state.error();
  }
  auto revision = read_u64(reader, "ServiceRecord.revision");
  if (!revision.has_value()) {
    return revision.error();
  }
  auto created_generation = read_u64(reader, "ServiceRecord.created_generation");
  if (!created_generation.has_value()) {
    return created_generation.error();
  }
  auto updated_generation = read_u64(reader, "ServiceRecord.updated_generation");
  if (!updated_generation.has_value()) {
    return updated_generation.error();
  }
  auto retired_generation = read_optional_u64(reader, "ServiceRecord.retired_generation");
  if (!retired_generation.has_value()) {
    return retired_generation.error();
  }
  auto tombstone = read_optional<Tombstone>(reader, "ServiceRecord.tombstone",
                                            [&limits](ByteReader& source) { return decode_tombstone(source, limits); });
  if (!tombstone.has_value()) {
    return tombstone.error();
  }
  auto metadata = decode_metadata(reader, limits);
  if (!metadata.has_value()) {
    return metadata.error();
  }
  auto provenance = decode_provenance(reader, limits);
  if (!provenance.has_value()) {
    return provenance.error();
  }
  auto origin_digest = read_digest(reader, "ServiceRecord.origin_digest");
  if (!origin_digest.has_value()) {
    return origin_digest.error();
  }
  return ServiceRecord{.id = std::move(id).value(),
                       .display_name = std::move(display_name).value(),
                       .state = state.value(),
                       .revision = RecordRevision::from_value(revision.value()),
                       .created_generation = RegistryGeneration::from_value(created_generation.value()),
                       .updated_generation = RegistryGeneration::from_value(updated_generation.value()),
                       .retired_generation = to_generation(std::move(retired_generation).value()),
                       .tombstone = std::move(tombstone).value(),
                       .metadata = std::move(metadata).value(),
                       .provenance = std::move(provenance).value(),
                       .origin_digest = origin_digest.value()};
}

Result<IsolationDomainRecord> decode_isolation_domain(ByteReader& reader, const RegistryLimits& limits) {
  auto id = read_identity<IsolationDomainId>(reader, limits.max_identity_bytes, "IsolationDomainRecord.id");
  if (!id.has_value()) {
    return id.error();
  }
  auto display_name =
      read_optional_text_field(reader, limits.max_display_name_bytes, "IsolationDomainRecord.display_name");
  if (!display_name.has_value()) {
    return display_name.error();
  }
  auto isolation_class = read_enum<IsolationClass>(reader, "IsolationDomainRecord.isolation_class",
                                                   static_cast<std::uint8_t>(IsolationClass::TenantPrivate));
  if (!isolation_class.has_value()) {
    return isolation_class.error();
  }
  auto state = read_enum<LifecycleState>(reader, "IsolationDomainRecord.state",
                                         static_cast<std::uint8_t>(LifecycleState::Tombstoned));
  if (!state.has_value()) {
    return state.error();
  }
  auto revision = read_u64(reader, "IsolationDomainRecord.revision");
  if (!revision.has_value()) {
    return revision.error();
  }
  auto membership_generation = read_u64(reader, "IsolationDomainRecord.membership_generation");
  if (!membership_generation.has_value()) {
    return membership_generation.error();
  }
  auto created_generation = read_u64(reader, "IsolationDomainRecord.created_generation");
  if (!created_generation.has_value()) {
    return created_generation.error();
  }
  auto updated_generation = read_u64(reader, "IsolationDomainRecord.updated_generation");
  if (!updated_generation.has_value()) {
    return updated_generation.error();
  }
  auto retired_generation = read_optional_u64(reader, "IsolationDomainRecord.retired_generation");
  if (!retired_generation.has_value()) {
    return retired_generation.error();
  }
  auto tombstone = read_optional<Tombstone>(
      reader, "IsolationDomainRecord.tombstone",
      [&limits](ByteReader& source) { return decode_tombstone(source, limits); });
  if (!tombstone.has_value()) {
    return tombstone.error();
  }
  auto metadata = decode_metadata(reader, limits);
  if (!metadata.has_value()) {
    return metadata.error();
  }
  auto provenance = decode_provenance(reader, limits);
  if (!provenance.has_value()) {
    return provenance.error();
  }
  auto origin_digest = read_digest(reader, "IsolationDomainRecord.origin_digest");
  if (!origin_digest.has_value()) {
    return origin_digest.error();
  }
  return IsolationDomainRecord{.id = std::move(id).value(),
                               .display_name = std::move(display_name).value(),
                               .isolation_class = isolation_class.value(),
                               .state = state.value(),
                               .revision = RecordRevision::from_value(revision.value()),
                               .membership_generation = DomainGeneration::from_value(membership_generation.value()),
                               .created_generation = RegistryGeneration::from_value(created_generation.value()),
                               .updated_generation = RegistryGeneration::from_value(updated_generation.value()),
                               .retired_generation = to_generation(std::move(retired_generation).value()),
                               .tombstone = std::move(tombstone).value(),
                               .metadata = std::move(metadata).value(),
                               .provenance = std::move(provenance).value(),
                               .origin_digest = origin_digest.value()};
}

Result<OwnershipEdge> decode_ownership_edge(ByteReader& reader, const RegistryLimits& limits) {
  auto child = read_identity<TenantId>(reader, limits.max_identity_bytes, "OwnershipEdge.child");
  if (!child.has_value()) {
    return child.error();
  }
  auto parent = read_identity<TenantId>(reader, limits.max_identity_bytes, "OwnershipEdge.parent");
  if (!parent.has_value()) {
    return parent.error();
  }
  auto kind = read_enum<OwnershipKind>(reader, "OwnershipEdge.kind",
                                       static_cast<std::uint8_t>(OwnershipKind::DataResidency));
  if (!kind.has_value()) {
    return kind.error();
  }
  const std::size_t state_offset = reader.position();
  auto state =
      read_enum<LifecycleState>(reader, "OwnershipEdge.state", static_cast<std::uint8_t>(LifecycleState::Tombstoned));
  if (!state.has_value()) {
    return state.error();
  }
  if (state.value() == LifecycleState::Tombstoned) {
    return field_error(ErrorCode::InvalidEnumValue, "OwnershipEdge.state", state_offset,
                       "Tombstoned is not a state an ownership edge can hold; only identities are tombstoned");
  }
  auto revision = read_u64(reader, "OwnershipEdge.revision");
  if (!revision.has_value()) {
    return revision.error();
  }
  auto created_generation = read_u64(reader, "OwnershipEdge.created_generation");
  if (!created_generation.has_value()) {
    return created_generation.error();
  }
  auto updated_generation = read_u64(reader, "OwnershipEdge.updated_generation");
  if (!updated_generation.has_value()) {
    return updated_generation.error();
  }
  auto provenance = decode_provenance(reader, limits);
  if (!provenance.has_value()) {
    return provenance.error();
  }
  auto origin_digest = read_digest(reader, "OwnershipEdge.origin_digest");
  if (!origin_digest.has_value()) {
    return origin_digest.error();
  }
  return OwnershipEdge{.child = std::move(child).value(),
                       .parent = std::move(parent).value(),
                       .kind = kind.value(),
                       .state = state.value(),
                       .revision = RecordRevision::from_value(revision.value()),
                       .created_generation = RegistryGeneration::from_value(created_generation.value()),
                       .updated_generation = RegistryGeneration::from_value(updated_generation.value()),
                       .provenance = std::move(provenance).value(),
                       .origin_digest = origin_digest.value()};
}

Result<ServiceBinding> decode_service_binding(ByteReader& reader, const RegistryLimits& limits) {
  auto service = read_identity<ServiceId>(reader, limits.max_identity_bytes, "ServiceBinding.service");
  if (!service.has_value()) {
    return service.error();
  }
  auto tenant = read_identity<TenantId>(reader, limits.max_identity_bytes, "ServiceBinding.tenant");
  if (!tenant.has_value()) {
    return tenant.error();
  }
  auto kind = read_enum<BindingKind>(reader, "ServiceBinding.kind", static_cast<std::uint8_t>(BindingKind::ConsumedBy));
  if (!kind.has_value()) {
    return kind.error();
  }
  const std::size_t state_offset = reader.position();
  auto state = read_enum<LifecycleState>(reader, "ServiceBinding.state",
                                         static_cast<std::uint8_t>(LifecycleState::Tombstoned));
  if (!state.has_value()) {
    return state.error();
  }
  if (state.value() == LifecycleState::Tombstoned) {
    return field_error(ErrorCode::InvalidEnumValue, "ServiceBinding.state", state_offset,
                       "Tombstoned is not a state a service binding can hold; only identities are tombstoned");
  }
  auto revision = read_u64(reader, "ServiceBinding.revision");
  if (!revision.has_value()) {
    return revision.error();
  }
  auto created_generation = read_u64(reader, "ServiceBinding.created_generation");
  if (!created_generation.has_value()) {
    return created_generation.error();
  }
  auto updated_generation = read_u64(reader, "ServiceBinding.updated_generation");
  if (!updated_generation.has_value()) {
    return updated_generation.error();
  }
  auto provenance = decode_provenance(reader, limits);
  if (!provenance.has_value()) {
    return provenance.error();
  }
  auto origin_digest = read_digest(reader, "ServiceBinding.origin_digest");
  if (!origin_digest.has_value()) {
    return origin_digest.error();
  }
  return ServiceBinding{.service = std::move(service).value(),
                        .tenant = std::move(tenant).value(),
                        .kind = kind.value(),
                        .state = state.value(),
                        .revision = RecordRevision::from_value(revision.value()),
                        .created_generation = RegistryGeneration::from_value(created_generation.value()),
                        .updated_generation = RegistryGeneration::from_value(updated_generation.value()),
                        .provenance = std::move(provenance).value(),
                        .origin_digest = origin_digest.value()};
}

Result<IsolationMembership> decode_isolation_membership(ByteReader& reader, const RegistryLimits& limits) {
  auto subject = decode_subject(reader, limits);
  if (!subject.has_value()) {
    return subject.error();
  }
  auto domain = read_identity<IsolationDomainId>(reader, limits.max_identity_bytes, "IsolationMembership.domain");
  if (!domain.has_value()) {
    return domain.error();
  }
  auto role = read_enum<MembershipRole>(reader, "IsolationMembership.role",
                                        static_cast<std::uint8_t>(MembershipRole::Fallback));
  if (!role.has_value()) {
    return role.error();
  }
  auto state = read_enum<MembershipState>(reader, "IsolationMembership.state",
                                          static_cast<std::uint8_t>(MembershipState::Withdrawn));
  if (!state.has_value()) {
    return state.error();
  }
  auto revision = read_u64(reader, "IsolationMembership.revision");
  if (!revision.has_value()) {
    return revision.error();
  }
  auto created_generation = read_u64(reader, "IsolationMembership.created_generation");
  if (!created_generation.has_value()) {
    return created_generation.error();
  }
  auto updated_generation = read_u64(reader, "IsolationMembership.updated_generation");
  if (!updated_generation.has_value()) {
    return updated_generation.error();
  }
  auto provenance = decode_provenance(reader, limits);
  if (!provenance.has_value()) {
    return provenance.error();
  }
  auto origin_digest = read_digest(reader, "IsolationMembership.origin_digest");
  if (!origin_digest.has_value()) {
    return origin_digest.error();
  }
  return IsolationMembership{.subject = std::move(subject).value(),
                             .domain = std::move(domain).value(),
                             .role = role.value(),
                             .state = state.value(),
                             .revision = RecordRevision::from_value(revision.value()),
                             .created_generation = RegistryGeneration::from_value(created_generation.value()),
                             .updated_generation = RegistryGeneration::from_value(updated_generation.value()),
                             .provenance = std::move(provenance).value(),
                             .origin_digest = origin_digest.value()};
}

Result<TombstoneRecord> decode_tombstone_record(ByteReader& reader, const RegistryLimits& limits) {
  auto kind = read_enum<SubjectKind>(reader, "TombstoneRecord.kind",
                                     static_cast<std::uint8_t>(SubjectKind::IsolationDomain));
  if (!kind.has_value()) {
    return kind.error();
  }
  auto identity = read_kind_identity(reader, kind.value(), limits.max_identity_bytes, "TombstoneRecord.identity");
  if (!identity.has_value()) {
    return identity.error();
  }
  const std::size_t state_offset = reader.position();
  auto state = read_enum<LifecycleState>(reader, "TombstoneRecord.state",
                                         static_cast<std::uint8_t>(LifecycleState::Tombstoned));
  if (!state.has_value()) {
    return state.error();
  }
  if (state.value() != LifecycleState::Tombstoned) {
    return field_error(ErrorCode::InvalidEnumValue, "TombstoneRecord.state", state_offset,
                       "a tombstone record holds state Tombstoned (6) and nothing else, not value " +
                           std::to_string(static_cast<std::uint8_t>(state.value())));
  }
  auto revision = read_u64(reader, "TombstoneRecord.revision");
  if (!revision.has_value()) {
    return revision.error();
  }
  auto retired_generation = read_u64(reader, "TombstoneRecord.retired_generation");
  if (!retired_generation.has_value()) {
    return retired_generation.error();
  }
  auto tombstoned_generation = read_u64(reader, "TombstoneRecord.tombstoned_generation");
  if (!tombstoned_generation.has_value()) {
    return tombstoned_generation.error();
  }
  auto permit = read_optional<RebindPermit>(reader, "TombstoneRecord.permit", [&limits](ByteReader& source) {
    return decode_rebind_permit(source, limits);
  });
  if (!permit.has_value()) {
    return permit.error();
  }
  auto note = read_text_field(reader, limits.max_provenance_note_bytes, "TombstoneRecord.note", true);
  if (!note.has_value()) {
    return note.error();
  }
  auto provenance = decode_provenance(reader, limits);
  if (!provenance.has_value()) {
    return provenance.error();
  }
  auto origin_digest = read_digest(reader, "TombstoneRecord.origin_digest");
  if (!origin_digest.has_value()) {
    return origin_digest.error();
  }
  return TombstoneRecord{.kind = kind.value(),
                         .identity = std::move(identity).value(),
                         .state = state.value(),
                         .revision = RecordRevision::from_value(revision.value()),
                         .retired_generation = RegistryGeneration::from_value(retired_generation.value()),
                         .tombstoned_generation = RegistryGeneration::from_value(tombstoned_generation.value()),
                         .permit = std::move(permit).value(),
                         .note = std::move(note).value(),
                         .provenance = std::move(provenance).value(),
                         .origin_digest = origin_digest.value()};
}

Result<AnyRecord> decode_any(ByteReader& reader, const RegistryLimits& limits) {
  const std::size_t offset = reader.position();
  auto kind = read_enum<RecordKind>(reader, "AnyRecord.kind", static_cast<std::uint8_t>(RecordKind::Tombstone));
  if (!kind.has_value()) {
    return kind.error();
  }
  switch (kind.value()) {
    case RecordKind::Tenant: {
      auto record = decode_tenant(reader, limits);
      if (!record.has_value()) {
        return record.error();
      }
      return AnyRecord{std::move(record).value()};
    }
    case RecordKind::Service: {
      auto record = decode_service(reader, limits);
      if (!record.has_value()) {
        return record.error();
      }
      return AnyRecord{std::move(record).value()};
    }
    case RecordKind::IsolationDomain: {
      auto record = decode_isolation_domain(reader, limits);
      if (!record.has_value()) {
        return record.error();
      }
      return AnyRecord{std::move(record).value()};
    }
    case RecordKind::OwnershipEdge: {
      auto record = decode_ownership_edge(reader, limits);
      if (!record.has_value()) {
        return record.error();
      }
      return AnyRecord{std::move(record).value()};
    }
    case RecordKind::ServiceBinding: {
      auto record = decode_service_binding(reader, limits);
      if (!record.has_value()) {
        return record.error();
      }
      return AnyRecord{std::move(record).value()};
    }
    case RecordKind::IsolationMembership: {
      auto record = decode_isolation_membership(reader, limits);
      if (!record.has_value()) {
        return record.error();
      }
      return AnyRecord{std::move(record).value()};
    }
    case RecordKind::Tombstone: {
      auto record = decode_tombstone_record(reader, limits);
      if (!record.has_value()) {
        return record.error();
      }
      return AnyRecord{std::move(record).value()};
    }
    default:
      return field_error(ErrorCode::InvalidEnumValue, "AnyRecord.kind", offset,
                         "record kind is not one this build defines");
  }
}

// ---------------------------------------------------------------------------
// Record digests
// ---------------------------------------------------------------------------

ContentDigest record_digest(const TenantRecord& record) {
  ByteWriter body;
  encode(body, record);
  return record_digest_of(RecordKind::Tenant, body);
}

ContentDigest record_digest(const ServiceRecord& record) {
  ByteWriter body;
  encode(body, record);
  return record_digest_of(RecordKind::Service, body);
}

ContentDigest record_digest(const IsolationDomainRecord& record) {
  ByteWriter body;
  encode(body, record);
  return record_digest_of(RecordKind::IsolationDomain, body);
}

ContentDigest record_digest(const OwnershipEdge& record) {
  ByteWriter body;
  encode(body, record);
  return record_digest_of(RecordKind::OwnershipEdge, body);
}

ContentDigest record_digest(const ServiceBinding& record) {
  ByteWriter body;
  encode(body, record);
  return record_digest_of(RecordKind::ServiceBinding, body);
}

ContentDigest record_digest(const IsolationMembership& record) {
  ByteWriter body;
  encode(body, record);
  return record_digest_of(RecordKind::IsolationMembership, body);
}

ContentDigest record_digest(const TombstoneRecord& record) {
  ByteWriter body;
  encode(body, record);
  return record_digest_of(RecordKind::Tombstone, body);
}

ContentDigest record_digest(const AnyRecord& record) {
  return std::visit([](const auto& value) { return record_digest(value); }, record);
}

std::string canonical_bytes(const AnyRecord& record) {
  ByteWriter writer;
  encode(writer, record);
  return text_of(writer.view());
}


// ---------------------------------------------------------------------------
// Request digests
// ---------------------------------------------------------------------------

RequestDigest request_digest(const CreateTenantRequest& request) {
  ByteWriter body;
  write_context(body, request.context);
  body.length_prefixed(request.id.value());
  body.optional(request.display_name, [&body](const std::string& name) { body.length_prefixed(name); });
  body.optional(request.owner, [&body](const PrincipalId& owner) { body.length_prefixed(owner.value()); });
  encode(body, request.metadata);
  return request_digest_of(OperationKind::CreateTenant, body);
}

RequestDigest request_digest(const CreateServiceRequest& request) {
  ByteWriter body;
  write_context(body, request.context);
  body.length_prefixed(request.id.value());
  body.optional(request.display_name, [&body](const std::string& name) { body.length_prefixed(name); });
  encode(body, request.metadata);
  return request_digest_of(OperationKind::CreateService, body);
}

RequestDigest request_digest(const CreateIsolationDomainRequest& request) {
  ByteWriter body;
  write_context(body, request.context);
  body.length_prefixed(request.id.value());
  encode(body, request.isolation_class);
  body.optional(request.display_name, [&body](const std::string& name) { body.length_prefixed(name); });
  encode(body, request.metadata);
  return request_digest_of(OperationKind::CreateIsolationDomain, body);
}

RequestDigest request_digest(const TransitionSubjectRequest& request) {
  ByteWriter body;
  write_context(body, request.context);
  encode(body, request.subject);
  body.u64(request.expected_revision.value());
  encode(body, request.target);
  return request_digest_of(OperationKind::TransitionSubject, body);
}

RequestDigest request_digest(const SetOwnerRequest& request) {
  ByteWriter body;
  write_context(body, request.context);
  body.length_prefixed(request.tenant.value());
  body.u64(request.expected_revision.value());
  body.optional(request.owner, [&body](const PrincipalId& owner) { body.length_prefixed(owner.value()); });
  return request_digest_of(OperationKind::SetOwner, body);
}

RequestDigest request_digest(const SetMetadataRequest& request) {
  ByteWriter body;
  write_context(body, request.context);
  encode(body, request.subject);
  body.u64(request.expected_revision.value());
  body.u32(static_cast<std::uint32_t>(request.remove_keys.size()));
  for (const MetadataKey& key : request.remove_keys) {
    body.length_prefixed(key.value());
  }
  body.u32(static_cast<std::uint32_t>(request.put_entries.size()));
  for (const MetadataEntry& entry : request.put_entries) {
    body.length_prefixed(entry.key.value());
    write_metadata_value(body, entry.value);
  }
  return request_digest_of(OperationKind::SetMetadata, body);
}

RequestDigest request_digest(const PutOwnershipRequest& request) {
  ByteWriter body;
  write_context(body, request.context);
  body.length_prefixed(request.child.value());
  body.length_prefixed(request.parent.value());
  encode(body, request.kind);
  encode(body, request.initial_state);
  body.optional(request.expected_revision, [&body](const RecordRevision& revision) { body.u64(revision.value()); });
  return request_digest_of(OperationKind::PutOwnership, body);
}

RequestDigest request_digest(const RemoveOwnershipRequest& request) {
  ByteWriter body;
  write_context(body, request.context);
  body.length_prefixed(request.child.value());
  body.length_prefixed(request.parent.value());
  body.u64(request.expected_revision.value());
  return request_digest_of(OperationKind::RemoveOwnership, body);
}

RequestDigest request_digest(const TransitionOwnershipRequest& request) {
  ByteWriter body;
  write_context(body, request.context);
  body.length_prefixed(request.child.value());
  body.length_prefixed(request.parent.value());
  body.u64(request.expected_revision.value());
  encode(body, request.target);
  return request_digest_of(OperationKind::TransitionOwnership, body);
}

RequestDigest request_digest(const PutServiceBindingRequest& request) {
  ByteWriter body;
  write_context(body, request.context);
  body.length_prefixed(request.service.value());
  body.length_prefixed(request.tenant.value());
  encode(body, request.kind);
  encode(body, request.initial_state);
  body.optional(request.expected_revision, [&body](const RecordRevision& revision) { body.u64(revision.value()); });
  return request_digest_of(OperationKind::PutServiceBinding, body);
}

RequestDigest request_digest(const RemoveServiceBindingRequest& request) {
  ByteWriter body;
  write_context(body, request.context);
  body.length_prefixed(request.service.value());
  body.length_prefixed(request.tenant.value());
  encode(body, request.kind);
  body.u64(request.expected_revision.value());
  return request_digest_of(OperationKind::RemoveServiceBinding, body);
}

RequestDigest request_digest(const TransitionServiceBindingRequest& request) {
  ByteWriter body;
  write_context(body, request.context);
  body.length_prefixed(request.service.value());
  body.length_prefixed(request.tenant.value());
  encode(body, request.kind);
  body.u64(request.expected_revision.value());
  encode(body, request.target);
  return request_digest_of(OperationKind::TransitionServiceBinding, body);
}

RequestDigest request_digest(const PutIsolationMembershipRequest& request) {
  ByteWriter body;
  write_context(body, request.context);
  encode(body, request.subject);
  body.length_prefixed(request.domain.value());
  encode(body, request.role);
  encode(body, request.initial_state);
  body.u64(request.expected_domain_generation.value());
  body.optional(request.expected_revision, [&body](const RecordRevision& revision) { body.u64(revision.value()); });
  return request_digest_of(OperationKind::PutIsolationMembership, body);
}

RequestDigest request_digest(const TransitionIsolationMembershipRequest& request) {
  ByteWriter body;
  write_context(body, request.context);
  encode(body, request.subject);
  body.length_prefixed(request.domain.value());
  body.u64(request.expected_revision.value());
  body.u64(request.expected_domain_generation.value());
  encode(body, request.target);
  return request_digest_of(OperationKind::TransitionIsolationMembership, body);
}

RequestDigest request_digest(const RemoveIsolationMembershipRequest& request) {
  ByteWriter body;
  write_context(body, request.context);
  encode(body, request.subject);
  body.length_prefixed(request.domain.value());
  body.u64(request.expected_revision.value());
  body.u64(request.expected_domain_generation.value());
  return request_digest_of(OperationKind::RemoveIsolationMembership, body);
}

RequestDigest request_digest(const TombstoneRequest& request) {
  ByteWriter body;
  write_context(body, request.context);
  encode(body, request.subject);
  body.u64(request.expected_revision.value());
  body.u8(static_cast<std::uint8_t>(request.acknowledgement.is_acknowledged() ? 1 : 0));
  body.optional(request.rebind, [&body](const RebindSuccessor& successor) {
    encode(body, successor.kind);
    body.length_prefixed(successor.text);
  });
  body.length_prefixed(request.note);
  return request_digest_of(OperationKind::Tombstone, body);
}

ContentDigest mutation_context_digest(const MutationContext& context) {
  ByteWriter body;
  write_context(body, context);
  Sha256 hasher;
  hasher.update(kRequestDigestDomain);
  hasher.update(kSeparator);
  hasher.update("mutation-context");
  hasher.update(kSeparator);
  hasher.update(body.view());
  return hasher.finish();
}

// ---------------------------------------------------------------------------
// Durable payloads
// ---------------------------------------------------------------------------

void encode(ByteWriter& writer, const IdempotencyLedgerEntry& entry) {
  writer.length_prefixed(entry.key.value());
  writer.digest(entry.request_digest);
  writer.u64(entry.sequence.value());
  writer.u64(entry.generation.value());
  encode(writer, entry.operation);
  writer.length_prefixed(entry.primary_key);
  writer.u64(entry.primary_revision.value());
  writer.length_prefixed(std::span<const std::byte>{entry.outcome_payload.data(), entry.outcome_payload.size()});
}

Result<IdempotencyLedgerEntry> decode_ledger_entry(ByteReader& reader, const RegistryLimits& limits) {
  auto key = decode_idempotency_key(reader);
  if (!key.has_value()) {
    return key.error();
  }
  auto request_digest = read_digest(reader, "IdempotencyLedgerEntry.request_digest");
  if (!request_digest.has_value()) {
    return request_digest.error();
  }
  auto sequence = read_u64(reader, "IdempotencyLedgerEntry.sequence");
  if (!sequence.has_value()) {
    return sequence.error();
  }
  auto generation = read_u64(reader, "IdempotencyLedgerEntry.generation");
  if (!generation.has_value()) {
    return generation.error();
  }
  auto operation = read_operation_kind(reader, "IdempotencyLedgerEntry.operation");
  if (!operation.has_value()) {
    return operation.error();
  }
  auto primary_key = read_text_field(reader, kMaxCanonicalKeyBytes, "IdempotencyLedgerEntry.primary_key");
  if (!primary_key.has_value()) {
    return primary_key.error();
  }
  auto primary_revision = read_u64(reader, "IdempotencyLedgerEntry.primary_revision");
  if (!primary_revision.has_value()) {
    return primary_revision.error();
  }
  auto outcome_payload =
      read_payload(reader, limits.max_idempotency_outcome_bytes, "IdempotencyLedgerEntry.outcome_payload");
  if (!outcome_payload.has_value()) {
    return outcome_payload.error();
  }
  return IdempotencyLedgerEntry{.key = std::move(key).value(),
                                .request_digest = request_digest.value(),
                                .sequence = JournalSequence::from_value(sequence.value()),
                                .generation = RegistryGeneration::from_value(generation.value()),
                                .operation = operation.value(),
                                .primary_key = std::move(primary_key).value(),
                                .primary_revision = RecordRevision::from_value(primary_revision.value()),
                                .outcome_payload = std::move(outcome_payload).value()};
}

void encode(ByteWriter& writer, const CommitRecord& record) {
  encode(writer, record.operation);
  writer.u64(record.generation.value());
  writer.u64(record.sequence.value());
  writer.u64(record.control_epoch.value());
  writer.u64(record.incarnation.value());
  writer.i64(record.committed_at.unix_milliseconds);
  writer.digest(record.request_digest);
  writer.optional(record.idempotency_key, [&writer](const IdempotencyKey& key) { encode(writer, key); });
  writer.length_prefixed(record.primary_key);
  writer.u64(record.primary_revision.value());
  writer.length_prefixed(std::span<const std::byte>{record.outcome_payload.data(), record.outcome_payload.size()});
  writer.u32(static_cast<std::uint32_t>(record.upserts.size()));
  for (const AnyRecord& upsert : record.upserts) {
    encode(writer, upsert);
  }
  writer.u32(static_cast<std::uint32_t>(record.deletes.size()));
  for (const std::string& key : record.deletes) {
    writer.length_prefixed(key);
  }
  write_domain_generations(writer, record.domain_generations);
}

Result<CommitRecord> decode_commit(ByteReader& reader, const RegistryLimits& limits) {
  const std::size_t offset = reader.position();
  if (reader.remaining() > limits.max_commit_payload_bytes) {
    return field_error(ErrorCode::PayloadTooLarge, "CommitRecord", offset,
                       "payload is " + std::to_string(reader.remaining()) + " bytes, the limit is " +
                           std::to_string(limits.max_commit_payload_bytes));
  }
  auto operation = read_operation_kind(reader, "CommitRecord.operation");
  if (!operation.has_value()) {
    return operation.error();
  }
  auto generation = read_u64(reader, "CommitRecord.generation");
  if (!generation.has_value()) {
    return generation.error();
  }
  auto sequence = read_u64(reader, "CommitRecord.sequence");
  if (!sequence.has_value()) {
    return sequence.error();
  }
  auto control_epoch = read_u64(reader, "CommitRecord.control_epoch");
  if (!control_epoch.has_value()) {
    return control_epoch.error();
  }
  auto incarnation = read_u64(reader, "CommitRecord.incarnation");
  if (!incarnation.has_value()) {
    return incarnation.error();
  }
  auto committed_at = read_i64(reader, "CommitRecord.committed_at");
  if (!committed_at.has_value()) {
    return committed_at.error();
  }
  auto request_digest = read_digest(reader, "CommitRecord.request_digest");
  if (!request_digest.has_value()) {
    return request_digest.error();
  }
  auto idempotency_key = read_optional<IdempotencyKey>(
      reader, "CommitRecord.idempotency_key", [](ByteReader& source) { return decode_idempotency_key(source); });
  if (!idempotency_key.has_value()) {
    return idempotency_key.error();
  }
  auto primary_key = read_text_field(reader, kMaxCanonicalKeyBytes, "CommitRecord.primary_key");
  if (!primary_key.has_value()) {
    return primary_key.error();
  }
  auto primary_revision = read_u64(reader, "CommitRecord.primary_revision");
  if (!primary_revision.has_value()) {
    return primary_revision.error();
  }
  auto outcome_payload = read_payload(reader, limits.max_idempotency_outcome_bytes, "CommitRecord.outcome_payload");
  if (!outcome_payload.has_value()) {
    return outcome_payload.error();
  }
  auto upserts = read_upserts(reader, limits);
  if (!upserts.has_value()) {
    return upserts.error();
  }
  auto deletes = read_deletes(reader, limits);
  if (!deletes.has_value()) {
    return deletes.error();
  }
  auto domain_generations =
      read_domain_generations(reader, limits, "CommitRecord.domain_generations", limits.max_isolation_domains);
  if (!domain_generations.has_value()) {
    return domain_generations.error();
  }
  return CommitRecord{.operation = operation.value(),
                      .generation = RegistryGeneration::from_value(generation.value()),
                      .sequence = JournalSequence::from_value(sequence.value()),
                      .control_epoch = ControlEpoch::from_value(control_epoch.value()),
                      .incarnation = Incarnation::from_value(incarnation.value()),
                      .committed_at = Timestamp{committed_at.value()},
                      .request_digest = request_digest.value(),
                      .idempotency_key = std::move(idempotency_key).value(),
                      .primary_key = std::move(primary_key).value(),
                      .primary_revision = RecordRevision::from_value(primary_revision.value()),
                      .outcome_payload = std::move(outcome_payload).value(),
                      .upserts = std::move(upserts).value(),
                      .deletes = std::move(deletes).value(),
                      .domain_generations = std::move(domain_generations).value()};
}

void encode(ByteWriter& writer, const BaselinePayload& payload) {
  writer.u64(payload.generation.value());
  write_record_list(writer, payload.tenants);
  write_record_list(writer, payload.services);
  write_record_list(writer, payload.isolation_domains);
  write_record_list(writer, payload.ownership_edges);
  write_record_list(writer, payload.service_bindings);
  write_record_list(writer, payload.isolation_memberships);
  write_record_list(writer, payload.tombstones);
  write_domain_generations(writer, payload.domain_generations);
  write_record_list(writer, payload.ledger);
}

Result<BaselinePayload> decode_baseline(ByteReader& reader, const RegistryLimits& limits) {
  const std::size_t offset = reader.position();
  if (reader.remaining() > limits.max_baseline_payload_bytes) {
    return field_error(ErrorCode::PayloadTooLarge, "BaselinePayload", offset,
                       "payload is " + std::to_string(reader.remaining()) + " bytes, the limit is " +
                           std::to_string(limits.max_baseline_payload_bytes));
  }
  auto generation = read_u64(reader, "BaselinePayload.generation");
  if (!generation.has_value()) {
    return generation.error();
  }
  auto tenants = read_list<TenantRecord>(reader, "BaselinePayload.tenants", record_limit(RecordKind::Tenant, limits),
                                         [&limits](ByteReader& source) { return decode_tenant(source, limits); });
  if (!tenants.has_value()) {
    return tenants.error();
  }
  auto services =
      read_list<ServiceRecord>(reader, "BaselinePayload.services", record_limit(RecordKind::Service, limits),
                               [&limits](ByteReader& source) { return decode_service(source, limits); });
  if (!services.has_value()) {
    return services.error();
  }
  auto isolation_domains = read_list<IsolationDomainRecord>(
      reader, "BaselinePayload.isolation_domains", record_limit(RecordKind::IsolationDomain, limits),
      [&limits](ByteReader& source) { return decode_isolation_domain(source, limits); });
  if (!isolation_domains.has_value()) {
    return isolation_domains.error();
  }
  auto ownership_edges = read_list<OwnershipEdge>(
      reader, "BaselinePayload.ownership_edges", record_limit(RecordKind::OwnershipEdge, limits),
      [&limits](ByteReader& source) { return decode_ownership_edge(source, limits); });
  if (!ownership_edges.has_value()) {
    return ownership_edges.error();
  }
  auto service_bindings = read_list<ServiceBinding>(
      reader, "BaselinePayload.service_bindings", record_limit(RecordKind::ServiceBinding, limits),
      [&limits](ByteReader& source) { return decode_service_binding(source, limits); });
  if (!service_bindings.has_value()) {
    return service_bindings.error();
  }
  auto isolation_memberships = read_list<IsolationMembership>(
      reader, "BaselinePayload.isolation_memberships", record_limit(RecordKind::IsolationMembership, limits),
      [&limits](ByteReader& source) { return decode_isolation_membership(source, limits); });
  if (!isolation_memberships.has_value()) {
    return isolation_memberships.error();
  }
  auto tombstones =
      read_list<TombstoneRecord>(reader, "BaselinePayload.tombstones", record_limit(RecordKind::Tombstone, limits),
                                 [&limits](ByteReader& source) { return decode_tombstone_record(source, limits); });
  if (!tombstones.has_value()) {
    return tombstones.error();
  }
  auto domain_generations = read_domain_generations(reader, limits, "BaselinePayload.domain_generations",
                                                    record_limit(RecordKind::IsolationDomain, limits));
  if (!domain_generations.has_value()) {
    return domain_generations.error();
  }
  auto ledger = read_list<IdempotencyLedgerEntry>(
      reader, "BaselinePayload.ledger", limits.max_idempotency_entries,
      [&limits](ByteReader& source) { return decode_ledger_entry(source, limits); });
  if (!ledger.has_value()) {
    return ledger.error();
  }
  return BaselinePayload{.generation = RegistryGeneration::from_value(generation.value()),
                         .tenants = std::move(tenants).value(),
                         .services = std::move(services).value(),
                         .isolation_domains = std::move(isolation_domains).value(),
                         .ownership_edges = std::move(ownership_edges).value(),
                         .service_bindings = std::move(service_bindings).value(),
                         .isolation_memberships = std::move(isolation_memberships).value(),
                         .tombstones = std::move(tombstones).value(),
                         .domain_generations = std::move(domain_generations).value(),
                         .ledger = std::move(ledger).value()};
}

}  // namespace detail
}  // namespace tenant_registry
