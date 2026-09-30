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

#include "tenant_registry/ids.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

#include "sha256.hpp"
#include "tenant_registry/digest.hpp"
#include "tenant_registry/errors.hpp"
#include "utf8.hpp"

namespace tenant_registry {

namespace {

constexpr bool is_ascii_alpha(char character) noexcept {
  return (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z');
}

constexpr bool is_ascii_digit(char character) noexcept { return character >= '0' && character <= '9'; }

constexpr bool is_ascii_alphanumeric(char character) noexcept {
  return is_ascii_alpha(character) || is_ascii_digit(character);
}

constexpr bool is_separator(char character) noexcept {
  return character == '.' || character == '_' || character == ':' || character == '-';
}

/// The complete character set of a canonical identity token.
constexpr bool is_identity_character(char character) noexcept {
  return is_ascii_alphanumeric(character) || is_separator(character);
}

std::string hex_of_byte(char character) {
  constexpr char kHexDigits[] = "0123456789abcdef";
  const std::uint8_t byte = static_cast<std::uint8_t>(character);
  std::string out;
  out += kHexDigits[byte >> 4];
  out += kHexDigits[byte & 0x0Fu];
  return out;
}

std::string_view kind_name(const IdentityRules& rules) noexcept {
  return rules.kind_tag != nullptr ? std::string_view{rules.kind_tag} : std::string_view{"identity"};
}

/// Advances one counter by exactly one, or refuses. It is the single place that
/// knows a counter is saturated, so no overload can wrap.
template <class Counter>
Result<Counter> advance_counter(Counter current) noexcept {
  constexpr std::uint64_t kMaximum = std::numeric_limits<std::uint64_t>::max();
  if (current.value() == kMaximum) {
    return Error{ErrorCode::CounterSaturated,
                 std::string{current.kind_token()} + " counter is saturated at " + std::to_string(kMaximum)};
  }
  return Counter::from_value(current.value() + 1);
}

}  // namespace

Result<std::string> validate_identity(std::string_view value, const IdentityRules& rules) {
  const std::string_view kind = kind_name(rules);
  if (value.empty()) {
    return Error{ErrorCode::InvalidIdentity, std::string{kind} + " identity must not be empty"};
  }
  if (value.size() > rules.max_length) {
    return Error{ErrorCode::InvalidIdentity, std::string{kind} + " identity is " + std::to_string(value.size()) +
                                                 " bytes and must be at most " +
                                                 std::to_string(rules.max_length) + " bytes"};
  }
  if (!detail::utf8_valid(value)) {
    return Error{ErrorCode::InvalidIdentity, std::string{kind} + " identity is not well formed UTF-8"};
  }
  for (std::size_t index = 0; index < value.size(); ++index) {
    if (!is_identity_character(value[index])) {
      return Error{ErrorCode::InvalidIdentity, std::string{kind} + " identity has a byte outside [A-Za-z0-9._:-] " +
                                                   "(0x" + hex_of_byte(value[index]) + ") at position " +
                                                   std::to_string(index)};
    }
  }
  if (!is_ascii_alphanumeric(value.front())) {
    return Error{ErrorCode::InvalidIdentity,
                 std::string{kind} + " identity must start with an alphanumeric character"};
  }
  if (is_separator(value.back())) {
    return Error{ErrorCode::InvalidIdentity,
                 std::string{kind} + " identity must not end with a separator character"};
  }
  return std::string{value};
}

Result<std::string> validate_text_field(std::string_view value, std::size_t max_bytes, const char* what) {
  const std::string_view field = what != nullptr ? std::string_view{what} : std::string_view{"text field"};
  // Empty text is legal only where the header says it is, which is the note
  // fields; those callers handle the empty case themselves. Everywhere else an
  // empty string is a missing value wearing a value's clothes, so it is refused
  // rather than stored as if a value had been declared.
  if (value.empty()) {
    return Error{ErrorCode::InvalidTextForm, std::string{field} + " must not be empty"};
  }
  if (!detail::utf8_valid(value)) {
    return Error{ErrorCode::InvalidUtf8, std::string{field} + " is not well formed UTF-8"};
  }
  if (!detail::has_no_control_bytes(value)) {
    return Error{ErrorCode::InvalidTextForm, std::string{field} + " contains a control byte"};
  }
  if (value.size() > max_bytes) {
    return Error{ErrorCode::InvalidTextForm, std::string{field} + " is " + std::to_string(value.size()) +
                                                 " bytes and must be at most " + std::to_string(max_bytes) +
                                                 " bytes"};
  }
  return std::string{value};
}

bool is_valid_utf8(std::string_view text) noexcept { return detail::utf8_valid(text); }

// ---------------------------------------------------------------------------
// Strong identities
// ---------------------------------------------------------------------------

Result<TenantId> TenantId::create(std::string_view value) {
  Result<std::string> validated = validate_identity(value, rules());
  if (!validated) {
    return validated.error();
  }
  return TenantId{std::move(validated).value()};
}

const IdentityRules& TenantId::rules() noexcept {
  static const IdentityRules kRules{"tenant", 128};
  return kRules;
}

ContentDigest TenantId::digest() const noexcept {
  detail::Sha256 hasher;
  hasher.update(kind_token());
  hasher.update(std::string_view{"\0", 1});
  hasher.update(value_);
  return hasher.finish();
}

Result<ServiceId> ServiceId::create(std::string_view value) {
  Result<std::string> validated = validate_identity(value, rules());
  if (!validated) {
    return validated.error();
  }
  return ServiceId{std::move(validated).value()};
}

const IdentityRules& ServiceId::rules() noexcept {
  static const IdentityRules kRules{"service", 128};
  return kRules;
}

ContentDigest ServiceId::digest() const noexcept {
  detail::Sha256 hasher;
  hasher.update(kind_token());
  hasher.update(std::string_view{"\0", 1});
  hasher.update(value_);
  return hasher.finish();
}

Result<IsolationDomainId> IsolationDomainId::create(std::string_view value) {
  Result<std::string> validated = validate_identity(value, rules());
  if (!validated) {
    return validated.error();
  }
  return IsolationDomainId{std::move(validated).value()};
}

const IdentityRules& IsolationDomainId::rules() noexcept {
  static const IdentityRules kRules{"isolation_domain", 128};
  return kRules;
}

ContentDigest IsolationDomainId::digest() const noexcept {
  detail::Sha256 hasher;
  hasher.update(kind_token());
  hasher.update(std::string_view{"\0", 1});
  hasher.update(value_);
  return hasher.finish();
}

Result<PrincipalId> PrincipalId::create(std::string_view value) {
  Result<std::string> validated = validate_identity(value, rules());
  if (!validated) {
    return validated.error();
  }
  return PrincipalId{std::move(validated).value()};
}

const IdentityRules& PrincipalId::rules() noexcept {
  static const IdentityRules kRules{"principal", 128};
  return kRules;
}

ContentDigest PrincipalId::digest() const noexcept {
  detail::Sha256 hasher;
  hasher.update(kind_token());
  hasher.update(std::string_view{"\0", 1});
  hasher.update(value_);
  return hasher.finish();
}

Result<SourceId> SourceId::create(std::string_view value) {
  Result<std::string> validated = validate_identity(value, rules());
  if (!validated) {
    return validated.error();
  }
  return SourceId{std::move(validated).value()};
}

const IdentityRules& SourceId::rules() noexcept {
  static const IdentityRules kRules{"source", 128};
  return kRules;
}

ContentDigest SourceId::digest() const noexcept {
  detail::Sha256 hasher;
  hasher.update(kind_token());
  hasher.update(std::string_view{"\0", 1});
  hasher.update(value_);
  return hasher.finish();
}

Result<MetadataKey> MetadataKey::create(std::string_view value) {
  Result<std::string> validated = validate_identity(value, rules());
  if (!validated) {
    return validated.error();
  }
  return MetadataKey{std::move(validated).value()};
}

const IdentityRules& MetadataKey::rules() noexcept {
  static const IdentityRules kRules{"metadata_key", 96};
  return kRules;
}

ContentDigest MetadataKey::digest() const noexcept {
  detail::Sha256 hasher;
  hasher.update(kind_token());
  hasher.update(std::string_view{"\0", 1});
  hasher.update(value_);
  return hasher.finish();
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

Result<RegistryGeneration> advance(RegistryGeneration current) noexcept { return advance_counter(current); }
Result<RecordRevision> advance(RecordRevision current) noexcept { return advance_counter(current); }
Result<DomainGeneration> advance(DomainGeneration current) noexcept { return advance_counter(current); }
Result<ControlEpoch> advance(ControlEpoch current) noexcept { return advance_counter(current); }
Result<JournalSequence> advance(JournalSequence current) noexcept { return advance_counter(current); }

// ---------------------------------------------------------------------------
// Request identity
// ---------------------------------------------------------------------------

Result<IdempotencyKey> IdempotencyKey::create(std::string_view value) {
  constexpr std::size_t kMinimumBytes = 8;
  constexpr std::size_t kMaximumBytes = 64;
  if (value.size() < kMinimumBytes || value.size() > kMaximumBytes) {
    return Error{ErrorCode::IdempotencyKeyMalformed,
                 "idempotency key is " + std::to_string(value.size()) +
                     " bytes and must be between " + std::to_string(kMinimumBytes) + " and " +
                     std::to_string(kMaximumBytes) + " bytes"};
  }
  for (std::size_t index = 0; index < value.size(); ++index) {
    if (!is_identity_character(value[index])) {
      return Error{ErrorCode::IdempotencyKeyMalformed,
                   "idempotency key has a byte outside [A-Za-z0-9._:-] (0x" + hex_of_byte(value[index]) +
                       ") at position " + std::to_string(index)};
    }
  }
  if (!is_ascii_alphanumeric(value.front())) {
    return Error{ErrorCode::IdempotencyKeyMalformed,
                 "idempotency key must start with an alphanumeric character"};
  }
  if (is_separator(value.back())) {
    return Error{ErrorCode::IdempotencyKeyMalformed,
                 "idempotency key must not end with a separator character"};
  }
  return IdempotencyKey{std::string{value}};
}

// ---------------------------------------------------------------------------
// Subject kinds
// ---------------------------------------------------------------------------

std::string_view to_token(SubjectKind kind) noexcept {
  switch (kind) {
    case SubjectKind::Unspecified:
      return "unspecified";
    case SubjectKind::Tenant:
      return "tenant";
    case SubjectKind::Service:
      return "service";
    case SubjectKind::IsolationDomain:
      return "isolation_domain";
  }
  // A value outside the enumeration has no token and never borrows one.
  return std::string_view{};
}

bool parse_subject_kind(std::string_view token, SubjectKind& out) noexcept {
  if (token == "tenant") {
    out = SubjectKind::Tenant;
    return true;
  }
  if (token == "service") {
    out = SubjectKind::Service;
    return true;
  }
  if (token == "isolation_domain") {
    out = SubjectKind::IsolationDomain;
    return true;
  }
  if (token == "unspecified") {
    out = SubjectKind::Unspecified;
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Tagged tenancy subjects
// ---------------------------------------------------------------------------

TenancySubject TenancySubject::of_tenant(TenantId id) noexcept {
  return TenancySubject{std::variant<TenantId, ServiceId, IsolationDomainId>{std::move(id)}};
}

TenancySubject TenancySubject::of_service(ServiceId id) noexcept {
  return TenancySubject{std::variant<TenantId, ServiceId, IsolationDomainId>{std::move(id)}};
}

TenancySubject TenancySubject::of_isolation_domain(IsolationDomainId id) noexcept {
  return TenancySubject{std::variant<TenantId, ServiceId, IsolationDomainId>{std::move(id)}};
}

SubjectKind TenancySubject::kind() const noexcept {
  // The alternative in use *is* the kind; there is no second tag that could
  // disagree with it. A variant that holds no alternative is not a subject of
  // any kind, and is reported as Unspecified rather than as one of the three.
  switch (value_.index()) {
    case 0:
      return SubjectKind::Tenant;
    case 1:
      return SubjectKind::Service;
    case 2:
      return SubjectKind::IsolationDomain;
    default:
      return SubjectKind::Unspecified;
  }
}

const TenantId* TenancySubject::tenant_if() const noexcept { return std::get_if<TenantId>(&value_); }

const ServiceId* TenancySubject::service_if() const noexcept { return std::get_if<ServiceId>(&value_); }

const IsolationDomainId* TenancySubject::isolation_domain_if() const noexcept {
  return std::get_if<IsolationDomainId>(&value_);
}

std::string_view TenancySubject::identity_value() const noexcept {
  return std::visit([](const auto& identity) noexcept -> std::string_view { return identity.value(); }, value_);
}

std::string TenancySubject::to_text() const {
  std::string out{to_token(kind())};
  out += ':';
  out += identity_value();
  return out;
}

bool operator==(const TenancySubject& lhs, const TenancySubject& rhs) noexcept { return lhs.value_ == rhs.value_; }

bool operator<(const TenancySubject& lhs, const TenancySubject& rhs) noexcept {
  // Canonical order is the byte order of the canonical token form, so a sorted
  // listing of subjects reads the way their text reads.
  const std::string_view left_kind = to_token(lhs.kind());
  const std::string_view right_kind = to_token(rhs.kind());
  if (left_kind != right_kind) {
    return left_kind < right_kind;
  }
  return lhs.identity_value() < rhs.identity_value();
}

}  // namespace tenant_registry
