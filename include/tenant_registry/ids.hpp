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

#ifndef TENANT_REGISTRY_IDS_HPP
#define TENANT_REGISTRY_IDS_HPP

#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

#include "tenant_registry/digest.hpp"
#include "tenant_registry/errors.hpp"

namespace tenant_registry {

/// The rules every canonical facility identity obeys.
///
/// An identity is an opaque, case sensitive, bounded token. It is never
/// interpreted as a path, never normalized, and never inferred from a display
/// name. Two identities are equal exactly when their bytes are equal.
struct IdentityRules {
  const char* kind_tag;
  std::size_t max_length;
};

/// Validates one identity token: non-empty, at most max_length bytes, valid
/// UTF-8, restricted to [A-Za-z0-9._:-], must begin with an alphanumeric
/// character, and must not end with a separator. Returns the token unchanged.
[[nodiscard]] Result<std::string> validate_identity(std::string_view value, const IdentityRules& rules);

/// Validates an opaque text field: valid UTF-8, no control characters other
/// than none at all, bounded length. Used for display names and notes.
[[nodiscard]] Result<std::string> validate_text_field(std::string_view value, std::size_t max_bytes,
                                                      const char* what);

/// True when the byte sequence is well formed UTF-8 without overlong forms,
/// without surrogates and without code points above U+10FFFF.
[[nodiscard]] bool is_valid_utf8(std::string_view text) noexcept;

// ---------------------------------------------------------------------------
// Strong identities. Each is a distinct type: a ServiceId can never be passed
// where a TenantId is expected, and the compiler enforces it.
// ---------------------------------------------------------------------------

#define TENANT_REGISTRY_DECLARE_IDENTITY(class_name, tag_token, max_len)          \
 public:                                                                          \
  class_name() = delete;                                                          \
  [[nodiscard]] static Result<class_name> create(std::string_view value);         \
  [[nodiscard]] static const IdentityRules& rules() noexcept;                     \
  [[nodiscard]] const std::string& value() const noexcept { return value_; }      \
  [[nodiscard]] std::string to_text() const { return value_; }                    \
  [[nodiscard]] ContentDigest digest() const noexcept;                            \
  [[nodiscard]] std::string_view kind_token() const noexcept { return tag_token; } \
  friend bool operator==(const class_name&, const class_name&) = default;         \
  friend auto operator<=>(const class_name&, const class_name&) = default;        \
  [[nodiscard]] std::size_t hash() const noexcept {                               \
    return std::hash<std::string_view>{}(value_);                                 \
  }                                                                               \
                                                                                  \
 private:                                                                         \
  explicit class_name(std::string value) noexcept : value_(std::move(value)) {}   \
  std::string value_;

/// A canonical tenant identity.
class TenantId {
  TENANT_REGISTRY_DECLARE_IDENTITY(TenantId, "tenant", 128)
};

/// A canonical facility service identity.
class ServiceId {
  TENANT_REGISTRY_DECLARE_IDENTITY(ServiceId, "service", 128)
};

/// A canonical isolation domain identity. It is declared, never inferred from a
/// name, a label, a rack, a VLAN or a path.
class IsolationDomainId {
  TENANT_REGISTRY_DECLARE_IDENTITY(IsolationDomainId, "isolation_domain", 128)
};

/// A canonical principal identity: the accountable actor that declared
/// something. This repository records who declared it; it does not authenticate
/// anyone and does not decide what a principal may do.
class PrincipalId {
  TENANT_REGISTRY_DECLARE_IDENTITY(PrincipalId, "principal", 128)
};

/// A canonical identity of the system a declaration arrived from.
class SourceId {
  TENANT_REGISTRY_DECLARE_IDENTITY(SourceId, "source", 128)
};

/// A canonical tenancy metadata key.
class MetadataKey {
  TENANT_REGISTRY_DECLARE_IDENTITY(MetadataKey, "metadata_key", 96)
};

#undef TENANT_REGISTRY_DECLARE_IDENTITY

// ---------------------------------------------------------------------------
// Monotonic counters. None of them wrap: every advance either succeeds or
// refuses with CounterSaturated, so a saturated counter can never silently
// become a small one and make stale state look current.
// ---------------------------------------------------------------------------

#define TENANT_REGISTRY_DECLARE_COUNTER(class_name, tag_token, initial_value)     \
 public:                                                                          \
  class_name() = default;                                                         \
  [[nodiscard]] static class_name initial() noexcept { return class_name{initial_value}; } \
  [[nodiscard]] static class_name from_value(std::uint64_t value) noexcept {      \
    return class_name{value};                                                     \
  }                                                                               \
  [[nodiscard]] std::uint64_t value() const noexcept { return value_; }           \
  [[nodiscard]] bool is_initial() const noexcept { return value_ == initial_value; } \
  [[nodiscard]] std::string to_text() const {                                     \
    return tag_token + std::string{":"} + std::to_string(value_);                 \
  }                                                                               \
  [[nodiscard]] std::string_view kind_token() const noexcept { return tag_token; } \
  friend bool operator==(const class_name&, const class_name&) = default;         \
  friend auto operator<=>(const class_name&, const class_name&) = default;        \
                                                                                  \
 private:                                                                         \
  explicit class_name(std::uint64_t value) noexcept : value_(value) {}            \
  std::uint64_t value_ = initial_value;

/// The registry wide generation. Every accepted mutation advances it by exactly
/// one. A caller binds a decision to the generation it read; a mutation against
/// any other generation is stale and is refused.
class RegistryGeneration {
  TENANT_REGISTRY_DECLARE_COUNTER(RegistryGeneration, "generation", 0)
};

/// The revision of a single record. Every accepted mutation that changes a
/// record advances that record's revision by exactly one.
class RecordRevision {
  TENANT_REGISTRY_DECLARE_COUNTER(RecordRevision, "revision", 0)
};

/// The generation of one isolation domain's membership set. It advances on
/// every change to that domain's membership, so a consumer that cached domain
/// membership can be fenced without consulting the whole registry.
class DomainGeneration {
  TENANT_REGISTRY_DECLARE_COUNTER(DomainGeneration, "domain_generation", 0)
};

/// The control epoch of the durable store. It advances every time a writer
/// takes control of a store, so live authority from a previous writer
/// incarnation is fenced by the act of taking control, not by a convention.
class ControlEpoch {
  TENANT_REGISTRY_DECLARE_COUNTER(ControlEpoch, "control_epoch", 0)
};

/// The identity of one writer incarnation. It is never reused.
class Incarnation {
  TENANT_REGISTRY_DECLARE_COUNTER(Incarnation, "incarnation", 0)
};

/// The position of one committed frame in the durable journal. It is the
/// durable ordering authority; it is not a generation and must not be compared
/// with one.
class JournalSequence {
  TENANT_REGISTRY_DECLARE_COUNTER(JournalSequence, "sequence", 0)
};

#undef TENANT_REGISTRY_DECLARE_COUNTER

/// Advances a counter, or refuses. There is no wrapping overload, on purpose.
[[nodiscard]] Result<RegistryGeneration> advance(RegistryGeneration current) noexcept;
[[nodiscard]] Result<RecordRevision> advance(RecordRevision current) noexcept;
[[nodiscard]] Result<DomainGeneration> advance(DomainGeneration current) noexcept;
[[nodiscard]] Result<ControlEpoch> advance(ControlEpoch current) noexcept;
[[nodiscard]] Result<JournalSequence> advance(JournalSequence current) noexcept;

// ---------------------------------------------------------------------------
// Request identity
// ---------------------------------------------------------------------------

/// A caller supplied key that makes a mutation replay safe.
///
/// A key is not an authority and grants nothing. It only lets a caller whose
/// response was lost ask the same question twice and get the first answer, with
/// the record content that was current when the answer was first produced.
class IdempotencyKey {
 public:
  IdempotencyKey() = delete;

  [[nodiscard]] static Result<IdempotencyKey> create(std::string_view value);

  [[nodiscard]] const std::string& value() const noexcept { return value_; }
  [[nodiscard]] std::string to_text() const { return value_; }

  friend bool operator==(const IdempotencyKey&, const IdempotencyKey&) = default;
  friend auto operator<=>(const IdempotencyKey&, const IdempotencyKey&) = default;

 private:
  explicit IdempotencyKey(std::string value) noexcept : value_(std::move(value)) {}
  std::string value_;
};

/// The digest of the canonical form of a request. Two requests have the same
/// digest exactly when their canonical encodings are identical byte for byte,
/// which is exactly when they ask for the same thing.
using RequestDigest = ContentDigest;

/// What a mutation is about. A subject is a tagged identity: the tag is part of
/// the value, so a tenant identity can never be mistaken for a service
/// identity even when the text is identical.
enum class SubjectKind : std::uint8_t {
  Unspecified = 0,
  Tenant = 1,
  Service = 2,
  IsolationDomain = 3,
};

[[nodiscard]] std::string_view to_token(SubjectKind kind) noexcept;
[[nodiscard]] bool parse_subject_kind(std::string_view token, SubjectKind& out) noexcept;

/// Any of the three identities this registry registers, tagged.
///
/// The tag is not a separate field that could disagree with the identity: the
/// value holds exactly one of the three identities, so "kind is Tenant but the
/// payload is a ServiceId" is not a representable state.
///
/// Isolation domains are reachable here because a lifecycle transition has to
/// be able to name one. They are *not* valid members of an isolation domain,
/// and every membership operation refuses one with InvalidIdKind rather than
/// quietly ignoring it: a domain is not isolated out of another domain.
class TenancySubject {
 public:
  TenancySubject() = delete;

  [[nodiscard]] static TenancySubject of_tenant(TenantId id) noexcept;
  [[nodiscard]] static TenancySubject of_service(ServiceId id) noexcept;
  [[nodiscard]] static TenancySubject of_isolation_domain(IsolationDomainId id) noexcept;

  [[nodiscard]] SubjectKind kind() const noexcept;
  [[nodiscard]] bool is_tenant() const noexcept { return kind() == SubjectKind::Tenant; }
  [[nodiscard]] bool is_service() const noexcept { return kind() == SubjectKind::Service; }
  [[nodiscard]] bool is_isolation_domain() const noexcept { return kind() == SubjectKind::IsolationDomain; }

  /// Each accessor returns nullptr rather than a default constructed identity
  /// when this subject is of a different kind, because there is no such thing
  /// as an empty tenant.
  [[nodiscard]] const TenantId* tenant_if() const noexcept;
  [[nodiscard]] const ServiceId* service_if() const noexcept;
  [[nodiscard]] const IsolationDomainId* isolation_domain_if() const noexcept;

  /// The identity bytes, whichever kind this is.
  [[nodiscard]] std::string_view identity_value() const noexcept;

  /// The canonical token form: "tenant:acme", "service:renderer" or
  /// "isolation_domain:zone-a".
  [[nodiscard]] std::string to_text() const;

  friend bool operator==(const TenancySubject& lhs, const TenancySubject& rhs) noexcept;
  friend bool operator<(const TenancySubject& lhs, const TenancySubject& rhs) noexcept;

 private:
  explicit TenancySubject(std::variant<TenantId, ServiceId, IsolationDomainId> value) noexcept
      : value_(std::move(value)) {}

  std::variant<TenantId, ServiceId, IsolationDomainId> value_;
};

}  // namespace tenant_registry

#endif  // TENANT_REGISTRY_IDS_HPP
