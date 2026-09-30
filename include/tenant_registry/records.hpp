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

#ifndef TENANT_REGISTRY_RECORDS_HPP
#define TENANT_REGISTRY_RECORDS_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "tenant_registry/digest.hpp"
#include "tenant_registry/errors.hpp"
#include "tenant_registry/ids.hpp"
#include "tenant_registry/lifecycle.hpp"
#include "tenant_registry/metadata.hpp"
#include "tenant_registry/provenance.hpp"

namespace tenant_registry {

/// The meaning of an ownership relationship. The kind is declared, never
/// inferred from a naming convention.
enum class OwnershipKind : std::uint8_t {
  Unspecified = 0,
  /// The accountable owner: exactly one in-force administrative owner per
  /// child, so that "who owns this tenant" always has one answer.
  Administrative = 1,
  /// Who runs it day to day.
  Operational = 2,
  /// Which jurisdiction's rules it is subject to.
  Regulatory = 3,
  /// Where its data is declared to reside.
  DataResidency = 4,
};

/// How a service relates to a tenant.
enum class BindingKind : std::uint8_t {
  Unspecified = 0,
  /// The tenant the service belongs to and answers to. At most one in-force
  /// binding of this kind per service.
  OperatedBy = 1,
  /// A tenant whose workload the service is declared to serve.
  Serves = 2,
  /// A tenant declared to consume the service.
  ConsumedBy = 3,
};

/// A subject's role inside one isolation domain.
enum class MembershipRole : std::uint8_t {
  Unspecified = 0,
  /// The subject's home domain. At most one in-force primary membership per
  /// subject across the whole registry.
  Primary = 1,
  /// An additional domain the subject is also isolated into.
  Secondary = 2,
  /// A domain the subject may fall back into. Declared, not assumed.
  Fallback = 3,
};

/// The reason a set of subjects is isolated together. It is declared, never
/// inferred from a name, a label, a rack, a VLAN or a path.
enum class IsolationClass : std::uint8_t {
  Unspecified = 0,
  /// A fault in one member must not propagate to another.
  FaultContainment = 1,
  /// An administrative boundary.
  Administrative = 2,
  /// A regulatory boundary.
  Regulatory = 3,
  /// A boundary that exists for exactly one tenant.
  TenantPrivate = 4,
};

[[nodiscard]] std::string_view to_token(OwnershipKind kind) noexcept;
[[nodiscard]] std::string_view to_token(BindingKind kind) noexcept;
[[nodiscard]] std::string_view to_token(MembershipRole role) noexcept;
[[nodiscard]] std::string_view to_token(IsolationClass isolation_class) noexcept;

[[nodiscard]] bool parse_ownership_kind(std::string_view token, OwnershipKind& out) noexcept;
[[nodiscard]] bool parse_binding_kind(std::string_view token, BindingKind& out) noexcept;
[[nodiscard]] bool parse_membership_role(std::string_view token, MembershipRole& out) noexcept;
[[nodiscard]] bool parse_isolation_class(std::string_view token, IsolationClass& out) noexcept;

// ---------------------------------------------------------------------------
// Tombstone and rebind
// ---------------------------------------------------------------------------

/// A bounded, explicit permission for one named successor to take over the
/// identity of a tombstoned record.
///
/// The permit names the successor before the tombstone is written. It cannot be
/// widened afterwards: the successor is fixed at tombstone time. A permit is
/// consumed at most once, and the consumption is itself a durable fact, so a
/// second attempt to take the identity is refused for a different and more
/// specific reason than the first.
class RebindPermit {
 public:
  RebindPermit() = delete;

  [[nodiscard]] static Result<RebindPermit> issue(SubjectKind successor_kind, std::string successor_text,
                                                  RegistryGeneration issued_generation, std::string note,
                                                  std::size_t max_text_bytes, std::size_t max_note_bytes);

  [[nodiscard]] SubjectKind successor_kind() const noexcept { return successor_kind_; }
  [[nodiscard]] const std::string& successor_text() const noexcept { return successor_text_; }
  [[nodiscard]] RegistryGeneration issued_generation() const noexcept { return issued_generation_; }
  [[nodiscard]] const std::optional<RegistryGeneration>& consumed_generation() const noexcept {
    return consumed_generation_;
  }
  [[nodiscard]] bool consumed() const noexcept { return consumed_generation_.has_value(); }
  [[nodiscard]] const std::string& note() const noexcept { return note_; }

  /// True when this permit authorizes exactly this successor identity.
  [[nodiscard]] bool admits(SubjectKind kind, std::string_view text) const noexcept;

  /// Returns a copy marked consumed at the given generation. The original is
  /// unchanged, so a permit can only ever be consumed by replacing its record
  /// in one committed mutation.
  [[nodiscard]] RebindPermit consumed_at(RegistryGeneration generation) const;

  [[nodiscard]] ContentDigest digest() const;
  [[nodiscard]] std::string to_text() const;

  friend bool operator==(const RebindPermit&, const RebindPermit&) noexcept;
  friend bool operator<(const RebindPermit&, const RebindPermit&) noexcept;

 private:
  RebindPermit(SubjectKind successor_kind, std::string successor_text, RegistryGeneration issued_generation,
               std::optional<RegistryGeneration> consumed_generation, std::string note) noexcept
      : successor_kind_(successor_kind),
        successor_text_(std::move(successor_text)),
        issued_generation_(issued_generation),
        consumed_generation_(consumed_generation),
        note_(std::move(note)) {}

  SubjectKind successor_kind_ = SubjectKind::Unspecified;
  std::string successor_text_;
  RegistryGeneration issued_generation_;
  std::optional<RegistryGeneration> consumed_generation_;
  std::string note_;
};

/// The durable, irreversible statement that an identity is fenced forever.
class Tombstone {
 public:
  Tombstone() = delete;

  [[nodiscard]] static Result<Tombstone> create(RegistryGeneration retired_generation,
                                                RegistryGeneration tombstoned_generation,
                                                std::optional<RebindPermit> permit, std::string note,
                                                std::size_t max_note_bytes);

  [[nodiscard]] RegistryGeneration retired_generation() const noexcept { return retired_generation_; }
  [[nodiscard]] RegistryGeneration tombstoned_generation() const noexcept { return tombstoned_generation_; }
  [[nodiscard]] const std::optional<RebindPermit>& rebind_permit() const noexcept { return permit_; }
  [[nodiscard]] const std::string& note() const noexcept { return note_; }

  [[nodiscard]] Tombstone with_permit(std::optional<RebindPermit> permit) const;
  [[nodiscard]] ContentDigest digest() const;
  [[nodiscard]] std::string to_text() const;

  friend bool operator==(const Tombstone&, const Tombstone&) noexcept;
  friend bool operator<(const Tombstone&, const Tombstone&) noexcept;

 private:
  Tombstone(RegistryGeneration retired_generation, RegistryGeneration tombstoned_generation,
            std::optional<RebindPermit> permit, std::string note) noexcept
      : retired_generation_(retired_generation),
        tombstoned_generation_(tombstoned_generation),
        permit_(std::move(permit)),
        note_(std::move(note)) {}

  RegistryGeneration retired_generation_;
  RegistryGeneration tombstoned_generation_;
  std::optional<RebindPermit> permit_;
  std::string note_;
};

// ---------------------------------------------------------------------------
// Records
//
// Records are aggregates of strong types. They are only ever produced by this
// library or by decoding a canonical encoding that has already been validated;
// every field is validated at the boundary that produced it, so a record in
// memory is always well formed. They are compared and encoded through their
// canonical form, never through memory layout.
// ---------------------------------------------------------------------------

/// One registered tenant identity.
struct TenantRecord {
  TenantId id;
  std::optional<std::string> display_name;
  LifecycleState state = LifecycleState::Unspecified;
  RecordRevision revision;
  RegistryGeneration created_generation;
  RegistryGeneration updated_generation;
  std::optional<RegistryGeneration> retired_generation;
  std::optional<Tombstone> tombstone;
  /// The accountable owner principal, if one has been set. This is an
  /// accountable actor, not a tenant: tenant-to-tenant ownership is an
  /// OwnershipEdge.
  std::optional<PrincipalId> owner;
  TenancyMetadata metadata;
  ProvenanceRecord provenance;
  /// The digest of the canonical create request that established this record.
  /// It binds the record to the exact declaration that made it.
  ContentDigest origin_digest;
};

/// One registered facility service identity.
struct ServiceRecord {
  ServiceId id;
  std::optional<std::string> display_name;
  LifecycleState state = LifecycleState::Unspecified;
  RecordRevision revision;
  RegistryGeneration created_generation;
  RegistryGeneration updated_generation;
  std::optional<RegistryGeneration> retired_generation;
  std::optional<Tombstone> tombstone;
  TenancyMetadata metadata;
  ProvenanceRecord provenance;
  ContentDigest origin_digest;
};

/// One declared isolation domain.
struct IsolationDomainRecord {
  IsolationDomainId id;
  std::optional<std::string> display_name;
  IsolationClass isolation_class = IsolationClass::Unspecified;
  LifecycleState state = LifecycleState::Unspecified;
  RecordRevision revision;
  /// Advances on every change to this domain's membership set. A consumer that
  /// cached membership binds to this value and is fenced when it moves.
  DomainGeneration membership_generation;
  RegistryGeneration created_generation;
  RegistryGeneration updated_generation;
  std::optional<RegistryGeneration> retired_generation;
  std::optional<Tombstone> tombstone;
  TenancyMetadata metadata;
  ProvenanceRecord provenance;
  ContentDigest origin_digest;
};

/// A declared ownership relationship from a parent tenant to a child tenant.
///
/// Ownership is stored only here. A tenant record never carries a parent
/// field, so there is exactly one place that can be right about ownership and
/// no second place that can disagree with it.
struct OwnershipEdge {
  TenantId child;
  TenantId parent;
  OwnershipKind kind = OwnershipKind::Unspecified;
  LifecycleState state = LifecycleState::Unspecified;
  RecordRevision revision;
  RegistryGeneration created_generation;
  RegistryGeneration updated_generation;
  ProvenanceRecord provenance;
  ContentDigest origin_digest;

  /// The canonical natural key of this relationship: child then parent.
  [[nodiscard]] std::string natural_key() const;
};

/// A declared relationship from a service to a tenant.
struct ServiceBinding {
  ServiceId service;
  TenantId tenant;
  BindingKind kind = BindingKind::Unspecified;
  LifecycleState state = LifecycleState::Unspecified;
  RecordRevision revision;
  RegistryGeneration created_generation;
  RegistryGeneration updated_generation;
  ProvenanceRecord provenance;
  ContentDigest origin_digest;

  [[nodiscard]] std::string natural_key() const;
};

/// A declared membership of one tenant or service in one isolation domain.
struct IsolationMembership {
  TenancySubject subject;
  IsolationDomainId domain;
  MembershipRole role = MembershipRole::Unspecified;
  MembershipState state = MembershipState::Unspecified;
  RecordRevision revision;
  RegistryGeneration created_generation;
  RegistryGeneration updated_generation;
  ProvenanceRecord provenance;
  ContentDigest origin_digest;

  [[nodiscard]] std::string natural_key() const;
};

/// Any one of the three identity records. The alternative in use is the kind;
/// there is no separate tag that could disagree with it.
using SubjectRecord = std::variant<TenantRecord, ServiceRecord, IsolationDomainRecord>;

/// The permanent record that one identity was fenced forever.
///
/// A tombstoned identity normally stays in the identity map with state
/// Tombstoned, so that "this identity is fenced" is answerable without a second
/// lookup. It moves here, under the canonical key
/// "tombstone:<kind token>:<identity>", at the moment an explicit rebind permit
/// is consumed and a fresh record takes the identity's place. From that moment
/// this record is the only remaining proof that the identity was fenced, so it
/// is never removed and never rewritten into something weaker.
struct TombstoneRecord {
  SubjectKind kind = SubjectKind::Unspecified;
  /// The fenced identity text.
  std::string identity;
  /// Always LifecycleState::Tombstoned. It is stored rather than implied so
  /// that an encoding which loses it is detectably malformed.
  LifecycleState state = LifecycleState::Tombstoned;
  RecordRevision revision;
  RegistryGeneration retired_generation;
  RegistryGeneration tombstoned_generation;
  /// The permit that was consumed to let a successor take the identity, marked
  /// consumed at the generation it was consumed. Present exactly when the
  /// tombstone has been reused.
  std::optional<RebindPermit> permit;
  std::string note;
  ProvenanceRecord provenance;
  ContentDigest origin_digest;
};

[[nodiscard]] SubjectKind kind_of(const SubjectRecord& record) noexcept;
[[nodiscard]] const TenantId& subject_id(const TenantRecord& record) noexcept;
[[nodiscard]] const ServiceId& subject_id(const ServiceRecord& record) noexcept;
[[nodiscard]] const IsolationDomainId& subject_id(const IsolationDomainRecord& record) noexcept;
[[nodiscard]] std::string subject_identity_text(const SubjectRecord& record);
[[nodiscard]] LifecycleState subject_state(const SubjectRecord& record) noexcept;
[[nodiscard]] RecordRevision subject_revision(const SubjectRecord& record) noexcept;

/// The canonical, human readable token of a record's identity, for example
/// "tenant:acme". Every refusal and every diagnostic uses this form.
[[nodiscard]] std::string identity_text(SubjectKind kind, std::string_view value);

/// True when the record has reached a state from which it can never move.
[[nodiscard]] bool is_terminal(const SubjectRecord& record) noexcept;

}  // namespace tenant_registry

#endif  // TENANT_REGISTRY_RECORDS_HPP
