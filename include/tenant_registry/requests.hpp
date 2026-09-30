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

#ifndef TENANT_REGISTRY_REQUESTS_HPP
#define TENANT_REGISTRY_REQUESTS_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "tenant_registry/digest.hpp"
#include "tenant_registry/errors.hpp"
#include "tenant_registry/ids.hpp"
#include "tenant_registry/lifecycle.hpp"
#include "tenant_registry/metadata.hpp"
#include "tenant_registry/provenance.hpp"
#include "tenant_registry/records.hpp"

namespace tenant_registry {

/// The exact operation a commit performed. It is recorded durably so that a
/// replayed request can be answered with what the original request did, not
/// with a guess.
enum class OperationKind : std::uint16_t {
  Unspecified = 0,
  CreateTenant = 1,
  CreateService = 2,
  CreateIsolationDomain = 3,
  TransitionSubject = 4,
  SetOwner = 5,
  SetMetadata = 6,
  PutOwnership = 7,
  RemoveOwnership = 8,
  TransitionOwnership = 9,
  PutServiceBinding = 10,
  RemoveServiceBinding = 11,
  TransitionServiceBinding = 12,
  PutIsolationMembership = 13,
  TransitionIsolationMembership = 14,
  RemoveIsolationMembership = 15,
  Tombstone = 16,
};

[[nodiscard]] std::string_view to_token(OperationKind kind) noexcept;
[[nodiscard]] bool parse_operation_kind(std::string_view token, OperationKind& out) noexcept;

/// The binding every mutating request must carry.
///
/// expected_generation is not a hint and not a default. A caller states which
/// generation of the registry it composed its decision against; if the registry
/// has moved past that generation the request is refused. There is deliberately
/// no way to say "whatever is current", because that is exactly the statement
/// that produces lost updates.
struct MutationContext {
  RegistryGeneration expected_generation;
  std::optional<IdempotencyKey> idempotency_key;
  ProvenanceRecord actor;
};

/// What a mutation did, or what it did the first time it was accepted.
struct MutationReceipt {
  OperationKind operation = OperationKind::Unspecified;
  /// The registry generation *after* the mutation.
  RegistryGeneration generation;
  /// The durable position of the commit that performed it.
  JournalSequence sequence;
  /// The revision of the principal record the operation was about.
  RecordRevision revision;
  /// The digest of the canonical request that produced it.
  RequestDigest request_digest;
  /// True when this answer came from the idempotency ledger rather than from a
  /// new commit. A replayed receipt reports the original generation, sequence
  /// and revision, so a caller cannot mistake a replay for progress.
  bool replayed = false;

  [[nodiscard]] std::string to_text() const;
};

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

struct CreateTenantRequest {
  MutationContext context;
  TenantId id;
  std::optional<std::string> display_name;
  /// The accountable owner principal. Unset means "no owner has been declared",
  /// which is preserved as such and is never defaulted to the caller.
  std::optional<PrincipalId> owner;
  TenancyMetadata metadata;
};

struct CreateTenantOutcome {
  MutationReceipt receipt;
  TenantRecord record;
};

struct CreateServiceRequest {
  MutationContext context;
  ServiceId id;
  std::optional<std::string> display_name;
  TenancyMetadata metadata;
};

struct CreateServiceOutcome {
  MutationReceipt receipt;
  ServiceRecord record;
};

struct CreateIsolationDomainRequest {
  MutationContext context;
  IsolationDomainId id;
  IsolationClass isolation_class;
  std::optional<std::string> display_name;
  TenancyMetadata metadata;
};

struct CreateIsolationDomainOutcome {
  MutationReceipt receipt;
  IsolationDomainRecord record;
};

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

struct TransitionSubjectRequest {
  MutationContext context;
  TenancySubject subject;
  RecordRevision expected_revision;
  LifecycleState target = LifecycleState::Unspecified;
};

struct TransitionSubjectOutcome {
  MutationReceipt receipt;
  SubjectRecord record;
};

// ---------------------------------------------------------------------------
// Ownership principal and metadata
// ---------------------------------------------------------------------------

struct SetOwnerRequest {
  MutationContext context;
  TenantId tenant;
  RecordRevision expected_revision;
  /// Unset clears the owner. Clearing is explicit; there is no accidental
  /// clear by omission, because the request itself must be written.
  std::optional<PrincipalId> owner;
};

struct SetMetadataRequest {
  MutationContext context;
  TenancySubject subject;
  RecordRevision expected_revision;
  std::vector<MetadataKey> remove_keys;
  std::vector<MetadataEntry> put_entries;
};

struct SetMetadataOutcome {
  MutationReceipt receipt;
  SubjectRecord record;
};

// ---------------------------------------------------------------------------
// Relationships
// ---------------------------------------------------------------------------

struct PutOwnershipRequest {
  MutationContext context;
  TenantId child;
  TenantId parent;
  OwnershipKind kind = OwnershipKind::Unspecified;
  LifecycleState initial_state = LifecycleState::Unspecified;
  /// Absent means "I assert this relationship does not exist". Present means
  /// "I assert it exists at exactly this revision". Either way, an assertion
  /// that does not hold is refused rather than silently resolved.
  std::optional<RecordRevision> expected_revision;
};

struct PutOwnershipOutcome {
  MutationReceipt receipt;
  OwnershipEdge edge;
};

struct RemoveOwnershipRequest {
  MutationContext context;
  TenantId child;
  TenantId parent;
  RecordRevision expected_revision;
};

struct TransitionOwnershipRequest {
  MutationContext context;
  TenantId child;
  TenantId parent;
  RecordRevision expected_revision;
  LifecycleState target = LifecycleState::Unspecified;
};

struct PutServiceBindingRequest {
  MutationContext context;
  ServiceId service;
  TenantId tenant;
  BindingKind kind = BindingKind::Unspecified;
  LifecycleState initial_state = LifecycleState::Unspecified;
  std::optional<RecordRevision> expected_revision;
};

struct PutServiceBindingOutcome {
  MutationReceipt receipt;
  ServiceBinding binding;
};

struct RemoveServiceBindingRequest {
  MutationContext context;
  ServiceId service;
  TenantId tenant;
  BindingKind kind = BindingKind::Unspecified;
  RecordRevision expected_revision;
};

struct TransitionServiceBindingRequest {
  MutationContext context;
  ServiceId service;
  TenantId tenant;
  BindingKind kind = BindingKind::Unspecified;
  RecordRevision expected_revision;
  LifecycleState target = LifecycleState::Unspecified;
};

// ---------------------------------------------------------------------------
// Isolation membership
// ---------------------------------------------------------------------------

struct PutIsolationMembershipRequest {
  MutationContext context;
  TenancySubject subject;
  IsolationDomainId domain;
  MembershipRole role = MembershipRole::Unspecified;
  MembershipState initial_state = MembershipState::Unspecified;
  /// The caller states which generation of this domain's membership set it saw.
  /// A membership write is a change to that set, so it must be addressed to the
  /// set as it was.
  DomainGeneration expected_domain_generation;
  std::optional<RecordRevision> expected_revision;
};

struct PutIsolationMembershipOutcome {
  MutationReceipt receipt;
  IsolationMembership membership;
  /// The domain generation after the change.
  DomainGeneration domain_generation;
};

struct TransitionIsolationMembershipRequest {
  MutationContext context;
  TenancySubject subject;
  IsolationDomainId domain;
  RecordRevision expected_revision;
  DomainGeneration expected_domain_generation;
  MembershipState target = MembershipState::Unspecified;
};

struct TransitionIsolationMembershipOutcome {
  MutationReceipt receipt;
  IsolationMembership membership;
  DomainGeneration domain_generation;
};

struct RemoveIsolationMembershipRequest {
  MutationContext context;
  TenancySubject subject;
  IsolationDomainId domain;
  RecordRevision expected_revision;
  DomainGeneration expected_domain_generation;
};

// ---------------------------------------------------------------------------
// Tombstone
// ---------------------------------------------------------------------------

/// The successor identity a tombstone permits to take over the fenced
/// identity. It is fixed when the tombstone is written.
struct RebindSuccessor {
  SubjectKind kind = SubjectKind::Unspecified;
  std::string text;
};

/// The explicit, per-request acknowledgement that tombstoning cannot be undone.
///
/// Acknowledgement is not the effect. Recording that a caller acknowledged an
/// irreversible action is not the same as the action having happened, and this
/// registry never treats one as the other: the tombstone is only durable once
/// its commit is durable.
struct IrreversibleAcknowledgement {
  bool acknowledges_permanent_identity_fencing = false;

  [[nodiscard]] static IrreversibleAcknowledgement acknowledged() noexcept {
    return IrreversibleAcknowledgement{true};
  }
  [[nodiscard]] bool is_acknowledged() const noexcept {
    return acknowledges_permanent_identity_fencing;
  }
};

struct TombstoneRequest {
  MutationContext context;
  TenancySubject subject;
  RecordRevision expected_revision;
  IrreversibleAcknowledgement acknowledgement;
  std::optional<RebindSuccessor> rebind;
  std::string note;
};

struct TombstoneOutcome {
  MutationReceipt receipt;
  SubjectRecord record;
};

}  // namespace tenant_registry

#endif  // TENANT_REGISTRY_REQUESTS_HPP
