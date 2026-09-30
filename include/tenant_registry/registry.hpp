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

#ifndef TENANT_REGISTRY_REGISTRY_HPP
#define TENANT_REGISTRY_REGISTRY_HPP

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "tenant_registry/digest.hpp"
#include "tenant_registry/errors.hpp"
#include "tenant_registry/ids.hpp"
#include "tenant_registry/limits.hpp"
#include "tenant_registry/persistence.hpp"
#include "tenant_registry/query.hpp"
#include "tenant_registry/records.hpp"
#include "tenant_registry/requests.hpp"
#include "tenant_registry/snapshot.hpp"

namespace tenant_registry {

namespace detail {
class RegistryCore;
}  // namespace detail

/// Options that bound how much an explanation is allowed to say.
struct ExplainOptions {
  /// How far up the ownership chain the explanation walks. The walk is bounded
  /// and never silently truncated: when it stops at this bound the explanation
  /// says so in unknowns.
  std::size_t max_lineage_depth = 16;
  bool include_metadata = true;
};

/// The canonical facility tenancy registry.
///
/// One instance owns the authoritative tenancy state for one facility. It is
/// move-only, it is never copied, and it is the only thing that may change that
/// state.
///
/// Concurrency model. Internally there is exactly one mutex and it is held for
/// the whole of every operation, read or write. There is therefore no
/// read-to-write upgrade on a shared lock -- there is no shared lock -- no lock
/// nesting, no lock ordering to get wrong, and no re-entrant acquisition
/// anywhere. Durable I/O happens while that mutex is held and that is
/// deliberate: the commit point must be ordered with the publication of the
/// state it protects. No user callback is invoked while the mutex is held
/// except the publish fault hook, which exists only for crash testing and is
/// documented as such. Cross-process exclusion is provided by the operating
/// system, not by this mutex.
class TenantRegistry {
 public:
  TenantRegistry() = delete;
  ~TenantRegistry();

  TenantRegistry(TenantRegistry&& other) noexcept;
  TenantRegistry& operator=(TenantRegistry&& other) noexcept;
  TenantRegistry(const TenantRegistry&) = delete;
  TenantRegistry& operator=(const TenantRegistry&) = delete;

  // -- opening --------------------------------------------------------------

  /// Opens a durable registry rooted at request.root.
  ///
  /// A read-write open takes the writer lock, recovers the store, and publishes
  /// a new control epoch. Every live authority issued before that moment is
  /// fenced by it. A read-only open does none of those things and applies the
  /// same integrity rules.
  [[nodiscard]] static Result<TenantRegistry> open(const RegistryOpenRequest& request);

  /// Opens a registry that has no durable state. It is fully functional, it
  /// reports no store identity, and it is never claimed to survive a restart.
  [[nodiscard]] static Result<TenantRegistry> open_ephemeral(const EphemeralOptions& options);

  /// True while this instance owns a live session. Every other member function
  /// has a precondition that this is true; a moved-from or closed instance must
  /// not be used. Members that can report a refusal do so with StoreClosed
  /// rather than relying on the precondition alone.
  [[nodiscard]] bool valid() const noexcept;

  // -- authority ------------------------------------------------------------

  [[nodiscard]] RegistryGeneration generation() const;
  [[nodiscard]] ControlEpoch control_epoch() const;
  [[nodiscard]] Incarnation incarnation() const;
  [[nodiscard]] AccessMode access_mode() const;
  [[nodiscard]] bool durable() const;
  [[nodiscard]] std::optional<StoreIdentity> store_identity() const;
  [[nodiscard]] JournalSequence committed_sequence() const;
  [[nodiscard]] const RegistryLimits& limits() const;
  [[nodiscard]] StoreRecoveryReport recovery_report() const;

  // -- mutations ------------------------------------------------------------

  [[nodiscard]] Result<CreateTenantOutcome> create_tenant(const CreateTenantRequest& request);
  [[nodiscard]] Result<CreateServiceOutcome> create_service(const CreateServiceRequest& request);
  [[nodiscard]] Result<CreateIsolationDomainOutcome> create_isolation_domain(
      const CreateIsolationDomainRequest& request);
  [[nodiscard]] Result<TransitionSubjectOutcome> transition_subject(const TransitionSubjectRequest& request);
  [[nodiscard]] Result<MutationReceipt> set_owner(const SetOwnerRequest& request);
  [[nodiscard]] Result<SetMetadataOutcome> set_metadata(const SetMetadataRequest& request);
  [[nodiscard]] Result<PutOwnershipOutcome> put_ownership(const PutOwnershipRequest& request);
  [[nodiscard]] Result<MutationReceipt> remove_ownership(const RemoveOwnershipRequest& request);
  [[nodiscard]] Result<MutationReceipt> transition_ownership(const TransitionOwnershipRequest& request);
  [[nodiscard]] Result<PutServiceBindingOutcome> put_service_binding(const PutServiceBindingRequest& request);
  [[nodiscard]] Result<MutationReceipt> remove_service_binding(const RemoveServiceBindingRequest& request);
  [[nodiscard]] Result<MutationReceipt> transition_service_binding(const TransitionServiceBindingRequest& request);
  [[nodiscard]] Result<PutIsolationMembershipOutcome> put_isolation_membership(
      const PutIsolationMembershipRequest& request);
  [[nodiscard]] Result<TransitionIsolationMembershipOutcome> transition_isolation_membership(
      const TransitionIsolationMembershipRequest& request);
  [[nodiscard]] Result<MutationReceipt> remove_isolation_membership(
      const RemoveIsolationMembershipRequest& request);
  [[nodiscard]] Result<TombstoneOutcome> tombstone(const TombstoneRequest& request);

  // -- queries --------------------------------------------------------------

  [[nodiscard]] Result<TenantRecord> find_tenant(const TenantId& id) const;
  [[nodiscard]] Result<ServiceRecord> find_service(const ServiceId& id) const;
  [[nodiscard]] Result<IsolationDomainRecord> find_isolation_domain(const IsolationDomainId& id) const;
  [[nodiscard]] Result<SubjectRecord> find_subject(const TenancySubject& subject) const;

  /// The permanent tombstone of an identity, when one exists, whether it is
  /// still in the identity map or has already been superseded by a permitted
  /// rebind. An identity that was never tombstoned has no tombstone, and this
  /// refuses with NotFound rather than returning an empty record.
  [[nodiscard]] Result<TombstoneRecord> find_tombstone(SubjectKind kind, std::string_view identity) const;

  /// Looks up a domain and checks the caller's cached membership generation in
  /// the same operation. A mismatched generation is refused with
  /// StaleDomainGeneration together with the current generation, so a consumer
  /// that cached membership learns exactly what to re-read.
  [[nodiscard]] Result<IsolationDomainRecord> find_isolation_domain(
      const IsolationDomainId& id, const DomainGeneration& expected_membership_generation) const;

  [[nodiscard]] Result<Page<TenantSummary>> list_tenants(const TenantQuery& query) const;
  [[nodiscard]] Result<Page<ServiceSummary>> list_services(const ServiceQuery& query) const;
  [[nodiscard]] Result<Page<DomainSummary>> list_isolation_domains(const DomainQuery& query) const;
  [[nodiscard]] Result<Page<MembershipSummary>> list_isolation_memberships(const MembershipQuery& query) const;
  [[nodiscard]] Result<Page<OwnershipEdge>> list_ownership(const OwnershipQuery& query) const;
  [[nodiscard]] Result<Page<ServiceBinding>> list_service_bindings(const BindingQuery& query) const;

  [[nodiscard]] Result<OwnershipTraversal> traverse_ownership(const OwnershipTraversalRequest& request) const;

  /// Every isolation domain the subject is in force in, in canonical order.
  [[nodiscard]] Result<std::vector<IsolationDomainId>> isolation_domains_of(
      const TenancySubject& subject) const;

  /// Every subject in force in one domain, in canonical order, bounded.
  [[nodiscard]] Result<std::vector<TenancySubject>> members_of(const IsolationDomainId& domain,
                                                              std::size_t limit) const;

  [[nodiscard]] Result<Explanation> explain(const TenancySubject& subject,
                                            const ExplainOptions& options = ExplainOptions{}) const;

  [[nodiscard]] RegistryStats stats() const;
  [[nodiscard]] RegistrySnapshot snapshot() const;

  /// The whole state rendered as canonical JSON. Bounded by the snapshot
  /// limits; refuses rather than producing a truncated document.
  [[nodiscard]] Result<std::string> export_json() const;

  // -- durable maintenance --------------------------------------------------

  /// Ensures every accepted mutation is durable. Every accepted mutation
  /// already is, so this is a no-op that exists so that a caller can say what
  /// it means. It refuses on a read-only session.
  [[nodiscard]] Status flush();

  /// Rewrites the journal as a fresh baseline plus the frames committed since.
  /// Compaction can never produce a state the ordinary reader would refuse: the
  /// new journal is built, flushed and verified before the manifest names it,
  /// and the reader validates the result exactly as it validates any other
  /// store.
  [[nodiscard]] Status compact();

  /// Releases the writer lock. Idempotent. Every later mutation is refused with
  /// StoreClosed. A read-only session has nothing to release.
  [[nodiscard]] Status close();

 private:
  explicit TenantRegistry(std::unique_ptr<detail::RegistryCore> core) noexcept;

  std::unique_ptr<detail::RegistryCore> core_;
};

// ---------------------------------------------------------------------------
// Canonical rendering, shared by the library, the CLI and the tests.
// ---------------------------------------------------------------------------

[[nodiscard]] std::string to_canonical(const TenantRecord& record);
[[nodiscard]] std::string to_canonical(const ServiceRecord& record);
[[nodiscard]] std::string to_canonical(const IsolationDomainRecord& record);
[[nodiscard]] std::string to_canonical(const SubjectRecord& record);
[[nodiscard]] std::string to_canonical(const OwnershipEdge& edge);
[[nodiscard]] std::string to_canonical(const ServiceBinding& binding);
[[nodiscard]] std::string to_canonical(const IsolationMembership& membership);
[[nodiscard]] std::string to_canonical(const TombstoneRecord& record);

[[nodiscard]] std::string to_json(const TenantRecord& record);
[[nodiscard]] std::string to_json(const ServiceRecord& record);
[[nodiscard]] std::string to_json(const IsolationDomainRecord& record);
[[nodiscard]] std::string to_json(const SubjectRecord& record);
[[nodiscard]] std::string to_json(const OwnershipEdge& edge);
[[nodiscard]] std::string to_json(const ServiceBinding& binding);
[[nodiscard]] std::string to_json(const IsolationMembership& membership);
[[nodiscard]] std::string to_json(const TombstoneRecord& record);

[[nodiscard]] std::string subject_kind_token(const SubjectRecord& record);

}  // namespace tenant_registry

#endif  // TENANT_REGISTRY_REGISTRY_HPP
