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

#ifndef TENANT_REGISTRY_QUERY_HPP
#define TENANT_REGISTRY_QUERY_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "tenant_registry/digest.hpp"
#include "tenant_registry/errors.hpp"
#include "tenant_registry/ids.hpp"
#include "tenant_registry/lifecycle.hpp"
#include "tenant_registry/records.hpp"

namespace tenant_registry {

/// One page of a bounded listing.
///
/// A page is never silently partial. When there is more to read, next_cursor is
/// present and truncated is true; when there is not, next_cursor is absent. The
/// two are never both unset while items are missing.
template <class T>
struct Page {
  std::vector<T> items;
  std::optional<std::string> next_cursor;
  bool truncated = false;
  /// How many records matched the filter, ignoring the page limit. This is a
  /// count of what matched, not a claim that the caller can see all of it.
  std::size_t total_matched = 0;
};

struct TenantSummary {
  TenantId id;
  std::optional<std::string> display_name;
  LifecycleState state = LifecycleState::Unspecified;
  RecordRevision revision;
};

struct ServiceSummary {
  ServiceId id;
  std::optional<std::string> display_name;
  LifecycleState state = LifecycleState::Unspecified;
  RecordRevision revision;
};

struct DomainSummary {
  IsolationDomainId id;
  std::optional<std::string> display_name;
  IsolationClass isolation_class = IsolationClass::Unspecified;
  LifecycleState state = LifecycleState::Unspecified;
  RecordRevision revision;
  DomainGeneration membership_generation;
};

struct MembershipSummary {
  TenancySubject subject;
  IsolationDomainId domain;
  MembershipRole role = MembershipRole::Unspecified;
  MembershipState state = MembershipState::Unspecified;
  RecordRevision revision;
};

/// A filter over tenants. Every field is a positive assertion; an unset field
/// means the assertion was not made, which is different from an assertion that
/// matches everything. The two are separated because a caller that forgot to
/// set a filter must not silently receive a wider answer than it asked for.
struct TenantQuery {
  std::optional<LifecycleState> state;
  std::optional<IsolationDomainId> member_of_domain;
  std::optional<MembershipState> member_state;
  std::optional<PrincipalId> owner;
  std::optional<TenantId> child_of;
  std::optional<TenantId> parent_of;
  std::size_t limit = 0;
  std::optional<std::string> cursor;
};

struct ServiceQuery {
  std::optional<LifecycleState> state;
  std::optional<TenantId> bound_to_tenant;
  std::optional<BindingKind> binding_kind;
  std::optional<IsolationDomainId> member_of_domain;
  std::size_t limit = 0;
  std::optional<std::string> cursor;
};

struct DomainQuery {
  std::optional<LifecycleState> state;
  std::optional<IsolationClass> isolation_class;
  std::size_t limit = 0;
  std::optional<std::string> cursor;
};

struct MembershipQuery {
  std::optional<IsolationDomainId> domain;
  std::optional<TenancySubject> subject;
  std::optional<MembershipState> state;
  std::optional<MembershipRole> role;
  std::size_t limit = 0;
  std::optional<std::string> cursor;
};

struct OwnershipQuery {
  std::optional<TenantId> child;
  std::optional<TenantId> parent;
  std::optional<OwnershipKind> kind;
  std::optional<LifecycleState> state;
  std::size_t limit = 0;
  std::optional<std::string> cursor;
};

struct BindingQuery {
  std::optional<ServiceId> service;
  std::optional<TenantId> tenant;
  std::optional<BindingKind> kind;
  std::optional<LifecycleState> state;
  std::size_t limit = 0;
  std::optional<std::string> cursor;
};

// ---------------------------------------------------------------------------
// Traversal
// ---------------------------------------------------------------------------

enum class TraversalDirection : std::uint8_t {
  Unspecified = 0,
  /// Walk from a tenant towards the tenants that own it.
  Ancestors = 1,
  /// Walk from a tenant towards the tenants it owns.
  Descendants = 2,
};

[[nodiscard]] std::string_view to_token(TraversalDirection direction) noexcept;
[[nodiscard]] bool parse_traversal_direction(std::string_view token, TraversalDirection& out) noexcept;

struct OwnershipTraversalRequest {
  TenantId start;
  TraversalDirection direction = TraversalDirection::Unspecified;
  /// When set, only edges of this kind are followed. Unset follows every kind,
  /// which is a wider answer and is only produced when the caller asked for it.
  std::optional<OwnershipKind> kind;
  std::optional<LifecycleState> only_state;
  std::size_t max_depth = 0;
  std::size_t max_results = 0;
};

struct OwnershipStep {
  TenantId from;
  TenantId to;
  OwnershipKind kind = OwnershipKind::Unspecified;
  LifecycleState state = LifecycleState::Unspecified;
  std::size_t depth = 0;
};

struct OwnershipTraversal {
  TenantId start;
  TraversalDirection direction = TraversalDirection::Unspecified;
  std::vector<OwnershipStep> steps;
  /// Every tenant reached, in deterministic breadth first order, excluding the
  /// start unless the start was reached again. A tenant reached by two paths
  /// appears once; the paths that reached it are in steps.
  std::vector<TenantId> reached;
  std::size_t max_depth_reached = 0;
  /// True when the walk stopped because a bound was reached. A truncated walk
  /// is not a complete answer and never claims to be.
  bool truncated = false;
  /// True when a bound other than max_results stopped the walk, so a caller can
  /// tell "there is more" from "there was too much".
  bool depth_limited = false;
};

// ---------------------------------------------------------------------------
// Explanation
// ---------------------------------------------------------------------------

/// Everything this registry knows about one subject, and an explicit statement
/// of what it does not know.
struct Explanation {
  TenancySubject subject;
  SubjectRecord record;
  /// The accountable owner principal, if one is declared.
  std::optional<PrincipalId> owner;
  /// Ownership edges where this subject is the child.
  std::vector<OwnershipEdge> owned_by;
  /// The tenant identities above this one, nearest first, following in-force
  /// ownership edges. Bounded by ExplainOptions::max_lineage_depth; when the
  /// walk stops at that bound the explanation says so in unknowns rather than
  /// presenting a partial chain as a complete one.
  std::vector<TenantId> ownership_lineage;
  /// Ownership edges where this subject is the parent.
  std::vector<OwnershipEdge> owns;
  std::vector<ServiceBinding> bindings;
  std::vector<IsolationMembership> memberships;
  std::vector<std::pair<IsolationDomainId, DomainGeneration>> domain_generations;
  /// A permit that would allow this identity to be reused, if one is
  /// outstanding. Present here so that "this retired identity may be rebound"
  /// is answerable without reading the raw record.
  std::optional<RebindPermit> outstanding_rebind_permit;
  RegistryGeneration generation;
  ControlEpoch control_epoch;
  Incarnation incarnation;
  /// Every question this explanation could not answer with a known value, in
  /// canonical order. An empty list means every field above is known.
  std::vector<std::string> unknowns;
  /// The canonical digest of everything above. Two explanations of the same
  /// state are byte for byte identical and therefore share a digest.
  [[nodiscard]] ContentDigest digest() const;
  [[nodiscard]] std::string to_json() const;
  [[nodiscard]] std::string to_text() const;
};

/// Counts of records in one lifecycle state.
struct StateCount {
  LifecycleState state = LifecycleState::Unspecified;
  std::uint64_t count = 0;
};

struct RegistryStats {
  RegistryGeneration generation;
  ControlEpoch control_epoch;
  Incarnation incarnation;
  std::optional<ContentDigest> store_id;
  JournalSequence committed_sequence;
  std::uint64_t tenants = 0;
  std::uint64_t services = 0;
  std::uint64_t isolation_domains = 0;
  std::uint64_t ownership_edges = 0;
  std::uint64_t service_bindings = 0;
  std::uint64_t isolation_memberships = 0;
  std::vector<StateCount> tenants_by_state;
  std::vector<StateCount> services_by_state;
  std::vector<StateCount> domains_by_state;
  [[nodiscard]] std::string to_text() const;
};

}  // namespace tenant_registry

#endif  // TENANT_REGISTRY_QUERY_HPP
