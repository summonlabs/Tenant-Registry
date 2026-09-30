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
#include <optional>
#include <string>

#include "test_support.hpp"

namespace treg_test {
namespace {

using tenant_registry::ErrorCode;
using tenant_registry::MutationReceipt;
using tenant_registry::OperationKind;
using tenant_registry::PutOwnershipOutcome;
using tenant_registry::PutOwnershipRequest;
using tenant_registry::RemoveOwnershipRequest;
using tenant_registry::subject_state;
using tenant_registry::TenancyMetadata;
using tenant_registry::TransitionOwnershipRequest;
using tenant_registry::TransitionSubjectOutcome;

std::size_t in_force_administrative_owners(const RegistrySnapshot& snapshot, const TenantId& child) {
  std::size_t count = 0;
  for (const OwnershipEdge& edge : snapshot.ownership_edges) {
    if (edge.child == child && edge.kind == OwnershipKind::Administrative && is_in_force(edge.state)) {
      ++count;
    }
  }
  return count;
}

PutOwnershipRequest ownership_request(const TenantRegistry& registry, const TenantId& child, const TenantId& parent,
                                      OwnershipKind kind, LifecycleState initial_state,
                                      std::optional<RecordRevision> expected_revision = std::nullopt) {
  return PutOwnershipRequest{context(registry.generation()), child, parent, kind, initial_state, expected_revision};
}

PutOwnershipOutcome put(Harness& harness, const TenantId& child, const TenantId& parent, OwnershipKind kind,
                        LifecycleState initial_state,
                        std::optional<RecordRevision> expected_revision = std::nullopt) {
  return unwrap(harness.registry().put_ownership(
                    ownership_request(harness.registry(), child, parent, kind, initial_state, expected_revision)),
                "put_ownership");
}

TREG_TEST(ownership, an_edge_is_put_transitioned_and_removed) {
  Harness harness = Harness::ephemeral();
  const TenantRecord child = harness.active_tenant("child");
  const TenantRecord parent = harness.active_tenant("parent");
  const RegistryGeneration before = harness.generation();

  const PutOwnershipOutcome created =
      put(harness, child.id, parent.id, OwnershipKind::Operational, LifecycleState::Active);
  const OwnershipEdge& edge = created.edge;
  TREG_CHECK_EQ(edge.child, child.id);
  TREG_CHECK_EQ(edge.parent, parent.id);
  TREG_CHECK_EQ(edge.kind, OwnershipKind::Operational);
  TREG_CHECK_EQ(edge.state, LifecycleState::Active);
  TREG_CHECK_EQ(edge.revision.value(), 1u);
  TREG_CHECK_EQ(edge.created_generation, created.receipt.generation);
  TREG_CHECK_EQ(edge.updated_generation, created.receipt.generation);
  TREG_CHECK_EQ(created.receipt.generation.value(), before.value() + 1);
  TREG_CHECK_EQ(created.receipt.operation, OperationKind::PutOwnership);
  TREG_CHECK_EQ(edge.provenance, context(before).actor);
  TREG_CHECK_EQ(edge.origin_digest, created.receipt.request_digest);
  TREG_CHECK_EQ(edge.natural_key(), std::string{"tenant:child|tenant:parent"});

  TREG_REQUIRE(harness.snapshot().ownership_edges.size() == 1u);
  TREG_CHECK_EQ(to_canonical(harness.snapshot().ownership_edges.at(0)), to_canonical(edge));

  const RegistryGeneration suspended_at = harness.generation();
  const auto suspended = harness.registry().transition_ownership(
      TransitionOwnershipRequest{context(suspended_at), child.id, parent.id, RecordRevision::from_value(1),
                                 LifecycleState::Suspended});
  TREG_REQUIRE_OK(suspended);
  TREG_CHECK_EQ(suspended.value().revision.value(), 2u);
  TREG_CHECK_EQ(suspended.value().generation.value(), suspended_at.value() + 1);
  TREG_CHECK_EQ(harness.snapshot().ownership_edges.at(0).state, LifecycleState::Suspended);

  const auto reinstated = harness.registry().transition_ownership(
      TransitionOwnershipRequest{context(harness.generation()), child.id, parent.id, RecordRevision::from_value(2),
                                 LifecycleState::Active});
  TREG_REQUIRE_OK(reinstated);
  TREG_CHECK_EQ(reinstated.value().revision.value(), 3u);
  TREG_CHECK_EQ(harness.snapshot().ownership_edges.at(0).state, LifecycleState::Active);
  TREG_CHECK_EQ(harness.snapshot().ownership_edges.at(0).created_generation, edge.created_generation);

  const RegistryGeneration removal_generation = harness.generation();
  const auto removed = harness.registry().remove_ownership(
      RemoveOwnershipRequest{context(removal_generation), child.id, parent.id, RecordRevision::from_value(3)});
  TREG_REQUIRE_OK(removed);
  TREG_CHECK_EQ(removed.value().generation.value(), removal_generation.value() + 1);
  TREG_CHECK(harness.snapshot().ownership_edges.empty());
  TREG_CHECK_EQ(harness.snapshot().digest(), harness.snapshot().digest());
  TREG_CHECK(harness.registry().list_ownership(OwnershipQuery{}).value().items.empty());

  // Removing again, and transitioning what no longer exists, are both refusals.
  TREG_CHECK_CODE(harness.registry().remove_ownership(
                      RemoveOwnershipRequest{context(harness.generation()), child.id, parent.id,
                                             RecordRevision::from_value(3)}),
                  ErrorCode::RelationshipAbsent);
  TREG_CHECK_CODE(harness.registry().transition_ownership(
                      TransitionOwnershipRequest{context(harness.generation()), child.id, parent.id,
                                                 RecordRevision::from_value(3), LifecycleState::Active}),
                  ErrorCode::RelationshipAbsent);
}

TREG_TEST(ownership, the_natural_key_is_the_child_then_the_parent) {
  Harness harness = Harness::ephemeral();
  const TenantRecord a = harness.active_tenant("a");
  const TenantRecord b = harness.active_tenant("b");
  const TenantRecord c = harness.active_tenant("c");

  const OwnershipEdge first = put(harness, a.id, b.id, OwnershipKind::Operational, LifecycleState::Declared).edge;
  const OwnershipEdge second = put(harness, b.id, c.id, OwnershipKind::Operational, LifecycleState::Declared).edge;
  const OwnershipEdge third = put(harness, a.id, c.id, OwnershipKind::Operational, LifecycleState::Declared).edge;

  TREG_CHECK_EQ(first.natural_key(), std::string{"tenant:a|tenant:b"});
  TREG_CHECK_EQ(second.natural_key(), std::string{"tenant:b|tenant:c"});
  TREG_CHECK_EQ(third.natural_key(), std::string{"tenant:a|tenant:c"});
  TREG_CHECK(first.natural_key() != second.natural_key());
  TREG_CHECK(first.natural_key() != third.natural_key());
  TREG_CHECK_EQ(harness.snapshot().ownership_edges.size(), 3u);
}

TREG_TEST(ownership, at_most_one_in_force_administrative_owner_per_child) {
  Harness harness = Harness::ephemeral();
  const TenantRecord child = harness.active_tenant("child");
  const TenantRecord first_owner = harness.active_tenant("owner-one");
  const TenantRecord second_owner = harness.active_tenant("owner-two");

  put(harness, child.id, first_owner.id, OwnershipKind::Administrative, LifecycleState::Active);
  TREG_CHECK_EQ(in_force_administrative_owners(harness.snapshot(), child.id), std::size_t{1});

  const auto conflict = harness.registry().put_ownership(
      ownership_request(harness.registry(), child.id, second_owner.id, OwnershipKind::Administrative,
                        LifecycleState::Active));
  TREG_CHECK_CODE(conflict, ErrorCode::BindingConflict);
  TREG_CHECK(conflict.error().detail().find("owner-one") != std::string::npos);
  TREG_CHECK_EQ(in_force_administrative_owners(harness.snapshot(), child.id), std::size_t{1});

  // Other kinds are answers to other questions and may coexist with the one
  // accountable owner, as long as they answer about a different relationship.
  put(harness, child.id, second_owner.id, OwnershipKind::Operational, LifecycleState::Active);
  TREG_CHECK_EQ(in_force_administrative_owners(harness.snapshot(), child.id), std::size_t{1});
  TREG_CHECK_EQ(harness.snapshot().ownership_edges.size(), 2u);

  // A declared administrative edge is not in force, so it is allowed to exist.
  const TenantRecord third_owner = harness.active_tenant("owner-three");
  const OwnershipEdge declared =
      put(harness, child.id, third_owner.id, OwnershipKind::Administrative, LifecycleState::Declared).edge;
  TREG_CHECK_EQ(declared.state, LifecycleState::Declared);
  TREG_CHECK_EQ(in_force_administrative_owners(harness.snapshot(), child.id), std::size_t{1});

  // Making it in force would produce two answers to one question, and is refused.
  const auto late_conflict = harness.registry().transition_ownership(
      TransitionOwnershipRequest{context(harness.generation()), child.id, third_owner.id, declared.revision,
                                 LifecycleState::Active});
  TREG_CHECK_CODE(late_conflict, ErrorCode::BindingConflict);
  TREG_CHECK_EQ(in_force_administrative_owners(harness.snapshot(), child.id), std::size_t{1});

  // With the first owner gone, the same transition is legal.
  const auto removed = harness.registry().remove_ownership(
      RemoveOwnershipRequest{context(harness.generation()), child.id, first_owner.id, RecordRevision::from_value(1)});
  TREG_REQUIRE_OK(removed);
  const auto promoted = harness.registry().transition_ownership(
      TransitionOwnershipRequest{context(harness.generation()), child.id, third_owner.id, declared.revision,
                                 LifecycleState::Active});
  TREG_REQUIRE_OK(promoted);
  TREG_CHECK_EQ(in_force_administrative_owners(harness.snapshot(), child.id), std::size_t{1});
}

TREG_TEST(ownership, a_tenant_cannot_own_itself) {
  Harness harness = Harness::ephemeral();
  const TenantRecord tenant = harness.active_tenant("self");
  const RegistrySnapshot before = harness.snapshot();
  const auto refusal = harness.registry().put_ownership(
      ownership_request(harness.registry(), tenant.id, tenant.id, OwnershipKind::Administrative,
                        LifecycleState::Active));
  TREG_CHECK_CODE(refusal, ErrorCode::SelfReference);
  TREG_CHECK(refusal.error().detail().find("self cannot own itself") != std::string::npos);
  TREG_CHECK(harness.snapshot().ownership_edges.empty());
  TREG_CHECK_EQ(harness.snapshot().digest(), before.digest());
}

TREG_TEST(ownership, a_cycle_is_refused) {
  Harness harness = Harness::ephemeral();
  const TenantRecord a = harness.active_tenant("a");
  const TenantRecord b = harness.active_tenant("b");
  const TenantRecord c = harness.active_tenant("c");
  put(harness, a.id, b.id, OwnershipKind::Operational, LifecycleState::Active);
  put(harness, b.id, c.id, OwnershipKind::Operational, LifecycleState::Active);
  const RegistrySnapshot before = harness.snapshot();

  const auto refusal = harness.registry().put_ownership(
      ownership_request(harness.registry(), c.id, a.id, OwnershipKind::Operational, LifecycleState::Active));
  TREG_CHECK_CODE(refusal, ErrorCode::OwnershipCycle);
  TREG_CHECK(refusal.error().detail().find("would create a cycle through c") != std::string::npos);
  TREG_CHECK_EQ(harness.snapshot().ownership_edges.size(), 2u);
  TREG_CHECK_EQ(harness.snapshot().digest(), before.digest());
}

TREG_TEST(ownership, a_chain_deeper_than_the_configured_limit_is_refused) {
  RegistryLimits limits;
  limits.max_ownership_depth = 2;
  Harness harness = Harness::ephemeral(limits);
  const TenantRecord t0 = harness.active_tenant("t0");
  const TenantRecord t1 = harness.active_tenant("t1");
  const TenantRecord t2 = harness.active_tenant("t2");
  const TenantRecord t3 = harness.active_tenant("t3");

  put(harness, t0.id, t1.id, OwnershipKind::Operational, LifecycleState::Active);
  put(harness, t1.id, t2.id, OwnershipKind::Operational, LifecycleState::Active);
  put(harness, t2.id, t3.id, OwnershipKind::Operational, LifecycleState::Active);
  const RegistrySnapshot before = harness.snapshot();

  const auto too_deep = harness.registry().put_ownership(
      ownership_request(harness.registry(), t3.id, t0.id, OwnershipKind::Operational, LifecycleState::Active));
  TREG_CHECK_CODE(too_deep, ErrorCode::OwnershipDepthExceeded);
  TREG_CHECK(too_deep.error().detail().find("2") != std::string::npos);
  TREG_CHECK_EQ(harness.snapshot().ownership_edges.size(), 3u);
  TREG_CHECK_EQ(harness.snapshot().digest(), before.digest());

  // The same chain is a cycle once the limit is the configured default, so the
  // refusal above is the depth bound and not the cycle walk.
  Harness deep = Harness::ephemeral();
  const TenantRecord d0 = deep.active_tenant("t0");
  const TenantRecord d1 = deep.active_tenant("t1");
  const TenantRecord d2 = deep.active_tenant("t2");
  const TenantRecord d3 = deep.active_tenant("t3");
  put(deep, d0.id, d1.id, OwnershipKind::Operational, LifecycleState::Active);
  put(deep, d1.id, d2.id, OwnershipKind::Operational, LifecycleState::Active);
  put(deep, d2.id, d3.id, OwnershipKind::Operational, LifecycleState::Active);
  TREG_CHECK_CODE(deep.registry().put_ownership(ownership_request(deep.registry(), d3.id, d0.id,
                                                                 OwnershipKind::Operational,
                                                                 LifecycleState::Active)),
                  ErrorCode::OwnershipCycle);
}

TREG_TEST(ownership, an_edge_to_a_tenant_that_cannot_receive_one_is_refused) {
  Harness harness = Harness::ephemeral();
  const TenantRecord child = harness.active_tenant("child");
  const TenantRecord suspended_parent = harness.active_tenant("suspended-parent");
  const TenantRecord retiring_parent = harness.active_tenant("retiring-parent");
  const TenantRecord declared_parent = harness.create_tenant("declared-parent");
  const TenantRecord declared_child = harness.create_tenant("declared-child");

  const TransitionSubjectOutcome suspended =
      unwrap(harness.registry().transition_subject(harness.transition_request(
                 TenancySubject::of_tenant(suspended_parent.id), suspended_parent.revision,
                 LifecycleState::Suspended)),
             "transition_subject");
  TREG_CHECK_EQ(subject_state(suspended.record), LifecycleState::Suspended);

  // A suspended tenant is still an answerable target, because suspension is recoverable.
  put(harness, child.id, suspended_parent.id, OwnershipKind::Operational, LifecycleState::Active);

  const auto to_retiring = harness.registry().transition_subject(harness.transition_request(
      TenancySubject::of_tenant(retiring_parent.id), retiring_parent.revision, LifecycleState::Retiring));
  TREG_REQUIRE_OK(to_retiring);
  TREG_CHECK_CODE(harness.registry().put_ownership(ownership_request(harness.registry(), child.id,
                                                                    retiring_parent.id, OwnershipKind::Operational,
                                                                    LifecycleState::Active)),
                  ErrorCode::ReferenceTerminal);
  TREG_CHECK_CODE(harness.registry().put_ownership(ownership_request(harness.registry(), child.id,
                                                                    declared_parent.id, OwnershipKind::Operational,
                                                                    LifecycleState::Active)),
                  ErrorCode::ReferenceTerminal);
  TREG_CHECK_CODE(harness.registry().put_ownership(ownership_request(harness.registry(), declared_child.id,
                                                                    suspended_parent.id, OwnershipKind::Operational,
                                                                    LifecycleState::Active)),
                  ErrorCode::ReferenceNotYetLive);
}

TREG_TEST(ownership, expected_revision_is_an_assertion_about_existence) {
  Harness harness = Harness::ephemeral();
  const TenantRecord child = harness.active_tenant("child");
  const TenantRecord parent = harness.active_tenant("parent");

  // Absent means "I assert this relationship does not exist"; it is checked.
  const PutOwnershipOutcome first =
      put(harness, child.id, parent.id, OwnershipKind::Operational, LifecycleState::Active);
  const auto duplicate = harness.registry().put_ownership(
      ownership_request(harness.registry(), child.id, parent.id, OwnershipKind::Operational, LifecycleState::Active));
  TREG_CHECK_CODE(duplicate, ErrorCode::DuplicateRelationship);
  TREG_CHECK(duplicate.error().detail().find("revision 1") != std::string::npos);

  // Present means "I assert it exists at exactly this revision"; a wrong
  // assertion is refused rather than resolved.
  const auto stale = harness.registry().put_ownership(
      ownership_request(harness.registry(), child.id, parent.id, OwnershipKind::Operational, LifecycleState::Active,
                        RecordRevision::from_value(7)));
  TREG_CHECK_CODE(stale, ErrorCode::StaleRecordRevision);
  TREG_CHECK(stale.error().detail().find("revision 1") != std::string::npos);
  TREG_CHECK(stale.error().detail().find("revision 7") != std::string::npos);

  const TenantRecord other = harness.active_tenant("other");
  const auto absent_asserted = harness.registry().put_ownership(
      ownership_request(harness.registry(), child.id, other.id, OwnershipKind::Operational, LifecycleState::Active,
                        RecordRevision::from_value(1)));
  TREG_CHECK_CODE(absent_asserted, ErrorCode::StaleRecordRevision);
  TREG_CHECK(absent_asserted.error().detail().find("no such relationship exists") != std::string::npos);

  // A right assertion updates the relationship in place.
  const RegistryGeneration update_generation = harness.generation();
  const PutOwnershipOutcome updated =
      put(harness, child.id, parent.id, OwnershipKind::Regulatory, LifecycleState::Declared,
          RecordRevision::from_value(1));
  TREG_CHECK_EQ(updated.edge.revision.value(), 2u);
  TREG_CHECK_EQ(updated.edge.kind, OwnershipKind::Regulatory);
  TREG_CHECK_EQ(updated.edge.state, LifecycleState::Declared);
  TREG_CHECK_EQ(updated.edge.created_generation, first.edge.created_generation);
  TREG_CHECK_EQ(updated.edge.updated_generation.value(), update_generation.value() + 1);
  TREG_CHECK_EQ(harness.snapshot().ownership_edges.size(), 1u);
  TREG_CHECK_EQ(harness.snapshot().ownership_edges.at(0).revision.value(), 2u);
}

TREG_TEST(ownership, a_relationship_moves_only_between_legal_states) {
  Harness harness = Harness::ephemeral();
  const TenantRecord child = harness.active_tenant("child");
  const TenantRecord parent = harness.active_tenant("parent");
  const OwnershipEdge edge = put(harness, child.id, parent.id, OwnershipKind::Operational,
                                 LifecycleState::Active)
                                 .edge;

  const auto unchanged = harness.registry().transition_ownership(
      TransitionOwnershipRequest{context(harness.generation()), child.id, parent.id, edge.revision,
                                 LifecycleState::Active});
  TREG_CHECK_CODE(unchanged, ErrorCode::LifecycleStateUnchanged);

  const auto illegal = harness.registry().transition_ownership(
      TransitionOwnershipRequest{context(harness.generation()), child.id, parent.id, edge.revision,
                                 LifecycleState::Declared});
  TREG_CHECK_CODE(illegal, ErrorCode::LifecycleTransitionIllegal);
  TREG_REQUIRE(!illegal.error().suppressed().empty());
  TREG_CHECK_EQ(illegal.error().suppressed().at(0),
                std::string{"legal targets from active: "} + std::string{legal_targets_text(LifecycleState::Active)});

  const auto immortal = harness.registry().transition_ownership(
      TransitionOwnershipRequest{context(harness.generation()), child.id, parent.id, edge.revision,
                                 LifecycleState::Tombstoned});
  TREG_CHECK_CODE(immortal, ErrorCode::InvalidEnumValue);

  const auto wrong_revision = harness.registry().transition_ownership(
      TransitionOwnershipRequest{context(harness.generation()), child.id, parent.id, RecordRevision::from_value(5),
                                 LifecycleState::Suspended});
  TREG_CHECK_CODE(wrong_revision, ErrorCode::StaleRecordRevision);
  TREG_CHECK_EQ(harness.snapshot().ownership_edges.at(0).state, LifecycleState::Active);
}

}  // namespace
}  // namespace treg_test
