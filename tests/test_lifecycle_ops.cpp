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

#include <cstdint>
#include <optional>
#include <string>

#include "test_support.hpp"

namespace treg_test {
namespace {

using tenant_registry::ErrorCode;
using tenant_registry::IrreversibleAcknowledgement;
using tenant_registry::is_terminal;
using tenant_registry::OperationKind;
using tenant_registry::PutIsolationMembershipOutcome;
using tenant_registry::PutIsolationMembershipRequest;
using tenant_registry::PutOwnershipOutcome;
using tenant_registry::PutOwnershipRequest;
using tenant_registry::PutServiceBindingOutcome;
using tenant_registry::PutServiceBindingRequest;
using tenant_registry::RemoveIsolationMembershipRequest;
using tenant_registry::RemoveOwnershipRequest;
using tenant_registry::RemoveServiceBindingRequest;
using tenant_registry::SetMetadataOutcome;
using tenant_registry::SetMetadataRequest;
using tenant_registry::SetOwnerRequest;
using tenant_registry::subject_revision;
using tenant_registry::subject_state;
using tenant_registry::TenancyMetadata;
using tenant_registry::TombstoneOutcome;
using tenant_registry::TombstoneRequest;
using tenant_registry::TransitionOwnershipRequest;
using tenant_registry::TransitionSubjectOutcome;

/// Moves one subject and checks the two invariants that hold of every accepted
/// lifecycle mutation: one generation and one revision, never two.
SubjectRecord step(Harness& harness, const TenancySubject& subject, RecordRevision revision,
                   LifecycleState target) {
  const RegistryGeneration generation_before = harness.generation();
  const TransitionSubjectOutcome outcome =
      unwrap(harness.registry().transition_subject(harness.transition_request(subject, revision, target)),
             "transition_subject");
  TREG_CHECK_EQ(harness.generation().value(), generation_before.value() + 1);
  TREG_CHECK_EQ(outcome.receipt.generation.value(), generation_before.value() + 1);
  TREG_CHECK_EQ(outcome.receipt.operation, OperationKind::TransitionSubject);
  TREG_CHECK(!outcome.receipt.replayed);
  TREG_CHECK_EQ(subject_state(outcome.record), target);
  TREG_CHECK_EQ(subject_revision(outcome.record).value(), revision.value() + 1);
  TREG_CHECK_EQ(outcome.receipt.revision, subject_revision(outcome.record));
  return outcome.record;
}

TREG_TEST(lifecycle_ops, the_whole_lifecycle_of_a_tenant_through_the_registry) {
  Harness harness = Harness::ephemeral();
  const TenantRecord declared = harness.create_tenant("acme", std::optional<std::string>{"Acme"});
  TREG_CHECK_EQ(declared.state, LifecycleState::Declared);
  const TenancySubject subject = TenancySubject::of_tenant(declared.id);

  const SubjectRecord active = step(harness, subject, declared.revision, LifecycleState::Active);
  const SubjectRecord suspended = step(harness, subject, subject_revision(active), LifecycleState::Suspended);
  const SubjectRecord reinstated = step(harness, subject, subject_revision(suspended), LifecycleState::Active);
  const SubjectRecord retiring = step(harness, subject, subject_revision(reinstated), LifecycleState::Retiring);
  const SubjectRecord aborted = step(harness, subject, subject_revision(retiring), LifecycleState::Active);
  const SubjectRecord withdrawing = step(harness, subject, subject_revision(aborted), LifecycleState::Retiring);

  const SubjectRecord retired = step(harness, subject, subject_revision(withdrawing), LifecycleState::Retired);
  const TenantRecord* retired_tenant = std::get_if<TenantRecord>(&retired);
  TREG_CHECK(retired_tenant != nullptr);
  if (retired_tenant != nullptr) {
    TREG_CHECK(retired_tenant->retired_generation.has_value());
    TREG_CHECK_EQ(*retired_tenant->retired_generation, retired_tenant->updated_generation);
    TREG_CHECK_EQ(retired_tenant->retired_generation->value(), harness.generation().value());
    TREG_CHECK(!retired_tenant->tombstone.has_value());
  }

  // Tombstoning is the one irreversible step, and it is not a transition.
  const RegistryGeneration before_tombstone = harness.generation();
  const TombstoneOutcome tombstoned =
      unwrap(harness.registry().tombstone(TombstoneRequest{context(before_tombstone), subject,
                                                           subject_revision(retired),
                                                           IrreversibleAcknowledgement::acknowledged(),
                                                           std::nullopt, std::string{"withdrawn and fenced"}}),
             "tombstone");
  TREG_CHECK_EQ(subject_state(tombstoned.record), LifecycleState::Tombstoned);
  TREG_CHECK_EQ(subject_revision(tombstoned.record).value(), subject_revision(retired).value() + 1);
  TREG_CHECK_EQ(harness.generation().value(), before_tombstone.value() + 1);
  const TenantRecord* fenced = std::get_if<TenantRecord>(&tombstoned.record);
  TREG_CHECK(fenced != nullptr);
  if (fenced != nullptr) {
    TREG_CHECK(fenced->tombstone.has_value());
    TREG_CHECK_EQ(fenced->tombstone->note(), "withdrawn and fenced");
    TREG_CHECK_EQ(fenced->tombstone->tombstoned_generation(), tombstoned.receipt.generation);
  }
}

TREG_TEST(lifecycle_ops, a_declaration_may_be_withdrawn_without_ever_being_admitted) {
  Harness harness = Harness::ephemeral();
  const TenantRecord declared = harness.create_tenant("never-live");
  const SubjectRecord retired =
      step(harness, TenancySubject::of_tenant(declared.id), declared.revision, LifecycleState::Retired);
  const TenantRecord* record = std::get_if<TenantRecord>(&retired);
  TREG_CHECK(record != nullptr);
  if (record != nullptr) {
    TREG_CHECK(record->retired_generation.has_value());
    TREG_CHECK_EQ(record->retired_generation->value(), harness.generation().value());
  }
}

TREG_TEST(lifecycle_ops, the_same_lifecycle_applies_to_a_service_and_a_domain) {
  Harness harness = Harness::ephemeral();
  const ServiceRecord service = harness.create_service("renderer");
  const TenancySubject service_subject = TenancySubject::of_service(service.id);
  const SubjectRecord service_active = step(harness, service_subject, service.revision, LifecycleState::Active);
  const SubjectRecord service_suspended =
      step(harness, service_subject, subject_revision(service_active), LifecycleState::Suspended);
  const SubjectRecord service_retiring =
      step(harness, service_subject, subject_revision(service_suspended), LifecycleState::Retiring);
  TREG_CHECK_EQ(subject_state(step(harness, service_subject, subject_revision(service_retiring),
                                   LifecycleState::Retired)),
                LifecycleState::Retired);

  const IsolationDomainRecord domain = harness.create_domain("zone-a", IsolationClass::Regulatory);
  const TenancySubject domain_subject = TenancySubject::of_isolation_domain(domain.id);
  const SubjectRecord domain_active = step(harness, domain_subject, domain.revision, LifecycleState::Active);
  const SubjectRecord domain_retiring =
      step(harness, domain_subject, subject_revision(domain_active), LifecycleState::Retiring);
  TREG_CHECK_EQ(subject_state(step(harness, domain_subject, subject_revision(domain_retiring),
                                   LifecycleState::Retired)),
                LifecycleState::Retired);
  TREG_CHECK_EQ(harness.service("renderer").state, LifecycleState::Retired);
  TREG_CHECK_EQ(harness.domain("zone-a").state, LifecycleState::Retired);
}

TREG_TEST(lifecycle_ops, a_transition_to_the_current_state_is_refused) {
  Harness harness = Harness::ephemeral();
  const TenantRecord active = harness.active_tenant("acme");
  const RegistrySnapshot before = harness.snapshot();

  const auto unchanged = harness.registry().transition_subject(
      harness.transition_request(TenancySubject::of_tenant(active.id), active.revision, LifecycleState::Active));
  TREG_CHECK_CODE(unchanged, ErrorCode::LifecycleStateUnchanged);
  TREG_CHECK(unchanged.error().detail().find("tenant:acme") != std::string::npos);
  TREG_CHECK(unchanged.error().detail().find("active") != std::string::npos);
  TREG_REQUIRE(!unchanged.error().suppressed().empty());
  TREG_CHECK_EQ(unchanged.error().suppressed().at(0),
                std::string{"legal targets from here: "} +
                    std::string{legal_targets_text(LifecycleState::Active)});

  // Still unchanged, and the record keeps its revision.
  TREG_CHECK_EQ(harness.snapshot().digest(), before.digest());
  TREG_CHECK_EQ(harness.tenant("acme").revision, active.revision);
}

TREG_TEST(lifecycle_ops, an_illegal_transition_is_refused_with_the_legal_targets_as_evidence) {
  Harness harness = Harness::ephemeral();
  const TenantRecord active = harness.active_tenant("acme");
  const TenancySubject subject = TenancySubject::of_tenant(active.id);
  const TenantRecord declared = harness.create_tenant("fresh");
  const RegistrySnapshot before = harness.snapshot();

  const auto backwards = harness.registry().transition_subject(
      harness.transition_request(subject, active.revision, LifecycleState::Declared));
  TREG_CHECK_CODE(backwards, ErrorCode::LifecycleTransitionIllegal);
  TREG_REQUIRE(!backwards.error().suppressed().empty());
  TREG_CHECK_EQ(backwards.error().suppressed().at(0),
                std::string{"legal targets from active: "} + std::string{legal_targets_text(LifecycleState::Active)});

  const auto skipped = harness.registry().transition_subject(
      harness.transition_request(TenancySubject::of_tenant(declared.id), declared.revision,
                                 LifecycleState::Suspended));
  TREG_CHECK_CODE(skipped, ErrorCode::LifecycleTransitionIllegal);
  TREG_REQUIRE(!skipped.error().suppressed().empty());
  TREG_CHECK_EQ(skipped.error().suppressed().at(0),
                std::string{"legal targets from declared: "} +
                    std::string{legal_targets_text(LifecycleState::Declared)});

  TREG_CHECK_EQ(harness.snapshot().digest(), before.digest());
  TREG_CHECK_EQ(harness.tenant("acme").state, LifecycleState::Active);
}

TREG_TEST(lifecycle_ops, tombstoned_is_not_reachable_through_an_ordinary_transition) {
  Harness harness = Harness::ephemeral();
  const TenantRecord active = harness.active_tenant("acme");
  const TenancySubject subject = TenancySubject::of_tenant(active.id);
  TREG_CHECK_CODE(harness.registry().transition_subject(
                      harness.transition_request(subject, active.revision, LifecycleState::Tombstoned)),
                  ErrorCode::IrreversibleActionNotAcknowledged);
  TREG_CHECK_EQ(harness.tenant("acme").state, LifecycleState::Active);
  TREG_CHECK_EQ(harness.tenant("acme").revision, active.revision);
}

TREG_TEST(lifecycle_ops, a_stale_record_revision_is_refused_naming_both_revisions) {
  Harness harness = Harness::ephemeral();
  const TenantRecord suspended = harness.active_tenant("acme");

  const auto stale = harness.registry().transition_subject(
      harness.transition_request(TenancySubject::of_tenant(suspended.id), RecordRevision::from_value(9),
                                 LifecycleState::Suspended));
  TREG_CHECK_CODE(stale, ErrorCode::StaleRecordRevision);
  TREG_CHECK(stale.error().detail().find("tenant:acme") != std::string::npos);
  TREG_CHECK(stale.error().detail().find("revision 2") != std::string::npos);
  TREG_CHECK(stale.error().detail().find("revision 9") != std::string::npos);
  TREG_CHECK_EQ(harness.tenant("acme").revision.value(), 2u);
  TREG_CHECK_EQ(harness.tenant("acme").state, LifecycleState::Active);
}

TREG_TEST(lifecycle_ops, every_accepted_mutation_advances_the_generation_by_exactly_one) {
  Harness harness = Harness::ephemeral();
  const auto expect_next_generation = [&harness](RegistryGeneration before, const MutationReceipt& receipt) {
    TREG_CHECK_EQ(harness.generation().value(), before.value() + 1);
    TREG_CHECK_EQ(receipt.generation.value(), before.value() + 1);
    TREG_CHECK_EQ(harness.snapshot().generation, receipt.generation);
  };

  RegistryGeneration before = harness.generation();
  const CreateTenantOutcome tenant =
      unwrap(harness.registry().create_tenant(CreateTenantRequest{context(before), tenant_id("acme"),
                                                                 std::nullopt, std::nullopt, TenancyMetadata{}}),
             "create_tenant");
  expect_next_generation(before, tenant.receipt);
  const TenancySubject subject = TenancySubject::of_tenant(tenant.record.id);

  before = harness.generation();
  const TransitionSubjectOutcome activated =
      unwrap(harness.registry().transition_subject(harness.transition_request(subject, tenant.record.revision,
                                                                             LifecycleState::Active)),
             "transition_subject");
  expect_next_generation(before, activated.receipt);

  before = harness.generation();
  const auto owner = harness.registry().set_owner(SetOwnerRequest{context(before), tenant.record.id,
                                                                 subject_revision(activated.record),
                                                                 std::optional<PrincipalId>{principal_id("ops")}});
  TREG_REQUIRE_OK(owner);
  expect_next_generation(before, owner.value());
  TREG_CHECK_EQ(harness.tenant("acme").owner.value_or(principal_id("none")), principal_id("ops"));

  before = harness.generation();
  const SetMetadataOutcome metadata =
      unwrap(harness.registry().set_metadata(SetMetadataRequest{context(before), subject,
                                                               harness.tenant("acme").revision, {},
                                                               {entry("region", "eu")}}),
             "set_metadata");
  expect_next_generation(before, metadata.receipt);
  TREG_CHECK_EQ(revision_of(metadata.record).value(), 4u);
  TREG_CHECK_EQ(harness.tenant("acme").metadata.size(), 1u);

  const TenantRecord parent = harness.active_tenant("parent");
  before = harness.generation();
  const PutOwnershipOutcome edge =
      unwrap(harness.registry().put_ownership(PutOwnershipRequest{context(before), tenant.record.id, parent.id,
                                                                  OwnershipKind::Operational,
                                                                  LifecycleState::Active, std::nullopt}),
             "put_ownership");
  expect_next_generation(before, edge.receipt);

  const ServiceRecord service = harness.active_service("renderer");
  before = harness.generation();
  const PutServiceBindingOutcome binding =
      unwrap(harness.registry().put_service_binding(PutServiceBindingRequest{context(before), service.id,
                                                                            tenant.record.id,
                                                                            BindingKind::Serves,
                                                                            LifecycleState::Active, std::nullopt}),
             "put_service_binding");
  expect_next_generation(before, binding.receipt);

  const IsolationDomainRecord domain = harness.active_domain("zone-a");
  before = harness.generation();
  const PutIsolationMembershipOutcome membership =
      unwrap(harness.registry().put_isolation_membership(PutIsolationMembershipRequest{
                 context(before), subject, domain.id, MembershipRole::Secondary, MembershipState::Bound,
                 harness.domain_generation("zone-a"), std::nullopt}),
             "put_isolation_membership");
  expect_next_generation(before, membership.receipt);

  before = harness.generation();
  const auto unbound = harness.registry().remove_service_binding(
      RemoveServiceBindingRequest{context(before), service.id, tenant.record.id, BindingKind::Serves,
                                  RecordRevision::from_value(1)});
  TREG_REQUIRE_OK(unbound);
  expect_next_generation(before, unbound.value());

  before = harness.generation();
  const auto unjoined = harness.registry().remove_isolation_membership(
      RemoveIsolationMembershipRequest{context(before), subject, domain.id, RecordRevision::from_value(1),
                                       harness.domain_generation("zone-a")});
  TREG_REQUIRE_OK(unjoined);
  expect_next_generation(before, unjoined.value());

  before = harness.generation();
  const auto unowned = harness.registry().remove_ownership(
      RemoveOwnershipRequest{context(before), tenant.record.id, parent.id, RecordRevision::from_value(1)});
  TREG_REQUIRE_OK(unowned);
  expect_next_generation(before, unowned.value());
}

TREG_TEST(lifecycle_ops, every_accepted_mutation_advances_the_record_revision_by_exactly_one) {
  Harness harness = Harness::ephemeral();
  const TenantRecord created = harness.create_tenant("acme");
  TREG_CHECK_EQ(created.revision.value(), 1u);
  const TenancySubject subject = TenancySubject::of_tenant(created.id);

  TREG_CHECK_EQ(subject_revision(step(harness, subject, created.revision, LifecycleState::Active)).value(), 2u);

  const RegistryGeneration generation_before = harness.generation();
  const auto owner = harness.registry().set_owner(SetOwnerRequest{context(generation_before), created.id,
                                                                 RecordRevision::from_value(2),
                                                                 std::optional<PrincipalId>{principal_id("ops")}});
  TREG_REQUIRE_OK(owner);
  TREG_CHECK_EQ(owner.value().revision.value(), 3u);
  TREG_CHECK_EQ(harness.tenant("acme").revision.value(), 3u);

  const SetMetadataOutcome metadata =
      unwrap(harness.registry().set_metadata(SetMetadataRequest{context(harness.generation()), subject,
                                                               RecordRevision::from_value(3), {},
                                                               {entry("a", "1"), entry("b", "2")}}),
             "set_metadata");
  TREG_CHECK_EQ(metadata.receipt.revision.value(), 4u);
  TREG_CHECK_EQ(revision_of(metadata.record).value(), 4u);
  TREG_CHECK_EQ(harness.tenant("acme").revision.value(), 4u);

  const SetMetadataOutcome trimmed =
      unwrap(harness.registry().set_metadata(SetMetadataRequest{context(harness.generation()), subject,
                                                               RecordRevision::from_value(4),
                                                               {metadata_key("a")}, {}}),
             "set_metadata");
  TREG_CHECK_EQ(trimmed.receipt.revision.value(), 5u);
  TREG_CHECK_EQ(harness.tenant("acme").revision.value(), 5u);
  TREG_CHECK(!harness.tenant("acme").metadata.contains(metadata_key("a")));
  TREG_CHECK(harness.tenant("acme").metadata.contains(metadata_key("b")));

  // A relationship carries its own revision, advanced by its own mutations only.
  const TenantRecord parent = harness.active_tenant("parent");
  const PutOwnershipOutcome edge =
      unwrap(harness.registry().put_ownership(PutOwnershipRequest{context(harness.generation()), created.id,
                                                                  parent.id, OwnershipKind::Operational,
                                                                  LifecycleState::Active, std::nullopt}),
             "put_ownership");
  TREG_CHECK_EQ(edge.edge.revision.value(), 1u);
  TREG_CHECK_EQ(edge.edge.created_generation, edge.edge.updated_generation);
  TREG_CHECK_EQ(harness.tenant("acme").revision.value(), 5u);

  const auto moved = harness.registry().transition_ownership(
      TransitionOwnershipRequest{context(harness.generation()), created.id, parent.id, RecordRevision::from_value(1),
                                 LifecycleState::Suspended});
  TREG_REQUIRE_OK(moved);
  TREG_CHECK_EQ(moved.value().revision.value(), 2u);
  TREG_CHECK_EQ(harness.snapshot().ownership_edges.at(0).state, LifecycleState::Suspended);
  TREG_CHECK_EQ(harness.snapshot().ownership_edges.at(0).revision.value(), 2u);
}

TREG_TEST(lifecycle_ops, a_refusal_changes_no_state_at_all) {
  Harness harness = Harness::ephemeral();
  const TenantRecord active = harness.active_tenant("acme");
  const TenantRecord declared = harness.create_tenant("fresh");
  const RegistrySnapshot before = harness.snapshot();

  const auto stale_generation = harness.registry().transition_subject(
      TransitionSubjectRequest{context(RegistryGeneration::from_value(999)), TenancySubject::of_tenant(active.id),
                               active.revision, LifecycleState::Suspended});
  TREG_CHECK_CODE(stale_generation, ErrorCode::StaleGeneration);

  const auto stale_revision = harness.registry().transition_subject(
      harness.transition_request(TenancySubject::of_tenant(active.id), RecordRevision::from_value(41),
                                 LifecycleState::Suspended));
  TREG_CHECK_CODE(stale_revision, ErrorCode::StaleRecordRevision);

  const auto unchanged = harness.registry().transition_subject(
      harness.transition_request(TenancySubject::of_tenant(active.id), active.revision, LifecycleState::Active));
  TREG_CHECK_CODE(unchanged, ErrorCode::LifecycleStateUnchanged);

  const auto illegal = harness.registry().transition_subject(
      harness.transition_request(TenancySubject::of_tenant(declared.id), declared.revision,
                                 LifecycleState::Suspended));
  TREG_CHECK_CODE(illegal, ErrorCode::LifecycleTransitionIllegal);

  const auto missing = harness.registry().transition_subject(harness.transition_request(
      TenancySubject::of_tenant(tenant_id("ghost")), RecordRevision::from_value(1), LifecycleState::Active));
  TREG_CHECK_CODE(missing, ErrorCode::NotFound);

  TREG_CHECK_EQ(harness.snapshot().digest(), before.digest());
  TREG_CHECK_EQ(harness.snapshot().to_canonical_bytes(), before.to_canonical_bytes());
  TREG_CHECK_EQ(harness.generation(), before.generation);
  TREG_CHECK_EQ(harness.tenant("acme").revision, active.revision);
}

TREG_TEST(lifecycle_ops, a_terminal_record_can_never_be_changed_again) {
  Harness harness = Harness::ephemeral();
  const TenantRecord created = harness.create_tenant("fenced");
  const TenancySubject subject = TenancySubject::of_tenant(created.id);
  const SubjectRecord active = step(harness, subject, created.revision, LifecycleState::Active);
  const SubjectRecord retiring = step(harness, subject, subject_revision(active), LifecycleState::Retiring);
  const SubjectRecord retired = step(harness, subject, subject_revision(retiring), LifecycleState::Retired);
  const TombstoneOutcome tombstoned =
      unwrap(harness.registry().tombstone(TombstoneRequest{context(harness.generation()), subject,
                                                           subject_revision(retired),
                                                           IrreversibleAcknowledgement::acknowledged(),
                                                           std::nullopt, std::string{}}),
             "tombstone");
  TREG_CHECK(is_terminal(tombstoned.record));
  const RecordRevision revision = subject_revision(tombstoned.record);
  const RegistrySnapshot before = harness.snapshot();

  TREG_CHECK_CODE(harness.registry().set_metadata(SetMetadataRequest{context(harness.generation()), subject,
                                                                    revision, {}, {}}),
                  ErrorCode::TerminalStateReached);
  TREG_CHECK_CODE(harness.registry().set_owner(SetOwnerRequest{context(harness.generation()), created.id, revision,
                                                              std::nullopt}),
                  ErrorCode::TerminalStateReached);

  // No transition leaves a terminal state; the only statement left is the target itself.
  const auto nowhere = harness.registry().transition_subject(
      harness.transition_request(subject, revision, LifecycleState::Active));
  TREG_CHECK_CODE(nowhere, ErrorCode::LifecycleTransitionIllegal);
  TREG_REQUIRE(!nowhere.error().suppressed().empty());
  TREG_CHECK_EQ(nowhere.error().suppressed().at(0),
                std::string{"legal targets from tombstoned: "} +
                    std::string{legal_targets_text(LifecycleState::Tombstoned)});

  TREG_CHECK_EQ(harness.snapshot().digest(), before.digest());
}

}  // namespace
}  // namespace treg_test
