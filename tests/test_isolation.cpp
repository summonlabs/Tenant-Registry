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
#include <vector>

#include "test_support.hpp"

namespace treg_test {
namespace {

using tenant_registry::DomainGeneration;
using tenant_registry::ErrorCode;
using tenant_registry::MembershipQuery;
using tenant_registry::MembershipSummary;
using tenant_registry::OperationKind;
using tenant_registry::Page;
using tenant_registry::PutIsolationMembershipOutcome;
using tenant_registry::PutIsolationMembershipRequest;
using tenant_registry::RemoveIsolationMembershipRequest;
using tenant_registry::SetMetadataRequest;
using tenant_registry::subject_state;
using tenant_registry::TenancyMetadata;
using tenant_registry::TransitionIsolationMembershipOutcome;
using tenant_registry::TransitionIsolationMembershipRequest;
using tenant_registry::TransitionSubjectOutcome;

PutIsolationMembershipRequest membership_request(const TenantRegistry& registry, const TenancySubject& subject,
                                                const IsolationDomainId& domain, MembershipRole role,
                                                MembershipState state, DomainGeneration domain_generation,
                                                std::optional<RecordRevision> expected_revision = std::nullopt) {
  return PutIsolationMembershipRequest{context(registry.generation()), subject, domain, role, state,
                                       domain_generation, expected_revision};
}

std::string joined(const std::vector<TenancySubject>& subjects) {
  std::string out;
  for (const TenancySubject& subject : subjects) {
    if (!out.empty()) {
      out += ",";
    }
    out += subject.to_text();
  }
  return out;
}

TREG_TEST(isolation, a_membership_is_put_transitioned_and_removed) {
  Harness harness = Harness::ephemeral();
  const TenantRecord tenant = harness.active_tenant("acme");
  const IsolationDomainRecord domain = harness.active_domain("zone-a", IsolationClass::FaultContainment);
  const RegistryGeneration before = harness.generation();

  const PutIsolationMembershipOutcome joined =
      unwrap(harness.registry().put_isolation_membership(
                 membership_request(harness.registry(), TenancySubject::of_tenant(tenant.id), domain.id,
                                    MembershipRole::Primary, MembershipState::Bound,
                                    harness.domain_generation("zone-a"))),
             "put_isolation_membership");
  TREG_CHECK_EQ(joined.membership.subject, TenancySubject::of_tenant(tenant.id));
  TREG_CHECK_EQ(joined.membership.domain, domain.id);
  TREG_CHECK_EQ(joined.membership.role, MembershipRole::Primary);
  TREG_CHECK_EQ(joined.membership.state, MembershipState::Bound);
  TREG_CHECK_EQ(joined.membership.revision.value(), 1u);
  TREG_CHECK_EQ(joined.membership.created_generation, joined.receipt.generation);
  TREG_CHECK_EQ(joined.membership.updated_generation, joined.receipt.generation);
  TREG_CHECK_EQ(joined.receipt.operation, OperationKind::PutIsolationMembership);
  TREG_CHECK_EQ(joined.receipt.generation.value(), before.value() + 1);
  TREG_CHECK_EQ(joined.domain_generation.value(), harness.domain_generation("zone-a").value());
  TREG_CHECK_EQ(joined.domain_generation.value(), 1u);
  TREG_CHECK_EQ(joined.membership.natural_key(), std::string{"tenant:acme|isolation_domain:zone-a"});

  // Declaring the same membership again is an update, not a second record.
  const PutIsolationMembershipOutcome redeclared =
      unwrap(harness.registry().put_isolation_membership(
                 membership_request(harness.registry(), TenancySubject::of_tenant(tenant.id), domain.id,
                                    MembershipRole::Primary, MembershipState::Bound,
                                    harness.domain_generation("zone-a"), RecordRevision::from_value(1))),
             "put_isolation_membership");
  TREG_CHECK_EQ(redeclared.membership.revision.value(), 2u);
  TREG_CHECK_EQ(redeclared.membership.created_generation, joined.membership.created_generation);
  TREG_CHECK_EQ(redeclared.domain_generation.value(), 2u);
  TREG_CHECK_EQ(harness.snapshot().isolation_memberships.size(), 1u);

  const TransitionIsolationMembershipOutcome suspended =
      unwrap(harness.registry().transition_isolation_membership(TransitionIsolationMembershipRequest{
                 context(harness.generation()), TenancySubject::of_tenant(tenant.id), domain.id,
                 RecordRevision::from_value(2), harness.domain_generation("zone-a"),
                 MembershipState::Suspended}),
             "transition_isolation_membership");
  TREG_CHECK_EQ(suspended.membership.state, MembershipState::Suspended);
  TREG_CHECK_EQ(suspended.membership.revision.value(), 3u);
  TREG_CHECK_EQ(suspended.domain_generation.value(), 3u);

  const TransitionIsolationMembershipOutcome rebound =
      unwrap(harness.registry().transition_isolation_membership(TransitionIsolationMembershipRequest{
                 context(harness.generation()), TenancySubject::of_tenant(tenant.id), domain.id,
                 RecordRevision::from_value(3), harness.domain_generation("zone-a"), MembershipState::Bound}),
             "transition_isolation_membership");
  TREG_CHECK_EQ(rebound.membership.state, MembershipState::Bound);
  TREG_CHECK_EQ(rebound.membership.revision.value(), 4u);
  TREG_CHECK_EQ(rebound.domain_generation.value(), 4u);

  // Withdrawal is terminal for the membership: it stops existing, so it is gone
  // from the state rather than kept as a record nobody may act on.
  const TransitionIsolationMembershipOutcome withdrawn =
      unwrap(harness.registry().transition_isolation_membership(TransitionIsolationMembershipRequest{
                 context(harness.generation()), TenancySubject::of_tenant(tenant.id), domain.id,
                 RecordRevision::from_value(4), harness.domain_generation("zone-a"), MembershipState::Withdrawn}),
             "transition_isolation_membership");
  TREG_CHECK_EQ(withdrawn.membership.state, MembershipState::Withdrawn);
  TREG_CHECK_EQ(withdrawn.domain_generation.value(), 5u);
  TREG_CHECK(harness.snapshot().isolation_memberships.empty());
  TREG_CHECK(harness.registry().list_isolation_memberships(MembershipQuery{}).value().items.empty());

  TREG_CHECK_CODE(harness.registry().transition_isolation_membership(TransitionIsolationMembershipRequest{
                      context(harness.generation()), TenancySubject::of_tenant(tenant.id), domain.id,
                      RecordRevision::from_value(5), harness.domain_generation("zone-a"),
                      MembershipState::Bound}),
                  ErrorCode::DomainMembershipAbsent);
  TREG_CHECK_CODE(harness.registry().remove_isolation_membership(RemoveIsolationMembershipRequest{
                      context(harness.generation()), TenancySubject::of_tenant(tenant.id), domain.id,
                      RecordRevision::from_value(5), harness.domain_generation("zone-a")}),
                  ErrorCode::DomainMembershipAbsent);
}

TREG_TEST(isolation, a_membership_requires_an_active_subject_and_an_active_domain) {
  Harness harness = Harness::ephemeral();
  const IsolationDomainRecord active_domain = harness.active_domain("zone-a");
  const IsolationDomainRecord declared_domain = harness.create_domain("zone-declared");
  const TenantRecord active_tenant = harness.active_tenant("active-tenant");
  const TenantRecord declared_tenant = harness.create_tenant("declared-tenant");
  const TenantRecord suspended_tenant = harness.active_tenant("suspended-tenant");

  const TransitionSubjectOutcome suspended =
      unwrap(harness.registry().transition_subject(harness.transition_request(
                 TenancySubject::of_tenant(suspended_tenant.id), suspended_tenant.revision,
                 LifecycleState::Suspended)),
             "transition_subject");
  TREG_CHECK_EQ(subject_state(suspended.record), LifecycleState::Suspended);

  const TenancySubject subjects[] = {TenancySubject::of_tenant(declared_tenant.id),
                                     TenancySubject::of_tenant(suspended_tenant.id)};
  for (const TenancySubject& subject : subjects) {
    TREG_CHECK_CODE(harness.registry().put_isolation_membership(
                        membership_request(harness.registry(), subject, active_domain.id, MembershipRole::Secondary,
                                           MembershipState::Bound, harness.domain_generation("zone-a"))),
                    ErrorCode::ReferenceNotYetLive);
  }

  const auto to_declared_domain = harness.registry().put_isolation_membership(
      membership_request(harness.registry(), TenancySubject::of_tenant(active_tenant.id), declared_domain.id,
                         MembershipRole::Secondary, MembershipState::Bound, DomainGeneration::initial()));
  TREG_CHECK_CODE(to_declared_domain, ErrorCode::ReferenceNotYetLive);
  TREG_CHECK(harness.snapshot().isolation_memberships.empty());

  // A suspended identity keeps what it has and may not gain more.
  const TenantRecord quiet = harness.active_tenant("quiet-tenant");
  const IsolationDomainRecord other_domain = harness.active_domain("zone-b");
  harness.join(TenancySubject::of_tenant(quiet.id), "zone-a", MembershipRole::Secondary);
  TREG_REQUIRE_OK(harness.registry().transition_subject(harness.transition_request(
      TenancySubject::of_tenant(quiet.id), harness.tenant("quiet-tenant").revision, LifecycleState::Suspended)));
  TREG_CHECK_EQ(harness.registry().isolation_domains_of(TenancySubject::of_tenant(quiet.id)).value().size(), std::size_t{1});
  TREG_CHECK_CODE(harness.registry().put_isolation_membership(
                      membership_request(harness.registry(), TenancySubject::of_tenant(quiet.id), other_domain.id,
                                         MembershipRole::Fallback, MembershipState::Bound,
                                         harness.domain_generation("zone-b"))),
                  ErrorCode::ReferenceNotYetLive);
}

TREG_TEST(isolation, the_domain_generation_advances_for_membership_changes_and_nothing_else) {
  Harness harness = Harness::ephemeral();
  const TenantRecord tenant = harness.active_tenant("acme");
  const TenantRecord other = harness.active_tenant("other");
  const TenantRecord third = harness.active_tenant("third");
  const IsolationDomainRecord domain = harness.active_domain("zone-a");
  harness.active_domain("zone-quiet");
  harness.active_service("renderer-service");
  const DomainGeneration start = harness.domain_generation("zone-a");
  TREG_CHECK_EQ(start.value(), 0u);

  // Everything that is not a membership change leaves the generation alone.
  const auto renamed = harness.registry().set_metadata(
      SetMetadataRequest{context(harness.generation()), TenancySubject::of_isolation_domain(domain.id),
                         harness.domain("zone-a").revision, {}, {entry("purpose", "containment")}});
  TREG_REQUIRE_OK(renamed);
  harness.join(TenancySubject::of_tenant(other.id), "zone-quiet", MembershipRole::Primary);
  harness.bind("renderer-service", "acme", BindingKind::Serves);
  harness.own("acme", "other", OwnershipKind::Operational, LifecycleState::Active);
  require_ok(harness.transition(TenancySubject::of_tenant(other.id), harness.tenant("other").revision,
                                LifecycleState::Suspended),
             "suspend other");
  TREG_CHECK_EQ(harness.domain("zone-a").revision.value(), 3u);
  TREG_CHECK_EQ(harness.domain_generation("zone-a"), start);
  TREG_CHECK_EQ(harness.domain_generation("zone-quiet").value(), 1u);

  // Each membership change, and only a membership change, moves it by one.
  harness.join(TenancySubject::of_tenant(tenant.id), "zone-a", MembershipRole::Primary);
  TREG_CHECK_EQ(harness.domain_generation("zone-a").value(), 1u);
  harness.join(TenancySubject::of_tenant(third.id), "zone-a", MembershipRole::Secondary);
  TREG_CHECK_EQ(harness.domain_generation("zone-a").value(), 2u);
  const auto moved = harness.registry().transition_isolation_membership(TransitionIsolationMembershipRequest{
      context(harness.generation()), TenancySubject::of_tenant(tenant.id), domain.id, RecordRevision::from_value(1),
      harness.domain_generation("zone-a"), MembershipState::Suspended});
  TREG_REQUIRE_OK(moved);
  TREG_CHECK_EQ(moved.value().domain_generation.value(), 3u);
  TREG_CHECK_EQ(harness.domain_generation("zone-a").value(), 3u);
  const auto dropped = harness.registry().remove_isolation_membership(RemoveIsolationMembershipRequest{
      context(harness.generation()), TenancySubject::of_tenant(third.id), domain.id, RecordRevision::from_value(1),
      harness.domain_generation("zone-a")});
  TREG_REQUIRE_OK(dropped);
  TREG_CHECK_EQ(harness.domain_generation("zone-a").value(), 4u);
  TREG_CHECK_EQ(harness.snapshot().isolation_memberships.size(), 2u);
}

TREG_TEST(isolation, a_write_against_a_stale_domain_generation_is_refused_naming_both) {
  Harness harness = Harness::ephemeral();
  const TenantRecord tenant = harness.active_tenant("acme");
  const TenantRecord other = harness.active_tenant("other");
  const IsolationDomainRecord domain = harness.active_domain("zone-a");
  harness.join(TenancySubject::of_tenant(tenant.id), "zone-a", MembershipRole::Primary);
  TREG_CHECK_EQ(harness.domain_generation("zone-a").value(), 1u);
  const RegistrySnapshot before = harness.snapshot();

  const auto stale = harness.registry().put_isolation_membership(
      membership_request(harness.registry(), TenancySubject::of_tenant(other.id), domain.id, MembershipRole::Secondary,
                         MembershipState::Bound, DomainGeneration::initial()));
  TREG_CHECK_CODE(stale, ErrorCode::StaleDomainGeneration);
  TREG_CHECK(stale.error().detail().find("generation 0") != std::string::npos);
  TREG_CHECK(stale.error().detail().find("generation 1") != std::string::npos);
  TREG_CHECK(stale.error().detail().find("isolation_domain:zone-a") != std::string::npos);

  // The read that a consumer does before deciding is fenced the same way.
  const auto fenced = harness.registry().find_isolation_domain(domain.id, DomainGeneration::initial());
  TREG_CHECK_CODE(fenced, ErrorCode::StaleDomainGeneration);
  TREG_CHECK(fenced.error().detail().find("generation 0") != std::string::npos);
  TREG_CHECK(fenced.error().detail().find("generation 1") != std::string::npos);
  TREG_REQUIRE_OK(harness.registry().find_isolation_domain(domain.id, harness.domain_generation("zone-a")));

  TREG_CHECK_CODE(harness.registry().transition_isolation_membership(TransitionIsolationMembershipRequest{
                      context(harness.generation()), TenancySubject::of_tenant(tenant.id), domain.id,
                      RecordRevision::from_value(1), DomainGeneration::initial(), MembershipState::Suspended}),
                  ErrorCode::StaleDomainGeneration);
  TREG_CHECK_CODE(harness.registry().remove_isolation_membership(RemoveIsolationMembershipRequest{
                      context(harness.generation()), TenancySubject::of_tenant(tenant.id), domain.id,
                      RecordRevision::from_value(1), DomainGeneration::initial()}),
                  ErrorCode::StaleDomainGeneration);

  TREG_CHECK_EQ(harness.snapshot().digest(), before.digest());
}

TREG_TEST(isolation, at_most_one_in_force_primary_membership_per_subject) {
  Harness harness = Harness::ephemeral();
  const TenantRecord tenant = harness.active_tenant("acme");
  const IsolationDomainRecord first = harness.active_domain("zone-first");
  const IsolationDomainRecord second = harness.active_domain("zone-second");
  harness.join(TenancySubject::of_tenant(tenant.id), "zone-first", MembershipRole::Primary);

  const auto conflict = harness.registry().put_isolation_membership(
      membership_request(harness.registry(), TenancySubject::of_tenant(tenant.id), second.id, MembershipRole::Primary,
                         MembershipState::Bound, harness.domain_generation("zone-second")));
  TREG_CHECK_CODE(conflict, ErrorCode::MembershipRoleConflict);
  TREG_CHECK(conflict.error().detail().find("zone-first") != std::string::npos);
  TREG_CHECK_EQ(harness.domain_generation("zone-second").value(), 0u);

  // Other roles, and a membership that is only proposed, are not in force.
  harness.join(TenancySubject::of_tenant(tenant.id), "zone-second", MembershipRole::Secondary);
  const IsolationDomainRecord third = harness.active_domain("zone-third");
  const PutIsolationMembershipOutcome fallback =
      unwrap(harness.registry().put_isolation_membership(
                 membership_request(harness.registry(), TenancySubject::of_tenant(tenant.id), third.id,
                                    MembershipRole::Fallback, MembershipState::Proposed,
                                    harness.domain_generation("zone-third"))),
             "put_isolation_membership");
  TREG_CHECK_EQ(fallback.membership.state, MembershipState::Proposed);

  const TenantRecord candidate = harness.active_tenant("candidate");
  harness.join(TenancySubject::of_tenant(candidate.id), "zone-first", MembershipRole::Primary);
  const PutIsolationMembershipOutcome proposed_second =
      unwrap(harness.registry().put_isolation_membership(
                 membership_request(harness.registry(), TenancySubject::of_tenant(candidate.id), second.id,
                                    MembershipRole::Primary, MembershipState::Proposed,
                                    harness.domain_generation("zone-second"))),
             "put_isolation_membership");
  TREG_CHECK_EQ(proposed_second.membership.state, MembershipState::Proposed);

  const auto late_conflict = harness.registry().transition_isolation_membership(
      TransitionIsolationMembershipRequest{context(harness.generation()), TenancySubject::of_tenant(candidate.id),
                                           second.id, proposed_second.membership.revision,
                                           harness.domain_generation("zone-second"), MembershipState::Bound});
  TREG_CHECK_CODE(late_conflict, ErrorCode::MembershipRoleConflict);
  TREG_CHECK(late_conflict.error().detail().find("zone-first") != std::string::npos);
}

TREG_TEST(isolation, an_isolation_domain_is_not_a_membership_subject) {
  Harness harness = Harness::ephemeral();
  const IsolationDomainRecord domain = harness.active_domain("zone-a");
  const IsolationDomainRecord other = harness.active_domain("zone-b");
  const TenancySubject subject = TenancySubject::of_isolation_domain(other.id);

  TREG_CHECK_CODE(harness.registry().put_isolation_membership(
                      membership_request(harness.registry(), subject, domain.id, MembershipRole::Primary,
                                         MembershipState::Bound, harness.domain_generation("zone-a"))),
                  ErrorCode::InvalidIdKind);
  TREG_CHECK_CODE(harness.registry().transition_isolation_membership(TransitionIsolationMembershipRequest{
                      context(harness.generation()), subject, domain.id, RecordRevision::from_value(1),
                      harness.domain_generation("zone-a"), MembershipState::Bound}),
                  ErrorCode::InvalidIdKind);
  TREG_CHECK_CODE(harness.registry().remove_isolation_membership(RemoveIsolationMembershipRequest{
                      context(harness.generation()), subject, domain.id, RecordRevision::from_value(1),
                      harness.domain_generation("zone-a")}),
                  ErrorCode::InvalidIdKind);
  TREG_CHECK_CODE(harness.registry().isolation_domains_of(subject), ErrorCode::InvalidIdKind);
  TREG_CHECK(harness.snapshot().isolation_memberships.empty());
}

TREG_TEST(isolation, domains_of_and_members_of_agree_with_the_membership_records) {
  Harness harness = Harness::ephemeral();
  const TenantRecord tenant = harness.active_tenant("acme");
  const ServiceRecord service = harness.active_service("renderer");
  const TenantRecord elsewhere = harness.active_tenant("elsewhere");
  const IsolationDomainRecord shared = harness.active_domain("shared");
  harness.active_domain("solo");

  harness.join(TenancySubject::of_tenant(tenant.id), "shared", MembershipRole::Primary);
  harness.join(TenancySubject::of_service(service.id), "shared", MembershipRole::Secondary);
  harness.join(TenancySubject::of_tenant(elsewhere.id), "solo", MembershipRole::Primary);

  const std::vector<IsolationDomainId> tenant_domains =
      unwrap(harness.registry().isolation_domains_of(TenancySubject::of_tenant(tenant.id)), "isolation_domains_of");
  TREG_REQUIRE(tenant_domains.size() == 1u);
  TREG_CHECK_EQ(tenant_domains.at(0), shared.id);
  TREG_CHECK_EQ(harness.registry().isolation_domains_of(TenancySubject::of_service(service.id)).value().size(), std::size_t{1});
  TREG_CHECK(harness.registry().isolation_domains_of(TenancySubject::of_tenant(elsewhere.id)).value().size() == 1u);

  const std::vector<TenancySubject> members = unwrap(harness.registry().members_of(shared.id, 0), "members_of");
  TREG_CHECK_EQ(joined(members), std::string{"service:renderer,tenant:acme"});

  // The listing of the same question gives the same members.
  const Page<MembershipSummary> listed = unwrap(
      harness.registry().list_isolation_memberships(
          MembershipQuery{.domain = std::optional<IsolationDomainId>{shared.id},
                          .state = std::optional<MembershipState>{MembershipState::Bound}}),
      "list_isolation_memberships");
  TREG_REQUIRE(listed.items.size() == 2u);
  std::string listed_text;
  for (const MembershipSummary& summary : listed.items) {
    TREG_CHECK_EQ(summary.domain, shared.id);
    TREG_CHECK_EQ(summary.state, MembershipState::Bound);
    if (!listed_text.empty()) {
      listed_text += ",";
    }
    listed_text += summary.subject.to_text();
  }
  TREG_CHECK_EQ(listed_text, std::string{"service:renderer,tenant:acme"});

  // A bound of its own is not a licence to truncate: an answer that does not fit
  // is refused.
  TREG_CHECK_CODE(harness.registry().members_of(shared.id, 1), ErrorCode::ListingLimitExceeded);
  TREG_CHECK_EQ(harness.registry().members_of(shared.id, 2).value().size(), std::size_t{2});
  TREG_CHECK_CODE(harness.registry().members_of(domain_id("ghost"), 0), ErrorCode::NotFound);
}

TREG_TEST(isolation, isolation_is_declared_and_never_inferred) {
  Harness harness = Harness::ephemeral();
  const TenantRecord quiet = harness.active_tenant("quiet");
  const TenantRecord proposed = harness.active_tenant("proposed-only");
  const ServiceRecord service = harness.active_service("renderer");
  harness.active_domain("zone-a");
  harness.active_domain("zone-b");

  // Nothing is a member of anything by default.
  TREG_CHECK(harness.registry().isolation_domains_of(TenancySubject::of_tenant(quiet.id)).value().empty());
  TREG_CHECK(harness.registry().isolation_domains_of(TenancySubject::of_service(service.id)).value().empty());
  TREG_CHECK(harness.snapshot().isolation_memberships.empty());

  harness.join(TenancySubject::of_tenant(proposed.id), "zone-a", MembershipRole::Primary,
               MembershipState::Proposed);
  TREG_CHECK(harness.registry().isolation_domains_of(TenancySubject::of_tenant(proposed.id)).value().empty());
  TREG_CHECK(harness.registry().members_of(domain_id("zone-a"), 0).value().empty());
  // Observing a proposal is not observing isolation, but the proposal is visible.
  TREG_CHECK_EQ(harness.registry().list_isolation_memberships(MembershipQuery{}).value().items.size(), 1u);
  TREG_CHECK_EQ(harness.registry().list_isolation_memberships(MembershipQuery{}).value().items.at(0).state,
                MembershipState::Proposed);

  // Only the declared, in-force membership asserts isolation.
  const TransitionIsolationMembershipOutcome bound =
      unwrap(harness.registry().transition_isolation_membership(TransitionIsolationMembershipRequest{
                 context(harness.generation()), TenancySubject::of_tenant(proposed.id), domain_id("zone-a"),
                 RecordRevision::from_value(1), harness.domain_generation("zone-a"), MembershipState::Bound}),
             "transition_isolation_membership");
  TREG_CHECK_EQ(bound.membership.state, MembershipState::Bound);
  TREG_CHECK_EQ(harness.registry().isolation_domains_of(TenancySubject::of_tenant(proposed.id)).value().size(), std::size_t{1});
  TREG_CHECK_EQ(harness.registry().members_of(domain_id("zone-a"), 0).value().size(), std::size_t{1});

  // No subject appears in a domain it was never declared in.
  TREG_CHECK(harness.registry().members_of(domain_id("zone-b"), 0).value().empty());
}

}  // namespace
}  // namespace treg_test
