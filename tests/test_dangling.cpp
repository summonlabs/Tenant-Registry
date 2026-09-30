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
#include <string>
#include <vector>

#include "test_support.hpp"

namespace treg_test {
namespace {

using tenant_registry::Error;
using tenant_registry::ErrorCode;
using tenant_registry::is_terminal;
using tenant_registry::OwnershipTraversalRequest;
using tenant_registry::PutIsolationMembershipRequest;
using tenant_registry::PutOwnershipRequest;
using tenant_registry::PutServiceBindingRequest;
using tenant_registry::RemoveIsolationMembershipRequest;
using tenant_registry::RemoveOwnershipRequest;
using tenant_registry::RemoveServiceBindingRequest;
using tenant_registry::SetMetadataRequest;
using tenant_registry::SetOwnerRequest;
using tenant_registry::TenancyMetadata;
using tenant_registry::TransitionIsolationMembershipRequest;

bool contains(const std::string& haystack, std::string_view needle) {
  return haystack.find(needle) != std::string::npos;
}

std::string evidence_of(const Error& error) {
  std::string text;
  for (const std::string& note : error.suppressed()) {
    if (!text.empty()) {
      text += " ";
    }
    text += note;
  }
  return text;
}

bool tenant_present(const RegistrySnapshot& snapshot, const TenantId& id) {
  for (const TenantRecord& record : snapshot.tenants) {
    if (record.id == id) {
      return true;
    }
  }
  return false;
}

bool service_present(const RegistrySnapshot& snapshot, const ServiceId& id) {
  for (const ServiceRecord& record : snapshot.services) {
    if (record.id == id) {
      return true;
    }
  }
  return false;
}

bool domain_present(const RegistrySnapshot& snapshot, const IsolationDomainId& id) {
  for (const IsolationDomainRecord& record : snapshot.isolation_domains) {
    if (record.id == id) {
      return true;
    }
  }
  return false;
}

bool subject_present(const RegistrySnapshot& snapshot, const TenancySubject& subject) {
  if (const TenantId* tenant = subject.tenant_if(); tenant != nullptr) {
    return tenant_present(snapshot, *tenant);
  }
  if (const ServiceId* service = subject.service_if(); service != nullptr) {
    return service_present(snapshot, *service);
  }
  return domain_present(snapshot, *subject.isolation_domain_if());
}

TREG_TEST(dangling, every_operation_against_a_missing_identity_is_refused_and_creates_nothing) {
  Harness harness = Harness::ephemeral();
  harness.active_tenant("acme");
  harness.active_service("renderer");
  harness.active_domain("zone-a");
  const RegistrySnapshot before = harness.snapshot();

  const TenantId ghost_tenant = tenant_id("ghost-tenant");
  const ServiceId ghost_service = service_id("ghost-service");
  const IsolationDomainId ghost_domain = domain_id("ghost-domain");
  const TenancySubject ghost_subject = TenancySubject::of_tenant(ghost_tenant);
  const RecordRevision any_revision = RecordRevision::from_value(1);

  TREG_CHECK_CODE(harness.registry().put_ownership(PutOwnershipRequest{
                      context(harness.generation()), ghost_tenant, tenant_id("acme"), OwnershipKind::Operational,
                      LifecycleState::Active, std::nullopt}),
                  ErrorCode::NotFound);
  TREG_CHECK_CODE(harness.registry().put_ownership(PutOwnershipRequest{
                      context(harness.generation()), tenant_id("acme"), ghost_tenant, OwnershipKind::Operational,
                      LifecycleState::Active, std::nullopt}),
                  ErrorCode::NotFound);
  TREG_CHECK_CODE(harness.registry().put_service_binding(PutServiceBindingRequest{
                      context(harness.generation()), ghost_service, tenant_id("acme"), BindingKind::Serves,
                      LifecycleState::Active, std::nullopt}),
                  ErrorCode::NotFound);
  TREG_CHECK_CODE(harness.registry().put_service_binding(PutServiceBindingRequest{
                      context(harness.generation()), service_id("renderer"), ghost_tenant, BindingKind::Serves,
                      LifecycleState::Active, std::nullopt}),
                  ErrorCode::NotFound);
  TREG_CHECK_CODE(harness.registry().put_isolation_membership(PutIsolationMembershipRequest{
                      context(harness.generation()), ghost_subject, domain_id("zone-a"), MembershipRole::Primary,
                      MembershipState::Bound, DomainGeneration::initial(), std::nullopt}),
                  ErrorCode::NotFound);
  TREG_CHECK_CODE(harness.registry().put_isolation_membership(PutIsolationMembershipRequest{
                      context(harness.generation()), TenancySubject::of_tenant(tenant_id("acme")), ghost_domain,
                      MembershipRole::Primary, MembershipState::Bound, DomainGeneration::initial(), std::nullopt}),
                  ErrorCode::NotFound);
  TREG_CHECK_CODE(harness.registry().transition_subject(harness.transition_request(ghost_subject, any_revision,
                                                                                  LifecycleState::Active)),
                  ErrorCode::NotFound);
  TREG_CHECK_CODE(harness.registry().set_owner(SetOwnerRequest{context(harness.generation()), ghost_tenant,
                                                              any_revision, std::nullopt}),
                  ErrorCode::NotFound);
  TREG_CHECK_CODE(harness.registry().set_metadata(SetMetadataRequest{context(harness.generation()), ghost_subject,
                                                                    any_revision, {}, {entry("a", "1")}}),
                  ErrorCode::NotFound);
  TREG_CHECK_CODE(harness.registry().remove_isolation_membership(RemoveIsolationMembershipRequest{
                      context(harness.generation()), TenancySubject::of_tenant(tenant_id("acme")), ghost_domain,
                      any_revision, DomainGeneration::initial()}),
                  ErrorCode::NotFound);
  TREG_CHECK_CODE(harness.registry().transition_isolation_membership(
                      TransitionIsolationMembershipRequest{context(harness.generation()),
                                                           TenancySubject::of_tenant(tenant_id("acme")), ghost_domain,
                                                           any_revision, DomainGeneration::initial(),
                                                           MembershipState::Bound}),
                  ErrorCode::NotFound);
  TREG_CHECK_CODE(harness.registry().traverse_ownership(OwnershipTraversalRequest{
                      ghost_tenant, TraversalDirection::Ancestors, std::nullopt, std::nullopt, 0, 0}),
                  ErrorCode::NotFound);
  TREG_CHECK_CODE(harness.registry().explain(ghost_subject), ErrorCode::NotFound);
  TREG_CHECK_CODE(harness.registry().members_of(ghost_domain, 0), ErrorCode::NotFound);
  TREG_CHECK_CODE(harness.registry().isolation_domains_of(ghost_subject), ErrorCode::NotFound);
  TREG_CHECK_CODE(harness.registry().find_tenant(ghost_tenant), ErrorCode::NotFound);
  TREG_CHECK_CODE(harness.registry().find_service(ghost_service), ErrorCode::NotFound);
  TREG_CHECK_CODE(harness.registry().find_isolation_domain(ghost_domain), ErrorCode::NotFound);

  // Refusing is not creating: the state is exactly what it was.
  TREG_CHECK_EQ(harness.snapshot().digest(), before.digest());
  TREG_CHECK_EQ(harness.snapshot().to_canonical_bytes(), before.to_canonical_bytes());
  TREG_CHECK_EQ(harness.generation(), before.generation);
  TREG_CHECK(harness.snapshot().ownership_edges.empty());
  TREG_CHECK(harness.snapshot().service_bindings.empty());
  TREG_CHECK(harness.snapshot().isolation_memberships.empty());
  TREG_CHECK_EQ(harness.snapshot().record_count(), std::size_t{3});
}

TREG_TEST(dangling, retiring_a_tenant_with_live_dependents_is_refused_with_evidence) {
  Harness harness = Harness::ephemeral();
  const TenantRecord child = harness.active_tenant("child-tenant");
  const TenantRecord middle = harness.active_tenant("middle-tenant");
  const TenantRecord owner = harness.active_tenant("owner-tenant");
  const ServiceRecord service = harness.active_service("svc");
  harness.active_domain("zone-a");
  harness.own("child-tenant", "middle-tenant", OwnershipKind::Operational, LifecycleState::Active);
  harness.own("middle-tenant", "owner-tenant", OwnershipKind::Operational, LifecycleState::Active);
  harness.bind("svc", "middle-tenant", BindingKind::Serves);
  harness.join(TenancySubject::of_tenant(middle.id), "zone-a", MembershipRole::Secondary);

  const RegistrySnapshot before = harness.snapshot();
  const auto refusal = harness.registry().transition_subject(
      harness.transition_request(TenancySubject::of_tenant(middle.id), middle.revision, LifecycleState::Retiring));
  TREG_CHECK_CODE(refusal, ErrorCode::HasLiveDependents);
  TREG_CHECK(contains(refusal.error().detail(), "tenant:middle-tenant"));
  const std::string evidence = evidence_of(refusal.error());
  TREG_CHECK(contains(evidence, "children=1"));
  TREG_CHECK(contains(evidence, "owners=1"));
  TREG_CHECK(contains(evidence, "service_bindings=1"));
  TREG_CHECK(contains(evidence, "isolation_memberships=1"));
  TREG_CHECK(contains(evidence, "first=ownership edge over child child-tenant"));

  // A refusal is not a state change.
  TREG_CHECK_EQ(harness.snapshot().digest(), before.digest());
  TREG_CHECK_EQ(harness.tenant("middle-tenant").state, LifecycleState::Active);
  TREG_CHECK_EQ(harness.tenant("middle-tenant").revision, middle.revision);
  TREG_CHECK(service.id == service.id);
  TREG_CHECK(child.id == child.id);
  TREG_CHECK(owner.id == owner.id);
}

TREG_TEST(dangling, removing_the_dependents_one_at_a_time_lets_the_retirement_succeed) {
  Harness harness = Harness::ephemeral();
  const TenantRecord child = harness.active_tenant("child-tenant");
  const TenantRecord middle = harness.active_tenant("middle-tenant");
  harness.active_service("svc");
  harness.active_domain("zone-a");
  harness.own("child-tenant", "middle-tenant", OwnershipKind::Operational, LifecycleState::Active);
  harness.bind("svc", "middle-tenant", BindingKind::Serves);
  harness.join(TenancySubject::of_tenant(middle.id), "zone-a", MembershipRole::Secondary);

  const auto attempt = [&harness, &middle]() {
    return harness.registry().transition_subject(harness.transition_request(
        TenancySubject::of_tenant(middle.id), harness.tenant("middle-tenant").revision, LifecycleState::Retiring));
  };

  TREG_CHECK_CODE(attempt(), ErrorCode::HasLiveDependents);

  const auto unbind = harness.registry().remove_service_binding(RemoveServiceBindingRequest{
      context(harness.generation()), service_id("svc"), middle.id, BindingKind::Serves, RecordRevision::from_value(1)});
  TREG_REQUIRE_OK(unbind);
  const auto after_unbind = attempt();
  TREG_CHECK_CODE(after_unbind, ErrorCode::HasLiveDependents);
  TREG_CHECK(contains(evidence_of(after_unbind.error()), "service_bindings=0"));
  TREG_CHECK(contains(evidence_of(after_unbind.error()), "children=1"));

  const auto unjoin = harness.registry().remove_isolation_membership(RemoveIsolationMembershipRequest{
      context(harness.generation()), TenancySubject::of_tenant(middle.id), domain_id("zone-a"),
      RecordRevision::from_value(1), harness.domain_generation("zone-a")});
  TREG_REQUIRE_OK(unjoin);
  TREG_CHECK_CODE(attempt(), ErrorCode::HasLiveDependents);

  const auto unown = harness.registry().remove_ownership(RemoveOwnershipRequest{
      context(harness.generation()), child.id, middle.id, RecordRevision::from_value(1)});
  TREG_REQUIRE_OK(unown);
  const auto now_allowed = attempt();
  TREG_REQUIRE_OK(now_allowed);
  TREG_CHECK_EQ(harness.tenant("middle-tenant").state, LifecycleState::Retiring);

  const auto retired = harness.registry().transition_subject(harness.transition_request(
      TenancySubject::of_tenant(middle.id), harness.tenant("middle-tenant").revision, LifecycleState::Retired));
  TREG_REQUIRE_OK(retired);
  TREG_CHECK(harness.tenant("middle-tenant").retired_generation.has_value());
  TREG_CHECK(harness.snapshot().service_bindings.empty());
  TREG_CHECK(harness.snapshot().isolation_memberships.empty());
  TREG_CHECK(harness.snapshot().ownership_edges.empty());
}

TREG_TEST(dangling, a_retiring_identity_cannot_be_named_by_a_new_relationship) {
  Harness harness = Harness::ephemeral();
  const TenantRecord retiring = harness.active_tenant("retiring-tenant");
  const TenantRecord other = harness.active_tenant("other-tenant");
  harness.active_service("svc");
  harness.active_domain("zone-a");
  require_ok(harness.transition(TenancySubject::of_tenant(retiring.id), retiring.revision, LifecycleState::Retiring),
             "begin retirement");

  TREG_CHECK_CODE(harness.registry().put_service_binding(PutServiceBindingRequest{
                      context(harness.generation()), service_id("svc"), retiring.id, BindingKind::Serves,
                      LifecycleState::Active, std::nullopt}),
                  ErrorCode::ReferenceTerminal);
  TREG_CHECK_CODE(harness.registry().put_ownership(PutOwnershipRequest{
                      context(harness.generation()), other.id, retiring.id, OwnershipKind::Operational,
                      LifecycleState::Active, std::nullopt}),
                  ErrorCode::ReferenceTerminal);
  TREG_CHECK_CODE(harness.registry().put_ownership(PutOwnershipRequest{
                      context(harness.generation()), retiring.id, other.id, OwnershipKind::Operational,
                      LifecycleState::Active, std::nullopt}),
                  ErrorCode::ReferenceNotYetLive);
  TREG_CHECK_CODE(harness.registry().put_isolation_membership(PutIsolationMembershipRequest{
                      context(harness.generation()), TenancySubject::of_tenant(retiring.id), domain_id("zone-a"),
                      MembershipRole::Secondary, MembershipState::Bound, harness.domain_generation("zone-a"),
                      std::nullopt}),
                  ErrorCode::ReferenceNotYetLive);
  TREG_CHECK(harness.snapshot().service_bindings.empty());
  TREG_CHECK(harness.snapshot().ownership_edges.empty());
  TREG_CHECK(harness.snapshot().isolation_memberships.empty());
}

TREG_TEST(dangling, a_service_and_a_domain_refuse_retirement_while_referred_to) {
  Harness harness = Harness::ephemeral();
  const TenantRecord tenant = harness.active_tenant("acme");
  const ServiceRecord service = harness.active_service("svc");
  const IsolationDomainRecord domain = harness.active_domain("zone-a");
  harness.bind("svc", "acme", BindingKind::Serves);
  harness.join(TenancySubject::of_tenant(tenant.id), "zone-a", MembershipRole::Primary);

  const auto service_refusal = harness.registry().transition_subject(harness.transition_request(
      TenancySubject::of_service(service.id), service.revision, LifecycleState::Retiring));
  TREG_CHECK_CODE(service_refusal, ErrorCode::HasLiveDependents);
  TREG_CHECK(contains(evidence_of(service_refusal.error()), "service_bindings=1"));
  TREG_CHECK(contains(evidence_of(service_refusal.error()), "first=service binding of svc"));

  const auto domain_refusal = harness.registry().transition_subject(harness.transition_request(
      TenancySubject::of_isolation_domain(domain.id), harness.domain("zone-a").revision, LifecycleState::Retiring));
  TREG_CHECK_CODE(domain_refusal, ErrorCode::HasLiveDependents);
  TREG_CHECK(contains(evidence_of(domain_refusal.error()), "isolation_memberships=1"));
  TREG_CHECK(contains(evidence_of(domain_refusal.error()), "first=isolation membership in zone-a"));
  TREG_CHECK_EQ(harness.service("svc").state, LifecycleState::Active);
  TREG_CHECK_EQ(harness.domain("zone-a").state, LifecycleState::Active);
}

TREG_TEST(dangling, the_state_never_holds_a_relationship_whose_endpoint_is_missing) {
  Harness harness = Harness::ephemeral();
  const TenantRecord child = harness.active_tenant("child-tenant");
  const TenantRecord parent = harness.active_tenant("parent-tenant");
  const ServiceRecord service = harness.active_service("renderer");
  const IsolationDomainRecord domain = harness.active_domain("zone-a");
  harness.own("child-tenant", "parent-tenant", OwnershipKind::Administrative, LifecycleState::Active);
  harness.bind("renderer", "child-tenant", BindingKind::OperatedBy);
  harness.join(TenancySubject::of_tenant(child.id), "zone-a", MembershipRole::Primary);
  harness.join(TenancySubject::of_service(service.id), "zone-a", MembershipRole::Secondary);

  // Attempts against identities that do not exist cannot leave a trace.
  TREG_CHECK_CODE(harness.registry().put_ownership(PutOwnershipRequest{
                      context(harness.generation()), tenant_id("ghost"), parent.id, OwnershipKind::Operational,
                      LifecycleState::Active, std::nullopt}),
                  ErrorCode::NotFound);
  TREG_CHECK_CODE(harness.registry().put_service_binding(PutServiceBindingRequest{
                      context(harness.generation()), service_id("ghost"), child.id, BindingKind::Serves,
                      LifecycleState::Active, std::nullopt}),
                  ErrorCode::NotFound);
  TREG_CHECK_CODE(harness.registry().put_isolation_membership(PutIsolationMembershipRequest{
                      context(harness.generation()), TenancySubject::of_tenant(tenant_id("ghost")), domain.id,
                      MembershipRole::Fallback, MembershipState::Bound, harness.domain_generation("zone-a"),
                      std::nullopt}),
                  ErrorCode::NotFound);

  const RegistrySnapshot snapshot = harness.snapshot();
  for (const OwnershipEdge& edge : snapshot.ownership_edges) {
    TREG_CHECK(tenant_present(snapshot, edge.child));
    TREG_CHECK(tenant_present(snapshot, edge.parent));
    TREG_CHECK(!is_terminal(edge.state));
  }
  for (const ServiceBinding& binding : snapshot.service_bindings) {
    TREG_CHECK(service_present(snapshot, binding.service));
    TREG_CHECK(tenant_present(snapshot, binding.tenant));
  }
  for (const IsolationMembership& membership : snapshot.isolation_memberships) {
    TREG_CHECK(subject_present(snapshot, membership.subject));
    TREG_CHECK(domain_present(snapshot, membership.domain));
    TREG_CHECK(membership.state == MembershipState::Bound || membership.state == MembershipState::Proposed ||
               membership.state == MembershipState::Suspended);
  }
  TREG_CHECK_EQ(snapshot.ownership_edges.size(), 1u);
  TREG_CHECK_EQ(snapshot.service_bindings.size(), 1u);
  TREG_CHECK_EQ(snapshot.isolation_memberships.size(), 2u);
  TREG_CHECK(child.id == child.id);

  // A relationship that is still there is never silently dropped, and one that
  // is removed never leaves a stub behind.
  const auto removed = harness.registry().remove_ownership(RemoveOwnershipRequest{
      context(harness.generation()), child.id, parent.id, RecordRevision::from_value(1)});
  TREG_REQUIRE_OK(removed);
  TREG_CHECK(harness.snapshot().ownership_edges.empty());
  TREG_CHECK(tenant_present(harness.snapshot(), child.id));
  TREG_CHECK(tenant_present(harness.snapshot(), parent.id));
}

}  // namespace
}  // namespace treg_test
