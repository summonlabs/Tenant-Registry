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

using tenant_registry::BindingQuery;
using tenant_registry::DomainQuery;
using tenant_registry::DomainSummary;
using tenant_registry::ErrorCode;
using tenant_registry::MembershipQuery;
using tenant_registry::MembershipSummary;
using tenant_registry::OwnershipEdge;
using tenant_registry::OwnershipQuery;
using tenant_registry::Page;
using tenant_registry::ServiceBinding;
using tenant_registry::ServiceQuery;
using tenant_registry::ServiceSummary;
using tenant_registry::TenantQuery;
using tenant_registry::TenantSummary;

std::string tenant_ids(const Page<TenantSummary>& page) {
  std::string out;
  for (const TenantSummary& summary : page.items) {
    if (!out.empty()) {
      out += ",";
    }
    out += summary.id.value();
  }
  return out;
}

std::string service_ids(const Page<ServiceSummary>& page) {
  std::string out;
  for (const ServiceSummary& summary : page.items) {
    if (!out.empty()) {
      out += ",";
    }
    out += summary.id.value();
  }
  return out;
}

std::string domain_ids(const Page<DomainSummary>& page) {
  std::string out;
  for (const DomainSummary& summary : page.items) {
    if (!out.empty()) {
      out += ",";
    }
    out += summary.id.value();
  }
  return out;
}

std::string membership_text(const Page<MembershipSummary>& page) {
  std::string out;
  for (const MembershipSummary& summary : page.items) {
    if (!out.empty()) {
      out += ",";
    }
    out += summary.subject.to_text();
    out += "@";
    out += summary.domain.value();
  }
  return out;
}

std::string ownership_text(const Page<OwnershipEdge>& page) {
  std::string out;
  for (const OwnershipEdge& edge : page.items) {
    if (!out.empty()) {
      out += ",";
    }
    out += edge.child.value();
    out += "->";
    out += edge.parent.value();
  }
  return out;
}

std::string binding_text(const Page<ServiceBinding>& page) {
  std::string out;
  for (const ServiceBinding& binding : page.items) {
    if (!out.empty()) {
      out += ",";
    }
    out += binding.service.value();
    out += "->";
    out += binding.tenant.value();
    out += ":";
    out += to_token(binding.kind);
  }
  return out;
}

/// A registry whose contents are known field by field, built in an order that
/// is deliberately not the order any query returns.
void build_populated(Harness& harness) {
  harness.active_tenant("t7", std::optional<PrincipalId>{principal_id("ops-b")});
  harness.active_tenant("t4");
  harness.create_tenant("t6");
  harness.active_tenant("t1", std::optional<PrincipalId>{principal_id("ops-a")});
  const TenantRecord t5 = harness.active_tenant("t5");
  harness.active_tenant("t2", std::optional<PrincipalId>{principal_id("ops-a")});
  harness.active_tenant("t3", std::optional<PrincipalId>{principal_id("ops-b")});
  require_ok(harness.transition(TenancySubject::of_tenant(t5.id), t5.revision, LifecycleState::Suspended),
             "suspend t5");

  harness.active_service("s2");
  harness.create_service("s4");
  harness.active_service("s1");
  harness.active_service("s3");

  harness.active_domain("d2", IsolationClass::Administrative);
  harness.create_domain("d3", IsolationClass::Regulatory);
  harness.active_domain("d1", IsolationClass::FaultContainment);

  harness.join(TenancySubject::of_tenant(tenant_id("t1")), "d1", MembershipRole::Primary);
  harness.join(TenancySubject::of_tenant(tenant_id("t2")), "d1", MembershipRole::Secondary);
  harness.join(TenancySubject::of_service(service_id("s1")), "d1", MembershipRole::Secondary);
  harness.join(TenancySubject::of_tenant(tenant_id("t3")), "d2", MembershipRole::Primary,
               MembershipState::Proposed);
  harness.join(TenancySubject::of_tenant(tenant_id("t4")), "d2", MembershipRole::Fallback);

  harness.own("t2", "t1", OwnershipKind::Administrative, LifecycleState::Active);
  harness.own("t3", "t1", OwnershipKind::Operational, LifecycleState::Active);
  harness.own("t4", "t2", OwnershipKind::Operational, LifecycleState::Declared);

  harness.bind("s1", "t1", BindingKind::OperatedBy, LifecycleState::Active);
  harness.bind("s2", "t1", BindingKind::Serves, LifecycleState::Active);
  harness.bind("s3", "t2", BindingKind::ConsumedBy, LifecycleState::Declared);
}

TREG_TEST(query, list_tenants_applies_every_filter) {
  Harness harness = Harness::ephemeral();
  build_populated(harness);

  TenantQuery all;
  const Page<TenantSummary> everything = unwrap(harness.registry().list_tenants(all), "list_tenants");
  TREG_CHECK_EQ(everything.total_matched, std::size_t{7});
  TREG_CHECK_EQ(tenant_ids(everything), std::string{"t1,t2,t3,t4,t5,t6,t7"});

  TenantQuery active;
  active.state = LifecycleState::Active;
  const Page<TenantSummary> active_page = unwrap(harness.registry().list_tenants(active), "list_tenants");
  TREG_CHECK_EQ(active_page.total_matched, std::size_t{5});
  TREG_CHECK_EQ(tenant_ids(active_page), std::string{"t1,t2,t3,t4,t7"});

  TenantQuery declared;
  declared.state = LifecycleState::Declared;
  TREG_CHECK_EQ(tenant_ids(unwrap(harness.registry().list_tenants(declared), "list_tenants")), std::string{"t6"});

  TenantQuery suspended;
  suspended.state = LifecycleState::Suspended;
  TREG_CHECK_EQ(tenant_ids(unwrap(harness.registry().list_tenants(suspended), "list_tenants")), std::string{"t5"});

  TenantQuery owned;
  owned.owner = principal_id("ops-a");
  const Page<TenantSummary> owned_page = unwrap(harness.registry().list_tenants(owned), "list_tenants");
  TREG_CHECK_EQ(owned_page.total_matched, std::size_t{2});
  TREG_CHECK_EQ(tenant_ids(owned_page), std::string{"t1,t2"});

  TenantQuery members;
  members.member_of_domain = domain_id("d1");
  TREG_CHECK_EQ(tenant_ids(unwrap(harness.registry().list_tenants(members), "list_tenants")),
                std::string{"t1,t2"});

  TenantQuery proposed;
  proposed.member_of_domain = domain_id("d2");
  proposed.member_state = MembershipState::Proposed;
  TREG_CHECK_EQ(tenant_ids(unwrap(harness.registry().list_tenants(proposed), "list_tenants")), std::string{"t3"});

  // A membership state without a domain is an assertion about nothing, and the
  // answer to nothing is nothing.
  TenantQuery orphan_state;
  orphan_state.member_state = MembershipState::Bound;
  TREG_CHECK(unwrap(harness.registry().list_tenants(orphan_state), "list_tenants").items.empty());

  TenantQuery owned_children;
  owned_children.child_of = tenant_id("t1");
  TREG_CHECK_EQ(tenant_ids(unwrap(harness.registry().list_tenants(owned_children), "list_tenants")),
                std::string{"t2,t3"});

  TenantQuery owner_of;
  owner_of.parent_of = tenant_id("t2");
  TREG_CHECK_EQ(tenant_ids(unwrap(harness.registry().list_tenants(owner_of), "list_tenants")), std::string{"t1"});
}

TREG_TEST(query, list_services_and_domains_apply_every_filter) {
  Harness harness = Harness::ephemeral();
  build_populated(harness);

  const Page<ServiceSummary> services = unwrap(harness.registry().list_services(ServiceQuery{}), "list_services");
  TREG_CHECK_EQ(services.total_matched, std::size_t{4});
  TREG_CHECK_EQ(service_ids(services), std::string{"s1,s2,s3,s4"});

  ServiceQuery active;
  active.state = LifecycleState::Active;
  TREG_CHECK_EQ(service_ids(unwrap(harness.registry().list_services(active), "list_services")),
                std::string{"s1,s2,s3"});

  ServiceQuery bound_to_t1;
  bound_to_t1.bound_to_tenant = tenant_id("t1");
  TREG_CHECK_EQ(service_ids(unwrap(harness.registry().list_services(bound_to_t1), "list_services")),
                std::string{"s1,s2"});

  ServiceQuery operated;
  operated.bound_to_tenant = tenant_id("t1");
  operated.binding_kind = BindingKind::OperatedBy;
  TREG_CHECK_EQ(service_ids(unwrap(harness.registry().list_services(operated), "list_services")),
                std::string{"s1"});

  ServiceQuery member;
  member.member_of_domain = domain_id("d1");
  TREG_CHECK_EQ(service_ids(unwrap(harness.registry().list_services(member), "list_services")),
                std::string{"s1"});

  const Page<DomainSummary> domains =
      unwrap(harness.registry().list_isolation_domains(DomainQuery{}), "list_isolation_domains");
  TREG_CHECK_EQ(domains.total_matched, std::size_t{3});
  TREG_CHECK_EQ(domain_ids(domains), std::string{"d1,d2,d3"});

  DomainQuery active_domains;
  active_domains.state = LifecycleState::Active;
  TREG_CHECK_EQ(domain_ids(unwrap(harness.registry().list_isolation_domains(active_domains),
                                  "list_isolation_domains")),
                std::string{"d1,d2"});

  DomainQuery administrative;
  administrative.isolation_class = IsolationClass::Administrative;
  TREG_CHECK_EQ(domain_ids(unwrap(harness.registry().list_isolation_domains(administrative),
                                  "list_isolation_domains")),
                std::string{"d2"});

  DomainQuery regulatory;
  regulatory.isolation_class = IsolationClass::Regulatory;
  TREG_CHECK_EQ(domain_ids(unwrap(harness.registry().list_isolation_domains(regulatory),
                                  "list_isolation_domains")),
                std::string{"d3"});
}

TREG_TEST(query, list_relationships_apply_every_filter) {
  Harness harness = Harness::ephemeral();
  build_populated(harness);

  const Page<MembershipSummary> memberships =
      unwrap(harness.registry().list_isolation_memberships(MembershipQuery{}), "list_isolation_memberships");
  TREG_CHECK_EQ(memberships.total_matched, std::size_t{5});
  TREG_CHECK_EQ(membership_text(memberships),
                std::string{"service:s1@d1,tenant:t1@d1,tenant:t2@d1,tenant:t3@d2,tenant:t4@d2"});

  MembershipQuery in_d1;
  in_d1.domain = domain_id("d1");
  TREG_CHECK_EQ(membership_text(unwrap(harness.registry().list_isolation_memberships(in_d1),
                                       "list_isolation_memberships")),
                std::string{"service:s1@d1,tenant:t1@d1,tenant:t2@d1"});

  MembershipQuery of_t1;
  of_t1.subject = TenancySubject::of_tenant(tenant_id("t1"));
  TREG_CHECK_EQ(membership_text(unwrap(harness.registry().list_isolation_memberships(of_t1),
                                       "list_isolation_memberships")),
                std::string{"tenant:t1@d1"});

  MembershipQuery bound;
  bound.state = MembershipState::Bound;
  TREG_CHECK_EQ(unwrap(harness.registry().list_isolation_memberships(bound),
                       "list_isolation_memberships").total_matched,
                std::size_t{4});

  MembershipQuery primary;
  primary.role = MembershipRole::Primary;
  TREG_CHECK_EQ(membership_text(unwrap(harness.registry().list_isolation_memberships(primary),
                                       "list_isolation_memberships")),
                std::string{"tenant:t1@d1,tenant:t3@d2"});

  const Page<OwnershipEdge> edges = unwrap(harness.registry().list_ownership(OwnershipQuery{}), "list_ownership");
  TREG_CHECK_EQ(edges.total_matched, std::size_t{3});
  TREG_CHECK_EQ(ownership_text(edges), std::string{"t2->t1,t3->t1,t4->t2"});

  OwnershipQuery of_child;
  of_child.child = tenant_id("t2");
  TREG_CHECK_EQ(ownership_text(unwrap(harness.registry().list_ownership(of_child), "list_ownership")),
                std::string{"t2->t1"});

  OwnershipQuery of_parent;
  of_parent.parent = tenant_id("t1");
  TREG_CHECK_EQ(ownership_text(unwrap(harness.registry().list_ownership(of_parent), "list_ownership")),
                std::string{"t2->t1,t3->t1"});

  OwnershipQuery operational;
  operational.kind = OwnershipKind::Operational;
  TREG_CHECK_EQ(unwrap(harness.registry().list_ownership(operational), "list_ownership").total_matched,
                std::size_t{2});

  OwnershipQuery in_force;
  in_force.state = LifecycleState::Active;
  TREG_CHECK_EQ(unwrap(harness.registry().list_ownership(in_force), "list_ownership").total_matched,
                std::size_t{2});

  const Page<ServiceBinding> bindings =
      unwrap(harness.registry().list_service_bindings(BindingQuery{}), "list_service_bindings");
  TREG_CHECK_EQ(bindings.total_matched, std::size_t{3});
  TREG_CHECK_EQ(binding_text(bindings), std::string{"s1->t1:operated_by,s2->t1:serves,s3->t2:consumed_by"});

  BindingQuery of_service;
  of_service.service = service_id("s2");
  TREG_CHECK_EQ(binding_text(unwrap(harness.registry().list_service_bindings(of_service),
                                    "list_service_bindings")),
                std::string{"s2->t1:serves"});

  BindingQuery of_tenant;
  of_tenant.tenant = tenant_id("t1");
  TREG_CHECK_EQ(unwrap(harness.registry().list_service_bindings(of_tenant), "list_service_bindings").total_matched,
                std::size_t{2});

  BindingQuery declared;
  declared.state = LifecycleState::Declared;
  TREG_CHECK_EQ(binding_text(unwrap(harness.registry().list_service_bindings(declared),
                                    "list_service_bindings")),
                std::string{"s3->t2:consumed_by"});
}

TREG_TEST(query, every_listing_is_ordered_by_canonical_key) {
  Harness harness = Harness::ephemeral();
  build_populated(harness);

  const Page<TenantSummary> tenants = unwrap(harness.registry().list_tenants(TenantQuery{}), "list_tenants");
  for (std::size_t index = 1; index < tenants.items.size(); ++index) {
    TREG_CHECK(tenants.items[index - 1].id.value() < tenants.items[index].id.value());
  }
  const Page<ServiceSummary> services = unwrap(harness.registry().list_services(ServiceQuery{}), "list_services");
  for (std::size_t index = 1; index < services.items.size(); ++index) {
    TREG_CHECK(services.items[index - 1].id.value() < services.items[index].id.value());
  }
  const Page<DomainSummary> domains =
      unwrap(harness.registry().list_isolation_domains(DomainQuery{}), "list_isolation_domains");
  for (std::size_t index = 1; index < domains.items.size(); ++index) {
    TREG_CHECK(domains.items[index - 1].id.value() < domains.items[index].id.value());
  }
  const Page<OwnershipEdge> edges = unwrap(harness.registry().list_ownership(OwnershipQuery{}), "list_ownership");
  for (std::size_t index = 1; index < edges.items.size(); ++index) {
    const bool ordered = edges.items[index - 1].child.value() < edges.items[index].child.value() ||
                         (edges.items[index - 1].child == edges.items[index].child &&
                          edges.items[index - 1].parent.value() < edges.items[index].parent.value());
    TREG_CHECK(ordered);
  }
  const Page<MembershipSummary> memberships =
      unwrap(harness.registry().list_isolation_memberships(MembershipQuery{}), "list_isolation_memberships");
  for (std::size_t index = 1; index < memberships.items.size(); ++index) {
    TREG_CHECK(memberships.items[index - 1].subject.to_text() < memberships.items[index].subject.to_text());
  }
  const Page<ServiceBinding> bindings =
      unwrap(harness.registry().list_service_bindings(BindingQuery{}), "list_service_bindings");
  for (std::size_t index = 1; index < bindings.items.size(); ++index) {
    const ServiceBinding& before = bindings.items[index - 1];
    const ServiceBinding& after = bindings.items[index];
    const bool ordered = before.service.value() < after.service.value() ||
                         (before.service == after.service && before.tenant.value() < after.tenant.value()) ||
                         (before.service == after.service && before.tenant == after.tenant &&
                          to_token(before.kind) < to_token(after.kind));
    TREG_CHECK(ordered);
  }
}

TREG_TEST(query, cursor_pagination_visits_every_record_exactly_once) {
  Harness harness = Harness::ephemeral();
  build_populated(harness);

  std::vector<std::string> visited;
  std::optional<std::string> cursor;
  std::size_t pages = 0;
  while (true) {
    TenantQuery query;
    query.limit = 2;
    query.cursor = cursor;
    const Page<TenantSummary> page = unwrap(harness.registry().list_tenants(query), "list_tenants");
    ++pages;
    // Every page reports the whole answer's size, and says whether it was cut.
    TREG_CHECK_EQ(page.total_matched, std::size_t{7});
    TREG_CHECK_EQ(page.truncated, page.next_cursor.has_value());
    for (const TenantSummary& summary : page.items) {
      TREG_CHECK_EQ(summary.state, harness.tenant(summary.id.value()).state);
      TREG_CHECK_EQ(summary.revision, harness.tenant(summary.id.value()).revision);
      visited.push_back(summary.id.value());
    }
    if (!page.next_cursor.has_value()) {
      break;
    }
    cursor = page.next_cursor;
    TREG_REQUIRE(pages < 10u);
  }

  TREG_CHECK_EQ(pages, std::size_t{4});
  TREG_REQUIRE(visited.size() == 7u);
  const std::string joined = visited.at(0) + "," + visited.at(1) + "," + visited.at(2) + "," + visited.at(3) + "," +
                             visited.at(4) + "," + visited.at(5) + "," + visited.at(6);
  TREG_CHECK_EQ(joined, std::string{"t1,t2,t3,t4,t5,t6,t7"});

  // A page that happens to be exactly the answer is not truncated and carries no
  // cursor, because there is nothing left to read.
  TenantQuery exact;
  exact.limit = 7;
  const Page<TenantSummary> whole = unwrap(harness.registry().list_tenants(exact), "list_tenants");
  TREG_CHECK_EQ(whole.items.size(), 7u);
  TREG_CHECK(!whole.truncated);
  TREG_CHECK(!whole.next_cursor.has_value());

  // The same walk with a filter over three matching records.
  std::vector<std::string> filtered;
  std::optional<std::string> filter_cursor;
  while (true) {
    TenantQuery query;
    query.state = LifecycleState::Active;
    query.limit = 1;
    query.cursor = filter_cursor;
    const Page<TenantSummary> page = unwrap(harness.registry().list_tenants(query), "list_tenants");
    TREG_CHECK_EQ(page.total_matched, std::size_t{5});
    for (const TenantSummary& summary : page.items) {
      filtered.push_back(summary.id.value());
    }
    if (!page.next_cursor.has_value()) {
      break;
    }
    filter_cursor = page.next_cursor;
    TREG_REQUIRE(filtered.size() < 10u);
  }
  TREG_REQUIRE(filtered.size() == 5u);
  TREG_CHECK_EQ(filtered.at(0), "t1");
  TREG_CHECK_EQ(filtered.at(4), "t7");
}

TREG_TEST(query, a_limit_above_the_configured_maximum_is_refused) {
  RegistryLimits limits;
  limits.default_listing_limit = 2;
  limits.max_listing_limit = 3;
  Harness harness = Harness::ephemeral(limits);
  harness.active_tenant("t1");
  harness.active_tenant("t2");
  harness.active_tenant("t3");

  TenantQuery too_big;
  too_big.limit = 4;
  const auto refusal = harness.registry().list_tenants(too_big);
  TREG_CHECK_CODE(refusal, ErrorCode::ListingLimitExceeded);
  TREG_CHECK(refusal.error().detail().find("4") != std::string::npos);
  TREG_CHECK(refusal.error().detail().find("3") != std::string::npos);

  TenantQuery at_the_bound;
  at_the_bound.limit = 3;
  TREG_CHECK_EQ(unwrap(harness.registry().list_tenants(at_the_bound), "list_tenants").items.size(), 3u);

  ServiceQuery service_query;
  service_query.limit = 4;
  TREG_CHECK_CODE(harness.registry().list_services(service_query), ErrorCode::ListingLimitExceeded);
  DomainQuery domain_query;
  domain_query.limit = 4;
  TREG_CHECK_CODE(harness.registry().list_isolation_domains(domain_query), ErrorCode::ListingLimitExceeded);
  MembershipQuery membership_query;
  membership_query.limit = 4;
  TREG_CHECK_CODE(harness.registry().list_isolation_memberships(membership_query),
                  ErrorCode::ListingLimitExceeded);
  OwnershipQuery ownership_query;
  ownership_query.limit = 4;
  TREG_CHECK_CODE(harness.registry().list_ownership(ownership_query), ErrorCode::ListingLimitExceeded);
  BindingQuery binding_query;
  binding_query.limit = 4;
  TREG_CHECK_CODE(harness.registry().list_service_bindings(binding_query), ErrorCode::ListingLimitExceeded);
}

TREG_TEST(query, a_limit_of_zero_uses_the_configured_default) {
  RegistryLimits limits;
  limits.default_listing_limit = 2;
  limits.max_listing_limit = 3;
  Harness harness = Harness::ephemeral(limits);
  harness.active_tenant("t1");
  harness.active_tenant("t2");
  harness.active_tenant("t3");
  harness.active_tenant("t4");
  harness.active_tenant("t5");

  // Zero is not a request for nothing; it is the absence of a request, and the
  // configured default answers it.
  TenantQuery unspecified;
  const Page<TenantSummary> page = unwrap(harness.registry().list_tenants(unspecified), "list_tenants");
  TREG_CHECK_EQ(page.items.size(), 2u);
  TREG_CHECK_EQ(page.total_matched, std::size_t{5});
  TREG_CHECK(page.truncated);
  TREG_REQUIRE(page.next_cursor.has_value());

  TenantQuery continuation;
  continuation.limit = 0;
  continuation.cursor = page.next_cursor;
  const Page<TenantSummary> second = unwrap(harness.registry().list_tenants(continuation), "list_tenants");
  TREG_CHECK_EQ(second.items.size(), 2u);
  TREG_CHECK_EQ(tenant_ids(second), std::string{"t3,t4"});
  TREG_CHECK_EQ(second.total_matched, std::size_t{5});
}

}  // namespace
}  // namespace treg_test
