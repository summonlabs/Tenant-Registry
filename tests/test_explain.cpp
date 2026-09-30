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
#include <optional>
#include <string>
#include <vector>

#include "test_support.hpp"

namespace treg_test {
namespace {

using tenant_registry::ErrorCode;
using tenant_registry::ExplainOptions;
using tenant_registry::Explanation;
using tenant_registry::IsolationMembership;
using tenant_registry::OwnershipEdge;
using tenant_registry::ServiceBinding;
using tenant_registry::SetMetadataOutcome;
using tenant_registry::SetMetadataRequest;
using tenant_registry::TenancyMetadata;

std::size_t count_of(const std::vector<std::string>& notes, std::string_view needle) {
  std::size_t count = 0;
  for (const std::string& note : notes) {
    if (note.find(needle) != std::string::npos) {
      ++count;
    }
  }
  return count;
}

bool any_of(const std::vector<std::string>& notes, std::string_view needle) {
  return count_of(notes, needle) != 0;
}

std::string canonical_text(const std::vector<OwnershipEdge>& edges) {
  std::string out;
  for (const OwnershipEdge& edge : edges) {
    if (!out.empty()) {
      out += "\n";
    }
    out += to_canonical(edge);
  }
  return out;
}

std::string canonical_text(const std::vector<ServiceBinding>& bindings) {
  std::string out;
  for (const ServiceBinding& binding : bindings) {
    if (!out.empty()) {
      out += "\n";
    }
    out += to_canonical(binding);
  }
  return out;
}

std::string canonical_text(const std::vector<IsolationMembership>& memberships) {
  std::string out;
  for (const IsolationMembership& membership : memberships) {
    if (!out.empty()) {
      out += "\n";
    }
    out += to_canonical(membership);
  }
  return out;
}

SetMetadataOutcome record_metadata(Harness& harness, const TenancySubject& subject, RecordRevision revision) {
  return unwrap(harness.registry().set_metadata(SetMetadataRequest{context(harness.generation()), subject, revision,
                                                                  {}, {entry("region", "eu")}}),
                "set_metadata");
}

TREG_TEST(explain, a_tenant_explanation_agrees_with_the_records) {
  Harness harness = Harness::ephemeral();
  const TenancyMetadata metadata = unwrap(TenancyMetadata::create({entry("region", "eu")}, 64, 512), "metadata");
  const TenantRecord owner = harness.create_tenant("owner-tenant", std::optional<std::string>{"Owner"},
                                                   std::optional<PrincipalId>{principal_id("ops-owner")},
                                                   TenancyMetadata{});
  require_ok(harness.transition(TenancySubject::of_tenant(owner.id), owner.revision, LifecycleState::Active),
             "activate owner");
  const TenantRecord kid = harness.create_tenant("kid-tenant", std::optional<std::string>{"Kid"},
                                                 std::optional<PrincipalId>{principal_id("ops-kid")}, metadata);
  require_ok(harness.transition(TenancySubject::of_tenant(kid.id), kid.revision, LifecycleState::Active),
             "activate kid");
  harness.active_tenant("grandchild-tenant");
  harness.active_service("renderer");
  const IsolationDomainRecord domain = harness.active_domain("zone-a", IsolationClass::TenantPrivate);
  harness.own("kid-tenant", "owner-tenant", OwnershipKind::Administrative, LifecycleState::Active);
  harness.own("grandchild-tenant", "kid-tenant", OwnershipKind::Operational, LifecycleState::Active);
  harness.bind("renderer", "kid-tenant", BindingKind::Serves);
  harness.join(TenancySubject::of_tenant(kid.id), "zone-a", MembershipRole::Primary);

  const Explanation explanation =
      unwrap(harness.registry().explain(TenancySubject::of_tenant(kid.id)), "explain");
  const RegistrySnapshot snapshot = harness.snapshot();

  TREG_CHECK_EQ(explanation.subject, TenancySubject::of_tenant(kid.id));
  TREG_CHECK_EQ(to_canonical(explanation.record), to_canonical(subject_record(harness.tenant("kid-tenant"))));
  TREG_CHECK(explanation.owner.has_value());
  TREG_CHECK_EQ(*explanation.owner, principal_id("ops-kid"));
  TREG_CHECK_EQ(explanation.generation, harness.generation());
  TREG_CHECK_EQ(explanation.control_epoch, harness.registry().control_epoch());
  TREG_CHECK_EQ(explanation.incarnation, harness.registry().incarnation());

  std::vector<OwnershipEdge> expected_owned_by;
  std::vector<OwnershipEdge> expected_owns;
  std::vector<ServiceBinding> expected_bindings;
  std::vector<IsolationMembership> expected_memberships;
  for (const OwnershipEdge& edge : snapshot.ownership_edges) {
    if (edge.child == kid.id) {
      expected_owned_by.push_back(edge);
    }
    if (edge.parent == kid.id) {
      expected_owns.push_back(edge);
    }
  }
  for (const ServiceBinding& binding : snapshot.service_bindings) {
    if (binding.tenant == kid.id) {
      expected_bindings.push_back(binding);
    }
  }
  for (const IsolationMembership& membership : snapshot.isolation_memberships) {
    if (membership.subject == TenancySubject::of_tenant(kid.id)) {
      expected_memberships.push_back(membership);
    }
  }
  TREG_REQUIRE(expected_owned_by.size() == 1u);
  TREG_REQUIRE(expected_owns.size() == 1u);
  TREG_REQUIRE(expected_bindings.size() == 1u);
  TREG_REQUIRE(expected_memberships.size() == 1u);

  TREG_CHECK_EQ(canonical_text(explanation.owned_by), canonical_text(expected_owned_by));
  TREG_CHECK_EQ(canonical_text(explanation.owns), canonical_text(expected_owns));
  TREG_CHECK_EQ(canonical_text(explanation.bindings), canonical_text(expected_bindings));
  TREG_CHECK_EQ(canonical_text(explanation.memberships), canonical_text(expected_memberships));

  TREG_REQUIRE(explanation.ownership_lineage.size() == 1u);
  TREG_CHECK_EQ(explanation.ownership_lineage.at(0), owner.id);
  TREG_REQUIRE(explanation.domain_generations.size() == 1u);
  TREG_CHECK_EQ(explanation.domain_generations.at(0).first, domain.id);
  TREG_CHECK_EQ(explanation.domain_generations.at(0).second, harness.domain_generation("zone-a"));
  TREG_CHECK(explanation.unknowns.empty());
}

TREG_TEST(explain, a_service_and_a_domain_explanation_agree_with_the_records) {
  Harness harness = Harness::ephemeral();
  harness.active_tenant("acme");
  const ServiceRecord service = harness.active_service("renderer");
  const IsolationDomainRecord domain = harness.active_domain("zone-a");
  harness.bind("renderer", "acme", BindingKind::OperatedBy);
  harness.join(TenancySubject::of_service(service.id), "zone-a", MembershipRole::Secondary);

  const Explanation service_explanation =
      unwrap(harness.registry().explain(TenancySubject::of_service(service.id)), "explain");
  TREG_CHECK_EQ(service_explanation.subject, TenancySubject::of_service(service.id));
  TREG_CHECK_EQ(to_canonical(service_explanation.record), to_canonical(subject_record(harness.service("renderer"))));
  TREG_CHECK(!service_explanation.owner.has_value());
  TREG_CHECK(service_explanation.owned_by.empty());
  TREG_CHECK(service_explanation.owns.empty());
  TREG_CHECK(service_explanation.ownership_lineage.empty());
  TREG_REQUIRE(service_explanation.bindings.size() == 1u);
  TREG_CHECK_EQ(service_explanation.bindings.at(0).service, service.id);
  TREG_REQUIRE(service_explanation.memberships.size() == 1u);
  TREG_CHECK_EQ(service_explanation.memberships.at(0).domain, domain.id);
  TREG_REQUIRE(service_explanation.domain_generations.size() == 1u);
  TREG_CHECK_EQ(service_explanation.domain_generations.at(0).second, harness.domain_generation("zone-a"));
  TREG_CHECK(any_of(service_explanation.unknowns, "display_name"));
  TREG_CHECK(any_of(service_explanation.unknowns, "metadata"));

  const Explanation domain_explanation =
      unwrap(harness.registry().explain(TenancySubject::of_isolation_domain(domain.id)), "explain");
  TREG_CHECK_EQ(domain_explanation.subject, TenancySubject::of_isolation_domain(domain.id));
  TREG_CHECK_EQ(to_canonical(domain_explanation.record), to_canonical(subject_record(harness.domain("zone-a"))));
  TREG_CHECK(domain_explanation.memberships.empty());
  TREG_CHECK(domain_explanation.bindings.empty());
  TREG_CHECK(any_of(domain_explanation.unknowns, "isolation_memberships"));
  TREG_CHECK(any_of(domain_explanation.unknowns, "service_bindings"));
  TREG_CHECK(any_of(domain_explanation.unknowns, "display_name"));
}

TREG_TEST(explain, unknowns_record_every_unset_field_and_never_omit_one) {
  Harness harness = Harness::ephemeral();
  const TenantRecord bare = harness.active_tenant("bare-tenant");

  const Explanation explanation =
      unwrap(harness.registry().explain(TenancySubject::of_tenant(bare.id)), "explain");
  TREG_REQUIRE(explanation.unknowns.size() == 6u);
  TREG_CHECK_EQ(count_of(explanation.unknowns, "display_name: unset"), std::size_t{1});
  TREG_CHECK_EQ(count_of(explanation.unknowns, "owner_principal: unset"), std::size_t{1});
  TREG_CHECK_EQ(count_of(explanation.unknowns, "ownership: no owner is declared for this tenant"), std::size_t{1});
  TREG_CHECK_EQ(count_of(explanation.unknowns, "isolation_memberships: none recorded"), std::size_t{1});
  TREG_CHECK_EQ(count_of(explanation.unknowns, "service_bindings: none recorded"), std::size_t{1});
  TREG_CHECK_EQ(count_of(explanation.unknowns, "metadata: no key has ever been recorded"), std::size_t{1});
  TREG_CHECK_EQ(explanation.unknowns.at(0), std::string{"display_name: unset"});
  TREG_CHECK_EQ(explanation.unknowns.at(1), std::string{"owner_principal: unset"});

  // Every field that becomes known stops being an unknown, one at a time.
  const TenantRecord named = harness.create_tenant("named-tenant", std::optional<std::string>{"Named"},
                                                  std::optional<PrincipalId>{principal_id("ops")});
  const Explanation named_explanation =
      unwrap(harness.registry().explain(TenancySubject::of_tenant(named.id)), "explain");
  TREG_CHECK_EQ(count_of(named_explanation.unknowns, "display_name"), std::size_t{0});
  TREG_CHECK_EQ(count_of(named_explanation.unknowns, "owner_principal"), std::size_t{0});
  TREG_CHECK_EQ(named_explanation.unknowns.size(), std::size_t{4});

  record_metadata(harness, TenancySubject::of_tenant(named.id), harness.tenant("named-tenant").revision);
  const Explanation with_metadata =
      unwrap(harness.registry().explain(TenancySubject::of_tenant(named.id)), "explain");
  TREG_CHECK_EQ(count_of(with_metadata.unknowns, "metadata"), std::size_t{0});
  TREG_CHECK_EQ(with_metadata.unknowns.size(), std::size_t{3});

  // A caller that said it does not want metadata is told that, not told nothing.
  const Explanation without_metadata =
      unwrap(harness.registry().explain(TenancySubject::of_tenant(named.id), ExplainOptions{16, false}), "explain");
  TREG_CHECK_EQ(count_of(without_metadata.unknowns, "metadata: not requested"), std::size_t{1});
}

TREG_TEST(explain, the_digest_is_stable_and_changes_with_the_state) {
  Harness harness = Harness::ephemeral();
  const TenantRecord tenant = harness.active_tenant("acme");
  const TenantRecord other = harness.active_tenant("other");
  const Explanation first = unwrap(harness.registry().explain(TenancySubject::of_tenant(tenant.id)), "explain");
  const Explanation second = unwrap(harness.registry().explain(TenancySubject::of_tenant(tenant.id)), "explain");

  TREG_CHECK_EQ(first.digest(), second.digest());
  TREG_CHECK_EQ(first.to_json(), second.to_json());
  TREG_CHECK_EQ(first.to_text(), second.to_text());
  TREG_CHECK(!first.digest().is_zero());

  const Explanation different_subject =
      unwrap(harness.registry().explain(TenancySubject::of_tenant(other.id)), "explain");
  TREG_CHECK(first.digest() != different_subject.digest());

  record_metadata(harness, TenancySubject::of_tenant(tenant.id), harness.tenant("acme").revision);
  const Explanation after = unwrap(harness.registry().explain(TenancySubject::of_tenant(tenant.id)), "explain");
  TREG_CHECK(first.digest() != after.digest());
  TREG_CHECK(first.to_json() != after.to_json());
  TREG_CHECK(first.to_text() != after.to_text());
  TREG_CHECK(any_of(after.unknowns, "metadata") == false);
}

TREG_TEST(explain, a_lineage_longer_than_the_bound_says_so) {
  Harness harness = Harness::ephemeral();
  harness.active_tenant("top");
  harness.active_tenant("middle");
  harness.active_tenant("bottom");
  harness.active_tenant("leaf");
  harness.own("middle", "top", OwnershipKind::Administrative, LifecycleState::Active);
  harness.own("bottom", "middle", OwnershipKind::Administrative, LifecycleState::Active);
  harness.own("leaf", "bottom", OwnershipKind::Administrative, LifecycleState::Active);

  const Explanation full =
      unwrap(harness.registry().explain(TenancySubject::of_tenant(tenant_id("leaf"))), "explain");
  TREG_REQUIRE(full.ownership_lineage.size() == 3u);
  TREG_CHECK_EQ(full.ownership_lineage.at(0), tenant_id("bottom"));
  TREG_CHECK_EQ(full.ownership_lineage.at(1), tenant_id("middle"));
  TREG_CHECK_EQ(full.ownership_lineage.at(2), tenant_id("top"));
  TREG_CHECK_EQ(count_of(full.unknowns, "truncated"), std::size_t{0});
  TREG_CHECK_EQ(count_of(full.unknowns, "ownership:"), std::size_t{0});

  const Explanation bounded =
      unwrap(harness.registry().explain(TenancySubject::of_tenant(tenant_id("leaf")), ExplainOptions{2, true}),
             "explain");
  TREG_REQUIRE(bounded.ownership_lineage.size() == 2u);
  TREG_CHECK_EQ(bounded.ownership_lineage.at(0), tenant_id("bottom"));
  TREG_CHECK_EQ(bounded.ownership_lineage.at(1), tenant_id("middle"));
  TREG_CHECK_EQ(count_of(bounded.unknowns, "truncated at the configured depth of 2"), std::size_t{1});
}

TREG_TEST(explain, a_missing_subject_and_an_excessive_lineage_depth_are_refused) {
  Harness harness = Harness::ephemeral();
  harness.active_tenant("acme");
  TREG_CHECK_CODE(harness.registry().explain(TenancySubject::of_tenant(tenant_id("ghost"))), ErrorCode::NotFound);
  TREG_CHECK_CODE(harness.registry().explain(TenancySubject::of_tenant(tenant_id("acme")),
                                             ExplainOptions{5000, true}),
                  ErrorCode::TraversalLimitExceeded);
}

TREG_TEST(explain, the_rendered_forms_are_deterministic_and_describe_the_subject) {
  Harness harness = Harness::ephemeral();
  const TenantRecord tenant = harness.active_tenant("acme");
  const Explanation explanation =
      unwrap(harness.registry().explain(TenancySubject::of_tenant(tenant.id)), "explain");

  const std::string json = explanation.to_json();
  const std::string text = explanation.to_text();
  TREG_CHECK_EQ(json, explanation.to_json());
  TREG_CHECK_EQ(text, explanation.to_text());
  TREG_CHECK(json.size() > 2u);
  TREG_CHECK_EQ(json.front(), '{');
  TREG_CHECK_EQ(json.back(), '}');
  // The rendering carries no line breaks or tabs; the spaces it does carry are
  // inside string values, where they are data and not layout.
  TREG_CHECK_EQ(json.find('\n'), std::string::npos);
  TREG_CHECK_EQ(json.find('\t'), std::string::npos);
  TREG_CHECK_EQ(json.find("\" \""), std::string::npos);
  TREG_CHECK(text.find("subject   : tenant:acme") != std::string::npos);
  TREG_CHECK(text.find("unknown   : display_name: unset") != std::string::npos);
  TREG_CHECK(text.find("digest    : " + explanation.digest().to_text()) != std::string::npos);
}

}  // namespace
}  // namespace treg_test
