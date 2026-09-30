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

using tenant_registry::ContentDigest;
using tenant_registry::ErrorCode;
using tenant_registry::IrreversibleAcknowledgement;
using tenant_registry::PutIsolationMembershipRequest;
using tenant_registry::PutOwnershipOutcome;
using tenant_registry::PutOwnershipRequest;
using tenant_registry::PutServiceBindingRequest;
using tenant_registry::RebindSuccessor;
using tenant_registry::RegistryStats;
using tenant_registry::SetMetadataOutcome;
using tenant_registry::SetMetadataRequest;
using tenant_registry::SetOwnerRequest;
using tenant_registry::TenancyMetadata;
using tenant_registry::TombstoneRequest;

std::string canonical_text(const std::vector<TenantRecord>& records) {
  std::string out;
  for (const TenantRecord& record : records) {
    if (!out.empty()) {
      out += "\n";
    }
    out += to_canonical(record);
  }
  return out;
}

PutOwnershipRequest edge_request(RegistryGeneration expected, const std::optional<IdempotencyKey>& key) {
  return PutOwnershipRequest{MutationContext{expected, key, provenance()}, tenant_id("t2"), tenant_id("t1"),
                             OwnershipKind::Operational, LifecycleState::Active, std::nullopt};
}

/// The same operations in the same order, plus, when extra is set, a replayed
/// request and two refused ones, none of which may leave a trace.
void settle(TenantRegistry& registry, bool extra) {
  const IdempotencyKey key = idempotency_key("edge-key");
  unwrap(registry.create_tenant(CreateTenantRequest{context(registry.generation()), tenant_id("t1"), std::nullopt,
                                                   std::nullopt, TenancyMetadata{}}),
         "create_tenant");
  unwrap(registry.create_tenant(CreateTenantRequest{context(registry.generation()), tenant_id("t2"), std::nullopt,
                                                   std::nullopt, TenancyMetadata{}}),
         "create_tenant");
  for (const char* name : {"t1", "t2"}) {
    const TenantRecord record = unwrap(registry.find_tenant(tenant_id(name)), "find_tenant");
    unwrap(registry.transition_subject(TransitionSubjectRequest{context(registry.generation()),
                                                               TenancySubject::of_tenant(record.id),
                                                               record.revision, LifecycleState::Active}),
           "transition_subject");
  }
  const RegistryGeneration expected = registry.generation();
  const PutOwnershipOutcome edge =
      unwrap(registry.put_ownership(edge_request(expected, key)), "put_ownership");
  TREG_CHECK(!edge.receipt.replayed);
  if (extra) {
    // The identical request again: the answer comes from the ledger, not from a
    // second application, even though the generation it names is now stale.
    const PutOwnershipOutcome replay =
        unwrap(registry.put_ownership(edge_request(expected, key)), "put_ownership");
    TREG_CHECK(replay.receipt.replayed);
    TREG_CHECK_EQ(replay.receipt.generation, edge.receipt.generation);

    const auto duplicate = registry.create_tenant(CreateTenantRequest{
        context(registry.generation()), tenant_id("t1"), std::nullopt, std::nullopt, TenancyMetadata{}});
    TREG_CHECK_CODE(duplicate, ErrorCode::IdentityAlreadyExists);
    const TenantRecord current = unwrap(registry.find_tenant(tenant_id("t1")), "find_tenant");
    const auto stale = registry.transition_subject(TransitionSubjectRequest{
        context(registry.generation()), TenancySubject::of_tenant(current.id), RecordRevision::from_value(99),
        LifecycleState::Suspended});
    TREG_CHECK_CODE(stale, ErrorCode::StaleRecordRevision);
  }

  const CreateIsolationDomainOutcome domain =
      unwrap(registry.create_isolation_domain(CreateIsolationDomainRequest{
                 context(registry.generation()), domain_id("d1"), IsolationClass::FaultContainment, std::nullopt,
                 TenancyMetadata{}}),
             "create_isolation_domain");
  unwrap(registry.transition_subject(TransitionSubjectRequest{context(registry.generation()),
                                                             TenancySubject::of_isolation_domain(
                                                                 domain.record.id),
                                                             domain.record.revision, LifecycleState::Active}),
         "transition_subject");
  const IsolationDomainRecord active_domain =
      unwrap(registry.find_isolation_domain(domain_id("d1")), "find_isolation_domain");
  unwrap(registry.put_isolation_membership(PutIsolationMembershipRequest{
             context(registry.generation()), TenancySubject::of_tenant(tenant_id("t1")), active_domain.id,
             MembershipRole::Primary, MembershipState::Bound, active_domain.membership_generation, std::nullopt}),
         "put_isolation_membership");

  const CreateServiceOutcome service =
      unwrap(registry.create_service(CreateServiceRequest{context(registry.generation()), service_id("s1"),
                                                          std::nullopt, TenancyMetadata{}}),
             "create_service");
  unwrap(registry.transition_subject(TransitionSubjectRequest{context(registry.generation()),
                                                             TenancySubject::of_service(service.record.id),
                                                             service.record.revision, LifecycleState::Active}),
         "transition_subject");
  unwrap(registry.put_service_binding(PutServiceBindingRequest{context(registry.generation()), service.record.id,
                                                              tenant_id("t1"), BindingKind::Serves,
                                                              LifecycleState::Active, std::nullopt}),
         "put_service_binding");
}

TREG_TEST(snapshot, every_collection_is_in_canonical_order) {
  Harness harness = Harness::ephemeral();
  harness.active_tenant("zulu");
  harness.active_tenant("alpha");
  harness.active_tenant("mike");
  harness.active_service("zulu-service");
  harness.active_service("alpha-service");
  harness.active_domain("zulu-domain");
  harness.active_domain("alpha-domain");
  harness.own("alpha", "mike", OwnershipKind::Operational, LifecycleState::Active);
  harness.own("alpha", "zulu", OwnershipKind::Operational, LifecycleState::Declared);
  harness.own("mike", "zulu", OwnershipKind::Operational, LifecycleState::Active);
  harness.bind("zulu-service", "alpha", BindingKind::Serves);
  harness.bind("alpha-service", "mike", BindingKind::Serves);
  harness.join(TenancySubject::of_tenant(tenant_id("zulu")), "alpha-domain", MembershipRole::Primary);
  harness.join(TenancySubject::of_tenant(tenant_id("alpha")), "zulu-domain", MembershipRole::Secondary);

  const RegistrySnapshot snapshot = harness.snapshot();
  TREG_REQUIRE(snapshot.tenants.size() == 3u);
  TREG_REQUIRE(snapshot.services.size() == 2u);
  TREG_REQUIRE(snapshot.isolation_domains.size() == 2u);
  TREG_CHECK_EQ(snapshot.tenants.at(0).id.value(), "alpha");
  TREG_CHECK_EQ(snapshot.tenants.at(1).id.value(), "mike");
  TREG_CHECK_EQ(snapshot.tenants.at(2).id.value(), "zulu");
  TREG_CHECK_EQ(snapshot.services.at(0).id.value(), "alpha-service");
  TREG_CHECK_EQ(snapshot.services.at(1).id.value(), "zulu-service");
  TREG_CHECK_EQ(snapshot.isolation_domains.at(0).id.value(), "alpha-domain");
  TREG_CHECK_EQ(snapshot.isolation_domains.at(1).id.value(), "zulu-domain");

  TREG_REQUIRE(snapshot.ownership_edges.size() == 3u);
  TREG_CHECK_EQ(snapshot.ownership_edges.at(0).child.value(), "alpha");
  TREG_CHECK_EQ(snapshot.ownership_edges.at(0).parent.value(), "mike");
  TREG_CHECK_EQ(snapshot.ownership_edges.at(1).child.value(), "alpha");
  TREG_CHECK_EQ(snapshot.ownership_edges.at(1).parent.value(), "zulu");
  TREG_CHECK_EQ(snapshot.ownership_edges.at(2).child.value(), "mike");
  TREG_REQUIRE(snapshot.service_bindings.size() == 2u);
  TREG_CHECK_EQ(snapshot.service_bindings.at(0).service.value(), "alpha-service");
  TREG_CHECK_EQ(snapshot.service_bindings.at(1).service.value(), "zulu-service");
  TREG_REQUIRE(snapshot.isolation_memberships.size() == 2u);
  TREG_CHECK_EQ(snapshot.isolation_memberships.at(0).subject.to_text(), "tenant:alpha");
  TREG_CHECK_EQ(snapshot.isolation_memberships.at(0).domain.value(), "zulu-domain");
  TREG_CHECK_EQ(snapshot.isolation_memberships.at(1).subject.to_text(), "tenant:zulu");
  TREG_REQUIRE(snapshot.domain_generations.size() == 2u);
  TREG_CHECK_EQ(snapshot.domain_generations.at(0).first.value(), "alpha-domain");
  TREG_CHECK_EQ(snapshot.domain_generations.at(1).first.value(), "zulu-domain");
}

TREG_TEST(snapshot, record_count_adds_up) {
  Harness harness = Harness::ephemeral();
  harness.active_tenant("alpha");
  harness.active_tenant("mike");
  harness.active_service("renderer");
  harness.active_domain("zone-a");
  harness.own("mike", "alpha", OwnershipKind::Operational, LifecycleState::Active);
  harness.bind("renderer", "alpha", BindingKind::Serves);
  harness.join(TenancySubject::of_tenant(tenant_id("alpha")), "zone-a", MembershipRole::Primary);

  const RegistrySnapshot snapshot = harness.snapshot();
  const std::size_t expected = snapshot.tenants.size() + snapshot.services.size() +
                               snapshot.isolation_domains.size() + snapshot.ownership_edges.size() +
                               snapshot.service_bindings.size() + snapshot.isolation_memberships.size() +
                               snapshot.tombstones.size();
  TREG_CHECK_EQ(snapshot.record_count(), expected);
  TREG_CHECK_EQ(snapshot.record_count(), std::size_t{7});
  TREG_CHECK_EQ(snapshot.generation, harness.generation());
  TREG_CHECK_EQ(snapshot.committed_sequence, harness.registry().committed_sequence());
  TREG_CHECK_EQ(snapshot.control_epoch, harness.registry().control_epoch());
  TREG_CHECK_EQ(snapshot.incarnation, harness.registry().incarnation());
  TREG_CHECK(!snapshot.store_id.has_value());

  const RegistryStats stats = harness.registry().stats();
  TREG_CHECK_EQ(stats.tenants + stats.services + stats.isolation_domains + stats.ownership_edges +
                    stats.service_bindings + stats.isolation_memberships,
                std::uint64_t{7});
  TREG_CHECK(!stats.store_id.has_value());
}

TREG_TEST(snapshot, two_registries_that_reached_the_same_state_share_a_digest) {
  EphemeralOptions options;
  options.limits = RegistryLimits{};
  options.clock = std::make_shared<FixedClock>(1);
  TenantRegistry plain = unwrap(TenantRegistry::open_ephemeral(options), "open_ephemeral");
  TenantRegistry disturbed = unwrap(TenantRegistry::open_ephemeral(options), "open_ephemeral");
  settle(plain, false);
  settle(disturbed, true);

  const RegistrySnapshot first = plain.snapshot();
  const RegistrySnapshot second = disturbed.snapshot();
  TREG_CHECK_EQ(first.generation, second.generation);
  TREG_CHECK_EQ(first.record_count(), second.record_count());
  TREG_CHECK_EQ(first.digest(), second.digest());
  TREG_CHECK_EQ(first.to_canonical_bytes(), second.to_canonical_bytes());
  TREG_CHECK_EQ(first.to_json(), second.to_json());
  TREG_CHECK_EQ(canonical_text(first.tenants), canonical_text(second.tenants));

  // The operations really were different: the disturbed registry was answered
  // from its ledger rather than recomputing, and still holds the same state.
  TREG_CHECK(!first.tenants.empty());
}

TREG_TEST(snapshot, the_digest_changes_when_any_field_changes) {
  Harness harness = Harness::ephemeral();
  harness.active_service("renderer");
  harness.active_domain("zone-a");
  const TenantRecord tenant = harness.create_tenant("acme", std::optional<std::string>{"Acme"},
                                                   std::optional<PrincipalId>{principal_id("ops")});
  require_ok(harness.transition(TenancySubject::of_tenant(tenant.id), tenant.revision, LifecycleState::Active),
             "activate");

  std::vector<ContentDigest> digests;
  digests.push_back(harness.snapshot().digest());

  // A refused relationship is not a state change at all.
  TREG_CHECK_CODE(harness.registry().put_ownership(PutOwnershipRequest{
                      context(harness.generation()), tenant.id, tenant_id("ghost"), OwnershipKind::Operational,
                      LifecycleState::Active, std::nullopt}),
                  ErrorCode::NotFound);
  TREG_CHECK_EQ(harness.snapshot().digest(), digests.back());

  const SetMetadataOutcome metadata =
      unwrap(harness.registry().set_metadata(SetMetadataRequest{context(harness.generation()),
                                                               TenancySubject::of_tenant(tenant.id),
                                                               harness.tenant("acme").revision, {},
                                                               {entry("region", "eu")}}),
             "set_metadata");
  TREG_CHECK_EQ(metadata.receipt.revision.value(), 3u);
  digests.push_back(harness.snapshot().digest());

  const auto owner = harness.registry().set_owner(SetOwnerRequest{context(harness.generation()), tenant.id,
                                                                 harness.tenant("acme").revision,
                                                                 std::optional<PrincipalId>{
                                                                     principal_id("other-owner")}});
  TREG_REQUIRE_OK(owner);
  digests.push_back(harness.snapshot().digest());

  const TenantRecord other = harness.active_tenant("other-tenant");
  harness.own("acme", "other-tenant", OwnershipKind::Operational, LifecycleState::Active);
  digests.push_back(harness.snapshot().digest());
  harness.bind("renderer", "acme", BindingKind::Serves);
  digests.push_back(harness.snapshot().digest());
  harness.join(TenancySubject::of_tenant(tenant.id), "zone-a", MembershipRole::Primary);
  digests.push_back(harness.snapshot().digest());
  require_ok(harness.transition(TenancySubject::of_tenant(other.id), harness.tenant("other-tenant").revision,
                                LifecycleState::Suspended),
             "suspend other");
  digests.push_back(harness.snapshot().digest());
  harness.active_tenant("late-tenant");
  digests.push_back(harness.snapshot().digest());

  for (std::size_t index = 1; index < digests.size(); ++index) {
    TREG_CHECK(digests.at(index - 1) != digests.at(index));
  }
}

TREG_TEST(snapshot, a_single_differing_field_changes_the_digest) {
  EphemeralOptions options;
  options.limits = RegistryLimits{};
  options.clock = std::make_shared<FixedClock>(1);
  TenantRegistry first = unwrap(TenantRegistry::open_ephemeral(options), "open_ephemeral");
  TenantRegistry second = unwrap(TenantRegistry::open_ephemeral(options), "open_ephemeral");
  const auto declare = [](TenantRegistry& registry, std::string_view value) {
    const CreateTenantOutcome created =
        unwrap(registry.create_tenant(CreateTenantRequest{context(registry.generation()), tenant_id("acme"),
                                                         std::nullopt, std::nullopt, TenancyMetadata{}}),
               "create_tenant");
    unwrap(registry.set_metadata(SetMetadataRequest{
               context(registry.generation()), TenancySubject::of_tenant(created.record.id), created.record.revision,
               {},
               {MetadataEntry{metadata_key("region"),
                              unwrap(MetadataValue::text(std::string{value}, 512), "MetadataValue::text")}}}),
           "set_metadata");
  };
  declare(first, "eu");
  declare(second, "us");
  TREG_CHECK_EQ(first.snapshot().generation, second.snapshot().generation);
  TREG_CHECK_EQ(first.snapshot().record_count(), second.snapshot().record_count());
  TREG_CHECK(first.snapshot().digest() != second.snapshot().digest());
  TREG_CHECK(first.snapshot().to_canonical_bytes() != second.snapshot().to_canonical_bytes());
}

TREG_TEST(snapshot, rendering_is_stable_across_calls) {
  Harness harness = Harness::ephemeral();
  harness.active_tenant("acme");
  const RegistrySnapshot snapshot = harness.snapshot();
  TREG_CHECK_EQ(snapshot.to_canonical_bytes(), snapshot.to_canonical_bytes());
  TREG_CHECK_EQ(snapshot.to_json(), snapshot.to_json());
  TREG_CHECK_EQ(snapshot.digest(), snapshot.digest());
  TREG_CHECK_EQ(harness.snapshot().to_canonical_bytes(), snapshot.to_canonical_bytes());
  TREG_CHECK_EQ(harness.snapshot().to_json(), snapshot.to_json());
  TREG_CHECK(!snapshot.to_canonical_bytes().empty());
  TREG_CHECK_EQ(snapshot.to_json().front(), '{');
  TREG_CHECK_EQ(snapshot.to_json().back(), '}');
  TREG_CHECK(snapshot.to_text().find("registry snapshot") != std::string::npos);
}

TREG_TEST(snapshot, domain_generation_lookup_agrees_with_the_records) {
  Harness harness = Harness::ephemeral();
  harness.active_tenant("acme");
  harness.active_domain("zone-a");
  harness.active_domain("zone-b");
  const RegistrySnapshot before = harness.snapshot();
  TREG_CHECK_EQ(*before.domain_generation(domain_id("zone-a")), harness.domain_generation("zone-a"));
  TREG_CHECK(!before.domain_generation(domain_id("zone-missing")).has_value());

  harness.join(TenancySubject::of_tenant(tenant_id("acme")), "zone-a", MembershipRole::Primary);
  const RegistrySnapshot after = harness.snapshot();
  TREG_REQUIRE(after.domain_generations.size() == 2u);
  for (const auto& entry : after.domain_generations) {
    const IsolationDomainRecord record =
        unwrap(harness.registry().find_isolation_domain(entry.first), "find_isolation_domain");
    TREG_CHECK_EQ(entry.second, record.membership_generation);
  }
  TREG_CHECK_EQ(after.domain_generation(domain_id("zone-a"))->value(), 1u);
  TREG_CHECK_EQ(*after.domain_generation(domain_id("zone-b")), DomainGeneration::initial());
  TREG_CHECK(after.domain_generation(domain_id("zone-a")) != before.domain_generation(domain_id("zone-a")));
}

TREG_TEST(snapshot, a_snapshot_is_not_affected_by_a_later_mutation) {
  Harness harness = Harness::ephemeral();
  const TenantRecord tenant = harness.active_tenant("acme", std::optional<PrincipalId>{principal_id("ops")});
  const RegistrySnapshot taken = harness.snapshot();
  const std::string bytes = taken.to_canonical_bytes();
  const ContentDigest digest = taken.digest();
  const std::string json = taken.to_json();

  unwrap(harness.registry().set_metadata(SetMetadataRequest{context(harness.generation()),
                                                           TenancySubject::of_tenant(tenant.id),
                                                           harness.tenant("acme").revision, {},
                                                           {entry("region", "eu")}}),
         "set_metadata");
  harness.active_service("renderer");
  harness.active_domain("zone-a");
  harness.bind("renderer", "acme", BindingKind::Serves);
  harness.join(TenancySubject::of_tenant(tenant.id), "zone-a", MembershipRole::Primary);

  TREG_CHECK_EQ(taken.to_canonical_bytes(), bytes);
  TREG_CHECK_EQ(taken.digest(), digest);
  TREG_CHECK_EQ(taken.to_json(), json);
  TREG_CHECK_EQ(taken.generation.value(), 2u);
  TREG_REQUIRE(taken.tenants.size() == 1u);
  TREG_CHECK(taken.tenants.at(0).metadata.empty());
  TREG_CHECK(taken.tenants.at(0).owner.has_value());
  TREG_CHECK(taken.service_bindings.empty());
  TREG_CHECK(taken.isolation_memberships.empty());
  TREG_CHECK(taken.to_canonical_bytes() != harness.snapshot().to_canonical_bytes());
  TREG_CHECK(taken.digest() != harness.snapshot().digest());

  // The live state really did move on, so the difference above is the mutation
  // and not a rendering artefact.
  TREG_CHECK(harness.snapshot().generation.value() > taken.generation.value());
}

TREG_TEST(snapshot, tombstones_are_permanent_records_in_canonical_order) {
  Harness harness = Harness::ephemeral();
  const auto fence = [&harness](std::string_view name) {
    const TenantRecord created = harness.create_tenant(name);
    require_ok(harness.transition(TenancySubject::of_tenant(created.id), created.revision,
                                  LifecycleState::Retired),
               "complete retirement");
    const TenantRecord retired = harness.tenant(name);
    unwrap(harness.registry().tombstone(TombstoneRequest{context(harness.generation()),
                                                         TenancySubject::of_tenant(retired.id), retired.revision,
                                                         IrreversibleAcknowledgement::acknowledged(),
                                                         RebindSuccessor{SubjectKind::Tenant, std::string{name}},
                                                         std::string{"fenced"}}),
           "tombstone");
    unwrap(harness.registry().create_tenant(CreateTenantRequest{context(harness.generation()), created.id,
                                                               std::nullopt, std::nullopt, TenancyMetadata{}}),
           "create_tenant");
  };
  fence("zeta");
  fence("alpha");

  const RegistrySnapshot snapshot = harness.snapshot();
  TREG_REQUIRE(snapshot.tombstones.size() == 2u);
  TREG_CHECK_EQ(snapshot.tombstones.at(0).identity, "alpha");
  TREG_CHECK_EQ(snapshot.tombstones.at(1).identity, "zeta");
  for (const TombstoneRecord& record : snapshot.tombstones) {
    TREG_CHECK_EQ(record.state, LifecycleState::Tombstoned);
    TREG_CHECK(record.permit.has_value());
    TREG_CHECK(record.permit->consumed());
  }
  // Each fenced identity is live again, and the tombstone is the record that
  // says it was fenced once.
  TREG_CHECK_EQ(snapshot.tenants.size(), 2u);
  TREG_CHECK_EQ(snapshot.record_count(), std::size_t{4});
  TREG_CHECK(snapshot.to_text().find("tombstones         : 2") != std::string::npos);
}

}  // namespace
}  // namespace treg_test
