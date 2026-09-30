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
#include <string>
#include <string_view>
#include <vector>

#include "test_support.hpp"

namespace treg_test {
namespace {

using tenant_registry::ErrorCode;
using tenant_registry::SourceId;
using tenant_registry::TenancyMetadata;
using tenant_registry::PutIsolationMembershipRequest;
using tenant_registry::PutOwnershipRequest;
using tenant_registry::TenantQuery;
using tenant_registry::validate_limits;

std::vector<std::string> text_lines(const std::string& text) {
  std::vector<std::string> lines;
  std::size_t position = 0;
  while (position <= text.size()) {
    const std::size_t newline = text.find('\n', position);
    if (newline == std::string::npos) {
      lines.push_back(text.substr(position));
      break;
    }
    lines.push_back(text.substr(position, newline - position));
    position = newline + 1;
  }
  return lines;
}

/// Sets exactly one limit to zero and proves validate_limits refuses it with a
/// reason that names the limit that is wrong.
void refuses_zero(const RegistryLimits& defaults, std::string_view name) {
  RegistryLimits broken = defaults;
  const std::string key{name};
  if (key == "max_identity_bytes") {
    broken.max_identity_bytes = 0;
  } else if (key == "max_display_name_bytes") {
    broken.max_display_name_bytes = 0;
  } else if (key == "max_metadata_key_bytes") {
    broken.max_metadata_key_bytes = 0;
  } else if (key == "max_metadata_value_bytes") {
    broken.max_metadata_value_bytes = 0;
  } else if (key == "max_provenance_note_bytes") {
    broken.max_provenance_note_bytes = 0;
  } else if (key == "max_principal_bytes") {
    broken.max_principal_bytes = 0;
  } else if (key == "max_source_bytes") {
    broken.max_source_bytes = 0;
  } else if (key == "max_tenants") {
    broken.max_tenants = 0;
  } else if (key == "max_services") {
    broken.max_services = 0;
  } else if (key == "max_isolation_domains") {
    broken.max_isolation_domains = 0;
  } else if (key == "max_ownership_edges") {
    broken.max_ownership_edges = 0;
  } else if (key == "max_service_bindings") {
    broken.max_service_bindings = 0;
  } else if (key == "max_isolation_memberships") {
    broken.max_isolation_memberships = 0;
  } else if (key == "max_metadata_entries_per_record") {
    broken.max_metadata_entries_per_record = 0;
  } else if (key == "max_bindings_per_service") {
    broken.max_bindings_per_service = 0;
  } else if (key == "max_memberships_per_subject") {
    broken.max_memberships_per_subject = 0;
  } else if (key == "max_memberships_per_domain") {
    broken.max_memberships_per_domain = 0;
  } else if (key == "max_children_per_tenant") {
    broken.max_children_per_tenant = 0;
  } else if (key == "max_ownership_depth") {
    broken.max_ownership_depth = 0;
  } else if (key == "max_traversal_depth") {
    broken.max_traversal_depth = 0;
  } else if (key == "max_traversal_results") {
    broken.max_traversal_results = 0;
  } else if (key == "default_listing_limit") {
    broken.default_listing_limit = 0;
  } else if (key == "max_listing_limit") {
    broken.max_listing_limit = 0;
  } else if (key == "max_idempotency_entries") {
    broken.max_idempotency_entries = 0;
  } else if (key == "max_idempotency_outcome_bytes") {
    broken.max_idempotency_outcome_bytes = 0;
  } else if (key == "max_journal_frames") {
    broken.max_journal_frames = 0;
  } else if (key == "max_journal_bytes") {
    broken.max_journal_bytes = 0;
  } else if (key == "max_commit_payload_bytes") {
    broken.max_commit_payload_bytes = 0;
  } else if (key == "max_baseline_payload_bytes") {
    broken.max_baseline_payload_bytes = 0;
  } else if (key == "max_snapshot_bytes") {
    broken.max_snapshot_bytes = 0;
  } else if (key == "max_manifest_bytes") {
    broken.max_manifest_bytes = 0;
  } else if (key == "max_store_roots_per_process") {
    broken.max_store_roots_per_process = 0;
  } else {
    // A name that matches no limit would make this test vacuous, so it fails
    // loudly instead of silently setting nothing.
    TREG_CHECK_EQ(key, std::string{"<no such limit>"});
    return;
  }

  std::string reason;
  TREG_CHECK(!validate_limits(broken, reason));
  TREG_CHECK(reason.find(name) != std::string::npos);
  TREG_CHECK(reason.find("greater than zero") != std::string::npos);
}

constexpr std::string_view kEveryLimitName[] = {
    "max_identity_bytes",        "max_display_name_bytes",       "max_metadata_key_bytes",
    "max_metadata_value_bytes",  "max_provenance_note_bytes",    "max_principal_bytes",
    "max_source_bytes",          "max_tenants",                  "max_services",
    "max_isolation_domains",     "max_ownership_edges",          "max_service_bindings",
    "max_isolation_memberships", "max_metadata_entries_per_record", "max_bindings_per_service",
    "max_memberships_per_subject", "max_memberships_per_domain", "max_children_per_tenant",
    "max_ownership_depth",       "max_traversal_depth",          "max_traversal_results",
    "default_listing_limit",     "max_listing_limit",            "max_idempotency_entries",
    "max_idempotency_outcome_bytes", "max_journal_frames",       "max_journal_bytes",
    "max_commit_payload_bytes",  "max_baseline_payload_bytes",   "max_snapshot_bytes",
    "max_manifest_bytes",        "max_store_roots_per_process",
};

}  // namespace

TREG_TEST(limits, defaults_are_coherent) {
  const RegistryLimits defaults;
  std::string reason{"stale text from an earlier call"};
  TREG_CHECK(validate_limits(defaults, reason));
  // A successful validation clears the reason rather than leaving the previous
  // one readable as if it described this limit set.
  TREG_CHECK(reason.empty());

  TREG_CHECK_EQ(defaults.max_identity_bytes, static_cast<std::size_t>(128));
  TREG_CHECK_EQ(defaults.max_display_name_bytes, static_cast<std::size_t>(256));
  TREG_CHECK_EQ(defaults.max_metadata_key_bytes, static_cast<std::size_t>(96));
  TREG_CHECK_EQ(defaults.max_metadata_value_bytes, static_cast<std::size_t>(512));
  TREG_CHECK_EQ(defaults.max_provenance_note_bytes, static_cast<std::size_t>(512));
  TREG_CHECK_EQ(defaults.max_metadata_entries_per_record, static_cast<std::size_t>(64));
  TREG_CHECK_EQ(defaults.max_tenants, static_cast<std::uint64_t>(100000));
  TREG_CHECK_EQ(defaults.max_services, static_cast<std::uint64_t>(100000));
  TREG_CHECK_EQ(defaults.max_isolation_domains, static_cast<std::uint64_t>(4096));
  TREG_CHECK_EQ(defaults.max_ownership_depth, static_cast<std::size_t>(64));
  TREG_CHECK_EQ(defaults.max_traversal_depth, static_cast<std::size_t>(32));
  TREG_CHECK_EQ(defaults.max_traversal_results, static_cast<std::size_t>(4096));
  TREG_CHECK_EQ(defaults.default_listing_limit, static_cast<std::size_t>(128));
  TREG_CHECK_EQ(defaults.max_listing_limit, static_cast<std::size_t>(1024));
  TREG_CHECK_EQ(defaults.max_idempotency_entries, static_cast<std::size_t>(65536));
  TREG_CHECK(defaults.default_listing_limit <= defaults.max_listing_limit);

  // The registry takes the defaults without complaint.
  const Harness harness = Harness::ephemeral();
  TREG_CHECK_EQ(harness.limits().max_tenants, defaults.max_tenants);
  TREG_CHECK_EQ(harness.limits().max_listing_limit, defaults.max_listing_limit);
}

TREG_TEST(limits, every_zero_limit_is_refused_with_a_reason_naming_it) {
  const RegistryLimits defaults;
  for (const std::string_view name : kEveryLimitName) {
    refuses_zero(defaults, name);
  }
  TREG_CHECK_EQ(sizeof(kEveryLimitName) / sizeof(kEveryLimitName[0]), static_cast<std::size_t>(32));

  // The checks run in a fixed order, so the first incoherence is the same one
  // on every build: with several limits zero the earliest declared one is the
  // one reported.
  RegistryLimits several = defaults;
  several.max_tenants = 0;
  several.max_services = 0;
  several.max_metadata_value_bytes = 0;
  std::string reason;
  TREG_CHECK(!validate_limits(several, reason));
  TREG_CHECK(reason.find("max_metadata_value_bytes") != std::string::npos);
}

TREG_TEST(limits, an_incoherent_listing_pair_is_refused) {
  RegistryLimits incoherent;
  incoherent.default_listing_limit = 2048;
  incoherent.max_listing_limit = 1024;
  std::string reason;
  TREG_CHECK(!validate_limits(incoherent, reason));
  TREG_CHECK(reason.find("default_listing_limit") != std::string::npos);
  TREG_CHECK(reason.find("max_listing_limit") != std::string::npos);
  TREG_CHECK(reason.find("2048") != std::string::npos);
  TREG_CHECK(reason.find("1024") != std::string::npos);

  // Equal is coherent: the default is usable because it is not above the
  // maximum.
  RegistryLimits equal;
  equal.default_listing_limit = 1024;
  equal.max_listing_limit = 1024;
  reason = "stale";
  TREG_CHECK(validate_limits(equal, reason));
  TREG_CHECK(reason.empty());

  RegistryLimits lowered;
  lowered.default_listing_limit = 4;
  lowered.max_listing_limit = 8;
  TREG_CHECK(validate_limits(lowered, reason));
}

TREG_TEST(limits, to_text_is_stable_complete_and_sorted) {
  const RegistryLimits defaults;
  const std::string first = defaults.to_text();
  TREG_CHECK_EQ(first, defaults.to_text());
  TREG_CHECK(!first.empty());

  const std::vector<std::string> lines = text_lines(first);
  // Every limit is rendered, so an omission would be visible in a diff.
  TREG_CHECK_EQ(lines.size(), static_cast<std::size_t>(32));
  for (const std::string& line : lines) {
    TREG_CHECK(line.find(" = ") != std::string::npos);
  }
  for (std::size_t index = 1; index < lines.size(); ++index) {
    const std::string& previous = lines[index - 1];
    const std::string& current = lines[index];
    TREG_CHECK(previous.substr(0, previous.find(" = ")) < current.substr(0, current.find(" = ")));
  }
  TREG_CHECK(first.find("max_tenants = 100000") != std::string::npos);
  TREG_CHECK(first.find("max_identity_bytes = 128") != std::string::npos);
  TREG_CHECK(first.find("default_listing_limit = 128") != std::string::npos);
  TREG_CHECK(first.find("max_metadata_entries_per_record = 64") != std::string::npos);

  // Changing one limit changes exactly one line, and the line it changes is the
  // limit that changed.
  RegistryLimits lowered = defaults;
  lowered.max_tenants = 5;
  const std::vector<std::string> lowered_lines = text_lines(lowered.to_text());
  TREG_REQUIRE(lowered_lines.size() == lines.size());
  std::size_t changed = 0;
  for (std::size_t index = 0; index < lines.size(); ++index) {
    if (lines[index] != lowered_lines[index]) {
      ++changed;
      TREG_CHECK_EQ(lowered_lines[index], std::string{"max_tenants = 5"});
    }
  }
  TREG_CHECK_EQ(changed, static_cast<std::size_t>(1));
}

TREG_TEST(limits, record_counts_are_enforced) {
  RegistryLimits limits;
  limits.max_tenants = 2;
  limits.max_services = 1;
  limits.max_isolation_domains = 1;
  Harness harness = Harness::ephemeral(limits);

  harness.create_tenant("one");
  harness.create_tenant("two");
  const CreateTenantRequest third{context(harness.generation()), tenant_id("three"), std::nullopt, std::nullopt,
                                  TenancyMetadata{}};
  TREG_CHECK_CODE(harness.registry().create_tenant(third), ErrorCode::LimitExceeded);

  harness.create_service("renderer");
  const CreateServiceRequest second_service{context(harness.generation()), service_id("worker"), std::nullopt,
                                            TenancyMetadata{}};
  TREG_CHECK_CODE(harness.registry().create_service(second_service), ErrorCode::LimitExceeded);

  const CreateIsolationDomainRequest domain{context(harness.generation()), domain_id("zone-a"),
                                            IsolationClass::FaultContainment, std::nullopt, TenancyMetadata{}};
  TREG_REQUIRE_OK(harness.registry().create_isolation_domain(domain));
  const CreateIsolationDomainRequest second_domain{context(harness.generation()), domain_id("zone-b"),
                                                   IsolationClass::FaultContainment, std::nullopt, TenancyMetadata{}};
  TREG_CHECK_CODE(harness.registry().create_isolation_domain(second_domain), ErrorCode::LimitExceeded);

  // The refusals are about the configured bound, not about a fixed one: the
  // registry still holds exactly what it was allowed to hold.
  TREG_CHECK_EQ(harness.snapshot().tenants.size(), static_cast<std::size_t>(2));
  TREG_CHECK_EQ(harness.snapshot().services.size(), static_cast<std::size_t>(1));
  TREG_CHECK_EQ(harness.snapshot().isolation_domains.size(), static_cast<std::size_t>(1));
}

TREG_TEST(limits, text_and_metadata_bounds_are_enforced) {
  RegistryLimits limits;
  limits.max_display_name_bytes = 4;
  limits.max_provenance_note_bytes = 4;
  limits.max_metadata_key_bytes = 3;
  limits.max_metadata_value_bytes = 3;
  limits.max_metadata_entries_per_record = 1;
  Harness harness = Harness::ephemeral(limits);

  // A request that fits every configured bound is accepted, so the refusals
  // below are about the bound and not about the request shape.
  const CreateTenantRequest acceptable{context(harness.generation()), tenant_id("fits"), std::string{"abcd"},
                                       std::nullopt, TenancyMetadata{}};
  TREG_REQUIRE_OK(harness.registry().create_tenant(acceptable));

  const CreateTenantRequest long_name{context(harness.generation()), tenant_id("long-name"), std::string{"abcde"},
                                      std::nullopt, TenancyMetadata{}};
  TREG_CHECK_CODE(harness.registry().create_tenant(long_name), ErrorCode::InvalidTextForm);

  const TenancyMetadata long_key =
      unwrap(TenancyMetadata::create({entry("abcd", "x")}, 64, 512), "TenancyMetadata::create");
  const CreateTenantRequest keyed{context(harness.generation()), tenant_id("long-key"), std::nullopt, std::nullopt,
                                  long_key};
  TREG_CHECK_CODE(harness.registry().create_tenant(keyed), ErrorCode::InvalidMetadata);

  const TenancyMetadata long_value =
      unwrap(TenancyMetadata::create({entry("abc", "abcd")}, 64, 512), "TenancyMetadata::create");
  const CreateTenantRequest valued{context(harness.generation()), tenant_id("long-value"), std::nullopt, std::nullopt,
                                   long_value};
  TREG_CHECK_CODE(harness.registry().create_tenant(valued), ErrorCode::InvalidMetadata);

  const TenancyMetadata too_many =
      unwrap(TenancyMetadata::create({entry("a", "1"), entry("b", "2")}, 64, 512), "TenancyMetadata::create");
  const CreateTenantRequest crowded{context(harness.generation()), tenant_id("crowded"), std::nullopt, std::nullopt,
                                    too_many};
  TREG_CHECK_CODE(harness.registry().create_tenant(crowded), ErrorCode::LimitExceeded);

  // The actor provenance is checked against the same configured bounds.
  const SourceId source = unwrap(SourceId::create("s"), "SourceId::create");
  const ProvenanceRecord verbose =
      unwrap(ProvenanceRecord::create(ProvenanceSource::TestFixture, source, principal_id("p"), std::nullopt,
                                      std::string{"abcde"}, 512),
             "ProvenanceRecord::create");
  const CreateTenantRequest talkative{context(harness.generation(), std::nullopt, verbose), tenant_id("talkative"),
                                      std::nullopt, std::nullopt, TenancyMetadata{}};
  TREG_CHECK_CODE(harness.registry().create_tenant(talkative), ErrorCode::InvalidProvenance);

  // Nothing above changed the registry.
  TREG_CHECK_EQ(harness.snapshot().tenants.size(), static_cast<std::size_t>(1));
}

TREG_TEST(limits, listing_bounds_are_enforced) {
  RegistryLimits limits;
  limits.default_listing_limit = 2;
  limits.max_listing_limit = 4;
  Harness harness = Harness::ephemeral(limits);
  harness.create_tenant("a");
  harness.create_tenant("b");
  harness.create_tenant("c");

  TenantQuery query;
  query.limit = 5;
  TREG_CHECK_CODE(harness.registry().list_tenants(query), ErrorCode::ListingLimitExceeded);

  // The maximum itself is usable: asking for more than a page is refused, but
  // asking for exactly the maximum is not.
  query.limit = 4;
  const Result<tenant_registry::Page<tenant_registry::TenantSummary>> all = harness.registry().list_tenants(query);
  TREG_REQUIRE_OK(all);
  TREG_CHECK_EQ(all.value().items.size(), static_cast<std::size_t>(3));
  TREG_CHECK_EQ(all.value().total_matched, static_cast<std::size_t>(3));
  TREG_CHECK(!all.value().truncated);
  TREG_CHECK(!all.value().next_cursor.has_value());

  query.limit = 2;
  const Result<tenant_registry::Page<tenant_registry::TenantSummary>> first_page =
      harness.registry().list_tenants(query);
  TREG_REQUIRE_OK(first_page);
  TREG_CHECK_EQ(first_page.value().items.size(), static_cast<std::size_t>(2));
  TREG_CHECK_EQ(first_page.value().total_matched, static_cast<std::size_t>(3));
  TREG_CHECK(first_page.value().truncated);
  TREG_REQUIRE(first_page.value().next_cursor.has_value());
  TREG_CHECK_EQ(first_page.value().items[0].id.value(), std::string{"a"});
  TREG_CHECK_EQ(first_page.value().items[1].id.value(), std::string{"b"});

  // A caller that does not state a page size gets the configured default, and a
  // default page that is not the whole answer says so.
  query.limit = 0;
  const Result<tenant_registry::Page<tenant_registry::TenantSummary>> default_page =
      harness.registry().list_tenants(query);
  TREG_REQUIRE_OK(default_page);
  TREG_CHECK_EQ(default_page.value().items.size(), static_cast<std::size_t>(2));
  TREG_CHECK(default_page.value().truncated);
  TREG_CHECK(default_page.value().next_cursor.has_value());

  query.limit = 1;
  query.cursor = first_page.value().next_cursor;
  const Result<tenant_registry::Page<tenant_registry::TenantSummary>> second_page =
      harness.registry().list_tenants(query);
  TREG_REQUIRE_OK(second_page);
  TREG_CHECK_EQ(second_page.value().items.size(), static_cast<std::size_t>(1));
  TREG_CHECK_EQ(second_page.value().items[0].id.value(), std::string{"c"});
  TREG_CHECK(!second_page.value().truncated);
  TREG_CHECK(!second_page.value().next_cursor.has_value());
}

TREG_TEST(limits, traversal_bounds_are_enforced) {
  RegistryLimits limits;
  limits.max_traversal_depth = 1;
  limits.max_traversal_results = 1;
  Harness harness = Harness::ephemeral(limits);
  harness.active_tenant("top");
  harness.active_tenant("middle");
  harness.active_tenant("bottom");
  harness.own("middle", "top");
  harness.own("bottom", "middle");

  const tenant_registry::OwnershipTraversalRequest too_deep{tenant_id("top"), TraversalDirection::Descendants,
                                                            std::nullopt, std::nullopt, 2, 0};
  TREG_CHECK_CODE(harness.registry().traverse_ownership(too_deep), ErrorCode::TraversalLimitExceeded);
  const tenant_registry::OwnershipTraversalRequest too_many{tenant_id("top"), TraversalDirection::Descendants,
                                                            std::nullopt, std::nullopt, 1, 2};
  TREG_CHECK_CODE(harness.registry().traverse_ownership(too_many), ErrorCode::TraversalLimitExceeded);

  // At the configured bound the walk is performed and reports that it was
  // bounded rather than presenting a partial answer as a complete one.
  const tenant_registry::OwnershipTraversalRequest bounded{tenant_id("top"), TraversalDirection::Descendants,
                                                           std::nullopt, std::nullopt, 1, 1};
  const Result<tenant_registry::OwnershipTraversal> walk = harness.registry().traverse_ownership(bounded);
  TREG_REQUIRE_OK(walk);
  TREG_CHECK(walk.value().truncated);
  TREG_CHECK_EQ(walk.value().reached.size(), static_cast<std::size_t>(1));
  TREG_CHECK_EQ(walk.value().reached[0].value(), std::string{"middle"});

  // An explicit zero means "use the configured bound", never "no bound".
  const tenant_registry::OwnershipTraversalRequest defaults{tenant_id("top"), TraversalDirection::Descendants,
                                                            std::nullopt, std::nullopt, 0, 0};
  TREG_REQUIRE_OK(harness.registry().traverse_ownership(defaults));

  // An unspecified direction is refused whatever the bounds say.
  const tenant_registry::OwnershipTraversalRequest undirected{tenant_id("top"), TraversalDirection::Unspecified,
                                                              std::nullopt, std::nullopt, 1, 1};
  TREG_CHECK_CODE(harness.registry().traverse_ownership(undirected), ErrorCode::InvalidEnumValue);
}

TREG_TEST(limits, ownership_depth_limit_is_enforced) {
  RegistryLimits limits;
  limits.max_ownership_depth = 1;
  Harness harness = Harness::ephemeral(limits);
  harness.active_tenant("grand");
  harness.active_tenant("parent");
  harness.active_tenant("child");
  harness.own("parent", "grand");

  const tenant_registry::PutOwnershipRequest deeper{context(harness.generation()), tenant_id("child"),
                                                    tenant_id("parent"), OwnershipKind::Administrative,
                                                    LifecycleState::Active, std::nullopt};
  TREG_CHECK_CODE(harness.registry().put_ownership(deeper), ErrorCode::OwnershipDepthExceeded);
}

TREG_TEST(limits, relationship_cardinality_is_enforced) {
  RegistryLimits binding_limits;
  binding_limits.max_bindings_per_service = 1;
  Harness binding_harness = Harness::ephemeral(binding_limits);
  binding_harness.active_service("renderer");
  binding_harness.active_tenant("one");
  binding_harness.active_tenant("two");
  binding_harness.bind("renderer", "one", BindingKind::OperatedBy);
  const tenant_registry::PutServiceBindingRequest second_binding{
      context(binding_harness.generation()), service_id("renderer"), tenant_id("two"), BindingKind::Serves,
      LifecycleState::Active, std::nullopt};
  TREG_CHECK_CODE(binding_harness.registry().put_service_binding(second_binding), ErrorCode::LimitExceeded);

  RegistryLimits domain_limits;
  domain_limits.max_memberships_per_domain = 1;
  Harness domain_harness = Harness::ephemeral(domain_limits);
  domain_harness.active_tenant("one");
  domain_harness.active_tenant("two");
  domain_harness.active_domain("zone-a");
  domain_harness.join(tenant_subject("one"), "zone-a");
  const PutIsolationMembershipRequest second_member{
      context(domain_harness.generation()), tenant_subject("two"), domain_id("zone-a"), MembershipRole::Primary,
      MembershipState::Bound, domain_harness.domain_generation("zone-a"), std::nullopt};
  TREG_CHECK_CODE(domain_harness.registry().put_isolation_membership(second_member), ErrorCode::LimitExceeded);

  RegistryLimits subject_limits;
  subject_limits.max_memberships_per_subject = 1;
  Harness subject_harness = Harness::ephemeral(subject_limits);
  subject_harness.active_tenant("one");
  subject_harness.active_domain("zone-a");
  subject_harness.active_domain("zone-b");
  subject_harness.join(tenant_subject("one"), "zone-a", MembershipRole::Primary);
  // Secondary on purpose: the refusal must be the configured membership bound
  // and not the one-primary-per-subject rule.
  const PutIsolationMembershipRequest second_domain{
      context(subject_harness.generation()), tenant_subject("one"), domain_id("zone-b"), MembershipRole::Secondary,
      MembershipState::Bound, subject_harness.domain_generation("zone-b"), std::nullopt};
  TREG_CHECK_CODE(subject_harness.registry().put_isolation_membership(second_domain), ErrorCode::LimitExceeded);
}

TREG_TEST(limits, idempotency_ledger_limit_is_enforced) {
  RegistryLimits limits;
  limits.max_idempotency_entries = 1;
  Harness harness = Harness::ephemeral(limits);
  const RegistryGeneration composed = harness.generation();

  const CreateTenantRequest first{context(composed, idempotency_key("key-0001")), tenant_id("one"), std::nullopt,
                                  std::nullopt, TenancyMetadata{}};
  const Result<CreateTenantOutcome> accepted = harness.registry().create_tenant(first);
  TREG_REQUIRE_OK(accepted);
  TREG_CHECK(!accepted.value().receipt.replayed);
  TREG_CHECK_EQ(accepted.value().record.id.value(), std::string{"one"});

  // A new key cannot be admitted once the ledger is full: it is refused rather
  // than accepted without the ability to replay it.
  const CreateTenantRequest second{context(harness.generation(), idempotency_key("key-0002")), tenant_id("two"),
                                   std::nullopt, std::nullopt, TenancyMetadata{}};
  TREG_CHECK_CODE(harness.registry().create_tenant(second), ErrorCode::IdempotencyLedgerFull);
  TREG_CHECK_CODE(harness.registry().find_tenant(tenant_id("two")), ErrorCode::NotFound);

  // A mutation without a key is unaffected by a full ledger.
  const CreateTenantRequest unkeyed{context(harness.generation()), tenant_id("three"), std::nullopt, std::nullopt,
                                    TenancyMetadata{}};
  TREG_REQUIRE_OK(harness.registry().create_tenant(unkeyed));

  // The identical request is still answered from the ledger, even though the
  // generation it was composed against has moved on. That is exactly the case
  // the ordering of idempotency before staleness exists for.
  const Result<CreateTenantOutcome> replayed = harness.registry().create_tenant(first);
  TREG_REQUIRE_OK(replayed);
  TREG_CHECK(replayed.value().receipt.replayed);
  TREG_CHECK_EQ(replayed.value().record.id.value(), std::string{"one"});
  TREG_CHECK_EQ(replayed.value().record.state, LifecycleState::Declared);
  TREG_CHECK_EQ(harness.snapshot().tenants.size(), static_cast<std::size_t>(2));

  // Reusing the key for a different request is a different refusal.
  const CreateTenantRequest different{context(composed, idempotency_key("key-0001")), tenant_id("four"),
                                      std::nullopt, std::nullopt, TenancyMetadata{}};
  TREG_CHECK_CODE(harness.registry().create_tenant(different), ErrorCode::IdempotencyKeyReused);
}

}  // namespace treg_test
