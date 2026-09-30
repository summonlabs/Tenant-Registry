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

using tenant_registry::ErrorCode;
using tenant_registry::MetadataKind;
using tenant_registry::OperationKind;
using tenant_registry::SetMetadataOutcome;
using tenant_registry::SetMetadataRequest;
using tenant_registry::subject_revision;
using tenant_registry::TenancyMetadata;

/// The metadata of whichever identity record the subject variant holds.
const TenancyMetadata& metadata_of(const SubjectRecord& record) {
  return std::visit([](const auto& stored) -> const TenancyMetadata& { return stored.metadata; }, record);
}

SetMetadataRequest metadata_request(const TenantRegistry& registry, const TenancySubject& subject,
                                    RecordRevision revision, std::vector<MetadataKey> remove_keys,
                                    std::vector<MetadataEntry> put_entries) {
  return SetMetadataRequest{context(registry.generation()), subject, revision, std::move(remove_keys),
                            std::move(put_entries)};
}

SetMetadataOutcome set(Harness& harness, const TenancySubject& subject, RecordRevision revision,
                       std::vector<MetadataKey> remove_keys, std::vector<MetadataEntry> put_entries) {
  return unwrap(harness.registry().set_metadata(
                    metadata_request(harness.registry(), subject, revision, std::move(remove_keys),
                                     std::move(put_entries))),
                "set_metadata");
}

TREG_TEST(metadata_ops, set_metadata_puts_replaces_and_removes) {
  Harness harness = Harness::ephemeral();
  const TenantRecord tenant = harness.create_tenant("acme");
  const TenancySubject subject = TenancySubject::of_tenant(tenant.id);
  const RegistryGeneration before = harness.generation();

  const SetMetadataOutcome added =
      set(harness, subject, tenant.revision,
          {}, {entry("region", "eu"), MetadataEntry{metadata_key("tier"), MetadataValue::integer(3)}});
  TREG_CHECK_EQ(added.receipt.operation, OperationKind::SetMetadata);
  TREG_CHECK_EQ(added.receipt.generation.value(), before.value() + 1);
  TREG_CHECK_EQ(added.receipt.revision.value(), 2u);
  TREG_CHECK_EQ(subject_revision(added.record).value(), 2u);
  TREG_REQUIRE(metadata_of(added.record).size() == 2u);
  TREG_CHECK_EQ(metadata_of(added.record).entries().at(0).key.value(), "region");
  TREG_CHECK_EQ(metadata_of(added.record).entries().at(1).key.value(), "tier");
  TREG_CHECK(metadata_of(added.record).contains(metadata_key("region")));
  TREG_CHECK_EQ(*metadata_of(added.record).find(metadata_key("region")).text_if(), "eu");
  TREG_CHECK_EQ(*metadata_of(added.record).find(metadata_key("tier")).integer_if(), std::int64_t{3});

  // Putting the same key again replaces its value; it does not add an entry.
  const SetMetadataOutcome replaced =
      set(harness, subject, subject_revision(added.record), {}, {entry("region", "us")});
  TREG_CHECK_EQ(metadata_of(replaced.record).size(), 2u);
  TREG_CHECK_EQ(*metadata_of(replaced.record).find(metadata_key("region")).text_if(), "us");

  // Removing what is there removes exactly that.
  const SetMetadataOutcome removed =
      set(harness, subject, subject_revision(replaced.record), {metadata_key("tier")}, {});
  TREG_CHECK_EQ(metadata_of(removed.record).size(), 1u);
  TREG_CHECK(!metadata_of(removed.record).contains(metadata_key("tier")));
  TREG_CHECK(metadata_of(removed.record).contains(metadata_key("region")));

  // Removing what was never there is not an error: the caller asked for the key
  // to be absent, and after this it is.
  const SetMetadataOutcome untouched =
      set(harness, subject, subject_revision(removed.record), {metadata_key("never-recorded")}, {});
  TREG_CHECK_EQ(metadata_of(untouched.record).size(), 1u);
  TREG_CHECK_EQ(subject_revision(untouched.record).value(), subject_revision(removed.record).value() + 1);
  TREG_CHECK_EQ(harness.tenant("acme").metadata.size(), 1u);
}

TREG_TEST(metadata_ops, the_returned_record_is_the_new_state) {
  Harness harness = Harness::ephemeral();
  const TenantRecord tenant = harness.create_tenant("acme");
  const TenancySubject subject = TenancySubject::of_tenant(tenant.id);
  const SetMetadataOutcome outcome = set(harness, subject, tenant.revision, {}, {entry("a", "1")});

  const SubjectRecord found = unwrap(harness.registry().find_subject(subject), "find_subject");
  TREG_CHECK_EQ(to_canonical(found), to_canonical(outcome.record));
  TREG_REQUIRE(harness.snapshot().tenants.size() == 1u);
  TREG_CHECK_EQ(to_canonical(harness.snapshot().tenants.at(0)), to_canonical(harness.tenant("acme")));
  TREG_CHECK_EQ(harness.snapshot().tenants.at(0).revision, outcome.receipt.revision);
}

TREG_TEST(metadata_ops, a_value_or_key_above_the_configured_limit_is_refused) {
  RegistryLimits limits;
  limits.max_metadata_value_bytes = 4;
  limits.max_metadata_key_bytes = 4;
  Harness harness = Harness::ephemeral(limits);
  const TenantRecord tenant = harness.create_tenant("acme");
  const TenancySubject subject = TenancySubject::of_tenant(tenant.id);

  const MetadataValue long_value = unwrap(MetadataValue::text("abcde", 512), "MetadataValue::text");
  const auto value_refusal =
      harness.registry().set_metadata(metadata_request(harness.registry(), subject, tenant.revision, {},
                                                       {MetadataEntry{metadata_key("key"), long_value}}));
  TREG_CHECK_CODE(value_refusal, ErrorCode::InvalidMetadata);
  TREG_CHECK(value_refusal.error().detail().find("key") != std::string::npos);

  const MetadataKey long_key = metadata_key("longer");
  const auto key_refusal = harness.registry().set_metadata(metadata_request(
      harness.registry(), subject, tenant.revision, {}, {MetadataEntry{long_key, MetadataValue::unknown()}}));
  TREG_CHECK_CODE(key_refusal, ErrorCode::InvalidMetadata);

  // Nothing was recorded, and nothing moved.
  TREG_CHECK_EQ(harness.tenant("acme").revision, tenant.revision);
  TREG_CHECK(!harness.tenant("acme").metadata.contains(long_key));
  TREG_CHECK_EQ(harness.tenant("acme").metadata.size(), 0u);
}

TREG_TEST(metadata_ops, more_entries_than_the_limit_allows_is_refused_with_limit_exceeded) {
  RegistryLimits limits;
  limits.max_metadata_entries_per_record = 2;
  Harness harness = Harness::ephemeral(limits);
  const TenantRecord tenant = harness.create_tenant("acme");
  const TenancySubject subject = TenancySubject::of_tenant(tenant.id);

  const SetMetadataOutcome two = set(harness, subject, tenant.revision, {}, {entry("a", "1"), entry("b", "2")});
  TREG_CHECK_EQ(metadata_of(two.record).size(), 2u);

  const auto third = harness.registry().set_metadata(metadata_request(
      harness.registry(), subject, subject_revision(two.record), {}, {entry("c", "3")}));
  TREG_CHECK_CODE(third, ErrorCode::LimitExceeded);
  TREG_CHECK(third.error().detail().find("3 entries") != std::string::npos);
  TREG_CHECK(third.error().detail().find("maximum is 2") != std::string::npos);
  TREG_CHECK_EQ(harness.tenant("acme").metadata.size(), 2u);
  TREG_CHECK(harness.tenant("acme").metadata.contains(metadata_key("a")));
  TREG_CHECK(!harness.tenant("acme").metadata.contains(metadata_key("c")));
  TREG_CHECK_EQ(harness.tenant("acme").revision, subject_revision(two.record));

  // Removing and adding in one request is one set, so it fits when the result
  // fits: the bound is on what is recorded, not on how many entries the caller
  // happened to mention.
  const SetMetadataOutcome swapped = set(harness, subject, subject_revision(two.record), {metadata_key("a")},
                                         {entry("c", "3")});
  TREG_CHECK_EQ(metadata_of(swapped.record).size(), 2u);
  TREG_CHECK(!metadata_of(swapped.record).contains(metadata_key("a")));
  TREG_CHECK(metadata_of(swapped.record).contains(metadata_key("c")));

  // The same bound is applied to a declaration, so a record can never be born
  // holding more than the registry admits.
  const TenancyMetadata too_many =
      unwrap(TenancyMetadata::create({entry("a", "1"), entry("b", "2"), entry("c", "3")}, 64, 512), "metadata");
  const auto declaration = harness.registry().create_tenant(
      CreateTenantRequest{context(harness.generation()), tenant_id("crowded"), std::nullopt, std::nullopt, too_many});
  TREG_CHECK_CODE(declaration, ErrorCode::LimitExceeded);
  TREG_CHECK_CODE(harness.registry().find_tenant(tenant_id("crowded")), ErrorCode::NotFound);
}

TREG_TEST(metadata_ops, a_stale_revision_is_refused) {
  Harness harness = Harness::ephemeral();
  const TenantRecord tenant = harness.create_tenant("acme");
  const TenancySubject subject = TenancySubject::of_tenant(tenant.id);
  const SetMetadataOutcome first = set(harness, subject, tenant.revision, {}, {entry("a", "1")});

  const auto stale = harness.registry().set_metadata(metadata_request(
      harness.registry(), subject, tenant.revision, {}, {entry("b", "2")}));
  TREG_CHECK_CODE(stale, ErrorCode::StaleRecordRevision);
  TREG_CHECK(stale.error().detail().find("tenant:acme") != std::string::npos);
  TREG_CHECK(stale.error().detail().find("revision 2") != std::string::npos);
  TREG_CHECK(stale.error().detail().find("revision 1") != std::string::npos);
  TREG_CHECK_EQ(harness.tenant("acme").revision, subject_revision(first.record));
  TREG_CHECK(!harness.tenant("acme").metadata.contains(metadata_key("b")));
}

TREG_TEST(metadata_ops, an_unset_key_reads_back_as_explicitly_unknown) {
  Harness harness = Harness::ephemeral();
  const TenantRecord tenant = harness.create_tenant("acme");
  const TenancySubject subject = TenancySubject::of_tenant(tenant.id);

  const MetadataValue absent = harness.tenant("acme").metadata.find(metadata_key("absent"));
  TREG_CHECK_EQ(absent.kind(), MetadataKind::Unknown);
  TREG_CHECK(!absent.is_known());
  TREG_CHECK(absent.text_if() == nullptr);
  TREG_CHECK(absent.token_if() == nullptr);
  TREG_CHECK(absent.integer_if() == nullptr);
  TREG_CHECK(absent.boolean_if() == nullptr);
  TREG_CHECK_EQ(absent.to_canonical(), std::string{"unknown"});
  TREG_CHECK(!harness.tenant("acme").metadata.contains(metadata_key("absent")));

  // Every recorded kind stays distinguishable from every other, including the
  // ones that look like "nothing" if a caller is careless.
  const MetadataEntry entries[] = {
      MetadataEntry{metadata_key("bool-false"), MetadataValue::boolean(false)},
      MetadataEntry{metadata_key("int-zero"), MetadataValue::integer(0)},
      MetadataEntry{metadata_key("text-zero"), unwrap(MetadataValue::text("0", 512), "MetadataValue::text")},
      MetadataEntry{metadata_key("token"), unwrap(MetadataValue::token("blue", 512), "MetadataValue::token")},
      MetadataEntry{metadata_key("unknown"), MetadataValue::unknown()}};
  const SetMetadataOutcome outcome = set(harness, subject, tenant.revision, {}, {entries[0], entries[1], entries[2],
                                                                                entries[3], entries[4]});
  const TenancyMetadata& stored = metadata_of(outcome.record);
  TREG_REQUIRE(stored.size() == 5u);
  TREG_CHECK(stored.find(metadata_key("bool-false")).is_known());
  TREG_CHECK_EQ(*stored.find(metadata_key("bool-false")).boolean_if(), false);
  TREG_CHECK(stored.find(metadata_key("bool-false")).text_if() == nullptr);
  TREG_CHECK(stored.find(metadata_key("int-zero")).is_known());
  TREG_CHECK_EQ(*stored.find(metadata_key("int-zero")).integer_if(), std::int64_t{0});
  TREG_CHECK_EQ(*stored.find(metadata_key("text-zero")).text_if(), "0");
  TREG_CHECK(stored.find(metadata_key("text-zero")).integer_if() == nullptr);
  TREG_CHECK(stored.find(metadata_key("token")).token_if() != nullptr);
  TREG_CHECK(stored.find(metadata_key("token")).text_if() == nullptr);
  TREG_CHECK(!stored.find(metadata_key("unknown")).is_known());
  TREG_CHECK_EQ(stored.find(metadata_key("unknown")).to_canonical(), std::string{"unknown"});
  TREG_CHECK_EQ(stored.size(), 5u);
}

TREG_TEST(metadata_ops, metadata_survives_a_snapshot) {
  Harness harness = Harness::ephemeral();
  const TenantRecord tenant = harness.create_tenant("acme");
  const TenancySubject subject = TenancySubject::of_tenant(tenant.id);
  const SetMetadataOutcome outcome =
      set(harness, subject, tenant.revision, {}, {entry("region", "eu"), entry("zone", "z1")});

  const RegistrySnapshot snapshot = harness.snapshot();
  TREG_REQUIRE(snapshot.tenants.size() == 1u);
  TREG_CHECK_EQ(snapshot.tenants.at(0).metadata, metadata_of(outcome.record));
  TREG_CHECK_EQ(snapshot.tenants.at(0).metadata, harness.tenant("acme").metadata);
  TREG_CHECK_EQ(snapshot.domain_generation(domain_id("absent")).has_value(), false);

  const std::string canonical = snapshot.to_canonical_bytes();
  TREG_CHECK(!canonical.empty());
  TREG_CHECK_EQ(harness.snapshot().to_canonical_bytes(), canonical);

  // The snapshot is a value: a later change does not reach into it.
  set(harness, subject, harness.tenant("acme").revision, {}, {entry("zone", "z2")});
  TREG_CHECK_EQ(snapshot.tenants.at(0).metadata, metadata_of(outcome.record));
  TREG_CHECK_EQ(*snapshot.tenants.at(0).metadata.find(metadata_key("zone")).text_if(), "z1");
  TREG_CHECK_EQ(harness.snapshot().to_canonical_bytes() == canonical, false);
}

TREG_TEST(metadata_ops, metadata_can_be_set_on_every_subject_kind) {
  Harness harness = Harness::ephemeral();
  const TenantRecord tenant = harness.create_tenant("acme");
  const ServiceRecord service = harness.create_service("renderer");
  const IsolationDomainRecord domain = harness.create_domain("zone-a", IsolationClass::Regulatory);

  const SubjectRecord tenant_record =
      set(harness, TenancySubject::of_tenant(tenant.id), tenant.revision, {}, {entry("a", "1")}).record;
  const SubjectRecord service_record =
      set(harness, TenancySubject::of_service(service.id), service.revision, {}, {entry("b", "2")}).record;
  const SubjectRecord domain_record =
      set(harness, TenancySubject::of_isolation_domain(domain.id), domain.revision, {}, {entry("c", "3")}).record;

  TREG_CHECK_EQ(subject_revision(tenant_record).value(), 2u);
  TREG_CHECK_EQ(subject_revision(service_record).value(), 2u);
  TREG_CHECK_EQ(subject_revision(domain_record).value(), 2u);
  TREG_CHECK_EQ(harness.tenant("acme").metadata.size(), 1u);
  TREG_CHECK_EQ(harness.service("renderer").metadata.size(), 1u);
  TREG_CHECK_EQ(harness.domain("zone-a").metadata.size(), 1u);
  TREG_CHECK_EQ(harness.domain_generation("zone-a").value(), 0u);
  TREG_CHECK_EQ(harness.generation().value(), 6u);

  // A subject that does not exist is refused rather than invented.
  const auto missing = harness.registry().set_metadata(
      metadata_request(harness.registry(), TenancySubject::of_tenant(tenant_id("ghost")), RecordRevision::from_value(1),
                       {}, {entry("a", "1")}));
  TREG_CHECK_CODE(missing, ErrorCode::NotFound);
}

}  // namespace
}  // namespace treg_test
