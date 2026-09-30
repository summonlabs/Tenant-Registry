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

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "byte_codec.hpp"
#include "canonical_codec.hpp"
#include "test_support.hpp"

namespace treg_test {
namespace {

using tenant_registry::ContentDigest;
using tenant_registry::detail::canonical_bytes;
using tenant_registry::detail::AnyRecord;
using tenant_registry::detail::ByteReader;
using tenant_registry::detail::ByteWriter;
using tenant_registry::detail::CommitRecord;
using tenant_registry::detail::RecordKind;
using tenant_registry::ErrorCode;
using tenant_registry::IsolationClass;
using tenant_registry::JournalSequence;
using tenant_registry::TenancyMetadata;
using tenant_registry::OperationKind;
using tenant_registry::RegistryLimits;
using tenant_registry::SubjectKind;
using tenant_registry::TombstoneRecord;

std::string hex_of(std::span<const std::byte> bytes) {
  constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (const std::byte value : bytes) {
    const std::uint8_t byte = static_cast<std::uint8_t>(value);
    out += kHex[byte >> 4];
    out += kHex[byte & 0x0Fu];
  }
  return out;
}

/// The reader borrows the buffer, so the buffer must be a named value that
/// outlives it: passing a temporary vector here would leave the reader pointing
/// at freed storage.
ByteReader reader_of(const std::vector<std::byte>& bytes) {
  return ByteReader{std::span<const std::byte>{bytes.data(), bytes.size()}};
}

template <class Record>
std::vector<std::byte> encoded_bytes(const Record& record) {
  ByteWriter writer;
  tenant_registry::detail::encode(writer, record);
  return writer.bytes();
}

/// Encodes, decodes with the matching decoder, and proves the decoded value is
/// the same record: the canonical rendering matches, the reader is exactly
/// consumed, and re-encoding reproduces the original bytes.
template <class Record, class DecodeOne>
void round_trip(const Record& record, DecodeOne&& decode_one) {
  const std::vector<std::byte> encoded = encoded_bytes(record);
  TREG_REQUIRE(!encoded.empty());
  ByteReader reader = reader_of(encoded);
  const Result<Record> decoded = decode_one(reader);
  TREG_REQUIRE_OK(decoded);
  TREG_CHECK(reader.require_end());
  TREG_CHECK_EQ(tenant_registry::to_canonical(decoded.value()), tenant_registry::to_canonical(record));
  TREG_CHECK_EQ(hex_of(encoded_bytes(decoded.value())), hex_of(encoded));
}

TenancyMetadata sample_metadata() {
  return unwrap(TenancyMetadata::create({entry("environment", "production"), entry("tier", "gold")}, 64, 512),
                "TenancyMetadata::create");
}

TenantRecord active_tenant_with_metadata(Harness& harness, std::string_view text) {
  const TenantRecord created = harness.create_tenant(text, std::nullopt, std::nullopt, sample_metadata());
  require_ok(harness.transition(TenancySubject::of_tenant(created.id), created.revision, LifecycleState::Active),
             "activate tenant");
  return harness.tenant(text);
}

TenantRecord active_tenant_full(Harness& harness, std::string_view text, std::optional<std::string> display_name,
                                std::optional<PrincipalId> owner, TenancyMetadata metadata) {
  const TenantRecord created =
      harness.create_tenant(text, std::move(display_name), std::move(owner), std::move(metadata));
  require_ok(harness.transition(TenancySubject::of_tenant(created.id), created.revision, LifecycleState::Active),
             "activate tenant");
  return harness.tenant(text);
}

}  // namespace

TREG_TEST(codec, every_record_type_encodes_and_decodes) {
  Harness harness = Harness::ephemeral();
  const RegistryLimits limits = harness.limits();

  const TenantRecord tenant =
      active_tenant_full(harness, "acme", std::string{"Acme Ltd"}, principal_id("alice"), sample_metadata());
  TREG_CHECK_EQ(tenant.state, LifecycleState::Active);
  TREG_REQUIRE(tenant.display_name.has_value());
  TREG_REQUIRE(tenant.owner.has_value());
  TREG_CHECK_EQ(tenant.metadata.size(), static_cast<std::size_t>(2));
  round_trip(tenant, [&limits](ByteReader& reader) { return tenant_registry::detail::decode_tenant(reader, limits); });

  // A record with every optional absent is a different encoding and must round
  // trip just as exactly.
  const TenantRecord bare = harness.create_tenant("bare");
  TREG_CHECK(!bare.display_name.has_value());
  TREG_CHECK(!bare.owner.has_value());
  TREG_CHECK(bare.metadata.empty());
  round_trip(bare, [&limits](ByteReader& reader) { return tenant_registry::detail::decode_tenant(reader, limits); });

  harness.active_tenant("child-t");
  harness.active_tenant("parent-t");

  const ServiceRecord created_service = harness.create_service("renderer", std::string{"Renderer"}, sample_metadata());
  require_ok(harness.transition(TenancySubject::of_service(created_service.id), created_service.revision,
                                LifecycleState::Active),
             "activate renderer");
  const ServiceRecord service = harness.service("renderer");
  round_trip(service,
             [&limits](ByteReader& reader) { return tenant_registry::detail::decode_service(reader, limits); });

  const IsolationDomainRecord created_domain = harness.create_domain("zone-a", IsolationClass::Regulatory);
  require_ok(harness.transition(TenancySubject::of_isolation_domain(created_domain.id), created_domain.revision,
                                LifecycleState::Active),
             "activate zone-a");
  const IsolationMembership membership = harness.join(tenant_subject("child-t"), "zone-a");
  const IsolationDomainRecord domain = harness.domain("zone-a");
  TREG_CHECK(domain.membership_generation.value() > created_domain.membership_generation.value());
  round_trip(domain,
             [&limits](ByteReader& reader) { return tenant_registry::detail::decode_isolation_domain(reader, limits); });

  const OwnershipEdge edge = harness.own("child-t", "parent-t");
  TREG_CHECK_EQ(edge.kind, OwnershipKind::Administrative);
  round_trip(edge,
             [&limits](ByteReader& reader) { return tenant_registry::detail::decode_ownership_edge(reader, limits); });

  const ServiceBinding binding = harness.bind("renderer", "child-t");
  round_trip(binding,
             [&limits](ByteReader& reader) { return tenant_registry::detail::decode_service_binding(reader, limits); });

  round_trip(membership, [&limits](ByteReader& reader) {
    return tenant_registry::detail::decode_isolation_membership(reader, limits);
  });

  // A tombstoned identity carries the nested tombstone and rebind permit, so it
  // is the richest identity encoding there is.
  harness.active_tenant("fenced");
  harness.retire_tenant("fenced");
  harness.tombstone("fenced", true, "fenced with a permitted successor");
  const TenantRecord tombstoned = harness.tenant("fenced");
  TREG_CHECK_EQ(tombstoned.state, LifecycleState::Tombstoned);
  TREG_REQUIRE(tombstoned.tombstone.has_value());
  TREG_REQUIRE(tombstoned.tombstone->rebind_permit().has_value());
  TREG_CHECK(!tombstoned.tombstone->rebind_permit()->consumed());
  round_trip(tombstoned, [&limits](ByteReader& reader) {
    return tenant_registry::detail::decode_tenant(reader, limits);
  });

  const TombstoneRecord tombstone_record =
      unwrap(harness.registry().find_tombstone(SubjectKind::Tenant, "fenced"), "find_tombstone");
  TREG_CHECK_EQ(tombstone_record.kind, SubjectKind::Tenant);
  TREG_CHECK_EQ(tombstone_record.identity, std::string{"fenced"});
  TREG_CHECK_EQ(tombstone_record.state, LifecycleState::Tombstoned);
  TREG_REQUIRE(tombstone_record.permit.has_value());
  round_trip(tombstone_record, [&limits](ByteReader& reader) {
    return tenant_registry::detail::decode_tombstone_record(reader, limits);
  });
}

TREG_TEST(codec, any_record_tag_is_part_of_the_encoding) {
  Harness harness = Harness::ephemeral();
  const RegistryLimits limits = harness.limits();
  const TenantRecord tenant = harness.active_tenant("acme");
  const AnyRecord any{tenant};

  ByteWriter writer;
  tenant_registry::detail::encode(writer, any);
  const std::vector<std::byte> encoded = writer.bytes();
  ByteReader reader = reader_of(encoded);
  const Result<AnyRecord> decoded = tenant_registry::detail::decode_any(reader, limits);
  TREG_REQUIRE_OK(decoded);
  TREG_CHECK(reader.require_end());
  TREG_CHECK_EQ(tenant_registry::detail::kind_of(decoded.value()), RecordKind::Tenant);
  TREG_CHECK(tenant_registry::detail::is_identity_record(decoded.value()));
  TREG_CHECK_EQ(canonical_bytes(decoded.value()), canonical_bytes(any));
  TREG_CHECK_EQ(hex_of(encoded_bytes(any)), hex_of(encoded));

  // The tag is the first byte and it is the record kind.
  TREG_REQUIRE(!encoded.empty());
  TREG_CHECK_EQ(static_cast<std::uint8_t>(encoded[0]), static_cast<std::uint8_t>(RecordKind::Tenant));
  TREG_CHECK_EQ(tenant_registry::detail::to_token(RecordKind::Tenant), std::string_view{"tenant"});
  TREG_CHECK_EQ(tenant_registry::detail::to_token(RecordKind::OwnershipEdge), std::string_view{"ownership_edge"});
  TREG_CHECK_EQ(tenant_registry::detail::to_token(RecordKind::Tombstone), std::string_view{"tombstone"});

  // A kind tag this build does not define is refused rather than mapped onto a
  // default record type.
  std::vector<std::byte> unknown_kind = encoded;
  unknown_kind[0] = std::byte{9};
  ByteReader unknown_reader = reader_of(unknown_kind);
  TREG_CHECK_CODE(tenant_registry::detail::decode_any(unknown_reader, limits), ErrorCode::InvalidEnumValue);
  std::vector<std::byte> zero_kind = encoded;
  zero_kind[0] = std::byte{0};
  ByteReader zero_reader = reader_of(zero_kind);
  TREG_CHECK_CODE(tenant_registry::detail::decode_any(zero_reader, limits), ErrorCode::InvalidEnumValue);
}

TREG_TEST(codec, commit_and_baseline_payloads_round_trip) {
  Harness harness = Harness::ephemeral();
  const RegistryLimits limits = harness.limits();
  const TenantRecord tenant = harness.active_tenant("acme");
  const ServiceRecord service = harness.active_service("renderer");

  const std::vector<std::byte> outcome{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
  CommitRecord commit;
  commit.operation = OperationKind::CreateTenant;
  commit.generation = RegistryGeneration::from_value(9);
  commit.sequence = JournalSequence::from_value(4);
  commit.control_epoch = ControlEpoch::from_value(2);
  commit.incarnation = Incarnation::from_value(3);
  commit.committed_at = Timestamp{1700000000000};
  commit.request_digest = ContentDigest::of(std::string_view{"request"});
  commit.idempotency_key = idempotency_key("req-0001");
  commit.primary_key = "tenant:acme";
  commit.primary_revision = RecordRevision::from_value(2);
  commit.outcome_payload = outcome;
  commit.upserts.push_back(AnyRecord{tenant});
  commit.upserts.push_back(AnyRecord{service});
  commit.deletes.push_back("ownership:gone|also-gone");
  commit.domain_generations.emplace_back(domain_id("zone-a"), DomainGeneration::from_value(5));

  const std::vector<std::byte> commit_bytes = encoded_bytes(commit);
  ByteReader commit_reader = reader_of(commit_bytes);
  const Result<CommitRecord> decoded_commit = tenant_registry::detail::decode_commit(commit_reader, limits);
  TREG_REQUIRE_OK(decoded_commit);
  TREG_CHECK(commit_reader.require_end());
  TREG_CHECK_EQ(decoded_commit.value().operation, OperationKind::CreateTenant);
  TREG_CHECK_EQ(decoded_commit.value().generation.value(), static_cast<std::uint64_t>(9));
  TREG_CHECK_EQ(decoded_commit.value().sequence.value(), static_cast<std::uint64_t>(4));
  TREG_CHECK_EQ(decoded_commit.value().control_epoch.value(), static_cast<std::uint64_t>(2));
  TREG_CHECK_EQ(decoded_commit.value().incarnation.value(), static_cast<std::uint64_t>(3));
  TREG_CHECK_EQ(decoded_commit.value().committed_at.unix_milliseconds, static_cast<std::int64_t>(1700000000000));
  TREG_CHECK_EQ(decoded_commit.value().request_digest, commit.request_digest);
  TREG_REQUIRE(decoded_commit.value().idempotency_key.has_value());
  TREG_CHECK_EQ(decoded_commit.value().idempotency_key->value(), std::string{"req-0001"});
  TREG_CHECK_EQ(decoded_commit.value().primary_key, std::string{"tenant:acme"});
  TREG_CHECK_EQ(decoded_commit.value().primary_revision.value(), static_cast<std::uint64_t>(2));
  TREG_CHECK_EQ(decoded_commit.value().outcome_payload, outcome);
  TREG_REQUIRE(decoded_commit.value().upserts.size() == static_cast<std::size_t>(2));
  TREG_CHECK_EQ(canonical_bytes(decoded_commit.value().upserts[0]), canonical_bytes(AnyRecord{tenant}));
  TREG_CHECK_EQ(canonical_bytes(decoded_commit.value().upserts[1]), canonical_bytes(AnyRecord{service}));
  TREG_REQUIRE(decoded_commit.value().deletes.size() == static_cast<std::size_t>(1));
  TREG_CHECK_EQ(decoded_commit.value().deletes[0], std::string{"ownership:gone|also-gone"});
  TREG_REQUIRE(decoded_commit.value().domain_generations.size() == static_cast<std::size_t>(1));
  TREG_CHECK_EQ(decoded_commit.value().domain_generations[0].first.value(), std::string{"zone-a"});
  TREG_CHECK_EQ(decoded_commit.value().domain_generations[0].second.value(), static_cast<std::uint64_t>(5));
  TREG_CHECK_EQ(hex_of(encoded_bytes(decoded_commit.value())), hex_of(commit_bytes));

  // A commit without an idempotency key encodes the absence explicitly and
  // decodes back to an absent key rather than to a defaulted one.
  CommitRecord unkeyed = commit;
  unkeyed.idempotency_key.reset();
  const std::vector<std::byte> unkeyed_bytes = encoded_bytes(unkeyed);
  TREG_CHECK(unkeyed_bytes.size() < commit_bytes.size());
  ByteReader unkeyed_reader = reader_of(unkeyed_bytes);
  const Result<CommitRecord> decoded_unkeyed = tenant_registry::detail::decode_commit(unkeyed_reader, limits);
  TREG_REQUIRE_OK(decoded_unkeyed);
  TREG_CHECK(!decoded_unkeyed.value().idempotency_key.has_value());

  // The ledger entry the commit carries round trips on its own too.
  const tenant_registry::detail::IdempotencyLedgerEntry ledger_entry{idempotency_key("req-0002"),
                                                                    ContentDigest::of(std::string_view{"digest"}),
                                                                    JournalSequence::from_value(7),
                                                                    RegistryGeneration::from_value(8),
                                                                    OperationKind::PutOwnership,
                                                                    "ownership:a|b",
                                                                    RecordRevision::from_value(6),
                                                                    outcome};
  const std::vector<std::byte> ledger_bytes = encoded_bytes(ledger_entry);
  ByteReader ledger_reader = reader_of(ledger_bytes);
  const Result<tenant_registry::detail::IdempotencyLedgerEntry> decoded_entry =
      tenant_registry::detail::decode_ledger_entry(ledger_reader, limits);
  TREG_REQUIRE_OK(decoded_entry);
  TREG_CHECK(ledger_reader.require_end());
  TREG_CHECK_EQ(decoded_entry.value().key.value(), std::string{"req-0002"});
  TREG_CHECK_EQ(decoded_entry.value().operation, OperationKind::PutOwnership);
  TREG_CHECK_EQ(decoded_entry.value().primary_key, std::string{"ownership:a|b"});
  TREG_CHECK_EQ(decoded_entry.value().sequence.value(), static_cast<std::uint64_t>(7));
  TREG_CHECK_EQ(hex_of(encoded_bytes(decoded_entry.value())), hex_of(ledger_bytes));

  tenant_registry::detail::BaselinePayload baseline;
  baseline.generation = RegistryGeneration::from_value(11);
  baseline.tenants.push_back(tenant);
  baseline.services.push_back(service);
  baseline.domain_generations.emplace_back(domain_id("zone-a"), DomainGeneration::from_value(2));
  baseline.ledger.push_back(ledger_entry);

  const std::vector<std::byte> baseline_bytes = encoded_bytes(baseline);
  ByteReader baseline_reader = reader_of(baseline_bytes);
  const Result<tenant_registry::detail::BaselinePayload> decoded_baseline =
      tenant_registry::detail::decode_baseline(baseline_reader, limits);
  TREG_REQUIRE_OK(decoded_baseline);
  TREG_CHECK(baseline_reader.require_end());
  TREG_CHECK_EQ(decoded_baseline.value().generation.value(), static_cast<std::uint64_t>(11));
  TREG_REQUIRE(decoded_baseline.value().tenants.size() == static_cast<std::size_t>(1));
  TREG_CHECK_EQ(tenant_registry::to_canonical(decoded_baseline.value().tenants[0]),
                tenant_registry::to_canonical(tenant));
  TREG_REQUIRE(decoded_baseline.value().services.size() == static_cast<std::size_t>(1));
  TREG_CHECK_EQ(tenant_registry::to_canonical(decoded_baseline.value().services[0]),
                tenant_registry::to_canonical(service));
  TREG_REQUIRE(decoded_baseline.value().ledger.size() == static_cast<std::size_t>(1));
  TREG_CHECK_EQ(decoded_baseline.value().ledger[0].key.value(), std::string{"req-0002"});
  TREG_CHECK_EQ(hex_of(encoded_bytes(decoded_baseline.value())), hex_of(baseline_bytes));
}

TREG_TEST(codec, truncated_input_is_refused) {
  Harness harness = Harness::ephemeral();
  const RegistryLimits limits = harness.limits();
  const TenantRecord tenant = harness.active_tenant("acme");
  const std::vector<std::byte> encoded = encoded_bytes(tenant);

  const std::size_t cuts[] = {0, 1, 2, 5, encoded.size() / 2, encoded.size() - 1};
  for (const std::size_t cut : cuts) {
    ByteReader reader{std::span<const std::byte>{encoded.data(), cut}};
    TREG_CHECK(!tenant_registry::detail::decode_tenant(reader, limits).has_value());
  }

  // A commit and a baseline cut short are refused as well.
  CommitRecord commit;
  commit.operation = OperationKind::CreateService;
  commit.primary_key = "service:renderer";
  commit.upserts.push_back(AnyRecord{harness.active_service("renderer")});
  const std::vector<std::byte> commit_bytes = encoded_bytes(commit);
  ByteReader commit_reader{std::span<const std::byte>{commit_bytes.data(), commit_bytes.size() - 1}};
  TREG_CHECK(!tenant_registry::detail::decode_commit(commit_reader, limits).has_value());

  tenant_registry::detail::BaselinePayload baseline;
  baseline.tenants.push_back(tenant);
  const std::vector<std::byte> baseline_bytes = encoded_bytes(baseline);
  ByteReader baseline_reader{std::span<const std::byte>{baseline_bytes.data(), baseline_bytes.size() - 1}};
  TREG_CHECK(!tenant_registry::detail::decode_baseline(baseline_reader, limits).has_value());
}

TREG_TEST(codec, trailing_bytes_are_not_a_complete_record) {
  Harness harness = Harness::ephemeral();
  const RegistryLimits limits = harness.limits();
  const TenantRecord tenant = harness.active_tenant("acme");
  std::vector<std::byte> padded = encoded_bytes(tenant);
  padded.push_back(std::byte{0x00});

  ByteReader reader = reader_of(padded);
  const Result<TenantRecord> decoded = tenant_registry::detail::decode_tenant(reader, limits);
  TREG_REQUIRE_OK(decoded);
  // The trailing byte is still there: the record is not complete until the
  // containing reader is exactly consumed, and require_end() says so.
  TREG_CHECK(!reader.require_end());
  TREG_CHECK_EQ(reader.remaining(), static_cast<std::size_t>(1));
  TREG_CHECK_EQ(tenant_registry::to_canonical(decoded.value()), tenant_registry::to_canonical(tenant));

  // A decoder that is handed only the record consumes exactly it.
  const std::vector<std::byte> exact_bytes = encoded_bytes(tenant);
  ByteReader exact = reader_of(exact_bytes);
  TREG_REQUIRE_OK(tenant_registry::detail::decode_tenant(exact, limits));
  TREG_CHECK(exact.require_end());
  TREG_CHECK_EQ(exact.remaining(), static_cast<std::size_t>(0));
}

TREG_TEST(codec, zero_and_unknown_enum_values_are_refused) {
  const RegistryLimits limits{};

  // A tenant state of zero is Unspecified, which is never a legal state, and a
  // state this build does not define is refused rather than clamped.
  ByteWriter writer;
  writer.length_prefixed("acme");
  writer.u8(0);  // display_name absent
  writer.u8(0);  // state: Unspecified
  const std::vector<std::byte> zero_state = writer.bytes();
  ByteReader zero_reader = reader_of(zero_state);
  TREG_CHECK_CODE(tenant_registry::detail::decode_tenant(zero_reader, limits), ErrorCode::InvalidEnumValue);

  ByteWriter unknown_writer;
  unknown_writer.length_prefixed("acme");
  unknown_writer.u8(0);
  unknown_writer.u8(9);  // state: not defined by LifecycleState
  const std::vector<std::byte> unknown_state = unknown_writer.bytes();
  ByteReader unknown_reader = reader_of(unknown_state);
  TREG_CHECK_CODE(tenant_registry::detail::decode_tenant(unknown_reader, limits), ErrorCode::InvalidEnumValue);

  // The primitive decoder agrees and leaves the output untouched.
  const std::array<std::byte, 1> zero{std::byte{0}};
  const std::array<std::byte, 1> unknown{std::byte{9}};
  const std::array<std::byte, 1> active{std::byte{2}};
  LifecycleState state = LifecycleState::Retired;
  ByteReader zero_enum_reader{std::span<const std::byte>{zero.data(), zero.size()}};
  TREG_CHECK(!tenant_registry::detail::decode(zero_enum_reader, state));
  TREG_CHECK_EQ(state, LifecycleState::Retired);
  ByteReader unknown_enum_reader{std::span<const std::byte>{unknown.data(), unknown.size()}};
  TREG_CHECK(!tenant_registry::detail::decode(unknown_enum_reader, state));
  TREG_CHECK_EQ(state, LifecycleState::Retired);
  ByteReader active_enum_reader{std::span<const std::byte>{active.data(), active.size()}};
  TREG_CHECK(tenant_registry::detail::decode(active_enum_reader, state));
  TREG_CHECK_EQ(state, LifecycleState::Active);
  ByteReader empty_enum_reader{std::span<const std::byte>{}};
  TREG_CHECK(!tenant_registry::detail::decode(empty_enum_reader, state));
  TREG_CHECK_EQ(state, LifecycleState::Active);

  // An operation kind of zero is refused before the rest of a commit is read.
  ByteWriter operation_writer;
  operation_writer.u16(0);
  const std::vector<std::byte> zero_operation = operation_writer.bytes();
  ByteReader operation_reader = reader_of(zero_operation);
  TREG_CHECK_CODE(tenant_registry::detail::decode_commit(operation_reader, limits), ErrorCode::InvalidEnumValue);

  // A metadata kind of zero is refused too, not read as Unknown.
  ByteWriter metadata_writer;
  metadata_writer.u32(1);
  metadata_writer.length_prefixed("key");
  metadata_writer.u8(0);
  const std::vector<std::byte> zero_kind = metadata_writer.bytes();
  ByteReader metadata_reader = reader_of(zero_kind);
  TREG_CHECK_CODE(tenant_registry::detail::decode_metadata(metadata_reader, limits), ErrorCode::InvalidEnumValue);
}

TREG_TEST(codec, over_long_payload_is_refused) {
  Harness harness = Harness::ephemeral();
  const RegistryLimits limits = harness.limits();
  const TenantRecord tenant = active_tenant_with_metadata(harness, "acme");

  CommitRecord commit;
  commit.operation = OperationKind::TransitionSubject;
  commit.primary_key = "tenant:acme";
  const std::vector<std::byte> commit_bytes = encoded_bytes(commit);
  RegistryLimits tiny_commit = limits;
  tiny_commit.max_commit_payload_bytes = 4;
  ByteReader commit_reader = reader_of(commit_bytes);
  TREG_CHECK_CODE(tenant_registry::detail::decode_commit(commit_reader, tiny_commit), ErrorCode::PayloadTooLarge);

  tenant_registry::detail::BaselinePayload baseline;
  baseline.generation = RegistryGeneration::from_value(1);
  const std::vector<std::byte> baseline_bytes = encoded_bytes(baseline);
  RegistryLimits tiny_baseline = limits;
  tiny_baseline.max_baseline_payload_bytes = 4;
  ByteReader baseline_reader = reader_of(baseline_bytes);
  TREG_CHECK_CODE(tenant_registry::detail::decode_baseline(baseline_reader, tiny_baseline),
                  ErrorCode::PayloadTooLarge);

  // A declared text length above the configured bound is refused before the
  // bytes behind it are read, so a length field can never make a decode
  // allocate without end.
  RegistryLimits tiny_value = limits;
  tiny_value.max_metadata_value_bytes = 1;
  const std::vector<std::byte> tenant_bytes = encoded_bytes(tenant);
  ByteReader tenant_reader = reader_of(tenant_bytes);
  TREG_CHECK_CODE(tenant_registry::detail::decode_tenant(tenant_reader, tiny_value), ErrorCode::LimitExceeded);

  // The configured identity bound is enforced on the read path too, so a store
  // written under a larger bound cannot smuggle an over-long identity past a
  // build that has lowered it.
  RegistryLimits tiny_identity = limits;
  tiny_identity.max_identity_bytes = 2;
  ByteReader identity_reader = reader_of(tenant_bytes);
  TREG_CHECK_CODE(tenant_registry::detail::decode_tenant(identity_reader, tiny_identity), ErrorCode::LimitExceeded);

  // The writer is bounded too: an encoder that runs out of room reports the
  // overflow instead of growing without end.
  ByteWriter small{8};
  tenant_registry::detail::encode(small, tenant);
  TREG_CHECK(small.overflowed());
  TREG_CHECK(small.size() <= static_cast<std::size_t>(8));
}

TREG_TEST(codec, duplicate_metadata_key_is_refused) {
  const RegistryLimits limits{};
  ByteWriter writer;
  writer.u32(2);
  writer.length_prefixed("key");
  writer.u8(static_cast<std::uint8_t>(tenant_registry::MetadataKind::Text));
  writer.length_prefixed("one");
  writer.length_prefixed("key");
  writer.u8(static_cast<std::uint8_t>(tenant_registry::MetadataKind::Integer));
  writer.i64(2);
  const std::vector<std::byte> duplicate = writer.bytes();
  ByteReader reader = reader_of(duplicate);
  TREG_CHECK_CODE(tenant_registry::detail::decode_metadata(reader, limits), ErrorCode::InvalidMetadata);

  // The same two entries under two different keys decode, so the refusal above
  // is about the duplicate and not about the shape of the payload.
  ByteWriter good_writer;
  good_writer.u32(2);
  good_writer.length_prefixed("key");
  good_writer.u8(static_cast<std::uint8_t>(tenant_registry::MetadataKind::Text));
  good_writer.length_prefixed("one");
  good_writer.length_prefixed("other");
  good_writer.u8(static_cast<std::uint8_t>(tenant_registry::MetadataKind::Integer));
  good_writer.i64(2);
  const std::vector<std::byte> good = good_writer.bytes();
  ByteReader good_reader = reader_of(good);
  const Result<TenancyMetadata> decoded = tenant_registry::detail::decode_metadata(good_reader, limits);
  TREG_REQUIRE_OK(decoded);
  TREG_CHECK(good_reader.require_end());
  TREG_CHECK_EQ(decoded.value().size(), static_cast<std::size_t>(2));
  TREG_CHECK(decoded.value().contains(metadata_key("key")));
  TREG_CHECK(decoded.value().contains(metadata_key("other")));
}

TREG_TEST(codec, digest_stability_and_reencoding) {
  Harness harness = Harness::ephemeral();
  const TenantRecord tenant = harness.active_tenant("acme");
  const TenantRecord other = harness.active_tenant("other");
  harness.active_service("renderer");
  harness.active_domain("zone-a");
  harness.active_tenant("child-t");
  harness.active_tenant("parent-t");
  const AnyRecord any{tenant};

  // The same value encoded twice gives identical bytes, and so does the same
  // value decoded and re-encoded.
  TREG_CHECK_EQ(hex_of(encoded_bytes(any)), hex_of(encoded_bytes(any)));
  TREG_CHECK_EQ(canonical_bytes(any), canonical_bytes(any));
  TREG_CHECK_EQ(tenant_registry::detail::record_digest(any).to_text(),
                tenant_registry::detail::record_digest(any).to_text());
  TREG_CHECK(tenant_registry::detail::record_digest(any) == tenant_registry::detail::record_digest(tenant));

  const std::vector<std::byte> encoded_any = encoded_bytes(any);
  ByteReader reader = reader_of(encoded_any);
  const Result<AnyRecord> decoded = tenant_registry::detail::decode_any(reader, harness.limits());
  TREG_REQUIRE_OK(decoded);
  TREG_CHECK_EQ(canonical_bytes(decoded.value()), canonical_bytes(any));
  TREG_CHECK(tenant_registry::detail::record_digest(decoded.value()) ==
             tenant_registry::detail::record_digest(any));

  // A different record digests differently.
  TREG_CHECK(tenant_registry::detail::record_digest(AnyRecord{other}) !=
             tenant_registry::detail::record_digest(any));

  // Canonical keys are unique across kinds and make the payload position of a
  // record addressable.
  TREG_CHECK_EQ(tenant_registry::detail::canonical_key(tenant), std::string{"tenant:acme"});
  TREG_CHECK_EQ(tenant_registry::detail::canonical_key(harness.service("renderer")),
                std::string{"service:renderer"});
  TREG_CHECK_EQ(tenant_registry::detail::canonical_key(harness.domain("zone-a")),
                std::string{"isolation_domain:zone-a"});
  TREG_CHECK_EQ(tenant_registry::detail::canonical_key(harness.own("child-t", "parent-t")),
                std::string{"ownership:child-t|parent-t"});
  TREG_CHECK_EQ(tenant_registry::detail::canonical_key(harness.bind("renderer", "child-t")),
                std::string{"binding:renderer|child-t|operated_by"});
}

}  // namespace treg_test
