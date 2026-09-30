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

#ifndef TENANT_REGISTRY_SRC_CANONICAL_CODEC_HPP
#define TENANT_REGISTRY_SRC_CANONICAL_CODEC_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "byte_codec.hpp"
#include "tenant_registry/digest.hpp"
#include "tenant_registry/errors.hpp"
#include "tenant_registry/ids.hpp"
#include "tenant_registry/limits.hpp"
#include "tenant_registry/query.hpp"
#include "tenant_registry/records.hpp"
#include "tenant_registry/requests.hpp"

namespace tenant_registry {
namespace detail {

/// The kind of a record in the durable log. The variant alternative is the
/// kind; this enum exists only so the kind can be written as one byte.
enum class RecordKind : std::uint8_t {
  Unspecified = 0,
  Tenant = 1,
  Service = 2,
  IsolationDomain = 3,
  OwnershipEdge = 4,
  ServiceBinding = 5,
  IsolationMembership = 6,
  Tombstone = 7,
};

[[nodiscard]] std::string_view to_token(RecordKind kind) noexcept;
[[nodiscard]] bool parse_record_kind(std::string_view token, RecordKind& out) noexcept;

/// Any record this registry stores. The alternative in use is the kind, so
/// there is no second field that could disagree with it.
using AnyRecord = std::variant<TenantRecord, ServiceRecord, IsolationDomainRecord, OwnershipEdge, ServiceBinding,
                               IsolationMembership, TombstoneRecord>;

[[nodiscard]] RecordKind kind_of(const AnyRecord& record) noexcept;
[[nodiscard]] bool is_identity_record(const AnyRecord& record) noexcept;

/// The canonical key of a record. It is unique across all record kinds, so a
/// delete set and an upsert set can never collide on it.
///
///   identity records      "tenant:acme", "service:renderer", "isolation_domain:zone-a"
///   ownership edges       "ownership:<child>|<parent>"
///   service bindings      "binding:<service>|<tenant>|<kind token>"
///   isolation memberships "membership:<subject token>|<domain>"
[[nodiscard]] std::string canonical_key(const AnyRecord& record);
[[nodiscard]] std::string canonical_key(const TenantRecord& record);
[[nodiscard]] std::string canonical_key(const ServiceRecord& record);
[[nodiscard]] std::string canonical_key(const IsolationDomainRecord& record);
[[nodiscard]] std::string canonical_key(const OwnershipEdge& record);
[[nodiscard]] std::string canonical_key(const ServiceBinding& record);
[[nodiscard]] std::string canonical_key(const IsolationMembership& record);
[[nodiscard]] std::string canonical_key(const TombstoneRecord& record);

// ---------------------------------------------------------------------------
// Primitive encoders. Every one of them writes exactly one canonical form.
// ---------------------------------------------------------------------------

void encode(ByteWriter& writer, LifecycleState value);
void encode(ByteWriter& writer, MembershipState value);
void encode(ByteWriter& writer, OwnershipKind value);
void encode(ByteWriter& writer, BindingKind value);
void encode(ByteWriter& writer, MembershipRole value);
void encode(ByteWriter& writer, IsolationClass value);
void encode(ByteWriter& writer, ProvenanceSource value);
void encode(ByteWriter& writer, SubjectKind value);
void encode(ByteWriter& writer, MetadataKind value);
void encode(ByteWriter& writer, OperationKind value);
void encode(ByteWriter& writer, RecordKind value);
void encode(ByteWriter& writer, TraversalDirection value);
void encode(ByteWriter& writer, const TenancySubject& value);
void encode(ByteWriter& writer, const ProvenanceRecord& value);
void encode(ByteWriter& writer, const TenancyMetadata& value);
void encode(ByteWriter& writer, const RebindPermit& value);
void encode(ByteWriter& writer, const Tombstone& value);
void encode(ByteWriter& writer, const IdempotencyKey& value);

/// Every decoder consumes exactly one canonical form and returns false when the
/// input is not exactly that. A decoder never substitutes a default for a value
/// it did not read.
[[nodiscard]] bool decode(ByteReader& reader, LifecycleState& out) noexcept;
[[nodiscard]] bool decode(ByteReader& reader, MembershipState& out) noexcept;
[[nodiscard]] bool decode(ByteReader& reader, OwnershipKind& out) noexcept;
[[nodiscard]] bool decode(ByteReader& reader, BindingKind& out) noexcept;
[[nodiscard]] bool decode(ByteReader& reader, MembershipRole& out) noexcept;
[[nodiscard]] bool decode(ByteReader& reader, IsolationClass& out) noexcept;
[[nodiscard]] bool decode(ByteReader& reader, ProvenanceSource& out) noexcept;
[[nodiscard]] bool decode(ByteReader& reader, SubjectKind& out) noexcept;
[[nodiscard]] bool decode(ByteReader& reader, MetadataKind& out) noexcept;
[[nodiscard]] bool decode(ByteReader& reader, OperationKind& out) noexcept;
[[nodiscard]] bool decode(ByteReader& reader, RecordKind& out) noexcept;
[[nodiscard]] bool decode(ByteReader& reader, TraversalDirection& out) noexcept;

[[nodiscard]] Result<TenancySubject> decode_subject(ByteReader& reader, const RegistryLimits& limits);
[[nodiscard]] Result<ProvenanceRecord> decode_provenance(ByteReader& reader, const RegistryLimits& limits);
[[nodiscard]] Result<TenancyMetadata> decode_metadata(ByteReader& reader, const RegistryLimits& limits);
[[nodiscard]] Result<RebindPermit> decode_rebind_permit(ByteReader& reader, const RegistryLimits& limits);
[[nodiscard]] Result<Tombstone> decode_tombstone(ByteReader& reader, const RegistryLimits& limits);
[[nodiscard]] Result<IdempotencyKey> decode_idempotency_key(ByteReader& reader);

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

void encode(ByteWriter& writer, const TenantRecord& record);
void encode(ByteWriter& writer, const ServiceRecord& record);
void encode(ByteWriter& writer, const IsolationDomainRecord& record);
void encode(ByteWriter& writer, const OwnershipEdge& record);
void encode(ByteWriter& writer, const ServiceBinding& record);
void encode(ByteWriter& writer, const IsolationMembership& record);
void encode(ByteWriter& writer, const TombstoneRecord& record);

/// Writes one record, tagged with its kind.
void encode(ByteWriter& writer, const AnyRecord& record);

[[nodiscard]] Result<TenantRecord> decode_tenant(ByteReader& reader, const RegistryLimits& limits);
[[nodiscard]] Result<ServiceRecord> decode_service(ByteReader& reader, const RegistryLimits& limits);
[[nodiscard]] Result<IsolationDomainRecord> decode_isolation_domain(ByteReader& reader,
                                                                   const RegistryLimits& limits);
[[nodiscard]] Result<OwnershipEdge> decode_ownership_edge(ByteReader& reader, const RegistryLimits& limits);
[[nodiscard]] Result<ServiceBinding> decode_service_binding(ByteReader& reader, const RegistryLimits& limits);
[[nodiscard]] Result<IsolationMembership> decode_isolation_membership(ByteReader& reader,
                                                                      const RegistryLimits& limits);
[[nodiscard]] Result<TombstoneRecord> decode_tombstone_record(ByteReader& reader, const RegistryLimits& limits);

/// Reads one kind tag, then the record that kind names. Trailing bytes are a
/// malformed record: the caller checks require_end() on the containing reader.
[[nodiscard]] Result<AnyRecord> decode_any(ByteReader& reader, const RegistryLimits& limits);

// ---------------------------------------------------------------------------
// Record digests
// ---------------------------------------------------------------------------

[[nodiscard]] ContentDigest record_digest(const TenantRecord& record);
[[nodiscard]] ContentDigest record_digest(const ServiceRecord& record);
[[nodiscard]] ContentDigest record_digest(const IsolationDomainRecord& record);
[[nodiscard]] ContentDigest record_digest(const OwnershipEdge& record);
[[nodiscard]] ContentDigest record_digest(const ServiceBinding& record);
[[nodiscard]] ContentDigest record_digest(const IsolationMembership& record);
[[nodiscard]] ContentDigest record_digest(const TombstoneRecord& record);
[[nodiscard]] ContentDigest record_digest(const AnyRecord& record);

/// The canonical bytes of one record, for hashing, export and comparison.
[[nodiscard]] std::string canonical_bytes(const AnyRecord& record);

// ---------------------------------------------------------------------------
// Request digests. Two requests share a digest exactly when they ask for the
// same thing: every field that changes the answer is bound, and nothing that
// does not is.
// ---------------------------------------------------------------------------

[[nodiscard]] RequestDigest request_digest(const CreateTenantRequest& request);
[[nodiscard]] RequestDigest request_digest(const CreateServiceRequest& request);
[[nodiscard]] RequestDigest request_digest(const CreateIsolationDomainRequest& request);
[[nodiscard]] RequestDigest request_digest(const TransitionSubjectRequest& request);
[[nodiscard]] RequestDigest request_digest(const SetOwnerRequest& request);
[[nodiscard]] RequestDigest request_digest(const SetMetadataRequest& request);
[[nodiscard]] RequestDigest request_digest(const PutOwnershipRequest& request);
[[nodiscard]] RequestDigest request_digest(const RemoveOwnershipRequest& request);
[[nodiscard]] RequestDigest request_digest(const TransitionOwnershipRequest& request);
[[nodiscard]] RequestDigest request_digest(const PutServiceBindingRequest& request);
[[nodiscard]] RequestDigest request_digest(const RemoveServiceBindingRequest& request);
[[nodiscard]] RequestDigest request_digest(const TransitionServiceBindingRequest& request);
[[nodiscard]] RequestDigest request_digest(const PutIsolationMembershipRequest& request);
[[nodiscard]] RequestDigest request_digest(const TransitionIsolationMembershipRequest& request);
[[nodiscard]] RequestDigest request_digest(const RemoveIsolationMembershipRequest& request);
[[nodiscard]] RequestDigest request_digest(const TombstoneRequest& request);

[[nodiscard]] ContentDigest mutation_context_digest(const MutationContext& context);

// ---------------------------------------------------------------------------
// Durable payloads
// ---------------------------------------------------------------------------

/// One entry of the idempotency ledger.
///
/// The ledger is what lets a caller whose response was lost ask the same
/// question twice and receive the first answer, including the record content
/// that was current when the answer was produced. It is rebuilt from the log on
/// every open, so it can never disagree with the log.
struct IdempotencyLedgerEntry {
  IdempotencyKey key;
  RequestDigest request_digest;
  JournalSequence sequence;
  RegistryGeneration generation;
  OperationKind operation = OperationKind::Unspecified;
  std::string primary_key;
  RecordRevision primary_revision;
  std::vector<std::byte> outcome_payload;
};

/// One committed mutation, exactly as it is stored.
struct CommitRecord {
  OperationKind operation = OperationKind::Unspecified;
  RegistryGeneration generation;
  JournalSequence sequence;
  ControlEpoch control_epoch;
  Incarnation incarnation;
  Timestamp committed_at;
  RequestDigest request_digest;
  std::optional<IdempotencyKey> idempotency_key;
  std::string primary_key;
  RecordRevision primary_revision;
  std::vector<std::byte> outcome_payload;
  std::vector<AnyRecord> upserts;
  std::vector<std::string> deletes;
  std::vector<std::pair<IsolationDomainId, DomainGeneration>> domain_generations;
};

/// The whole authoritative state at one generation. Written only by compaction.
struct BaselinePayload {
  RegistryGeneration generation;
  std::vector<TenantRecord> tenants;
  std::vector<ServiceRecord> services;
  std::vector<IsolationDomainRecord> isolation_domains;
  std::vector<OwnershipEdge> ownership_edges;
  std::vector<ServiceBinding> service_bindings;
  std::vector<IsolationMembership> isolation_memberships;
  std::vector<TombstoneRecord> tombstones;
  std::vector<std::pair<IsolationDomainId, DomainGeneration>> domain_generations;
  std::vector<IdempotencyLedgerEntry> ledger;
};

void encode(ByteWriter& writer, const IdempotencyLedgerEntry& entry);
[[nodiscard]] Result<IdempotencyLedgerEntry> decode_ledger_entry(ByteReader& reader,
                                                                const RegistryLimits& limits);

void encode(ByteWriter& writer, const CommitRecord& record);
[[nodiscard]] Result<CommitRecord> decode_commit(ByteReader& reader, const RegistryLimits& limits);

void encode(ByteWriter& writer, const BaselinePayload& payload);
[[nodiscard]] Result<BaselinePayload> decode_baseline(ByteReader& reader, const RegistryLimits& limits);

/// The domain separated prefix every request digest is built from.
inline constexpr std::string_view kRequestDigestDomain = "tenant-registry/request/v1";

/// The domain separated prefix every record digest is built from.
inline constexpr std::string_view kRecordDigestDomain = "tenant-registry/record/v1";

/// The domain separated prefix the baseline payload digest is built from.
inline constexpr std::string_view kBaselineDigestDomain = "tenant-registry/baseline/v1";

/// The domain separated prefix the snapshot digest is built from.
inline constexpr std::string_view kSnapshotDigestDomain = "tenant-registry/snapshot/v1";

/// The ASCII text the genesis chain seed is derived from.
inline constexpr std::string_view kChainSeedDomain = "tenant-registry/journal/v1/";

}  // namespace detail
}  // namespace tenant_registry

#endif  // TENANT_REGISTRY_SRC_CANONICAL_CODEC_HPP
