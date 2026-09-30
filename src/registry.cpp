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

#include "tenant_registry/registry.hpp"

#include <array>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "canonical_codec.hpp"
#include "durable_store.hpp"
#include "registry_internal.hpp"
#include "registry_state.hpp"
#include "tenant_registry/lifecycle.hpp"

namespace tenant_registry {
namespace detail {

RegistryCore::RegistryCore(RegistryLimits limits_in, std::shared_ptr<Clock> clock_in)
    : limits(std::move(limits_in)),
      clock(std::move(clock_in)),
      state(limits),
      sequence(JournalSequence::initial()),
      control_epoch(ControlEpoch::initial()),
      incarnation(Incarnation::initial()),
      report{false,
             false,
             false,
             0,
             0,
             0,
             std::nullopt,
             ControlEpoch::initial(),
             Incarnation::initial(),
             JournalSequence::initial(),
             RegistryGeneration::initial(),
             false,
             {}} {}

RegistryCore::~RegistryCore() = default;

bool is_identity_any(const AnyRecord& record) noexcept {
  return std::holds_alternative<TenantRecord>(record) || std::holds_alternative<ServiceRecord>(record) ||
         std::holds_alternative<IsolationDomainRecord>(record);
}

LifecycleState identity_state(const AnyRecord& record) noexcept {
  if (const auto* tenant = std::get_if<TenantRecord>(&record); tenant != nullptr) {
    return tenant->state;
  }
  if (const auto* service = std::get_if<ServiceRecord>(&record); service != nullptr) {
    return service->state;
  }
  if (const auto* domain = std::get_if<IsolationDomainRecord>(&record); domain != nullptr) {
    return domain->state;
  }
  return LifecycleState::Unspecified;
}

std::string_view identity_value(const AnyRecord& record) noexcept {
  if (const auto* tenant = std::get_if<TenantRecord>(&record); tenant != nullptr) {
    return tenant->id.value();
  }
  if (const auto* service = std::get_if<ServiceRecord>(&record); service != nullptr) {
    return service->id.value();
  }
  if (const auto* domain = std::get_if<IsolationDomainRecord>(&record); domain != nullptr) {
    return domain->id.value();
  }
  return {};
}

SubjectKind identity_kind(const AnyRecord& record) noexcept {
  if (std::holds_alternative<TenantRecord>(record)) {
    return SubjectKind::Tenant;
  }
  if (std::holds_alternative<ServiceRecord>(record)) {
    return SubjectKind::Service;
  }
  if (std::holds_alternative<IsolationDomainRecord>(record)) {
    return SubjectKind::IsolationDomain;
  }
  return SubjectKind::Unspecified;
}

RecordRevision revision_of(const AnyRecord& record) noexcept {
  if (const auto* tenant = std::get_if<TenantRecord>(&record); tenant != nullptr) {
    return tenant->revision;
  }
  if (const auto* service = std::get_if<ServiceRecord>(&record); service != nullptr) {
    return service->revision;
  }
  if (const auto* domain = std::get_if<IsolationDomainRecord>(&record); domain != nullptr) {
    return domain->revision;
  }
  if (const auto* edge = std::get_if<OwnershipEdge>(&record); edge != nullptr) {
    return edge->revision;
  }
  if (const auto* binding = std::get_if<ServiceBinding>(&record); binding != nullptr) {
    return binding->revision;
  }
  if (const auto* membership = std::get_if<IsolationMembership>(&record); membership != nullptr) {
    return membership->revision;
  }
  if (const auto* tombstone = std::get_if<TombstoneRecord>(&record); tombstone != nullptr) {
    return tombstone->revision;
  }
  return RecordRevision::initial();
}

Status check_identity_text(SubjectKind kind, std::string_view text) {
  switch (kind) {
    case SubjectKind::Tenant: {
      const auto checked = TenantId::create(text);
      return checked ? Status::success() : Status::failure(checked.error());
    }
    case SubjectKind::Service: {
      const auto checked = ServiceId::create(text);
      return checked ? Status::success() : Status::failure(checked.error());
    }
    case SubjectKind::IsolationDomain: {
      const auto checked = IsolationDomainId::create(text);
      return checked ? Status::success() : Status::failure(checked.error());
    }
    case SubjectKind::Unspecified:
      break;
  }
  return Status::failure(ErrorCode::InvalidIdKind, "the identity kind is unspecified");
}

Status ensure_writable(const RegistryCore& core) {
  if (core.closed) {
    return Status::failure(ErrorCode::StoreClosed, "this registry session has been closed");
  }
  if (core.mode != AccessMode::ReadWrite) {
    return Status::failure(ErrorCode::StoreNotWritable,
                           "this registry session was opened read-only and cannot change anything");
  }
  return Status::success();
}

Status check_provenance(const ProvenanceRecord& provenance, const RegistryLimits& limits) {
  if (provenance.source() == ProvenanceSource::Unspecified) {
    return Status::failure(ErrorCode::InvalidProvenance, "the actor has no declared provenance source");
  }
  if (provenance.source() < ProvenanceSource::OperatorDeclaration ||
      provenance.source() > ProvenanceSource::TestFixture) {
    // A source this build does not define would be stored and then refused by
    // the decoder on the next read, so it is refused here instead.
    return Status::failure(ErrorCode::InvalidEnumValue, "the actor provenance source is not one this build defines");
  }
  if (provenance.source_id().value().size() > limits.max_source_bytes) {
    return Status::failure(ErrorCode::InvalidProvenance, "the actor source identity is longer than the configured limit");
  }
  if (provenance.principal().value().size() > limits.max_principal_bytes) {
    return Status::failure(ErrorCode::InvalidProvenance,
                           "the actor principal identity is longer than the configured limit");
  }
  if (provenance.note().size() > limits.max_provenance_note_bytes) {
    return Status::failure(ErrorCode::InvalidProvenance, "the actor note is longer than the configured limit");
  }
  return Status::success();
}

Result<std::optional<std::string>> check_optional_text(const std::optional<std::string>& value, std::size_t max_bytes,
                                                      const char* what) {
  if (!value.has_value()) {
    return std::optional<std::string>{};
  }
  auto checked = validate_text_field(*value, max_bytes, what);
  if (!checked) {
    return checked.error();
  }
  return std::optional<std::string>{std::move(checked).value()};
}

Result<ContextResolution> resolve_context(const RegistryCore& core, OperationKind operation, RequestDigest digest,
                                          const MutationContext& context) {
  const auto writable = ensure_writable(core);
  if (!writable.ok()) {
    return writable.error();
  }

  // Idempotency is resolved before staleness. A caller that never saw the
  // answer to an accepted request must be able to ask again even though the
  // registry has moved on since; refusing that as stale would be exactly the
  // lost-response failure this ordering exists to prevent.
  if (context.idempotency_key.has_value()) {
    const auto found = core.state.ledger.find(context.idempotency_key->value());
    if (found != core.state.ledger.end()) {
      if (found->second.request_digest != digest) {
        return Error{ErrorCode::IdempotencyKeyReused,
                     "the idempotency key '" + std::string{context.idempotency_key->value()} +
                         "' was already used for a different request; a key identifies one request and only one"};
      }
      ContextResolution resolution;
      resolution.replay = true;
      resolution.entry = &found->second;
      resolution.receipt = MutationReceipt{found->second.operation,
                                           found->second.generation,
                                           found->second.sequence,
                                           found->second.primary_revision,
                                           found->second.request_digest,
                                           true};
      return resolution;
    }
    if (core.state.ledger_full()) {
      return Error{ErrorCode::IdempotencyLedgerFull,
                   "the idempotency ledger holds " + std::to_string(core.state.ledger_size()) +
                       " entries, which is the configured limit; a new keyed request is refused rather than "
                       "accepted without the ability to replay it"};
    }
  }

  if (context.expected_generation != core.state.generation) {
    return Error{ErrorCode::StaleGeneration,
                 "the request was composed against generation " +
                     std::to_string(context.expected_generation.value()) + " but the registry is at generation " +
                     std::to_string(core.state.generation.value()) +
                     "; the request is refused rather than applied to a state it did not see"};
  }

  (void)operation;
  return ContextResolution{};
}

std::vector<std::byte> outcome_of(const AnyRecord& record) {
  ByteWriter writer;
  encode(writer, record);
  return std::move(writer).take();
}

Result<AnyRecord> decode_outcome(const IdempotencyLedgerEntry& entry, const RegistryLimits& limits) {
  if (entry.outcome_payload.size() > limits.max_idempotency_outcome_bytes) {
    return Error{ErrorCode::StoreCorrupt, "an idempotency ledger entry carries more outcome content than the limit allows"};
  }
  ByteReader reader{std::span<const std::byte>{entry.outcome_payload.data(), entry.outcome_payload.size()}};
  auto record = decode_any(reader, limits);
  if (!record) {
    return record.error();
  }
  if (!reader.require_end()) {
    return Error{ErrorCode::StoreCorrupt, "an idempotency ledger entry has trailing bytes after its outcome record"};
  }
  return std::move(record).value();
}

Result<MutationReceipt> apply_commit(RegistryCore& core, PendingCommit pending) {
  RegistryState& state = core.state;

  const auto next_generation = advance(state.generation);
  if (!next_generation) {
    return next_generation.error();
  }
  const auto next_sequence = advance(core.sequence);
  if (!next_sequence) {
    return next_sequence.error();
  }

  CommitRecord record{pending.operation,
                      next_generation.value(),
                      next_sequence.value(),
                      core.control_epoch,
                      core.incarnation,
                      core.clock->now(),
                      pending.request_digest,
                      pending.idempotency_key,
                      pending.primary_key,
                      pending.primary_revision,
                      pending.outcome_payload,
                      pending.upserts,
                      pending.deletes,
                      pending.domain_generations};

  if (core.durable) {
    if (!core.store.has_value()) {
      return Error{ErrorCode::InternalInvariantViolated, "a durable session has no durable store"};
    }
    ByteWriter writer{core.limits.max_commit_payload_bytes};
    encode(writer, record);
    if (writer.overflowed()) {
      return Error{ErrorCode::PayloadTooLarge,
                   "the commit for this request does not fit in the configured commit payload limit"};
    }
    const auto& bytes = writer.bytes();
    const auto status = core.store->commit(FrameKind::Commit, next_generation.value(),
                                           std::span<const std::byte>{bytes.data(), bytes.size()});
    if (!status.ok()) {
      return status.error();
    }
  }

  // Deletes come first. A permitted rebind frees an identity by deleting the
  // fenced record and then inserts a fresh one under that same identity key, so
  // applying the upserts first would delete the new record.
  for (const auto& key : pending.deletes) {
    state.erase(key);
  }
  for (auto& upsert : pending.upserts) {
    state.apply(std::move(upsert));
  }
  state.generation = next_generation.value();
  core.sequence = next_sequence.value();

  if (pending.idempotency_key.has_value()) {
    const std::string key = std::string{pending.idempotency_key->value()};
    IdempotencyLedgerEntry entry{*pending.idempotency_key,
                                 pending.request_digest,
                                 next_sequence.value(),
                                 next_generation.value(),
                                 pending.operation,
                                 std::move(pending.primary_key),
                                 pending.primary_revision,
                                 std::move(pending.outcome_payload)};
    state.ledger.insert_or_assign(key, std::move(entry));
  }

  return MutationReceipt{pending.operation,
                         next_generation.value(),
                         next_sequence.value(),
                         pending.primary_revision,
                         pending.request_digest,
                         false};
}

Status replay_frames(RegistryCore& core) {
  if (!core.store.has_value()) {
    return Status::success();
  }
  RegistryState& state = core.state;
  const auto& frames = core.store->frames();
  if (frames.size() > core.limits.max_journal_frames) {
    return Status::failure(ErrorCode::LimitExceeded,
                           "the journal holds more committed frames than the configured limit");
  }

  if (frames.empty()) {
    return Status::success();
  }
  if (frames.front().sequence.is_initial() || frames.front().generation.is_initial()) {
    return Status::failure(ErrorCode::StoreCorrupt,
                           "the first committed frame has no sequence or no generation to follow");
  }
  // A compacted journal begins with a baseline at whatever sequence and
  // generation the state had reached, so the walk is anchored on the frame that
  // is present rather than on zero. The one-step rule is what is checked, and
  // it is checked for every frame.
  RegistryGeneration expected_generation =
      RegistryGeneration::from_value(frames.front().generation.value() - 1);
  JournalSequence expected_sequence = JournalSequence::from_value(frames.front().sequence.value() - 1);

  for (const auto& frame : frames) {
    const auto next_sequence = advance(expected_sequence);
    if (!next_sequence) {
      return Status::failure(next_sequence.error());
    }
    if (frame.sequence != next_sequence.value()) {
      return Status::failure(ErrorCode::StoreCorrupt,
                             "committed frame sequence " + std::to_string(frame.sequence.value()) +
                                 " does not follow sequence " + std::to_string(expected_sequence.value()));
    }
    expected_sequence = frame.sequence;

    const auto next_generation = advance(expected_generation);
    if (!next_generation) {
      return Status::failure(next_generation.error());
    }
    if (frame.generation != next_generation.value()) {
      return Status::failure(ErrorCode::StoreCorrupt,
                             "committed frame " + std::to_string(frame.sequence.value()) +
                                 " does not advance the generation by exactly one");
    }
    expected_generation = frame.generation;

    ByteReader reader{std::span<const std::byte>{frame.payload.data(), frame.payload.size()}};

    if (frame.kind == FrameKind::Baseline) {
      auto baseline = decode_baseline(reader, core.limits);
      if (!baseline) {
        return Status::failure(baseline.error());
      }
      if (!reader.require_end()) {
        return Status::failure(ErrorCode::StoreCorrupt, "a baseline frame has trailing bytes");
      }
      if (baseline.value().generation != frame.generation) {
        return Status::failure(ErrorCode::StoreCorrupt,
                               "a baseline frame states a generation that disagrees with its frame header");
      }
      state.reset();
      for (auto& tenant : baseline.value().tenants) {
        state.apply(AnyRecord{std::move(tenant)});
      }
      for (auto& service : baseline.value().services) {
        state.apply(AnyRecord{std::move(service)});
      }
      for (auto& domain : baseline.value().isolation_domains) {
        state.apply(AnyRecord{std::move(domain)});
      }
      for (auto& edge : baseline.value().ownership_edges) {
        state.apply(AnyRecord{std::move(edge)});
      }
      for (auto& binding : baseline.value().service_bindings) {
        state.apply(AnyRecord{std::move(binding)});
      }
      for (auto& membership : baseline.value().isolation_memberships) {
        state.apply(AnyRecord{std::move(membership)});
      }
      for (auto& tombstone : baseline.value().tombstones) {
        state.apply(AnyRecord{std::move(tombstone)});
      }
      for (auto& entry : baseline.value().ledger) {
        const std::string key = std::string{entry.key.value()};
        state.ledger.insert_or_assign(key, std::move(entry));
      }
      if (state.ledger.size() > core.limits.max_idempotency_entries) {
        return Status::failure(ErrorCode::LimitExceeded,
                               "the baseline carries an idempotency ledger larger than the configured limit");
      }
      state.generation = frame.generation;
      continue;
    }

    if (frame.kind != FrameKind::Commit) {
      return Status::failure(ErrorCode::StoreCorrupt, "a committed frame has a kind this build does not know");
    }

    auto commit = decode_commit(reader, core.limits);
    if (!commit) {
      return Status::failure(commit.error());
    }
    if (!reader.require_end()) {
      return Status::failure(ErrorCode::StoreCorrupt, "a commit frame has trailing bytes");
    }
    if (commit.value().generation != frame.generation || commit.value().sequence != frame.sequence) {
      return Status::failure(ErrorCode::StoreCorrupt,
                             "a commit frame disagrees with its own frame header about generation or sequence");
    }
    if (commit.value().control_epoch != frame.control_epoch ||
        commit.value().incarnation != frame.incarnation) {
      return Status::failure(ErrorCode::StoreCorrupt,
                             "a commit frame disagrees with its own frame header about the writer incarnation");
    }

    // A domain whose membership generation moved must also be present in the
    // same commit, so that the two can never drift apart.
    for (const auto& [domain_id, generation] : commit.value().domain_generations) {
      bool found = false;
      for (const auto& upsert : commit.value().upserts) {
        const auto* domain = std::get_if<IsolationDomainRecord>(&upsert);
        if (domain != nullptr && domain->id == domain_id) {
          if (domain->membership_generation != generation) {
            return Status::failure(ErrorCode::StoreCorrupt,
                                   "a commit states a domain membership generation its own upsert disagrees with");
          }
          found = true;
          break;
        }
      }
      if (!found) {
        return Status::failure(ErrorCode::StoreCorrupt,
                               "a commit advances a domain membership generation without upserting that domain");
      }
    }

    for (const auto& key : commit.value().deletes) {
      state.erase(key);
    }
    for (const auto& upsert : commit.value().upserts) {
      state.apply(upsert);
    }
    state.generation = frame.generation;

    if (commit.value().idempotency_key.has_value()) {
      if (state.ledger_full()) {
        return Status::failure(ErrorCode::LimitExceeded,
                               "replaying the journal would exceed the configured idempotency ledger limit");
      }
      const std::string key = std::string{commit.value().idempotency_key->value()};
      IdempotencyLedgerEntry entry{*commit.value().idempotency_key,
                                   commit.value().request_digest,
                                   commit.value().sequence,
                                   commit.value().generation,
                                   commit.value().operation,
                                   commit.value().primary_key,
                                   commit.value().primary_revision,
                                   commit.value().outcome_payload};
      state.ledger.insert_or_assign(key, std::move(entry));
    }
  }

  if (state.generation != expected_generation) {
    return Status::failure(ErrorCode::StoreCorrupt,
                           "the replayed state does not sit at the generation the journal reaches");
  }
  return Status::success();
}

}  // namespace detail

// ---------------------------------------------------------------------------
// Lifecycle of a session
// ---------------------------------------------------------------------------

TenantRegistry::TenantRegistry(std::unique_ptr<detail::RegistryCore> core) noexcept : core_(std::move(core)) {}

TenantRegistry::~TenantRegistry() = default;
TenantRegistry::TenantRegistry(TenantRegistry&& other) noexcept = default;
TenantRegistry& TenantRegistry::operator=(TenantRegistry&& other) noexcept = default;

Result<TenantRegistry> TenantRegistry::open(const RegistryOpenRequest& request) {
  std::string reason;
  if (!validate_limits(request.store.limits, reason)) {
    return Error{ErrorCode::InvalidArgument, "the configured limits are incoherent: " + reason};
  }
  if (request.mode != AccessMode::ReadOnly && request.mode != AccessMode::ReadWrite) {
    return Error{ErrorCode::InvalidArgument,
                 "the access mode must be explicitly ReadOnly or ReadWrite; an unspecified mode is refused rather "
                 "than defaulted"};
  }
  if (const auto root = store_layout::validate_store_root(request.root); !root.ok()) {
    return root.error();
  }

  auto clock = request.clock ? request.clock : std::make_shared<SystemClock>();
  auto core = std::make_unique<detail::RegistryCore>(request.store.limits, std::move(clock));
  core->mode = request.mode;
  core->durable = true;

  auto store = detail::DurableStore::open(request.root, request.mode, request.store);
  if (!store) {
    return store.error();
  }
  core->store.emplace(std::move(store).value());
  core->control_epoch = core->store->control_epoch();
  core->incarnation = core->store->incarnation();
  core->sequence = core->store->committed_sequence();
  core->report = core->store->recovery_report();

  const auto replayed = detail::replay_frames(*core);
  if (!replayed.ok()) {
    return replayed.error();
  }

  std::string detail;
  const auto validated = core->state.validate(detail);
  if (!validated.ok()) {
    return validated.error();
  }
  if (core->state.generation != core->store->committed_generation()) {
    return Error{ErrorCode::StoreCorrupt,
                 "the replayed state sits at generation " + std::to_string(core->state.generation.value()) +
                     " but the manifest commits generation " +
                     std::to_string(core->store->committed_generation().value())};
  }

  return TenantRegistry{std::move(core)};
}

Result<TenantRegistry> TenantRegistry::open_ephemeral(const EphemeralOptions& options) {
  std::string reason;
  if (!validate_limits(options.limits, reason)) {
    return Error{ErrorCode::InvalidArgument, "the configured limits are incoherent: " + reason};
  }
  auto clock = options.clock ? options.clock : std::make_shared<SystemClock>();
  auto core = std::make_unique<detail::RegistryCore>(options.limits, std::move(clock));
  core->mode = AccessMode::ReadWrite;
  core->durable = false;
  core->control_epoch = ControlEpoch::from_value(1);
  core->incarnation = Incarnation::from_value(1);
  core->sequence = JournalSequence::initial();
  core->report = StoreRecoveryReport{false,
                                     false,
                                     false,
                                 0,
                                 0,
                                 0,
                                 std::nullopt,
                                 core->control_epoch,
                                 core->incarnation,
                                 core->sequence,
                                 core->state.generation,
                                 false,
                                 {}};
  return TenantRegistry{std::move(core)};
}

bool TenantRegistry::valid() const noexcept { return core_ != nullptr && !core_->closed; }

RegistryGeneration TenantRegistry::generation() const { return core_->state.generation; }

ControlEpoch TenantRegistry::control_epoch() const { return core_->control_epoch; }

Incarnation TenantRegistry::incarnation() const { return core_->incarnation; }

AccessMode TenantRegistry::access_mode() const { return core_->mode; }

bool TenantRegistry::durable() const { return core_->durable; }

std::optional<StoreIdentity> TenantRegistry::store_identity() const {
  if (!core_->store.has_value()) {
    return std::nullopt;
  }
  return core_->store->identity();
}

JournalSequence TenantRegistry::committed_sequence() const { return core_->sequence; }

const RegistryLimits& TenantRegistry::limits() const { return core_->limits; }

StoreRecoveryReport TenantRegistry::recovery_report() const { return core_->report; }

Status TenantRegistry::flush() {
  if (core_ == nullptr) {
    return Status::failure(ErrorCode::StoreClosed, "this registry session has been moved from");
  }
  auto guard = core_->lock();
  if (const auto writable = detail::ensure_writable(*core_); !writable.ok()) {
    return writable;
  }
  // Every accepted mutation is flushed, read back, verified and published
  // before it is acknowledged, so there is nothing left to flush. This exists
  // so that a caller can say what it means, and it refuses on a session that
  // cannot write rather than silently succeeding.
  return Status::success();
}

Status TenantRegistry::close() {
  if (core_ == nullptr) {
    return Status::success();
  }
  auto guard = core_->lock();
  if (core_->closed) {
    return Status::success();
  }
  core_->closed = true;
  if (core_->store.has_value()) {
    const auto status = core_->store->close();
    if (!status.ok()) {
      return status;
    }
  }
  return Status::success();
}

}  // namespace tenant_registry
