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

#ifndef TENANT_REGISTRY_SRC_REGISTRY_INTERNAL_HPP
#define TENANT_REGISTRY_SRC_REGISTRY_INTERNAL_HPP

#include <cstddef>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "canonical_codec.hpp"
#include "durable_store.hpp"
#include "registry_state.hpp"
#include "tenant_registry/clock.hpp"
#include "tenant_registry/errors.hpp"
#include "tenant_registry/ids.hpp"
#include "tenant_registry/persistence.hpp"
#include "tenant_registry/query.hpp"
#include "tenant_registry/records.hpp"
#include "tenant_registry/requests.hpp"
#include "tenant_registry/snapshot.hpp"

namespace tenant_registry {
namespace detail {

/// A mutation that has passed every check and is ready to be committed.
///
/// It is built completely before anything is written, so a rejection halfway
/// through building it cannot leave a half applied change anywhere: the only
/// place state changes is apply_commit, and apply_commit either does all of it
/// or none of it.
struct PendingCommit {
  OperationKind operation = OperationKind::Unspecified;
  RequestDigest request_digest;
  std::optional<IdempotencyKey> idempotency_key;
  std::string primary_key;
  RecordRevision primary_revision;
  std::vector<AnyRecord> upserts;
  std::vector<std::string> deletes;
  std::vector<std::pair<IsolationDomainId, DomainGeneration>> domain_generations;
  std::vector<std::byte> outcome_payload;
};

/// What the common preamble of a mutation decided.
struct ContextResolution {
  /// True when this exact request was already accepted and the answer is being
  /// replayed rather than recomputed.
  bool replay = false;
  /// The ledger entry that holds the original answer. It points into the live
  /// ledger and is valid for as long as the caller holds the core lock.
  const IdempotencyLedgerEntry* entry = nullptr;
  /// The original receipt. Meaningful only when replay is true.
  MutationReceipt receipt;
};

/// One registry instance: the authoritative state plus everything needed to
/// make a change to it durable.
///
/// The mutex is held for the whole of every operation, read or write. There is
/// one mutex and one acquisition per operation, so there is no upgrade path, no
/// nesting, no ordering between two locks, and no re-entrancy. Durable I/O
/// happens while it is held, deliberately: the commit point must be ordered
/// with the publication of the state it protects.
class RegistryCore {
 public:
  RegistryCore(RegistryLimits limits_in, std::shared_ptr<Clock> clock_in);
  ~RegistryCore();

  RegistryCore(const RegistryCore&) = delete;
  RegistryCore& operator=(const RegistryCore&) = delete;

  [[nodiscard]] std::unique_lock<std::mutex> lock() const { return std::unique_lock<std::mutex>{mutex_}; }

  RegistryLimits limits;
  std::shared_ptr<Clock> clock;
  RegistryState state;
  AccessMode mode = AccessMode::Unspecified;
  bool durable = false;
  std::optional<DurableStore> store;
  bool closed = false;
  JournalSequence sequence;
  ControlEpoch control_epoch;
  Incarnation incarnation;
  StoreRecoveryReport report;

 private:
  mutable std::mutex mutex_;
};

/// Refuses when the session cannot change anything. A closed session is closed
/// whatever its mode was, so StoreClosed takes precedence over StoreNotWritable.
[[nodiscard]] Status ensure_writable(const RegistryCore& core);

/// Validates an actor provenance record against the limits.
[[nodiscard]] Status check_provenance(const ProvenanceRecord& provenance, const RegistryLimits& limits);

/// Validates an optional text field and returns it unchanged.
[[nodiscard]] Result<std::optional<std::string>> check_optional_text(const std::optional<std::string>& value,
                                                                   std::size_t max_bytes, const char* what);

/// Resolves the idempotency question first and the staleness question second,
/// in that order, because a caller whose response was lost must be able to
/// retry a request that is now stale and still receive the answer it never saw.
[[nodiscard]] Result<ContextResolution> resolve_context(const RegistryCore& core, OperationKind operation,
                                                        RequestDigest digest,
                                                        const MutationContext& context);

/// Encodes one record as the outcome payload of a commit.
[[nodiscard]] std::vector<std::byte> outcome_of(const AnyRecord& record);

/// Decodes a ledger entry's outcome payload back into the record it holds.
[[nodiscard]] Result<AnyRecord> decode_outcome(const IdempotencyLedgerEntry& entry,
                                               const RegistryLimits& limits);

/// Applies a prepared commit.
///
/// The durable frame is written, flushed, read back and published before a
/// single field of the in-memory state changes. If any of that fails the
/// in-memory state is untouched and the caller sees the refusal, so a caller
/// can never be told that something happened when it did not, and can never be
/// told that nothing happened when it did.
[[nodiscard]] Result<MutationReceipt> apply_commit(RegistryCore& core, PendingCommit pending);

/// Replays every committed frame into the state. Refuses, rather than
/// installing a partial state, when a frame does not decode or when the state
/// it produces violates an invariant.
[[nodiscard]] Status replay_frames(RegistryCore& core);

/// Builds a snapshot of the state. The caller must already hold the core lock;
/// this never takes it, so it cannot deadlock against a caller that does.
[[nodiscard]] RegistrySnapshot build_snapshot(const RegistryCore& core);

/// True when the record is one of the three identity records.
[[nodiscard]] bool is_identity_any(const AnyRecord& record) noexcept;

/// The lifecycle state of any identity record.
[[nodiscard]] LifecycleState identity_state(const AnyRecord& record) noexcept;

/// The identity text of any identity record.
[[nodiscard]] std::string_view identity_value(const AnyRecord& record) noexcept;

/// The subject kind of any identity record. Unspecified for anything else.
[[nodiscard]] SubjectKind identity_kind(const AnyRecord& record) noexcept;

/// The revision of any record, whatever its kind.
[[nodiscard]] RecordRevision revision_of(const AnyRecord& record) noexcept;

/// True when the identity text is valid for this subject kind.
[[nodiscard]] Status check_identity_text(SubjectKind kind, std::string_view text);

}  // namespace detail
}  // namespace tenant_registry

#endif  // TENANT_REGISTRY_SRC_REGISTRY_INTERNAL_HPP
