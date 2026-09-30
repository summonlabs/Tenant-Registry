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

#ifndef TENANT_REGISTRY_SRC_DURABLE_STORE_HPP
#define TENANT_REGISTRY_SRC_DURABLE_STORE_HPP

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "file_lock.hpp"
#include "file_ops.hpp"
#include "tenant_registry/errors.hpp"
#include "tenant_registry/ids.hpp"
#include "tenant_registry/limits.hpp"
#include "tenant_registry/persistence.hpp"

namespace tenant_registry {
namespace detail {

/// The two frame kinds a journal can contain.
enum class FrameKind : std::uint16_t {
  Unspecified = 0,
  /// One committed mutation.
  Commit = 1,
  /// The whole state as of one generation. Written only by compaction.
  Baseline = 2,
};

[[nodiscard]] std::string_view to_token(FrameKind kind) noexcept;

/// One frame as it was read back from the journal during recovery.
struct JournalFrame {
  FrameKind kind = FrameKind::Unspecified;
  JournalSequence sequence;
  RegistryGeneration generation;
  ControlEpoch control_epoch;
  Incarnation incarnation;
  std::vector<std::byte> payload;
};

/// The durable store: a manifest, an append-only journal and a writer lock.
///
/// The manifest is the authority. It is a fixed size, checksummed image that is
/// replaced atomically; a frame is committed exactly when the manifest names
/// it. Everything the journal contains past the committed point was never
/// acknowledged to any caller and is dropped on the next write open.
///
/// Recovery chooses exactly one authoritative state or refuses. It never
/// guesses, never merges, and never starts empty when durable state exists: a
/// store whose manifest cannot be verified, whose frames do not form the
/// committed prefix, or whose chain head does not match produces StoreCorrupt
/// and no state at all.
class DurableStore {
 public:
  DurableStore() = default;
  ~DurableStore();

  DurableStore(DurableStore&& other) noexcept;
  DurableStore& operator=(DurableStore&& other) noexcept;
  DurableStore(const DurableStore&) = delete;
  DurableStore& operator=(const DurableStore&) = delete;

  /// Opens the store at root.
  ///
  /// A read-write open creates the store when it does not exist, takes the
  /// writer lock, recovers, and publishes a manifest whose control epoch is one
  /// past the one it found. Taking control therefore fences every authority
  /// issued by a previous writer, atomically with the publication that makes
  /// the new epoch authoritative.
  [[nodiscard]] static Result<DurableStore> open(const std::filesystem::path& root, AccessMode mode,
                                                 const StoreOptions& options);

  /// The committed frames, in sequence order, ready to be replayed.
  [[nodiscard]] const std::vector<JournalFrame>& frames() const noexcept { return frames_; }

  [[nodiscard]] const StoreRecoveryReport& recovery_report() const noexcept { return report_; }
  [[nodiscard]] const std::optional<StoreIdentity>& identity() const noexcept { return identity_; }
  [[nodiscard]] ControlEpoch control_epoch() const noexcept { return control_epoch_; }
  [[nodiscard]] Incarnation incarnation() const noexcept { return incarnation_; }
  [[nodiscard]] JournalSequence committed_sequence() const noexcept { return committed_sequence_; }
  [[nodiscard]] RegistryGeneration committed_generation() const noexcept { return committed_generation_; }
  [[nodiscard]] bool read_only() const noexcept { return mode_ == AccessMode::ReadOnly; }
  [[nodiscard]] bool closed() const noexcept { return closed_; }
  [[nodiscard]] const std::filesystem::path& root() const noexcept { return root_; }

  /// Appends one frame and publishes it. On success the frame is on the device
  /// and the manifest names it; on failure nothing observable changed.
  [[nodiscard]] Status commit(FrameKind kind, RegistryGeneration generation,
                              std::span<const std::byte> payload);

  /// Replaces the journal with one that begins with a baseline frame carrying
  /// the whole state, then publishes a manifest naming it. The previous journal
  /// stays intact until the new one has been flushed, verified and named.
  [[nodiscard]] Status rewrite_with_baseline(RegistryGeneration generation,
                                             std::span<const std::byte> payload);

  /// Releases the writer lock. Idempotent.
  [[nodiscard]] Status close();

 private:
  [[nodiscard]] Status append_and_publish(FrameKind kind, RegistryGeneration generation,
                                          std::span<const std::byte> payload);
  [[nodiscard]] Status publish_manifest(std::uint64_t journal_ordinal, JournalSequence sequence,
                                        RegistryGeneration generation, const ContentDigest& chain_head);

  std::filesystem::path root_;
  AccessMode mode_ = AccessMode::Unspecified;
  bool closed_ = true;

  FileLock lock_;
  std::optional<StoreIdentity> identity_;
  ControlEpoch control_epoch_;
  Incarnation incarnation_;
  JournalSequence committed_sequence_;
  RegistryGeneration committed_generation_;
  ContentDigest chain_head_;
  ContentDigest chain_seed_;
  JournalSequence chain_base_sequence_;
  std::uint64_t journal_ordinal_ = 1;
  std::uint64_t committed_end_ = 0;
  AppendFile journal_;
  StoreRecoveryReport report_;
  std::vector<JournalFrame> frames_;
  RegistryLimits limits_;
  PublishFaultHooks faults_;
};

}  // namespace detail
}  // namespace tenant_registry

#endif  // TENANT_REGISTRY_SRC_DURABLE_STORE_HPP
