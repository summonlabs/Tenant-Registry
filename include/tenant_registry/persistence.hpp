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

#ifndef TENANT_REGISTRY_PERSISTENCE_HPP
#define TENANT_REGISTRY_PERSISTENCE_HPP

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "tenant_registry/clock.hpp"
#include "tenant_registry/digest.hpp"
#include "tenant_registry/errors.hpp"
#include "tenant_registry/ids.hpp"
#include "tenant_registry/limits.hpp"

namespace tenant_registry {

/// Whether a session may change the store or only read it.
///
/// A read-only session never takes the writer lock, never publishes, and never
/// repairs. It reads the manifest and the frames the manifest names, and it
/// applies exactly the same integrity and rollback rules as a read-write open:
/// a read-only inspection of a store that a writer would refuse is itself
/// refused.
enum class AccessMode : std::uint8_t {
  Unspecified = 0,
  ReadOnly = 1,
  ReadWrite = 2,
};

[[nodiscard]] std::string_view to_token(AccessMode mode) noexcept;

/// The durable store layout.
///
/// The store is three files inside one directory:
///
///   tenant-registry.manifest  the authority. Fixed size, checksummed, replaced
///                             atomically. It names the active journal, the
///                             number of committed frames, the generation those
///                             frames reach, the chain head over them, and the
///                             control epoch and incarnation of the writer that
///                             last took control.
///   tenant-registry-<n>.journal
///                             an append-only sequence of frames. A frame is
///                             committed only when it is complete, flushed, and
///                             named by the manifest.
///   tenant-registry.lock      the writer lock. Held for the lifetime of a
///                             read-write session and released by the operating
///                             system if the process dies.
///
/// The commit point is the atomic replacement of the manifest. Everything
/// before it is staging; nothing after it is ever observed.
namespace store_layout {

inline constexpr std::string_view kManifestFileName = "tenant-registry.manifest";
inline constexpr std::string_view kLockFileName = "tenant-registry.lock";
inline constexpr std::string_view kJournalStem = "tenant-registry-";
inline constexpr std::string_view kJournalSuffix = ".journal";

/// The exact byte length of a manifest image.
inline constexpr std::uint64_t kManifestImageBytes = 256;

/// The exact byte length of a frame header.
inline constexpr std::uint64_t kFrameHeaderBytes = 88;

/// The exact byte length of the trailing completion marker of a frame.
inline constexpr std::uint64_t kFrameTrailerBytes = 4;

/// The name of the journal file that holds sequence numbers starting at
/// `ordinal`.
[[nodiscard]] std::string journal_file_name(std::uint64_t ordinal);

/// Parses a journal file name back to its ordinal. False when the name is not
/// exactly a journal name this layout could have produced.
[[nodiscard]] bool parse_journal_file_name(std::string_view name, std::uint64_t& ordinal) noexcept;

/// Rejects a caller supplied directory that cannot safely hold a store: it must
/// not be empty, must not be a reserved Windows device name, must not contain a
/// traversal component, and must not already exist as a file.
[[nodiscard]] Status validate_store_root(const std::filesystem::path& root);

}  // namespace store_layout

/// The identity of one durable store. It is minted when the store is created
/// and never changes, so a caller can pin it and refuse to be pointed at a
/// different store than the one it meant.
struct StoreIdentity {
  ContentDigest id;
  /// The file name of the journal the manifest currently names. A file name
  /// only: it never contains a separator and is never joined with untrusted
  /// text.
  std::string journal_name;
};

/// The stages of the commit protocol, in order.
///
/// Each stage is a place a process can die. The crash consistency claim of this
/// repository is exactly: dying at any of these stages leaves a store that
/// reopens to either the state before the commit or the state after it, and
/// never to anything in between.
enum class PublishStage : std::uint8_t {
  Unspecified = 0,
  /// After the new state has been computed, before a byte is written.
  BeforeJournalAppend = 1,
  /// After the frame bytes have been written, before they are flushed.
  AfterJournalAppendBeforeFlush = 2,
  /// After the frame has been flushed to the device.
  AfterJournalFlush = 3,
  /// After the frame has been read back from the device and verified.
  AfterReadBackVerify = 4,
  /// After the manifest image has been staged and flushed, before it replaces
  /// the live manifest.
  BeforeManifestPublish = 5,
  /// After the manifest has been atomically replaced.
  AfterManifestPublish = 6,
};

[[nodiscard]] std::string_view to_token(PublishStage stage) noexcept;
[[nodiscard]] bool parse_publish_stage(std::string_view token, PublishStage& out) noexcept;

/// Instrumentation that is invoked at each commit stage.
///
/// This exists so that crash consistency and partial write behaviour can be
/// proved against real processes rather than argued about. It is test-only
/// equipment: the callback is invoked *while the writer mutex is held*, so it
/// must not call back into the registry, must not throw, and must not block on
/// anything the registry owns. Leaving the callback unset -- which is what
/// every production caller does -- costs one empty std::function check per
/// stage.
///
/// Invoking it with a hook that terminates the process is the supported way to
/// produce a real abrupt death at a real commit stage.
struct PublishFaultHooks {
  std::function<void(PublishStage)> at_stage;

  [[nodiscard]] bool active() const noexcept { return static_cast<bool>(at_stage); }
  void fire(PublishStage stage) const {
    if (at_stage) {
      at_stage(stage);
    }
  }
};

/// Options that describe where durable state lives and how it is treated.
struct StoreOptions {
  RegistryLimits limits;

  PublishFaultHooks faults;

  /// Rollback protection. When set, opening refuses with StoreRolledBack when
  /// the store's committed generation is below this value.
  std::optional<RegistryGeneration> min_committed_generation;

  /// Store pinning. When set, opening refuses with StoreIdentityMismatch when
  /// the store was created with a different identity.
  std::optional<ContentDigest> expected_store_id;

  /// A short note recorded in the writer lock file, so an operator can see who
  /// holds a store. It is evidence for an operator, never an authority.
  std::string holder_note;
};

/// What recovering the store actually did. This is reported rather than
/// assumed, so a caller can tell a clean open from a repaired one.
struct StoreRecoveryReport {
  bool store_created = false;
  bool manifest_present = false;
  /// True when complete but unpublished frames were found past the committed
  /// point and dropped. Their effects were never acknowledged to any caller.
  bool uncommitted_tail_discarded = false;
  std::uint64_t uncommitted_bytes_discarded = 0;
  std::uint64_t frames_replayed = 0;
  std::uint64_t baseline_frames = 0;
  /// The control epoch the store carried before this session took control.
  /// Absent for a store that did not exist yet.
  std::optional<ControlEpoch> previous_control_epoch;
  /// The control epoch this session holds.
  ControlEpoch control_epoch;
  Incarnation incarnation;
  JournalSequence committed_sequence;
  RegistryGeneration committed_generation;
  bool read_only = false;
  /// Anything the recovery had to decide, stated in the order it decided it.
  std::vector<std::string> notes;
};

/// Everything needed to open a durable registry.
struct RegistryOpenRequest {
  std::filesystem::path root;
  AccessMode mode = AccessMode::ReadWrite;
  StoreOptions store;
  /// Unset uses the system clock. The clock is recorded as evidence and never
  /// decides authority.
  std::shared_ptr<Clock> clock;
};

/// Everything needed to open a registry that has no durable state at all.
struct EphemeralOptions {
  RegistryLimits limits;
  std::shared_ptr<Clock> clock;
};

}  // namespace tenant_registry

#endif  // TENANT_REGISTRY_PERSISTENCE_HPP
