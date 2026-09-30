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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "sha256.hpp"
#include "test_support.hpp"

namespace treg_test {
namespace {

using tenant_registry::AccessMode;
using tenant_registry::ErrorCode;
using tenant_registry::StoreRecoveryReport;

namespace layout = tenant_registry::store_layout;

// ---------------------------------------------------------------------------
// The frozen container layout.
//
// Every offset used below is the contract published in persistence.hpp. The
// sizes are checked against the public constants, so this file cannot drift
// away from the container it is testing without failing to compile.
// ---------------------------------------------------------------------------

constexpr std::size_t kFrameHeaderBytes = 88;
constexpr std::size_t kFrameTrailerBytes = 4;
/// Little endian u16 format version inside a frame header.
constexpr std::size_t kFrameVersionAt = 4;
/// Little endian u64 sequence number inside a frame header.
constexpr std::size_t kFrameSequenceAt = 8;
/// Reserved field, which must be zero.
constexpr std::size_t kFrameReservedAt = 40;
/// Little endian u32 payload length inside a frame header.
constexpr std::size_t kFramePayloadLengthAt = 44;
/// Header CRC-32 over the first 48 bytes of the frame header.
constexpr std::size_t kFrameHeaderChecksumAt = 48;
/// Payload CRC-32, payload SHA-256, and the payload itself.
constexpr std::size_t kFramePayloadChecksumAt = 52;
constexpr std::size_t kFramePayloadDigestAt = 56;
constexpr std::size_t kFramePayloadAt = 88;
constexpr std::size_t kFrameDigestBytes = 32;
/// Little endian u64 committed generation inside the manifest image.
constexpr std::size_t kManifestCommittedGenerationAt = 48;

static_assert(kFrameHeaderBytes == tenant_registry::store_layout::kFrameHeaderBytes,
              "the frame header size is part of the frozen container contract");
static_assert(kFrameTrailerBytes == tenant_registry::store_layout::kFrameTrailerBytes,
              "the frame trailer size is part of the frozen container contract");

// ---------------------------------------------------------------------------
// Bytes on disk
// ---------------------------------------------------------------------------

[[nodiscard]] std::vector<std::byte> read_bytes(const std::filesystem::path& path) {
  std::ifstream reader{path, std::ios::binary};
  if (!reader) {
    fail_now("could not open " + path.string() + " for reading");
  }
  const std::string contents{std::istreambuf_iterator<char>{reader}, std::istreambuf_iterator<char>{}};
  std::vector<std::byte> bytes;
  bytes.reserve(contents.size());
  for (const char character : contents) {
    bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(character)));
  }
  return bytes;
}

void write_bytes(const std::filesystem::path& path, std::span<const std::byte> bytes) {
  std::ofstream writer{path, std::ios::binary | std::ios::trunc};
  if (!writer) {
    fail_now("could not open " + path.string() + " for writing");
  }
  if (!bytes.empty()) {
    writer.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  }
  writer.flush();
  if (!writer) {
    fail_now("could not write " + path.string());
  }
}

[[nodiscard]] std::uint16_t read_u16(std::span<const std::byte> bytes, std::size_t at) {
  std::uint32_t value = 0;
  for (std::uint32_t index = 0; index < 2; ++index) {
    value |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[at + index])) << (8u * index);
  }
  return static_cast<std::uint16_t>(value);
}

[[nodiscard]] std::uint32_t read_u32(std::span<const std::byte> bytes, std::size_t at) {
  std::uint32_t value = 0;
  for (std::uint32_t index = 0; index < 4; ++index) {
    value |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[at + index])) << (8u * index);
  }
  return value;
}

[[nodiscard]] std::uint64_t read_u64(std::span<const std::byte> bytes, std::size_t at) {
  std::uint64_t value = 0;
  for (std::uint32_t index = 0; index < 8; ++index) {
    value |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(bytes[at + index])) << (8u * index);
  }
  return value;
}

void write_u64(std::span<std::byte> bytes, std::size_t at, std::uint64_t value) {
  for (std::uint32_t index = 0; index < 8; ++index) {
    bytes[at + index] = static_cast<std::byte>((value >> (8u * index)) & 0xFFu);
  }
}

// ---------------------------------------------------------------------------
// Store paths
// ---------------------------------------------------------------------------

[[nodiscard]] std::filesystem::path manifest_path(const std::filesystem::path& root) {
  return root / std::string{layout::kManifestFileName};
}

[[nodiscard]] std::vector<std::filesystem::path> journal_paths(const std::filesystem::path& root) {
  std::vector<std::filesystem::path> found;
  std::error_code error;
  for (const auto& entry : std::filesystem::directory_iterator{root, error}) {
    std::uint64_t ordinal = 0;
    if (layout::parse_journal_file_name(entry.path().filename().string(), ordinal)) {
      found.push_back(entry.path());
    }
  }
  return found;
}

/// The one journal the store holds. A store that has never been compacted twice
/// holds exactly one, and every test in this file works on such a store.
[[nodiscard]] std::filesystem::path the_journal(const std::filesystem::path& root) {
  const std::vector<std::filesystem::path> found = journal_paths(root);
  if (found.size() != 1) {
    fail_now("expected exactly one journal under " + root.string() + " but found " + std::to_string(found.size()));
  }
  return found.front();
}

// ---------------------------------------------------------------------------
// A directory that removes itself, including when a fatal TREG_REQUIRE aborts
// the test by throwing.
// ---------------------------------------------------------------------------

class TempDirectory {
 public:
  explicit TempDirectory(std::filesystem::path path) : path_(std::move(path)) {}
  ~TempDirectory() { remove_tree(path_); }

  TempDirectory(const TempDirectory&) = delete;
  TempDirectory& operator=(const TempDirectory&) = delete;

  [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

 private:
  std::filesystem::path path_;
};

// ---------------------------------------------------------------------------
// Opening
// ---------------------------------------------------------------------------

/// Attempts an open and hands the refusal back to the caller. A test that
/// expects a refusal must never go through Harness::durable, which fails the
/// test on a refusal instead of reporting its code.
[[nodiscard]] Result<TenantRegistry> open_store(const std::filesystem::path& root, bool read_only) {
  RegistryOpenRequest request;
  request.root = root;
  request.mode = read_only ? AccessMode::ReadOnly : AccessMode::ReadWrite;
  request.clock = std::make_shared<FixedClock>(1'700'000'000'000);
  return TenantRegistry::open(request);
}

// ---------------------------------------------------------------------------
// Comparing what is on disk, byte for byte
// ---------------------------------------------------------------------------

struct FileImage {
  std::string name;
  std::vector<std::byte> bytes;
};

using StoreImage = std::vector<FileImage>;

/// Every state file of the store, in name order.
///
/// The writer lock is deliberately not part of this image. It is evidence about
/// which process holds the store, it is rewritten by any read-write open that
/// reaches the point of taking control, and it is never authority over the
/// state. Everything else -- the manifest and the journals -- is state, and a
/// refused open must leave all of it exactly as it found it.
[[nodiscard]] StoreImage capture_store_image(const std::filesystem::path& root) {
  StoreImage image;
  std::error_code error;
  for (const auto& entry : std::filesystem::directory_iterator{root, error}) {
    if (!entry.is_regular_file(error)) {
      continue;
    }
    const std::string name = entry.path().filename().string();
    if (name == std::string{layout::kLockFileName}) {
      continue;
    }
    image.push_back(FileImage{name, read_bytes(entry.path())});
  }
  std::sort(image.begin(), image.end(),
            [](const FileImage& lhs, const FileImage& rhs) { return lhs.name < rhs.name; });
  return image;
}

/// The manifest within a store image. A journal name sorts before the manifest
/// name, so the manifest is never assumed to be the first file.
[[nodiscard]] const FileImage& manifest_image(const StoreImage& image) {
  for (const FileImage& file : image) {
    if (file.name == std::string{layout::kManifestFileName}) {
      return file;
    }
  }
  fail_now("the store image holds no manifest");
}

/// An empty string when the two images are identical, otherwise the first
/// difference found, named by file and offset.
[[nodiscard]] std::string image_difference(const StoreImage& expected, const StoreImage& actual) {
  if (expected.size() != actual.size()) {
    return "the store holds " + std::to_string(actual.size()) + " state files where " +
           std::to_string(expected.size()) + " were expected";
  }
  for (std::size_t index = 0; index < expected.size(); ++index) {
    if (expected[index].name != actual[index].name) {
      return "the state file " + actual[index].name + " is not the expected " + expected[index].name;
    }
    const std::vector<std::byte>& want = expected[index].bytes;
    const std::vector<std::byte>& have = actual[index].bytes;
    if (want == have) {
      continue;
    }
    const std::size_t common = want.size() < have.size() ? want.size() : have.size();
    for (std::size_t offset = 0; offset < common; ++offset) {
      if (want[offset] != have[offset]) {
        return "the bytes of " + expected[index].name + " differ at offset " + std::to_string(offset);
      }
    }
    return "the bytes of " + expected[index].name + " differ in length";
  }
  return {};
}

// ---------------------------------------------------------------------------
// Walking frames
// ---------------------------------------------------------------------------

/// The size of the frame that starts at offset, taken from its own header.
[[nodiscard]] std::size_t frame_total_bytes(std::span<const std::byte> journal, std::size_t offset) {
  const std::uint32_t payload = read_u32(journal, offset + kFramePayloadLengthAt);
  return kFrameHeaderBytes + static_cast<std::size_t>(payload) + kFrameTrailerBytes;
}

[[nodiscard]] bool bytes_are(std::span<const std::byte> journal, std::size_t at, std::string_view magic) {
  if (at + magic.size() > journal.size()) {
    return false;
  }
  for (std::size_t index = 0; index < magic.size(); ++index) {
    if (std::to_integer<char>(journal[at + index]) != magic[index]) {
      return false;
    }
  }
  return true;
}

/// True when the frame at offset satisfies, on its own, every check a frame has
/// to satisfy: magic, format version, reserved field, header checksum, payload
/// length, payload checksum, payload digest and completion trailer.
///
/// It exists so that a test which appends a frame past the commit point can
/// prove that the frame it appended is a complete frame rather than assume it.
[[nodiscard]] bool frame_verifies(std::span<const std::byte> journal, std::size_t offset) {
  if (offset + kFrameHeaderBytes + kFrameTrailerBytes > journal.size()) {
    return false;
  }
  if (!bytes_are(journal, offset, "TRFR")) {
    return false;
  }
  const std::span<const std::byte> header = journal.subspan(offset, kFrameHeaderBytes);
  if (read_u16(header, kFrameVersionAt) != tenant_registry::kStoreFormatVersion) {
    return false;
  }
  if (read_u32(header, kFrameReservedAt) != 0u) {
    return false;
  }
  if (tenant_registry::crc32(header.first(kFrameHeaderChecksumAt)) !=
      read_u32(header, kFrameHeaderChecksumAt)) {
    return false;
  }
  const std::uint32_t length = read_u32(header, kFramePayloadLengthAt);
  const std::size_t total = kFrameHeaderBytes + static_cast<std::size_t>(length) + kFrameTrailerBytes;
  if (offset + total > journal.size()) {
    return false;
  }
  const std::span<const std::byte> payload = journal.subspan(offset + kFramePayloadAt, length);
  if (tenant_registry::crc32(payload) != read_u32(header, kFramePayloadChecksumAt)) {
    return false;
  }
  const ContentDigest digest = tenant_registry::detail::sha256(payload);
  for (std::size_t index = 0; index < kFrameDigestBytes; ++index) {
    if (std::to_integer<std::uint8_t>(header[kFramePayloadDigestAt + index]) != digest.bytes()[index]) {
      return false;
    }
  }
  return bytes_are(journal, offset + kFrameHeaderBytes + static_cast<std::size_t>(length), "TREN");
}

/// The offset of the last complete frame in a journal.
[[nodiscard]] std::size_t last_frame_offset(std::span<const std::byte> journal) {
  std::size_t offset = 0;
  for (;;) {
    TREG_REQUIRE(journal.size() - offset >= kFrameHeaderBytes + kFrameTrailerBytes);
    const std::size_t total = frame_total_bytes(journal, offset);
    if (offset + total >= journal.size()) {
      return offset;
    }
    offset += total;
  }
}

// ---------------------------------------------------------------------------
// The known state every test in this file starts from
// ---------------------------------------------------------------------------

/// Performs the known mutations on an open session and reports how many
/// committed mutations that took.
///
/// Each helper call performs exactly one commit, except the active_ helpers,
/// which are a create followed by a lifecycle transition and so are two. The
/// count is cross-checked against the durable sequence and the generation
/// before this returns, so the frame count these tests compare against is a
/// fact about the store rather than a restatement of it.
[[nodiscard]] std::uint64_t seed_known_state(Harness& harness) {
  std::uint64_t mutations = 0;
  harness.active_tenant("acme");
  mutations += 2;  // create, then declare Active
  harness.active_tenant("beta");
  mutations += 2;
  const TenantRecord gamma = harness.create_tenant("gamma");  // declared and left declared
  mutations += 1;
  TREG_CHECK_EQ(gamma.state, LifecycleState::Declared);
  harness.active_service("renderer");
  mutations += 2;
  harness.active_domain("zone-a");
  mutations += 2;
  harness.bind("renderer", "acme");
  mutations += 1;
  harness.join(tenant_subject("acme"), "zone-a");
  mutations += 1;
  harness.own("beta", "acme");
  mutations += 1;
  TREG_REQUIRE(harness.registry().committed_sequence().value() == mutations);
  TREG_REQUIRE(harness.generation().value() == mutations);
  return mutations;
}

/// The seeded state, captured while the seeding session is still open.
///
/// The digest is RegistrySnapshot::digest(), which covers the tenancy state and
/// nothing else: two registries holding the same records at the same generation
/// share it across restarts and across stores. The control epoch, the
/// incarnation, the store identity and the journal position are deliberately
/// not part of it, which is exactly what makes it the right thing for a test
/// about whether recovery reached the right state.
struct Seeded {
  RegistryGeneration generation;
  ContentDigest digest;
  std::uint64_t mutations = 0;
  ControlEpoch epoch;
};

[[nodiscard]] Seeded seed_and_capture(const std::filesystem::path& root) {
  Harness harness = Harness::durable(root);
  Seeded seeded;
  seeded.mutations = seed_known_state(harness);
  seeded.generation = harness.generation();
  seeded.digest = harness.snapshot().digest();
  seeded.epoch = harness.registry().control_epoch();
  require_ok(harness.registry().close(), "close");
  return seeded;
}

}  // namespace

// ---------------------------------------------------------------------------
// 1. A clean reopen replays exactly the committed mutations, and says so.
// ---------------------------------------------------------------------------

TREG_TEST(recovery, a_clean_reopen_replays_exactly_the_committed_mutations) {
  const std::filesystem::path root = make_temp_directory("recovery-clean-reopen");
  const TempDirectory guard{root};

  const Seeded seeded = seed_and_capture(root);
  TREG_CHECK_EQ(seeded.mutations, std::uint64_t{12});

  auto opened = open_store(root, false);
  TREG_REQUIRE_OK(opened);
  TenantRegistry& registry = opened.value();

  const StoreRecoveryReport report = registry.recovery_report();
  TREG_CHECK_EQ(report.store_created, false);
  TREG_CHECK_EQ(report.manifest_present, true);
  TREG_CHECK_EQ(report.frames_replayed, seeded.mutations);
  TREG_CHECK_EQ(report.baseline_frames, std::uint64_t{0});
  TREG_CHECK_EQ(report.uncommitted_tail_discarded, false);
  TREG_CHECK_EQ(report.uncommitted_bytes_discarded, std::uint64_t{0});
  TREG_CHECK_EQ(report.read_only, false);
  TREG_REQUIRE(report.previous_control_epoch.has_value());
  TREG_CHECK_EQ(*report.previous_control_epoch, seeded.epoch);
  TREG_CHECK_EQ(report.committed_sequence.value(), seeded.mutations);
  TREG_CHECK_EQ(report.committed_generation, seeded.generation);

  // The state itself is exactly the state that was closed over.
  TREG_CHECK_EQ(registry.generation(), seeded.generation);
  TREG_CHECK_EQ(registry.committed_sequence().value(), seeded.mutations);
  TREG_CHECK_EQ(registry.snapshot().digest(), seeded.digest);
  TREG_CHECK_EQ(registry.find_tenant(tenant_id("acme")).value().state, LifecycleState::Active);

  // Taking control fences the previous writer, so the epoch this session holds
  // is ahead of the one the store carried.
  TREG_CHECK(registry.control_epoch() > seeded.epoch);
  require_ok(registry.close(), "close");
}

// ---------------------------------------------------------------------------
// 2. Compaction replaces the journal with a baseline that carries the same
//    state, and the frames committed on top of it replay on top of exactly
//    that state.
// ---------------------------------------------------------------------------

TREG_TEST(recovery, compaction_and_the_frames_on_top_of_it_replay_to_the_same_state) {
  const std::filesystem::path root = make_temp_directory("recovery-compaction");
  const TempDirectory guard{root};

  RegistryGeneration compacted_generation;
  ContentDigest compacted_digest;
  RegistryGeneration generation;
  ContentDigest digest;
  std::uint64_t seeded_mutations = 0;

  {
    Harness harness = Harness::durable(root);
    seeded_mutations = seed_known_state(harness);
    compacted_generation = harness.generation();
    compacted_digest = harness.snapshot().digest();
    const RecordRevision acme_revision = harness.tenant("acme").revision;

    require_ok(harness.registry().compact(), "compact");
    // Compaction must not change what the state is. A baseline that disagreed
    // with the state it replaced would be a silent rewrite of the registry.
    TREG_CHECK_EQ(harness.snapshot().digest(), compacted_digest);
    TREG_CHECK_EQ(harness.generation(), compacted_generation);
    TREG_CHECK_EQ(harness.tenant("acme").revision, acme_revision);
    require_ok(harness.registry().close(), "close");
  }

  {
    // The baseline alone replays to exactly the state that was compacted: the
    // same digest, the same generation, and nothing else replayed.
    Harness harness = Harness::durable(root);
    const StoreRecoveryReport report = harness.registry().recovery_report();
    TREG_CHECK_EQ(report.baseline_frames, std::uint64_t{1});
    TREG_CHECK_EQ(report.frames_replayed, std::uint64_t{1});
    TREG_CHECK_EQ(report.committed_sequence.value(), seeded_mutations + std::uint64_t{1});
    TREG_CHECK_EQ(harness.generation(), compacted_generation);
    TREG_CHECK_EQ(harness.snapshot().digest(), compacted_digest);
    TREG_CHECK_EQ(harness.tenant("acme").state, LifecycleState::Active);
    TREG_CHECK_EQ(harness.domain("zone-a").state, LifecycleState::Active);
    require_ok(harness.registry().close(), "close");
  }

  {
    // Three commits on top of the baseline: a create, then a create and a
    // transition. They are the frames the baseline has to be replayed under.
    Harness harness = Harness::durable(root);
    const TenantRecord after_compaction = harness.create_tenant("after-compaction");
    TREG_CHECK_EQ(after_compaction.state, LifecycleState::Declared);
    harness.active_tenant("delta");
    generation = harness.generation();
    digest = harness.snapshot().digest();
    TREG_CHECK_EQ(harness.registry().committed_sequence().value(), seeded_mutations + std::uint64_t{4});
    require_ok(harness.registry().close(), "close");
  }

  {
    Harness harness = Harness::durable(root);
    const StoreRecoveryReport report = harness.registry().recovery_report();
    // One baseline, then the three frames committed on top of it.
    TREG_CHECK_EQ(report.baseline_frames, std::uint64_t{1});
    TREG_CHECK_EQ(report.frames_replayed, std::uint64_t{4});
    TREG_CHECK_EQ(report.committed_sequence.value(), seeded_mutations + std::uint64_t{4});
    TREG_CHECK_EQ(report.uncommitted_tail_discarded, false);

    // The reopen reaches exactly the state the previous session was holding,
    // and that state still contains everything the state before compaction
    // contained, at the revisions it had.
    TREG_CHECK_EQ(harness.generation(), generation);
    TREG_CHECK_EQ(harness.snapshot().digest(), digest);
    TREG_CHECK(harness.generation() > compacted_generation);
    TREG_CHECK_EQ(harness.snapshot().tenants.size(), std::size_t{5});
    TREG_CHECK_EQ(harness.snapshot().services.size(), std::size_t{1});
    TREG_CHECK_EQ(harness.snapshot().ownership_edges.size(), std::size_t{1});
    TREG_CHECK_EQ(harness.snapshot().service_bindings.size(), std::size_t{1});
    TREG_CHECK_EQ(harness.snapshot().isolation_memberships.size(), std::size_t{1});
    require_ok(harness.registry().close(), "close");
  }
}

// ---------------------------------------------------------------------------
// 3. Bytes past the commit point are not state, and a store that carries them
//    still opens, still mutates and is still durable.
// ---------------------------------------------------------------------------

TREG_TEST(recovery, garbage_appended_past_the_commit_point_is_dropped_and_the_store_stays_usable) {
  const std::filesystem::path root = make_temp_directory("recovery-garbage");
  const TempDirectory guard{root};

  const Seeded seeded = seed_and_capture(root);
  const std::filesystem::path journal = the_journal(root);
  const std::uintmax_t committed_bytes = std::filesystem::file_size(journal);
  TREG_REQUIRE(committed_bytes > 0);

  const std::vector<std::byte> garbage{std::byte{'G'}, std::byte{'A'}, std::byte{'R'}, std::byte{'B'},
                                       std::byte{'A'}, std::byte{'G'}, std::byte{'E'}};
  std::vector<std::byte> bytes = read_bytes(journal);
  bytes.insert(bytes.end(), garbage.begin(), garbage.end());
  write_bytes(journal, bytes);
  TREG_REQUIRE(std::filesystem::file_size(journal) == committed_bytes + garbage.size());

  RegistryGeneration generation;
  ContentDigest digest;
  {
    Harness harness = Harness::durable(root);
    const StoreRecoveryReport report = harness.registry().recovery_report();
    TREG_CHECK_EQ(report.frames_replayed, seeded.mutations);
    TREG_CHECK_EQ(report.uncommitted_tail_discarded, true);
    TREG_CHECK_EQ(report.uncommitted_bytes_discarded, static_cast<std::uint64_t>(garbage.size()));
    TREG_CHECK_EQ(harness.generation(), seeded.generation);
    TREG_CHECK_EQ(harness.snapshot().digest(), seeded.digest);
    TREG_CHECK_EQ(harness.tenant("acme").state, LifecycleState::Active);
    TREG_CHECK_EQ(harness.snapshot().tenants.size(), std::size_t{3});

    // The unpublished bytes cannot be read back any more: they were removed
    // before this session appended anything to them.
    TREG_CHECK_EQ(std::filesystem::file_size(journal), committed_bytes);

    // A mutation made after the repair is durable.
    const TenantRecord after_garbage = harness.create_tenant("after-the-garbage");
    TREG_CHECK_EQ(after_garbage.state, LifecycleState::Declared);
    generation = harness.generation();
    digest = harness.snapshot().digest();
    require_ok(harness.registry().close(), "close");
  }

  {
    Harness harness = Harness::durable(root);
    TREG_CHECK_EQ(harness.generation(), generation);
    TREG_CHECK_EQ(harness.snapshot().digest(), digest);
    TREG_CHECK(harness.registry().find_tenant(tenant_id("after-the-garbage")).has_value());
    TREG_CHECK_EQ(harness.snapshot().tenants.size(), std::size_t{4});
    require_ok(harness.registry().close(), "close");
  }
}

// ---------------------------------------------------------------------------
// 4. Durable state that cannot be verified is refused, never restarted empty.
// ---------------------------------------------------------------------------

TREG_TEST(recovery, a_manifest_whose_journal_is_missing_is_refused_rather_than_opened_empty) {
  const std::filesystem::path root = make_temp_directory("recovery-missing-journal");
  const TempDirectory guard{root};

  const Seeded seeded = seed_and_capture(root);
  const std::filesystem::path journal = the_journal(root);

  std::error_code error;
  TREG_REQUIRE(std::filesystem::remove(journal, error));
  TREG_REQUIRE(!error);
  TREG_REQUIRE(!std::filesystem::exists(journal));

  const StoreImage corrupted = capture_store_image(root);
  TREG_CHECK_EQ(corrupted.size(), std::size_t{1});
  TREG_CHECK_EQ(manifest_image(corrupted).name, std::string{layout::kManifestFileName});

  // The manifest is present and names a journal that is gone. That is durable
  // state the reader cannot verify, so the open is refused rather than turned
  // into a new, empty store.
  auto opened = open_store(root, false);
  TREG_CHECK_CODE(opened, ErrorCode::StoreCorrupt);
  TREG_CHECK_EQ(opened.has_value(), false);

  // A read-only inspection refuses the same store with the same code.
  auto read_only = open_store(root, true);
  TREG_CHECK_CODE(read_only, ErrorCode::StoreCorrupt);

  // The refusal rewrote nothing and invented no journal to go with the
  // manifest, so the state is still exactly the state the deletion left.
  TREG_CHECK_EQ(image_difference(corrupted, capture_store_image(root)), std::string{});
  TREG_CHECK_EQ(journal_paths(root).size(), std::size_t{0});
  TREG_CHECK_EQ(std::filesystem::exists(manifest_path(root)), true);

  // A second attempt is refused in exactly the same way: the first refusal did
  // not quietly repair the store into something openable.
  auto again = open_store(root, false);
  TREG_CHECK_CODE(again, ErrorCode::StoreCorrupt);
  TREG_CHECK_EQ(image_difference(corrupted, capture_store_image(root)), std::string{});

  // The manifest still commits the generation the store reached, so the reader
  // did not replace it with one that describes an empty store.
  TREG_CHECK_EQ(read_u64(manifest_image(corrupted).bytes, kManifestCommittedGenerationAt),
                seeded.generation.value());
}

// ---------------------------------------------------------------------------
// 5. One frame fewer than the manifest commits is a rollback, and a rollback is
//    never silently accepted.
// ---------------------------------------------------------------------------

TREG_TEST(recovery, a_journal_one_frame_short_of_the_manifest_is_refused) {
  const std::filesystem::path root = make_temp_directory("recovery-short-journal");
  const TempDirectory guard{root};

  const Seeded seeded = seed_and_capture(root);
  const std::filesystem::path journal = the_journal(root);
  const std::vector<std::byte> bytes = read_bytes(journal);
  TREG_REQUIRE(bytes.size() > kFrameHeaderBytes + kFrameTrailerBytes);

  const std::size_t last = last_frame_offset(bytes);
  TREG_REQUIRE(last > 0);
  const std::size_t last_bytes = frame_total_bytes(bytes, last);
  TREG_REQUIRE(last + last_bytes == bytes.size());

  // The journal keeps exactly one frame fewer than the manifest commits.
  write_bytes(journal, std::span<const std::byte>{bytes.data(), last});
  TREG_CHECK_EQ(std::filesystem::file_size(journal), static_cast<std::uintmax_t>(last));

  const StoreImage corrupted = capture_store_image(root);
  auto opened = open_store(root, false);
  TREG_CHECK_CODE(opened, ErrorCode::StoreCorrupt);
  TREG_CHECK_EQ(opened.has_value(), false);

  auto read_only = open_store(root, true);
  TREG_CHECK_CODE(read_only, ErrorCode::StoreCorrupt);

  // Refusing the rollback did not rewrite the journal, and did not rewrite the
  // manifest into one that agrees with the shorter journal.
  TREG_CHECK_EQ(image_difference(corrupted, capture_store_image(root)), std::string{});
  TREG_CHECK_EQ(std::filesystem::file_size(journal), static_cast<std::uintmax_t>(last));
  TREG_CHECK_EQ(read_u64(manifest_image(corrupted).bytes, kManifestCommittedGenerationAt),
                seeded.generation.value());

  auto again = open_store(root, false);
  TREG_CHECK_CODE(again, ErrorCode::StoreCorrupt);
  TREG_CHECK_EQ(image_difference(corrupted, capture_store_image(root)), std::string{});
}

// ---------------------------------------------------------------------------
// 6. A complete, verified frame past the committed end is ignored: the manifest
//    is the commit point, not the end of the file.
// ---------------------------------------------------------------------------

TREG_TEST(recovery, a_complete_frame_past_the_commit_point_is_ignored) {
  const std::filesystem::path root = make_temp_directory("recovery-uncommitted-frame");
  const TempDirectory guard{root};

  const Seeded seeded = seed_and_capture(root);
  const std::filesystem::path journal = the_journal(root);
  const std::vector<std::byte> bytes = read_bytes(journal);
  TREG_REQUIRE(bytes.size() > kFrameHeaderBytes + kFrameTrailerBytes);

  const std::size_t last = last_frame_offset(bytes);
  const std::size_t last_bytes = frame_total_bytes(bytes, last);
  TREG_REQUIRE(last + last_bytes == bytes.size());

  // The next frame a commit would have written: the last published frame with
  // its sequence advanced and its header checksum repaired, so the frame
  // verifies completely. It was never published, so it is not state.
  std::vector<std::byte> uncommitted{bytes.begin() + static_cast<std::ptrdiff_t>(last), bytes.end()};
  TREG_CHECK_EQ(uncommitted.size(), last_bytes);
  write_u64(uncommitted, kFrameSequenceAt, read_u64(bytes, last + kFrameSequenceAt) + 1);
  const std::uint32_t header_checksum =
      tenant_registry::crc32(std::span<const std::byte>{uncommitted.data(), kFrameHeaderChecksumAt});
  uncommitted[kFrameHeaderChecksumAt + 0] = static_cast<std::byte>(header_checksum & 0xFFu);
  uncommitted[kFrameHeaderChecksumAt + 1] = static_cast<std::byte>((header_checksum >> 8) & 0xFFu);
  uncommitted[kFrameHeaderChecksumAt + 2] = static_cast<std::byte>((header_checksum >> 16) & 0xFFu);
  uncommitted[kFrameHeaderChecksumAt + 3] = static_cast<std::byte>((header_checksum >> 24) & 0xFFu);

  // Every committed frame verifies, and so does the frame appended past the
  // commit point: what the reader has to ignore is a complete frame, not a
  // damaged one.
  for (std::size_t offset = 0; offset < bytes.size();) {
    TREG_REQUIRE(frame_verifies(bytes, offset));
    offset += frame_total_bytes(bytes, offset);
  }
  TREG_REQUIRE(frame_verifies(uncommitted, 0));

  std::vector<std::byte> extended = bytes;
  extended.insert(extended.end(), uncommitted.begin(), uncommitted.end());
  write_bytes(journal, extended);
  const StoreImage with_uncommitted = capture_store_image(root);

  // A read-only inspection sees the committed state and changes nothing: it may
  // not even drop the bytes it is ignoring.
  {
    auto opened = open_store(root, true);
    TREG_REQUIRE_OK(opened);
    TenantRegistry& registry = opened.value();
    const StoreRecoveryReport report = registry.recovery_report();
    TREG_CHECK_EQ(report.read_only, true);
    TREG_CHECK_EQ(report.frames_replayed, seeded.mutations);
    TREG_CHECK_EQ(report.uncommitted_tail_discarded, true);
    TREG_CHECK_EQ(report.uncommitted_bytes_discarded, static_cast<std::uint64_t>(uncommitted.size()));
    TREG_CHECK_EQ(registry.generation(), seeded.generation);
    TREG_CHECK_EQ(registry.snapshot().digest(), seeded.digest);
  }
  TREG_CHECK_EQ(image_difference(with_uncommitted, capture_store_image(root)), std::string{});

  // A read-write open reaches the same state and discards the unpublished tail.
  {
    auto opened = open_store(root, false);
    TREG_REQUIRE_OK(opened);
    TenantRegistry& registry = opened.value();
    const StoreRecoveryReport report = registry.recovery_report();
    TREG_CHECK_EQ(report.frames_replayed, seeded.mutations);
    TREG_CHECK_EQ(report.uncommitted_tail_discarded, true);
    TREG_CHECK_EQ(report.uncommitted_bytes_discarded, static_cast<std::uint64_t>(uncommitted.size()));
    TREG_CHECK_EQ(registry.generation(), seeded.generation);
    TREG_CHECK_EQ(registry.snapshot().digest(), seeded.digest);
    TREG_CHECK_EQ(registry.snapshot().tenants.size(), std::size_t{3});
    require_ok(registry.close(), "close");
  }
  TREG_CHECK_EQ(std::filesystem::file_size(journal), static_cast<std::uintmax_t>(last + last_bytes));
}

}  // namespace treg_test
