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

namespace layout = tenant_registry::store_layout;

// ---------------------------------------------------------------------------
// The frozen container layout.
//
// Every offset below is the contract published in persistence.hpp. The sizes
// are checked against the public constants, so this file cannot drift away from
// the container it is testing without failing to compile.
// ---------------------------------------------------------------------------

constexpr std::size_t kManifestByteCount = 256;
constexpr std::size_t kManifestMagicAt = 0;
constexpr std::size_t kManifestVersionAt = 4;
constexpr std::size_t kManifestReservedAt = 6;
constexpr std::size_t kManifestSequenceAt = 40;
constexpr std::size_t kManifestChainHeadAt = 56;
constexpr std::size_t kManifestNameLengthAt = 128;
constexpr std::size_t kManifestNameAt = 132;
constexpr std::size_t kManifestNameBytes = 120;
constexpr std::size_t kManifestChecksumAt = 252;
constexpr std::size_t kManifestChecksumCovered = 252;

constexpr std::size_t kFrameHeaderBytes = 88;
constexpr std::size_t kFrameTrailerBytes = 4;
constexpr std::size_t kFrameVersionAt = 4;
constexpr std::size_t kFrameGenerationAt = 16;
constexpr std::size_t kFrameReservedAt = 40;
constexpr std::size_t kFramePayloadLengthAt = 44;
/// Header CRC-32 over the first 48 bytes of the frame header.
constexpr std::size_t kFrameHeaderChecksumAt = 48;
constexpr std::size_t kFramePayloadChecksumAt = 52;
constexpr std::size_t kFramePayloadDigestAt = 56;
constexpr std::size_t kFramePayloadAt = 88;
constexpr std::size_t kFrameDigestBytes = 32;

static_assert(kManifestByteCount == tenant_registry::store_layout::kManifestImageBytes,
              "the manifest image size is part of the frozen container contract");
static_assert(kFrameHeaderBytes == tenant_registry::store_layout::kFrameHeaderBytes,
              "the frame header size is part of the frozen container contract");
static_assert(kFrameTrailerBytes == tenant_registry::store_layout::kFrameTrailerBytes,
              "the frame trailer size is part of the frozen container contract");

/// How far above the truth the committed sequence case raises the manifest's
/// committed sequence. It has to stay below RegistryLimits::max_journal_frames:
/// above that bound the store is refused as over its limit, which is a
/// different claim from "the committed prefix is not intact".
constexpr std::uint64_t kUnreachableSequenceDistance = 500'000;

/// The number of committed frames the known store holds.
constexpr std::uint64_t kKnownFrames = 12;

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

void write_u16(std::span<std::byte> bytes, std::size_t at, std::uint16_t value) {
  for (std::uint32_t index = 0; index < 2; ++index) {
    bytes[at + index] = static_cast<std::byte>((static_cast<std::uint32_t>(value) >> (8u * index)) & 0xFFu);
  }
}

void write_u32(std::span<std::byte> bytes, std::size_t at, std::uint32_t value) {
  for (std::uint32_t index = 0; index < 4; ++index) {
    bytes[at + index] = static_cast<std::byte>((value >> (8u * index)) & 0xFFu);
  }
}

void write_u64(std::span<std::byte> bytes, std::size_t at, std::uint64_t value) {
  for (std::uint32_t index = 0; index < 8; ++index) {
    bytes[at + index] = static_cast<std::byte>((value >> (8u * index)) & 0xFFu);
  }
}

// ---------------------------------------------------------------------------
// Checksums
//
// Repairing a checksum after editing a field is what turns a test of the
// checksum into a test of the validation behind it. The frame header CRC covers
// only the first 48 bytes of a frame header, so the payload CRC and the payload
// SHA-256 can be repaired without touching the header checksum, which is what
// case k needs.
// ---------------------------------------------------------------------------

void repair_manifest_checksum(std::vector<std::byte>& image) {
  TREG_REQUIRE(image.size() == kManifestByteCount);
  write_u32(image, kManifestChecksumAt,
            tenant_registry::crc32(std::span<const std::byte>{image.data(), kManifestChecksumCovered}));
}

void repair_frame_payload_checksums(std::vector<std::byte>& frame, std::size_t at) {
  const std::span<const std::byte> payload{frame.data() + at + kFramePayloadAt,
                                           read_u32(frame, at + kFramePayloadLengthAt)};
  write_u32(frame, at + kFramePayloadChecksumAt, tenant_registry::crc32(payload));
  const ContentDigest digest = tenant_registry::detail::sha256(payload);
  for (std::size_t index = 0; index < kFrameDigestBytes; ++index) {
    frame[at + kFramePayloadDigestAt + index] = static_cast<std::byte>(digest.bytes()[index]);
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

/// The one journal the known store holds.
[[nodiscard]] std::filesystem::path the_journal(const std::filesystem::path& root) {
  const std::vector<std::filesystem::path> found = journal_paths(root);
  if (found.size() != 1) {
    fail_now("expected exactly one journal under " + root.string() + " but found " + std::to_string(found.size()));
  }
  return found.front();
}

// ---------------------------------------------------------------------------
// Walking frames
// ---------------------------------------------------------------------------

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
/// Case j relies on the payload checksum catching a flipped payload byte, and
/// case k relies on the frame being complete and internally consistent after
/// the payload checksums have been repaired, so that the chain head is what
/// refuses it. This is how each case proves its own premise.
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

/// The names of the entries of a directory, sorted into one comparable string.
[[nodiscard]] std::string directory_entry_text(const std::filesystem::path& path) {
  std::vector<std::string> names;
  std::error_code error;
  for (const auto& entry : std::filesystem::directory_iterator{path, error}) {
    names.push_back(entry.path().filename().string());
  }
  std::sort(names.begin(), names.end());
  std::string text;
  for (const std::string& name : names) {
    text += name;
    text += ';';
  }
  return text;
}

// ---------------------------------------------------------------------------
// The known store every case is a copy of
// ---------------------------------------------------------------------------

/// Builds the store every corruption case is applied to: several tenants, a
/// service, a domain, a binding, a membership and an ownership edge, so that a
/// corruption can never be masked by an empty state.
struct KnownStore {
  std::filesystem::path root;
  std::uint64_t frames = 0;
  RegistryGeneration generation;
  ContentDigest digest;
};

[[nodiscard]] KnownStore build_known_store(const std::filesystem::path& root) {
  Harness harness = Harness::durable(root);
  std::uint64_t frames = 0;
  harness.active_tenant("acme");
  frames += 2;  // create, then declare Active
  harness.active_tenant("beta");
  frames += 2;
  const TenantRecord gamma = harness.create_tenant("gamma");  // declared and left declared
  frames += 1;
  TREG_CHECK_EQ(gamma.state, LifecycleState::Declared);
  harness.active_service("renderer");
  frames += 2;
  harness.active_domain("zone-a");
  frames += 2;
  harness.bind("renderer", "acme");
  frames += 1;
  harness.join(tenant_subject("acme"), "zone-a");
  frames += 1;
  harness.own("beta", "acme");
  frames += 1;
  TREG_REQUIRE(frames == kKnownFrames);
  TREG_REQUIRE(harness.registry().committed_sequence().value() == frames);
  TREG_REQUIRE(harness.generation().value() == frames);
  const KnownStore known{root, frames, harness.generation(), harness.snapshot().digest()};
  require_ok(harness.registry().close(), "close");
  return known;
}

/// Every file of the store copied byte for byte into a fresh directory.
void copy_store(const std::filesystem::path& source, const std::filesystem::path& destination) {
  std::error_code error;
  std::filesystem::create_directories(destination, error);
  if (error) {
    fail_now("could not create " + destination.string());
  }
  for (const auto& entry : std::filesystem::directory_iterator{source, error}) {
    std::error_code kind_error;
    if (!entry.is_regular_file(kind_error)) {
      continue;
    }
    std::error_code copy_error;
    std::filesystem::copy_file(entry.path(), destination / entry.path().filename(),
                               std::filesystem::copy_options::overwrite_existing, copy_error);
    if (copy_error) {
      fail_now("could not copy " + entry.path().string() + " into " + destination.string());
    }
  }
  if (error) {
    fail_now("could not list " + source.string());
  }
}

// ---------------------------------------------------------------------------
// The corruptions. Each one changes exactly one thing.
// ---------------------------------------------------------------------------

using Corruption = void (*)(const std::filesystem::path& store);

// -- the manifest ------------------------------------------------------------

void corrupt_manifest_magic(const std::filesystem::path& store) {
  std::vector<std::byte> image = read_bytes(manifest_path(store));
  TREG_REQUIRE(image.size() == kManifestByteCount);
  image[kManifestMagicAt] = std::byte{'X'};
  write_bytes(manifest_path(store), image);
}

void corrupt_manifest_truncated(const std::filesystem::path& store) {
  std::vector<std::byte> image = read_bytes(manifest_path(store));
  TREG_REQUIRE(image.size() == kManifestByteCount);
  image.resize(100);
  write_bytes(manifest_path(store), image);
}

void corrupt_manifest_zeroed(const std::filesystem::path& store) {
  const std::vector<std::byte> image(kManifestByteCount, std::byte{0});
  write_bytes(manifest_path(store), image);
}

void corrupt_manifest_version(const std::filesystem::path& store) {
  std::vector<std::byte> image = read_bytes(manifest_path(store));
  TREG_REQUIRE(image.size() == kManifestByteCount);
  write_u16(image, kManifestVersionAt, 99);
  repair_manifest_checksum(image);
  write_bytes(manifest_path(store), image);
}

void corrupt_manifest_reserved(const std::filesystem::path& store) {
  std::vector<std::byte> image = read_bytes(manifest_path(store));
  TREG_REQUIRE(image.size() == kManifestByteCount);
  write_u16(image, kManifestReservedAt, 7);
  repair_manifest_checksum(image);
  write_bytes(manifest_path(store), image);
}

void corrupt_manifest_sequence(const std::filesystem::path& store) {
  std::vector<std::byte> image = read_bytes(manifest_path(store));
  TREG_REQUIRE(image.size() == kManifestByteCount);
  write_u64(image, kManifestSequenceAt, read_u64(image, kManifestSequenceAt) + kUnreachableSequenceDistance);
  repair_manifest_checksum(image);
  write_bytes(manifest_path(store), image);
}

void corrupt_manifest_chain_head(const std::filesystem::path& store) {
  std::vector<std::byte> image = read_bytes(manifest_path(store));
  TREG_REQUIRE(image.size() == kManifestByteCount);
  image[kManifestChainHeadAt] ^= std::byte{0x5A};
  repair_manifest_checksum(image);
  write_bytes(manifest_path(store), image);
}

void corrupt_manifest_name_length(const std::filesystem::path& store) {
  std::vector<std::byte> image = read_bytes(manifest_path(store));
  TREG_REQUIRE(image.size() == kManifestByteCount);
  write_u32(image, kManifestNameLengthAt, 999);
  repair_manifest_checksum(image);
  write_bytes(manifest_path(store), image);
}

void corrupt_manifest_name_traversal(const std::filesystem::path& store) {
  constexpr std::string_view kEscape = "../escape.journal";
  std::vector<std::byte> image = read_bytes(manifest_path(store));
  TREG_REQUIRE(image.size() == kManifestByteCount);
  for (std::size_t index = 0; index < kManifestNameBytes; ++index) {
    image[kManifestNameAt + index] =
        index < kEscape.size() ? static_cast<std::byte>(kEscape[index]) : std::byte{0};
  }
  write_u32(image, kManifestNameLengthAt, static_cast<std::uint32_t>(kEscape.size()));
  repair_manifest_checksum(image);
  write_bytes(manifest_path(store), image);
}

void corrupt_manifest_removed(const std::filesystem::path& store) {
  std::error_code error;
  TREG_REQUIRE(std::filesystem::remove(manifest_path(store), error));
  TREG_REQUIRE(!error);
  TREG_REQUIRE(!std::filesystem::exists(manifest_path(store)));
}

// -- the journal -------------------------------------------------------------

void corrupt_first_frame_payload(const std::filesystem::path& store) {
  const std::filesystem::path journal = the_journal(store);
  std::vector<std::byte> bytes = read_bytes(journal);
  TREG_REQUIRE(bytes.size() > kFramePayloadAt + 1);
  TREG_REQUIRE(frame_verifies(bytes, 0));
  bytes[kFramePayloadAt + 1] ^= std::byte{0xFF};
  // The frame is now refused by its own payload checksum, before the chain head
  // is ever consulted.
  TREG_REQUIRE(!frame_verifies(bytes, 0));
  write_bytes(journal, bytes);
}

void corrupt_first_frame_payload_with_checksums_repaired(const std::filesystem::path& store) {
  const std::filesystem::path journal = the_journal(store);
  std::vector<std::byte> bytes = read_bytes(journal);
  TREG_REQUIRE(bytes.size() > kFramePayloadAt + 1);
  TREG_REQUIRE(frame_verifies(bytes, 0));
  bytes[kFramePayloadAt + 1] ^= std::byte{0xFF};
  const std::uint32_t header_checksum = read_u32(bytes, kFrameHeaderChecksumAt);
  repair_frame_payload_checksums(bytes, 0);
  // The frame is complete and internally consistent again, and the header
  // checksum never covered the payload checksums, so it is still the one the
  // frame was written with. What refuses this store is the chain head.
  TREG_REQUIRE(read_u32(bytes, kFrameHeaderChecksumAt) == header_checksum);
  TREG_REQUIRE(frame_verifies(bytes, 0));
  write_bytes(journal, bytes);
}

void corrupt_frame_header(const std::filesystem::path& store) {
  const std::filesystem::path journal = the_journal(store);
  std::vector<std::byte> bytes = read_bytes(journal);
  TREG_REQUIRE(bytes.size() > kFrameGenerationAt + 1);
  bytes[kFrameGenerationAt] ^= std::byte{0x01};
  write_bytes(journal, bytes);
}

void corrupt_last_frame_trailer_removed(const std::filesystem::path& store) {
  const std::filesystem::path journal = the_journal(store);
  std::vector<std::byte> bytes = read_bytes(journal);
  const std::size_t last = last_frame_offset(bytes);
  TREG_REQUIRE(last + frame_total_bytes(bytes, last) == bytes.size());
  bytes.resize(bytes.size() - kFrameTrailerBytes);
  write_bytes(journal, bytes);
}

void corrupt_last_frame_truncated(const std::filesystem::path& store) {
  const std::filesystem::path journal = the_journal(store);
  std::vector<std::byte> bytes = read_bytes(journal);
  const std::size_t last = last_frame_offset(bytes);
  const std::size_t total = frame_total_bytes(bytes, last);
  TREG_REQUIRE(last + total == bytes.size());
  TREG_REQUIRE(total / 2 > kFrameTrailerBytes);
  bytes.resize(last + total / 2);
  write_bytes(journal, bytes);
}

void corrupt_journal_prepended(const std::filesystem::path& store) {
  const std::filesystem::path journal = the_journal(store);
  const std::vector<std::byte> bytes = read_bytes(journal);
  std::vector<std::byte> prefixed{std::byte{'J'}, std::byte{'U'}, std::byte{'N'}, std::byte{'K'}};
  prefixed.insert(prefixed.end(), bytes.begin(), bytes.end());
  write_bytes(journal, prefixed);
}

void corrupt_journal_emptied(const std::filesystem::path& store) {
  write_bytes(the_journal(store), std::span<const std::byte>{});
}

// ---------------------------------------------------------------------------
// The sweep
// ---------------------------------------------------------------------------

/// One corruption, applied to a fresh copy of the known store.
struct CorruptionCase {
  std::string_view id;
  std::string_view what;
  ErrorCode expected;
  Corruption corrupt;
  /// True for the case whose damaged field is a path, where the test must also
  /// prove that nothing was created outside the store directory.
  bool escape_check;
};

[[nodiscard]] std::string case_name(const CorruptionCase& one) {
  return "case " + std::string{one.id} + " (" + std::string{one.what} + ")";
}

void expect_open_refused(const CorruptionCase& one, const std::filesystem::path& store, bool read_only,
                         const char* file, int line) {
  const std::string name = case_name(one);
  const std::string mode = read_only ? "read-only" : "read-write";
  auto opened = open_store(store, read_only);
  if (opened) {
    report_failure(file, line, name + ": the " + mode + " open succeeded instead of being refused with " +
                                    std::string{tenant_registry::to_token(one.expected)});
    return;
  }
  if (opened.error().code() != one.expected) {
    report_failure(file, line, name + ": the " + mode + " open was refused with " +
                                    std::string{tenant_registry::to_token(opened.error().code())} +
                                    " instead of " + std::string{tenant_registry::to_token(one.expected)} + ": " +
                                    opened.error().detail());
  }
}

/// Copies the known store into a fresh directory, applies exactly one
/// corruption, and proves that the store is refused with exactly the expected
/// code by a read-write open and by a read-only one, and that both refusals
/// left every corrupted byte exactly where the corruption put it.
void run_corruption_case(const KnownStore& known, const CorruptionCase& one, const char* file, int line) {
  const std::string name = case_name(one);
  const std::filesystem::path directory = make_temp_directory("corrupt-" + std::string{one.id});
  const TempDirectory guard{directory};
  const std::filesystem::path store = directory / "store";
  copy_store(known.root, store);

  const StoreImage copied = capture_store_image(store);
  const std::string copy_difference = image_difference(capture_store_image(known.root), copied);
  if (!copy_difference.empty()) {
    report_failure(file, line, name + ": the copy of the known store is not byte for byte identical: " + copy_difference);
    return;
  }

  // Control: the copy on its own is a healthy store holding exactly the known
  // state. Without this, a refusal could be blamed on the copy rather than on
  // the one corruption the case applies.
  {
    auto control = open_store(store, false);
    if (!control) {
      report_failure(file, line, name + ": the untouched copy of the known store was refused with " +
                                      std::string{tenant_registry::to_token(control.error().code())} + ": " +
                                      control.error().detail());
      return;
    }
    TenantRegistry& registry = control.value();
    if (registry.generation() != known.generation || registry.snapshot().digest() != known.digest ||
        registry.recovery_report().frames_replayed != known.frames) {
      report_failure(file, line, name + ": the untouched copy of the known store does not hold the known state");
      return;
    }
    const Status closed = registry.close();
    if (!closed.ok()) {
      report_failure(file, line, name + ": the control session could not be closed: " + closed.error().detail());
      return;
    }
  }

  const std::string outside_before = directory_entry_text(directory);
  const StoreImage intact = capture_store_image(store);
  one.corrupt(store);
  const StoreImage corrupted = capture_store_image(store);
  if (image_difference(intact, corrupted).empty()) {
    report_failure(file, line, name + ": the corruption changed nothing on disk, so the case proves nothing");
    return;
  }

  expect_open_refused(one, store, false, file, line);
  const std::string after_read_write = image_difference(corrupted, capture_store_image(store));
  if (!after_read_write.empty()) {
    report_failure(file, line, name + ": the refused read-write open rewrote the store: " + after_read_write);
    return;
  }

  // Read-only inspection obeys exactly the same integrity rules, and changes
  // even less: it does not take the writer lock at all.
  expect_open_refused(one, store, true, file, line);
  const std::string after_read_only = image_difference(corrupted, capture_store_image(store));
  if (!after_read_only.empty()) {
    report_failure(file, line, name + ": the refused read-only open rewrote the store: " + after_read_only);
    return;
  }

  if (one.escape_check) {
    const std::string outside_after = directory_entry_text(directory);
    if (outside_after != outside_before) {
      report_failure(file, line, name + ": the directory that holds the store holds " + outside_after +
                                      " where it held " + outside_before + " before the open");
    }
    if (std::filesystem::exists(directory / "escape.journal")) {
      report_failure(file, line, name + ": a journal was created outside the store directory");
    }
  }
}

}  // namespace

// ---------------------------------------------------------------------------
// a to i: the manifest is the authority, and a manifest that cannot be verified
// refuses the store.
// ---------------------------------------------------------------------------

TREG_TEST(corruption, a_corrupted_manifest_is_refused_case_by_case) {
  const std::filesystem::path base = make_temp_directory("corrupt-manifest-base");
  const TempDirectory guard{base};
  const KnownStore known = build_known_store(base);
  TREG_REQUIRE(known.frames == kKnownFrames);

  const CorruptionCase cases[] = {
      {"a", "a byte flipped in the manifest magic", ErrorCode::StoreCorrupt, corrupt_manifest_magic, false},
      {"b", "the manifest truncated to 100 bytes", ErrorCode::StoreCorrupt, corrupt_manifest_truncated, false},
      {"c", "the whole manifest zeroed", ErrorCode::StoreCorrupt, corrupt_manifest_zeroed, false},
      {"d", "the manifest format version set to 99 with the checksum repaired", ErrorCode::StoreFormatUnsupported,
       corrupt_manifest_version, false},
      {"e", "the manifest reserved field set to 7 with the checksum repaired", ErrorCode::StoreCorrupt,
       corrupt_manifest_reserved, false},
      {"f", "the committed sequence raised far above the truth with the checksum repaired", ErrorCode::StoreCorrupt,
       corrupt_manifest_sequence, false},
      {"g", "a byte flipped in the manifest chain head with the checksum repaired", ErrorCode::StoreCorrupt,
       corrupt_manifest_chain_head, false},
      {"h", "a journal name length of 999 with the checksum repaired", ErrorCode::StoreCorrupt,
       corrupt_manifest_name_length, false},
      {"i", "a journal name of ../escape.journal with the checksum repaired", ErrorCode::StoreCorrupt,
       corrupt_manifest_name_traversal, true},
  };
  for (const CorruptionCase& one : cases) {
    run_corruption_case(known, one, __FILE__, __LINE__);
  }
}

// ---------------------------------------------------------------------------
// j to p: a frame is believed only when it verifies completely, and the
// manifest -- not the end of the file -- decides where the committed prefix
// ends.
// ---------------------------------------------------------------------------

TREG_TEST(corruption, a_corrupted_frame_is_refused_case_by_case) {
  const std::filesystem::path base = make_temp_directory("corrupt-frame-base");
  const TempDirectory guard{base};
  const KnownStore known = build_known_store(base);
  TREG_REQUIRE(known.frames == kKnownFrames);

  const CorruptionCase cases[] = {
      {"j", "a byte flipped in the first committed frame's payload", ErrorCode::StoreCorrupt,
       corrupt_first_frame_payload, false},
      {"k", "the same payload byte flipped with the payload CRC and SHA-256 repaired", ErrorCode::StoreCorrupt,
       corrupt_first_frame_payload_with_checksums_repaired, false},
      {"l", "a byte flipped in a frame header", ErrorCode::StoreCorrupt, corrupt_frame_header, false},
      {"m", "the last committed frame's trailer removed", ErrorCode::StoreCorrupt,
       corrupt_last_frame_trailer_removed, false},
      {"n", "the journal truncated so the last committed frame is incomplete", ErrorCode::StoreCorrupt,
       corrupt_last_frame_truncated, false},
      {"o", "four bytes prepended to the journal", ErrorCode::StoreCorrupt, corrupt_journal_prepended, false},
      {"p", "the journal replaced with an empty file", ErrorCode::StoreCorrupt, corrupt_journal_emptied, false},
  };
  for (const CorruptionCase& one : cases) {
    run_corruption_case(known, one, __FILE__, __LINE__);
  }
}

// ---------------------------------------------------------------------------
// q: the manifest deleted while the journal is kept. Durable state that cannot
// be verified is refused, and it is never replaced by an empty store.
// ---------------------------------------------------------------------------

TREG_TEST(corruption, a_manifest_deleted_while_the_journal_remains_is_never_an_empty_open) {
  const std::filesystem::path base = make_temp_directory("corrupt-no-manifest-base");
  const TempDirectory base_guard{base};
  const KnownStore known = build_known_store(base);

  const std::filesystem::path directory = make_temp_directory("corrupt-q");
  const TempDirectory guard{directory};
  const std::filesystem::path store = directory / "store";
  copy_store(known.root, store);
  corrupt_manifest_removed(store);

  const StoreImage corrupted = capture_store_image(store);
  TREG_CHECK_EQ(corrupted.size(), std::size_t{1});

  auto opened = open_store(store, false);
  TREG_CHECK_CODE(opened, ErrorCode::StoreCorrupt);
  TREG_CHECK_EQ(opened.has_value(), false);
  TREG_CHECK_EQ(image_difference(corrupted, capture_store_image(store)), std::string{});

  // No manifest was invented and the journal is still the only durable state:
  // the reader did not start an empty store where a journal exists.
  TREG_CHECK_EQ(std::filesystem::exists(manifest_path(store)), false);
  TREG_CHECK_EQ(journal_paths(store).size(), std::size_t{1});
  TREG_CHECK(std::filesystem::file_size(journal_paths(store).front()) > std::uintmax_t{0});

  // Read-only inspection refuses the same store with the same code, and the
  // state is still exactly what the deletion left behind.
  auto read_only = open_store(store, true);
  TREG_CHECK_CODE(read_only, ErrorCode::StoreCorrupt);
  TREG_CHECK_EQ(image_difference(corrupted, capture_store_image(store)), std::string{});
  TREG_CHECK_EQ(std::filesystem::exists(manifest_path(store)), false);
  TREG_CHECK_EQ(journal_paths(store).size(), std::size_t{1});
}

}  // namespace treg_test
