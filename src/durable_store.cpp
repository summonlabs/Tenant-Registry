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

#include "durable_store.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "sha256.hpp"
#include "tenant_registry/version.hpp"

namespace tenant_registry {
namespace detail {

namespace {

// ---------------------------------------------------------------------------
// Layout. Every offset the durable container uses is named here and checked
// against the frozen contract in persistence.hpp, so a frame or a manifest is
// never addressed by a number nobody can trace.
// ---------------------------------------------------------------------------

constexpr std::size_t kManifestBytes = 256;
constexpr std::size_t kFrameHeaderBytes = 88;
constexpr std::size_t kFrameTrailerBytes = 4;
static_assert(kManifestBytes == store_layout::kManifestImageBytes, "the manifest image size is frozen");
static_assert(kFrameHeaderBytes == store_layout::kFrameHeaderBytes, "the frame header size is frozen");
static_assert(kFrameTrailerBytes == store_layout::kFrameTrailerBytes, "the frame trailer size is frozen");

constexpr std::size_t kManifestMagicAt = 0;
constexpr std::size_t kManifestVersionAt = 4;
constexpr std::size_t kManifestReservedAt = 6;
constexpr std::size_t kManifestStoreIdAt = 8;
constexpr std::size_t kManifestStoreIdBytes = 16;
constexpr std::size_t kManifestEpochAt = 24;
constexpr std::size_t kManifestIncarnationAt = 32;
constexpr std::size_t kManifestSequenceAt = 40;
constexpr std::size_t kManifestGenerationAt = 48;
constexpr std::size_t kManifestChainHeadAt = 56;
constexpr std::size_t kManifestBaseSequenceAt = 88;
constexpr std::size_t kManifestChainSeedAt = 96;
constexpr std::size_t kManifestNameLengthAt = 128;
constexpr std::size_t kManifestNameAt = 132;
constexpr std::size_t kManifestNameBytes = 120;
constexpr std::size_t kManifestChecksumAt = 252;
constexpr std::size_t kManifestChecksumCovered = 252;

constexpr std::size_t kFrameMagicAt = 0;
constexpr std::size_t kFrameVersionAt = 4;
constexpr std::size_t kFrameKindAt = 6;
constexpr std::size_t kFrameSequenceAt = 8;
constexpr std::size_t kFrameGenerationAt = 16;
constexpr std::size_t kFrameEpochAt = 24;
constexpr std::size_t kFrameIncarnationAt = 32;
constexpr std::size_t kFrameReservedAt = 40;
constexpr std::size_t kFramePayloadLengthAt = 44;
constexpr std::size_t kFrameHeaderChecksumAt = 48;
constexpr std::size_t kFramePayloadChecksumAt = 52;
constexpr std::size_t kFramePayloadDigestAt = 56;
constexpr std::size_t kFramePayloadAt = 88;
constexpr std::size_t kFrameDigestBytes = 32;

constexpr std::array<char, 4> kFrameMagic{'T', 'R', 'F', 'R'};
constexpr std::array<char, 4> kFrameTrailer{'T', 'R', 'E', 'N'};
constexpr std::array<char, 4> kManifestMagic{'T', 'R', 'M', 'F'};

/// The domain separated prefix of the chain seed of a genesis journal.
constexpr std::string_view kGenesisSeedPrefix = "tenant-registry/journal/v1/";

/// The transient file a manifest image is staged in. It deliberately does not
/// parse as a journal name, so the sweep can never confuse the two.
constexpr std::string_view kManifestStagingPrefix = ".tenant-registry-manifest.";
constexpr std::string_view kManifestStagingSuffix = ".staging";

/// How many entries a store root may hold before listing it is refused rather
/// than truncated.
constexpr std::size_t kMaxStoreDirectoryEntries = 4096;

/// How many components a store root path may have.
constexpr std::size_t kMaxStoreRootComponents = 256;

/// How much of a holder note is copied into the writer lock record.
constexpr std::size_t kMaxHolderNoteBytes = 200;

[[nodiscard]] bool path_is_directory(const std::filesystem::path& path) {
  return tenant_registry::detail::is_directory(path);
}

// ---------------------------------------------------------------------------
// Canonical little endian integers. Nothing in this file is ever encoded or
// decoded through its in-memory representation.
// ---------------------------------------------------------------------------

[[nodiscard]] std::uint16_t read_u16(const std::byte* bytes) noexcept {
  const std::uint32_t low = std::to_integer<std::uint8_t>(bytes[0]);
  const std::uint32_t high = std::to_integer<std::uint8_t>(bytes[1]);
  return static_cast<std::uint16_t>(low | (high << 8));
}

[[nodiscard]] std::uint32_t read_u32(const std::byte* bytes) noexcept {
  std::uint32_t value = 0;
  for (std::size_t index = 0; index < 4; ++index) {
    value |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[index])) << (8u * index);
  }
  return value;
}

[[nodiscard]] std::uint64_t read_u64(const std::byte* bytes) noexcept {
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < 8; ++index) {
    value |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(bytes[index])) << (8u * index);
  }
  return value;
}

void write_u16(std::byte* bytes, std::uint16_t value) noexcept {
  bytes[0] = static_cast<std::byte>(value & 0xFFu);
  bytes[1] = static_cast<std::byte>((value >> 8) & 0xFFu);
}

void write_u32(std::byte* bytes, std::uint32_t value) noexcept {
  for (std::size_t index = 0; index < 4; ++index) {
    bytes[index] = static_cast<std::byte>((value >> (8u * index)) & 0xFFu);
  }
}

void write_u64(std::byte* bytes, std::uint64_t value) noexcept {
  for (std::size_t index = 0; index < 8; ++index) {
    bytes[index] = static_cast<std::byte>((value >> (8u * index)) & 0xFFu);
  }
}

[[nodiscard]] bool has_magic(const std::byte* bytes, const std::array<char, 4>& magic) noexcept {
  for (std::size_t index = 0; index < magic.size(); ++index) {
    if (std::to_integer<char>(bytes[index]) != magic[index]) {
      return false;
    }
  }
  return true;
}

void put_magic(std::byte* bytes, const std::array<char, 4>& magic) noexcept {
  for (std::size_t index = 0; index < magic.size(); ++index) {
    bytes[index] = static_cast<std::byte>(magic[index]);
  }
}

// ---------------------------------------------------------------------------
// Digests and identities
// ---------------------------------------------------------------------------

[[nodiscard]] std::string hex_encode(std::span<const std::uint8_t> bytes) {
  constexpr char kDigits[] = "0123456789abcdef";
  std::string text;
  text.reserve(bytes.size() * 2);
  for (const std::uint8_t byte : bytes) {
    text.push_back(kDigits[byte >> 4]);
    text.push_back(kDigits[byte & 0x0Fu]);
  }
  return text;
}

/// The frozen digest interface has no constructor from raw bytes, so a digest
/// that was read out of a container is rebuilt through its canonical lower case
/// hexadecimal form, which is the one textual form it has.
[[nodiscard]] bool digest_from_raw(const std::byte* bytes, ContentDigest& out) {
  const std::span<const std::uint8_t> raw{reinterpret_cast<const std::uint8_t*>(bytes), kFrameDigestBytes};
  return ContentDigest::parse(hex_encode(raw), out);
}

/// A store id is 16 random bytes. It is carried in the first half of the 32 byte
/// digest the frozen interface offers, with the second half zero, so the
/// identity a creating session mints is the identity every later session reads.
[[nodiscard]] bool store_id_from_raw(const std::byte* bytes, ContentDigest& out) {
  std::array<std::uint8_t, 32> identity{};
  for (std::size_t index = 0; index < kManifestStoreIdBytes; ++index) {
    identity[index] = std::to_integer<std::uint8_t>(bytes[index]);
  }
  return ContentDigest::parse(hex_encode(identity), out);
}

[[nodiscard]] bool store_id_from_bytes(std::span<const std::uint8_t, kManifestStoreIdBytes> bytes,
                                       ContentDigest& out) {
  std::array<std::uint8_t, 32> identity{};
  for (std::size_t index = 0; index < bytes.size(); ++index) {
    identity[index] = bytes[index];
  }
  return ContentDigest::parse(hex_encode(identity), out);
}

[[nodiscard]] std::string store_id_hex(const ContentDigest& store_id) {
  return hex_encode(std::span<const std::uint8_t>{store_id.bytes().data(), kManifestStoreIdBytes});
}

[[nodiscard]] ContentDigest genesis_chain_seed(const ContentDigest& store_id) {
  std::string preimage{kGenesisSeedPrefix};
  preimage += store_id_hex(store_id);
  return sha256(preimage);
}

/// One step of the hash chain: the head before the frame, followed by the
/// complete frame bytes, hashed. A single pass over a journal therefore proves
/// its order, its length and its content.
[[nodiscard]] ContentDigest advance_chain(const ContentDigest& head, std::span<const std::byte> frame_bytes) {
  Sha256 hasher;
  hasher.update(std::as_bytes(std::span{head.bytes()}));
  hasher.update(frame_bytes);
  return hasher.finish();
}

[[nodiscard]] int hex_value(char digit) noexcept {
  if (digit >= '0' && digit <= '9') {
    return digit - '0';
  }
  if (digit >= 'a' && digit <= 'f') {
    return digit - 'a' + 10;
  }
  return -1;
}

[[nodiscard]] bool hex_decode(std::string_view text, std::span<std::uint8_t> out) noexcept {
  if (text.size() != out.size() * 2) {
    return false;
  }
  for (std::size_t index = 0; index < out.size(); ++index) {
    const int high = hex_value(text[index * 2]);
    const int low = hex_value(text[index * 2 + 1]);
    if (high < 0 || low < 0) {
      return false;
    }
    out[index] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return true;
}

[[nodiscard]] bool random_u64(std::uint64_t& out) {
  const std::string token = random_token();
  if (token.size() < 16) {
    return false;
  }
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < 16; ++index) {
    const int digit = hex_value(token[index]);
    if (digit < 0) {
      return false;
    }
    value = (value << 4) | static_cast<std::uint64_t>(digit);
  }
  out = value;
  return true;
}

/// A writer incarnation is never reused. It is minted from the random source and
/// is strictly greater than the one it replaces, so no later session can be
/// mistaken for an earlier one.
[[nodiscard]] std::uint64_t fresh_incarnation(std::uint64_t previous) {
  std::uint64_t minted = 0;
  const bool minted_ok = random_u64(minted);
  if (previous == std::numeric_limits<std::uint64_t>::max()) {
    if (minted_ok && minted != 0 && minted != previous) {
      return minted;
    }
    return 1;
  }
  const std::uint64_t successor = previous + 1;
  if (minted_ok && minted > successor) {
    return minted;
  }
  return successor;
}

// ---------------------------------------------------------------------------
// The writer lock record
// ---------------------------------------------------------------------------

[[nodiscard]] std::string lock_record_text(std::string_view holder_note) {
  const std::size_t length = holder_note.size() < kMaxHolderNoteBytes ? holder_note.size() : kMaxHolderNoteBytes;
  std::string note;
  note.reserve(length);
  for (std::size_t index = 0; index < length; ++index) {
    const char character = holder_note[index];
    const bool printable = character >= 0x20 && character <= 0x7E;
    note.push_back(printable ? character : '.');
  }
  if (note.empty()) {
    note = "unspecified";
  }
  const auto elapsed = std::chrono::system_clock::now().time_since_epoch();
  const std::int64_t milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
  std::string record = "tenant-registry writer; holder=";
  record += note;
  record += "; pid=";
  record += std::to_string(current_process_id());
  record += "; unix_ms=";
  record += std::to_string(milliseconds);
  return record;
}

// ---------------------------------------------------------------------------
// The manifest image
// ---------------------------------------------------------------------------

struct ManifestImage {
  ContentDigest store_id;
  ContentDigest chain_head;
  ContentDigest chain_seed;
  std::string journal_name;
  std::uint64_t journal_ordinal = 0;
  std::uint64_t control_epoch = 0;
  std::uint64_t incarnation = 0;
  std::uint64_t committed_sequence = 0;
  std::uint64_t committed_generation = 0;
  std::uint64_t chain_base_sequence = 0;
};

enum class ManifestVerdict {
  Ok,
  Corrupt,
  UnsupportedFormat,
};

void encode_manifest(const ManifestImage& image, std::span<std::byte> out) {
  std::fill(out.begin(), out.end(), std::byte{0});
  std::byte* bytes = out.data();
  put_magic(bytes + kManifestMagicAt, kManifestMagic);
  write_u16(bytes + kManifestVersionAt, kStoreFormatVersion);
  write_u16(bytes + kManifestReservedAt, 0u);
  for (std::size_t index = 0; index < kManifestStoreIdBytes; ++index) {
    bytes[kManifestStoreIdAt + index] = static_cast<std::byte>(image.store_id.bytes()[index]);
  }
  write_u64(bytes + kManifestEpochAt, image.control_epoch);
  write_u64(bytes + kManifestIncarnationAt, image.incarnation);
  write_u64(bytes + kManifestSequenceAt, image.committed_sequence);
  write_u64(bytes + kManifestGenerationAt, image.committed_generation);
  for (std::size_t index = 0; index < kFrameDigestBytes; ++index) {
    bytes[kManifestChainHeadAt + index] = static_cast<std::byte>(image.chain_head.bytes()[index]);
  }
  write_u64(bytes + kManifestBaseSequenceAt, image.chain_base_sequence);
  for (std::size_t index = 0; index < kFrameDigestBytes; ++index) {
    bytes[kManifestChainSeedAt + index] = static_cast<std::byte>(image.chain_seed.bytes()[index]);
  }
  write_u32(bytes + kManifestNameLengthAt, static_cast<std::uint32_t>(image.journal_name.size()));
  for (std::size_t index = 0; index < image.journal_name.size(); ++index) {
    bytes[kManifestNameAt + index] = static_cast<std::byte>(image.journal_name[index]);
  }
  write_u32(bytes + kManifestChecksumAt,
            crc32(std::span<const std::byte>{bytes, kManifestChecksumCovered}));
}

[[nodiscard]] ManifestVerdict decode_manifest(std::span<const std::byte> image, ManifestImage& out,
                                              std::string& reason) {
  if (image.size() != kManifestBytes) {
    reason = "the manifest is not exactly 256 bytes";
    return ManifestVerdict::Corrupt;
  }
  const std::byte* bytes = image.data();
  if (!has_magic(bytes + kManifestMagicAt, kManifestMagic)) {
    reason = "the manifest magic bytes are wrong";
    return ManifestVerdict::Corrupt;
  }
  const std::uint16_t version = read_u16(bytes + kManifestVersionAt);
  if (version != kStoreFormatVersion) {
    reason = "the manifest format version is not one this build can read";
    return ManifestVerdict::UnsupportedFormat;
  }
  if (read_u16(bytes + kManifestReservedAt) != 0u) {
    reason = "the manifest reserved field is not zero";
    return ManifestVerdict::Corrupt;
  }
  if (crc32(std::span<const std::byte>{bytes, kManifestChecksumCovered}) != read_u32(bytes + kManifestChecksumAt)) {
    reason = "the manifest checksum does not match its contents";
    return ManifestVerdict::Corrupt;
  }
  const std::uint32_t name_length = read_u32(bytes + kManifestNameLengthAt);
  if (name_length == 0u || static_cast<std::size_t>(name_length) > kManifestNameBytes) {
    reason = "the manifest journal name length is out of range";
    return ManifestVerdict::Corrupt;
  }
  for (std::size_t index = static_cast<std::size_t>(name_length); index < kManifestNameBytes; ++index) {
    if (std::to_integer<std::uint8_t>(bytes[kManifestNameAt + index]) != 0u) {
      reason = "the manifest journal name is not zero padded";
      return ManifestVerdict::Corrupt;
    }
  }
  const std::string_view name{reinterpret_cast<const char*>(bytes + kManifestNameAt),
                              static_cast<std::size_t>(name_length)};
  std::uint64_t ordinal = 0;
  if (!store_layout::parse_journal_file_name(name, ordinal)) {
    reason = "the manifest journal name is not a journal file name";
    return ManifestVerdict::Corrupt;
  }
  if (!store_id_from_raw(bytes + kManifestStoreIdAt, out.store_id) ||
      !digest_from_raw(bytes + kManifestChainHeadAt, out.chain_head) ||
      !digest_from_raw(bytes + kManifestChainSeedAt, out.chain_seed)) {
    reason = "the manifest holds a malformed digest field";
    return ManifestVerdict::Corrupt;
  }
  out.journal_ordinal = ordinal;
  out.journal_name.assign(name);
  out.control_epoch = read_u64(bytes + kManifestEpochAt);
  out.incarnation = read_u64(bytes + kManifestIncarnationAt);
  out.committed_sequence = read_u64(bytes + kManifestSequenceAt);
  out.committed_generation = read_u64(bytes + kManifestGenerationAt);
  out.chain_base_sequence = read_u64(bytes + kManifestBaseSequenceAt);
  return ManifestVerdict::Ok;
}

// ---------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------

struct FrameView {
  FrameKind kind = FrameKind::Unspecified;
  std::uint64_t sequence = 0;
  std::uint64_t generation = 0;
  std::uint64_t control_epoch = 0;
  std::uint64_t incarnation = 0;
  std::uint32_t payload_length = 0;
  std::size_t total_bytes = 0;
};

/// Verifies one complete frame that starts at offset. Every check the contract
/// names is made here and nowhere else, so a frame is only ever believed once:
/// magic, version, kind, reserved field, header checksum, payload length limit,
/// payload length, payload checksum, payload digest and completion trailer.
[[nodiscard]] bool verify_frame_at(std::span<const std::byte> image, std::size_t offset,
                                   const RegistryLimits& limits, FrameView& view, std::string& reason) {
  if (offset > image.size()) {
    reason = "the frame offset is outside the journal";
    return false;
  }
  const std::size_t available = image.size() - offset;
  if (available < kFrameHeaderBytes + kFrameTrailerBytes) {
    reason = "the frame header is not fully present";
    return false;
  }
  const std::byte* header = image.data() + offset;
  if (!has_magic(header + kFrameMagicAt, kFrameMagic)) {
    reason = "the frame magic bytes are wrong";
    return false;
  }
  if (read_u16(header + kFrameVersionAt) != kStoreFormatVersion) {
    reason = "the frame format version is not one this build can read";
    return false;
  }
  const std::uint16_t raw_kind = read_u16(header + kFrameKindAt);
  FrameKind kind = FrameKind::Unspecified;
  if (raw_kind == static_cast<std::uint16_t>(FrameKind::Commit)) {
    kind = FrameKind::Commit;
  } else if (raw_kind == static_cast<std::uint16_t>(FrameKind::Baseline)) {
    kind = FrameKind::Baseline;
  } else {
    reason = "the frame kind is not one this format defines";
    return false;
  }
  if (read_u32(header + kFrameReservedAt) != 0u) {
    reason = "the frame reserved field is not zero";
    return false;
  }
  if (crc32(std::span<const std::byte>{header, kFrameHeaderChecksumAt}) !=
      read_u32(header + kFrameHeaderChecksumAt)) {
    reason = "the frame header checksum does not match";
    return false;
  }
  const std::uint32_t payload_length = read_u32(header + kFramePayloadLengthAt);
  const std::uint64_t max_payload = kind == FrameKind::Baseline ? limits.max_baseline_payload_bytes
                                                                : limits.max_commit_payload_bytes;
  if (static_cast<std::uint64_t>(payload_length) > max_payload) {
    reason = "the frame payload is longer than the limit for its kind";
    return false;
  }
  const std::size_t total = kFrameHeaderBytes + static_cast<std::size_t>(payload_length) + kFrameTrailerBytes;
  if (available < total) {
    reason = "the frame is truncated";
    return false;
  }
  const std::span<const std::byte> payload{header + kFramePayloadAt, static_cast<std::size_t>(payload_length)};
  if (crc32(payload) != read_u32(header + kFramePayloadChecksumAt)) {
    reason = "the frame payload checksum does not match";
    return false;
  }
  ContentDigest stored;
  if (!digest_from_raw(header + kFramePayloadDigestAt, stored)) {
    reason = "the frame holds a malformed payload digest";
    return false;
  }
  if (sha256(payload) != stored) {
    reason = "the frame payload digest does not match";
    return false;
  }
  if (!has_magic(header + kFrameHeaderBytes + static_cast<std::size_t>(payload_length), kFrameTrailer)) {
    reason = "the frame completion trailer is missing";
    return false;
  }
  view.kind = kind;
  view.sequence = read_u64(header + kFrameSequenceAt);
  view.generation = read_u64(header + kFrameGenerationAt);
  view.control_epoch = read_u64(header + kFrameEpochAt);
  view.incarnation = read_u64(header + kFrameIncarnationAt);
  view.payload_length = payload_length;
  view.total_bytes = total;
  return true;
}

[[nodiscard]] std::vector<std::byte> encode_frame(FrameKind kind, JournalSequence sequence,
                                                  RegistryGeneration generation, ControlEpoch control_epoch,
                                                  Incarnation incarnation, std::span<const std::byte> payload) {
  const std::size_t total = kFrameHeaderBytes + payload.size() + kFrameTrailerBytes;
  std::vector<std::byte> frame(total, std::byte{0});
  std::byte* header = frame.data();
  put_magic(header + kFrameMagicAt, kFrameMagic);
  write_u16(header + kFrameVersionAt, kStoreFormatVersion);
  write_u16(header + kFrameKindAt, static_cast<std::uint16_t>(kind));
  write_u64(header + kFrameSequenceAt, sequence.value());
  write_u64(header + kFrameGenerationAt, generation.value());
  write_u64(header + kFrameEpochAt, control_epoch.value());
  write_u64(header + kFrameIncarnationAt, incarnation.value());
  write_u32(header + kFrameReservedAt, 0u);
  write_u32(header + kFramePayloadLengthAt, static_cast<std::uint32_t>(payload.size()));
  write_u32(header + kFrameHeaderChecksumAt, crc32(std::span<const std::byte>{header, kFrameHeaderChecksumAt}));
  write_u32(header + kFramePayloadChecksumAt, crc32(payload));
  const ContentDigest payload_digest = sha256(payload);
  for (std::size_t index = 0; index < kFrameDigestBytes; ++index) {
    header[kFramePayloadDigestAt + index] = static_cast<std::byte>(payload_digest.bytes()[index]);
  }
  if (!payload.empty()) {
    std::copy(payload.begin(), payload.end(), frame.begin() + static_cast<std::ptrdiff_t>(kFramePayloadAt));
  }
  put_magic(header + kFrameHeaderBytes + payload.size(), kFrameTrailer);
  return frame;
}

// ---------------------------------------------------------------------------
// Journal recovery
// ---------------------------------------------------------------------------

/// Verifies and decodes the committed prefix of a journal.
///
/// The scan walks frames from offset zero, verifying each one completely and
/// advancing the hash chain as it goes. It stops at the first frame that is not
/// fully present or does not verify: everything from there on was flushed by a
/// commit that never published, so it is not state. The committed prefix is the
/// prefix the manifest commits, and nothing else is ever believed.
[[nodiscard]] Status scan_journal(std::span<const std::byte> journal, const ManifestImage& manifest,
                                  const RegistryLimits& limits, std::vector<JournalFrame>& frames,
                                  std::uint64_t& committed_end, std::uint64_t& uncommitted_bytes,
                                  std::uint64_t& baseline_frames) {
  if (manifest.chain_base_sequence == std::numeric_limits<std::uint64_t>::max()) {
    return Status::failure(ErrorCode::StoreCorrupt, "the manifest chain base sequence cannot be followed by a frame");
  }
  if (manifest.committed_sequence < manifest.chain_base_sequence) {
    return Status::failure(ErrorCode::StoreCorrupt, "the committed sequence precedes the chain base sequence");
  }
  const std::uint64_t committed_frames = manifest.committed_sequence - manifest.chain_base_sequence;
  if (committed_frames > limits.max_journal_frames) {
    return Status::failure(ErrorCode::LimitExceeded,
                           "the manifest commits more frames than the journal frame limit allows");
  }

  ContentDigest head = manifest.chain_seed;
  ContentDigest committed_head = manifest.chain_seed;
  std::uint64_t verified = 0;
  std::uint64_t last_sequence = manifest.chain_base_sequence;
  std::size_t offset = 0;
  std::size_t committed_bytes = 0;

  while (offset < journal.size()) {
    if (verified >= limits.max_journal_frames) {
      return Status::failure(ErrorCode::LimitExceeded, "the journal holds more frames than the journal frame limit allows");
    }
    FrameView view;
    std::string reason;
    if (!verify_frame_at(journal, offset, limits, view, reason)) {
      break;
    }
    if (view.sequence != last_sequence + 1) {
      break;
    }
    if (verified < committed_frames) {
      JournalFrame record;
      record.kind = view.kind;
      record.sequence = JournalSequence::from_value(view.sequence);
      record.generation = RegistryGeneration::from_value(view.generation);
      record.control_epoch = ControlEpoch::from_value(view.control_epoch);
      record.incarnation = Incarnation::from_value(view.incarnation);
      const std::byte* payload = journal.data() + offset + kFramePayloadAt;
      record.payload.assign(payload, payload + view.payload_length);
      if (view.kind == FrameKind::Baseline) {
        ++baseline_frames;
      }
      frames.push_back(std::move(record));
    }
    head = advance_chain(head, journal.subspan(offset, view.total_bytes));
    ++verified;
    last_sequence = view.sequence;
    offset += view.total_bytes;
    if (verified == committed_frames) {
      committed_bytes = offset;
      committed_head = head;
    }
  }

  if (verified < committed_frames) {
    return Status::failure(ErrorCode::StoreCorrupt,
                           "the committed prefix of the journal is not intact: the manifest commits " +
                               std::to_string(committed_frames) + " frames and only " + std::to_string(verified) +
                               " verify");
  }
  // The manifest records the chain head over the committed prefix and nothing
  // else. When it commits no frame at all that head is the chain seed, which is
  // where the scan starts, so this one comparison covers a brand new store and a
  // commit that was flushed but never published alike. Frames past the committed
  // point are not state: they were never acknowledged to any caller, and a store
  // whose first commit died before publication reopens empty rather than
  // refusing, which is exactly the commit point guarantee.
  if (committed_head != manifest.chain_head) {
    return Status::failure(ErrorCode::StoreCorrupt,
                           "the chain head over the committed frames is not the chain head the manifest records");
  }
  if (journal.size() > committed_bytes) {
    uncommitted_bytes = static_cast<std::uint64_t>(journal.size() - committed_bytes);
  }
  committed_end = static_cast<std::uint64_t>(committed_bytes);
  return Status::success();
}

/// Puts the journal length back to the committed end. Bytes past it were never
/// published, so they are removed before anything is appended to them; a journal
/// that is shorter than its committed prefix has lost state and is refused.
[[nodiscard]] Status normalize_journal(AppendFile& journal, std::uint64_t committed_end) {
  const Result<std::uint64_t> size_now = journal.size();
  if (!size_now) {
    return Status::failure(size_now.error());
  }
  if (size_now.value() < committed_end) {
    return Status::failure(ErrorCode::StoreCorrupt, "the journal is shorter than its committed prefix");
  }
  if (size_now.value() > committed_end) {
    return journal.truncate(committed_end);
  }
  return Status::success();
}

/// True when the bytes read back are exactly the frame that was written and are
/// internally consistent as well.
[[nodiscard]] bool read_back_matches(std::span<const std::byte> readback, std::span<const std::byte> expected,
                                     const RegistryLimits& limits, std::string& reason) {
  if (readback.size() != expected.size()) {
    reason = "the frame read back has a different length";
    return false;
  }
  FrameView view;
  if (!verify_frame_at(readback, 0, limits, view, reason)) {
    return false;
  }
  if (view.total_bytes != readback.size()) {
    reason = "the frame read back has trailing bytes";
    return false;
  }
  if (!std::equal(readback.begin(), readback.end(), expected.begin())) {
    reason = "the frame read back differs from the frame written";
    return false;
  }
  return true;
}

/// Removes every file in the root that parses as a journal name and is not the
/// journal the manifest names. A journal that could not be removed is reported
/// and left for the next write open.
[[nodiscard]] Status sweep_old_journals(const std::filesystem::path& root, std::string_view current_name,
                                        StoreRecoveryReport& report) {
  const Result<std::vector<std::string>> names = list_directory_names(root, kMaxStoreDirectoryEntries);
  if (!names) {
    return Status::failure(names.error());
  }
  for (const std::string& name : names.value()) {
    std::uint64_t ordinal = 0;
    if (!store_layout::parse_journal_file_name(name, ordinal)) {
      continue;
    }
    if (name == current_name) {
      continue;
    }
    const std::filesystem::path stale = root / name;
    if (path_is_directory(stale)) {
      report.notes.push_back("a directory named " + name + " parses as a journal name and was left alone");
      continue;
    }
    const Status removed = remove_file(stale);
    if (!removed.ok()) {
      report.notes.push_back("the superseded journal " + name +
                             " could not be removed and will be swept again on the next write open");
    }
  }
  return Status::success();
}

// ---------------------------------------------------------------------------
// Store root validation
// ---------------------------------------------------------------------------

/// True when a path component is a name Windows resolves to a device rather
/// than to a file, including through a trailing extension or trailing dots and
/// spaces. The check is applied on every platform so that the same root is
/// accepted or refused everywhere.
[[nodiscard]] bool is_reserved_device_name(std::string_view component) noexcept {
  if (component.empty()) {
    return false;
  }
  const std::size_t dot = component.find('.');
  std::string_view base = dot == std::string_view::npos ? component : component.substr(0, dot);
  while (!base.empty() && (base.back() == ' ' || base.back() == '.')) {
    base.remove_suffix(1);
  }
  if (base.empty() || base.size() > 4) {
    return false;
  }
  char upper[4] = {'\0', '\0', '\0', '\0'};
  for (std::size_t index = 0; index < base.size(); ++index) {
    const char character = base[index];
    upper[index] = character >= 'a' && character <= 'z' ? static_cast<char>(character - 'a' + 'A') : character;
  }
  const std::string_view name{upper, base.size()};
  if (name == "CON" || name == "PRN" || name == "AUX" || name == "NUL") {
    return true;
  }
  if (name.size() == 4 && (name.compare(0, 3, "COM") == 0 || name.compare(0, 3, "LPT") == 0)) {
    return name[3] >= '1' && name[3] <= '9';
  }
  return false;
}

}  // namespace

// ---------------------------------------------------------------------------
// Frame kinds
// ---------------------------------------------------------------------------

std::string_view to_token(FrameKind kind) noexcept {
  switch (kind) {
    case FrameKind::Commit:
      return "commit";
    case FrameKind::Baseline:
      return "baseline";
    case FrameKind::Unspecified:
      return "unspecified";
  }
  return "unspecified";
}

// ---------------------------------------------------------------------------
// The durable store layout: the part that needs the shared helpers above.
// ---------------------------------------------------------------------------

Status validate_store_root_impl(const std::filesystem::path& root) {
  if (root.empty() || root.native().empty()) {
    return Status::failure(ErrorCode::StorePathRejected, "the store root path is empty");
  }
  std::size_t components = 0;
  for (const std::filesystem::path& component : root) {
    ++components;
    if (components > kMaxStoreRootComponents) {
      return Status::failure(ErrorCode::StorePathRejected,
                             "the store root path has more components than this build accepts");
    }
    const std::string name = to_utf8(component);
    if (name.empty()) {
      continue;
    }
    if (name == "." || name == "..") {
      return Status::failure(ErrorCode::StorePathRejected, "the store root path contains a traversal component");
    }
    if (is_reserved_device_name(name)) {
      return Status::failure(ErrorCode::StorePathRejected, "the store root path contains a reserved device name");
    }
  }
  if (path_exists(root) && !path_is_directory(root)) {
    return Status::failure(ErrorCode::StorePathRejected, "the store root exists and is not a directory");
  }
  return Status::success();
}

// ---------------------------------------------------------------------------
// Lifetime
// ---------------------------------------------------------------------------

DurableStore::~DurableStore() { (void)close(); }

DurableStore::DurableStore(DurableStore&& other) noexcept
    : root_(std::move(other.root_)),
      mode_(other.mode_),
      closed_(other.closed_),
      lock_(std::move(other.lock_)),
      identity_(std::move(other.identity_)),
      control_epoch_(other.control_epoch_),
      incarnation_(other.incarnation_),
      committed_sequence_(other.committed_sequence_),
      committed_generation_(other.committed_generation_),
      chain_head_(other.chain_head_),
      chain_seed_(other.chain_seed_),
      chain_base_sequence_(other.chain_base_sequence_),
      journal_ordinal_(other.journal_ordinal_),
      committed_end_(other.committed_end_),
      journal_(std::move(other.journal_)),
      report_(std::move(other.report_)),
      frames_(std::move(other.frames_)),
      limits_(other.limits_),
      faults_(std::move(other.faults_)) {
  other.closed_ = true;
}

DurableStore& DurableStore::operator=(DurableStore&& other) noexcept {
  if (this != &other) {
    (void)journal_.close();
    lock_.release();
    root_ = std::move(other.root_);
    mode_ = other.mode_;
    closed_ = other.closed_;
    lock_ = std::move(other.lock_);
    identity_ = std::move(other.identity_);
    control_epoch_ = other.control_epoch_;
    incarnation_ = other.incarnation_;
    committed_sequence_ = other.committed_sequence_;
    committed_generation_ = other.committed_generation_;
    chain_head_ = other.chain_head_;
    chain_seed_ = other.chain_seed_;
    chain_base_sequence_ = other.chain_base_sequence_;
    journal_ordinal_ = other.journal_ordinal_;
    committed_end_ = other.committed_end_;
    journal_ = std::move(other.journal_);
    report_ = std::move(other.report_);
    frames_ = std::move(other.frames_);
    limits_ = other.limits_;
    faults_ = std::move(other.faults_);
    other.closed_ = true;
  }
  return *this;
}

Status DurableStore::close() {
  if (closed_) {
    return Status::success();
  }
  const Status journal_closed = journal_.close();
  lock_.release();
  closed_ = true;
  if (!journal_closed.ok()) {
    return journal_closed;
  }
  return Status::success();
}

// ---------------------------------------------------------------------------
// Open and recovery
// ---------------------------------------------------------------------------

Result<DurableStore> DurableStore::open(const std::filesystem::path& root, AccessMode mode,
                                        const StoreOptions& options) {
  const Status root_status = store_layout::validate_store_root(root);
  if (!root_status.ok()) {
    return root_status.error();
  }
  const bool read_write = mode == AccessMode::ReadWrite;
  if (!read_write && mode != AccessMode::ReadOnly) {
    return make_error(ErrorCode::InvalidArgument, "the access mode must be ReadOnly or ReadWrite");
  }

  DurableStore store;
  store.root_ = root;
  store.mode_ = mode;
  store.limits_ = options.limits;
  store.faults_ = options.faults;
  store.closed_ = false;

  const auto take_writer_lock = [&store, &root, &options]() -> Status {
    Result<FileLock> acquired = FileLock::acquire(
        root / std::string{store_layout::kLockFileName}, lock_record_text(options.holder_note));
    if (!acquired) {
      return Status::failure(acquired.error());
    }
    store.lock_ = std::move(acquired).value();
    return Status::success();
  };

  if (!path_is_directory(root)) {
    if (path_exists(root)) {
      return make_error(ErrorCode::StorePathRejected, "the store root exists and is not a directory");
    }
    if (!read_write) {
      return make_error(ErrorCode::StoreNotFound,
                        "no durable store exists at this root and a read-only session may not create one");
    }
    const Status created_root = ensure_directory(root);
    if (!created_root.ok()) {
      return created_root.error();
    }
  }

  const std::filesystem::path manifest_path = root / std::string{store_layout::kManifestFileName};
  std::vector<std::byte> manifest_bytes;
  bool manifest_present = false;
  {
    Result<std::vector<std::byte>> manifest_read =
        read_file_bounded(manifest_path, options.limits.max_manifest_bytes);
    if (manifest_read) {
      manifest_bytes = std::move(manifest_read).value();
      manifest_present = true;
    } else if (manifest_read.code() == ErrorCode::StoreNotFound) {
      manifest_present = false;
    } else if (manifest_read.code() == ErrorCode::PayloadTooLarge) {
      return make_error(ErrorCode::StoreCorrupt,
                        "a file named like the manifest is larger than the manifest limit, so it is not a manifest");
    } else {
      return manifest_read.error();
    }
  }

  // -- a store that does not exist yet --------------------------------------
  if (!manifest_present) {
    const Result<std::vector<std::string>> names = list_directory_names(root, kMaxStoreDirectoryEntries);
    if (!names) {
      return names.error();
    }
    for (const std::string& name : names.value()) {
      std::uint64_t ordinal = 0;
      if (store_layout::parse_journal_file_name(name, ordinal)) {
        return make_error(ErrorCode::StoreCorrupt,
                          "durable state exists: the root holds the journal " + name +
                              " but no manifest, so it cannot be verified");
      }
    }
    if (!read_write) {
      return make_error(ErrorCode::StoreNotFound, "no durable store exists at this root");
    }
    // Taking the lock before anything is created is what stops two processes
    // that race to create the same store from both succeeding.
    const Status locked = take_writer_lock();
    if (!locked.ok()) {
      return locked.error();
    }

    std::array<std::uint8_t, kManifestStoreIdBytes> raw_id{};
    if (!hex_decode(random_token(), raw_id)) {
      return make_error(ErrorCode::InternalInvariantViolated, "a store identity could not be minted");
    }
    ContentDigest store_id;
    if (!store_id_from_bytes(raw_id, store_id)) {
      return make_error(ErrorCode::InternalInvariantViolated, "a store identity could not be encoded");
    }
    const ContentDigest seed = genesis_chain_seed(store_id);
    const std::uint64_t ordinal = 1;
    const std::string journal_name = store_layout::journal_file_name(ordinal);
    const std::filesystem::path journal_path = root / journal_name;

    const Status created_journal = write_new_file(journal_path, std::span<const std::byte>{});
    if (!created_journal.ok()) {
      return created_journal.error();
    }
    const Status journal_synced = sync_directory(root);
    if (!journal_synced.ok()) {
      (void)remove_file(journal_path);
      return journal_synced.error();
    }

    store.identity_ = StoreIdentity{store_id, journal_name};
    store.control_epoch_ = ControlEpoch::from_value(1);
    store.incarnation_ = Incarnation::from_value(fresh_incarnation(0));
    store.committed_sequence_ = JournalSequence::from_value(0);
    store.committed_generation_ = RegistryGeneration::from_value(0);
    store.chain_base_sequence_ = JournalSequence::from_value(0);
    store.chain_seed_ = seed;
    store.chain_head_ = seed;
    store.journal_ordinal_ = ordinal;
    store.committed_end_ = 0;

    const Status published =
        store.publish_manifest(ordinal, store.committed_sequence_, store.committed_generation_, seed);
    if (!published.ok()) {
      // No manifest was published, so the root must not be left holding a
      // journal that no manifest explains.
      (void)remove_file(journal_path);
      return published.error();
    }
    Result<AppendFile> handle = AppendFile::open_existing(journal_path);
    if (!handle) {
      return handle.error();
    }
    store.journal_ = std::move(handle).value();

    store.report_.store_created = true;
    store.report_.manifest_present = false;
    store.report_.frames_replayed = 0;
    store.report_.baseline_frames = 0;
    store.report_.control_epoch = store.control_epoch_;
    store.report_.incarnation = store.incarnation_;
    store.report_.committed_sequence = store.committed_sequence_;
    store.report_.committed_generation = store.committed_generation_;
    store.report_.read_only = false;
    store.report_.notes.push_back("no durable state was found; the store was created with journal " + journal_name);
    return std::move(store);
  }

  // -- a store that exists --------------------------------------------------
  ManifestImage manifest;
  std::string reason;
  const ManifestVerdict verdict = decode_manifest(manifest_bytes, manifest, reason);
  if (verdict == ManifestVerdict::UnsupportedFormat) {
    return make_error(ErrorCode::StoreFormatUnsupported, reason);
  }
  if (verdict != ManifestVerdict::Ok) {
    return make_error(ErrorCode::StoreCorrupt, reason);
  }
  store.report_.manifest_present = true;

  if (read_write) {
    const Status locked = take_writer_lock();
    if (!locked.ok()) {
      return locked.error();
    }
  }

  const std::filesystem::path journal_path = root / manifest.journal_name;
  std::vector<std::byte> journal;
  {
    Result<std::vector<std::byte>> journal_read =
        read_file_bounded(journal_path, options.limits.max_journal_bytes);
    if (!journal_read) {
      if (journal_read.code() == ErrorCode::StoreNotFound) {
        return make_error(ErrorCode::StoreCorrupt, "the manifest names the journal " + manifest.journal_name +
                                                       ", which is not present");
      }
      return journal_read.error();
    }
    journal = std::move(journal_read).value();
  }

  std::vector<JournalFrame> frames;
  std::uint64_t committed_end = 0;
  std::uint64_t uncommitted_bytes = 0;
  std::uint64_t baseline_frames = 0;
  const Status scanned =
      scan_journal(journal, manifest, options.limits, frames, committed_end, uncommitted_bytes, baseline_frames);
  if (!scanned.ok()) {
    return scanned.error();
  }

  if (read_write) {
    Result<AppendFile> handle = AppendFile::open_existing(journal_path);
    if (!handle) {
      return handle.error();
    }
    AppendFile file = std::move(handle).value();
    const Result<std::uint64_t> size_now = file.size();
    if (!size_now) {
      return size_now.error();
    }
    if (size_now.value() != static_cast<std::uint64_t>(journal.size())) {
      return make_error(ErrorCode::StoreCorrupt, "the journal changed length while it was being recovered");
    }
    const Status normalized = normalize_journal(file, committed_end);
    if (!normalized.ok()) {
      return normalized.error();
    }
    store.journal_ = std::move(file);
  }

  store.identity_ = StoreIdentity{manifest.store_id, manifest.journal_name};
  store.chain_seed_ = manifest.chain_seed;
  store.chain_base_sequence_ = JournalSequence::from_value(manifest.chain_base_sequence);
  store.chain_head_ = manifest.chain_head;
  store.committed_sequence_ = JournalSequence::from_value(manifest.committed_sequence);
  store.committed_generation_ = RegistryGeneration::from_value(manifest.committed_generation);
  store.journal_ordinal_ = manifest.journal_ordinal;
  store.committed_end_ = committed_end;
  store.frames_ = std::move(frames);

  store.report_.frames_replayed = static_cast<std::uint64_t>(store.frames_.size());
  store.report_.baseline_frames = baseline_frames;
  store.report_.uncommitted_tail_discarded = uncommitted_bytes > 0;
  store.report_.uncommitted_bytes_discarded = uncommitted_bytes;
  store.report_.committed_sequence = store.committed_sequence_;
  store.report_.committed_generation = store.committed_generation_;

  // -- rollback protection --------------------------------------------------
  if (options.min_committed_generation.has_value() &&
      store.committed_generation_ < *options.min_committed_generation) {
    return make_error(ErrorCode::StoreRolledBack, "the store is committed at generation " +
                                                      std::to_string(store.committed_generation_.value()) +
                                                      ", below the required minimum generation " +
                                                      std::to_string(options.min_committed_generation->value()));
  }

  // -- store pinning --------------------------------------------------------
  if (options.expected_store_id.has_value() && store.identity_->id != *options.expected_store_id) {
    return make_error(ErrorCode::StoreIdentityMismatch,
                      "the store identity is " + store.identity_->id.to_short_text() +
                          ", not the expected identity " + options.expected_store_id->to_short_text());
  }

  if (read_write) {
    // Taking control is what fences every authority issued by the previous
    // writer: the epoch advances and a fresh incarnation is minted, atomically
    // with the publication that makes them authoritative.
    const Result<ControlEpoch> next_epoch = advance(ControlEpoch::from_value(manifest.control_epoch));
    if (!next_epoch) {
      return next_epoch.error();
    }
    store.control_epoch_ = next_epoch.value();
    store.incarnation_ = Incarnation::from_value(fresh_incarnation(manifest.incarnation));
    store.report_.previous_control_epoch = ControlEpoch::from_value(manifest.control_epoch);
    const Status published = store.publish_manifest(store.journal_ordinal_, store.committed_sequence_,
                                                    store.committed_generation_, store.chain_head_);
    if (!published.ok()) {
      return published.error();
    }
    const Status swept = sweep_old_journals(root, manifest.journal_name, store.report_);
    if (!swept.ok()) {
      return swept.error();
    }
    if (uncommitted_bytes > 0) {
      store.report_.notes.push_back(std::to_string(uncommitted_bytes) +
                                    " bytes past the committed point were discarded");
    }
  } else {
    store.control_epoch_ = ControlEpoch::from_value(manifest.control_epoch);
    store.incarnation_ = Incarnation::from_value(manifest.incarnation);
    store.report_.read_only = true;
    if (uncommitted_bytes > 0) {
      store.report_.notes.push_back(std::to_string(uncommitted_bytes) +
                                    " bytes past the committed point were ignored because this session is read-only");
    }
    const std::filesystem::path lock_path = root / std::string{store_layout::kLockFileName};
    if (path_exists(lock_path)) {
      const Result<std::string> record = read_lock_record(lock_path);
      if (record) {
        if (record.value().empty()) {
          store.report_.notes.push_back("the writer lock file is present and holds no record");
        } else {
          store.report_.notes.push_back("writer lock record: " + record.value());
        }
        store.report_.notes.push_back("a writer may hold this store; a read-only session does not take the lock");
      } else {
        store.report_.notes.push_back(std::string{"the writer lock record could not be read: "} +
                                      std::string{record.error().token()});
      }
    } else {
      store.report_.notes.push_back("no writer lock file is present");
    }
  }

  store.report_.control_epoch = store.control_epoch_;
  store.report_.incarnation = store.incarnation_;
  return std::move(store);
}

// ---------------------------------------------------------------------------
// Publication
// ---------------------------------------------------------------------------

Status DurableStore::publish_manifest(std::uint64_t journal_ordinal, JournalSequence sequence,
                                      RegistryGeneration generation, const ContentDigest& chain_head) {
  if (!identity_.has_value()) {
    return Status::failure(ErrorCode::InternalInvariantViolated, "the store identity is not established");
  }
  const std::string journal_name = store_layout::journal_file_name(journal_ordinal);
  if (journal_name.size() > kManifestNameBytes) {
    return Status::failure(ErrorCode::InternalInvariantViolated,
                           "the journal file name is longer than the manifest can hold");
  }

  ManifestImage image;
  image.store_id = identity_->id;
  image.chain_head = chain_head;
  image.chain_seed = chain_seed_;
  image.journal_name = journal_name;
  image.control_epoch = control_epoch_.value();
  image.incarnation = incarnation_.value();
  image.committed_sequence = sequence.value();
  image.committed_generation = generation.value();
  image.chain_base_sequence = chain_base_sequence_.value();

  std::array<std::byte, kManifestBytes> bytes{};
  encode_manifest(image, bytes);

  const std::filesystem::path live = root_ / std::string{store_layout::kManifestFileName};
  const std::filesystem::path staging =
      root_ / (std::string{kManifestStagingPrefix} + random_token() + std::string{kManifestStagingSuffix});
  const Status written = write_new_file(staging, bytes);
  if (!written.ok()) {
    (void)remove_file(staging);
    return written;
  }
  const Status replaced = replace_file(staging, live);
  if (!replaced.ok()) {
    (void)remove_file(staging);
    return replaced;
  }
  return Status::success();
}

// ---------------------------------------------------------------------------
// Commit
// ---------------------------------------------------------------------------

Status DurableStore::commit(FrameKind kind, RegistryGeneration generation, std::span<const std::byte> payload) {
  if (closed_) {
    return Status::failure(ErrorCode::StoreClosed, "this durable store session is closed");
  }
  if (mode_ != AccessMode::ReadWrite) {
    return Status::failure(ErrorCode::StoreNotWritable, "this session opened the store read-only");
  }
  return append_and_publish(kind, generation, payload);
}

Status DurableStore::append_and_publish(FrameKind kind, RegistryGeneration generation,
                                        std::span<const std::byte> payload) {
  if (kind != FrameKind::Commit && kind != FrameKind::Baseline) {
    return Status::failure(ErrorCode::InvalidArgument, "a frame kind of Unspecified cannot be committed");
  }
  const std::uint64_t max_payload =
      kind == FrameKind::Baseline ? limits_.max_baseline_payload_bytes : limits_.max_commit_payload_bytes;
  if (static_cast<std::uint64_t>(payload.size()) > max_payload) {
    return Status::failure(ErrorCode::PayloadTooLarge,
                           "the payload is " + std::to_string(payload.size()) + " bytes, above the limit of " +
                               std::to_string(max_payload) + " bytes for this frame kind");
  }

  faults_.fire(PublishStage::BeforeJournalAppend);

  const Result<JournalSequence> next_sequence = advance(committed_sequence_);
  if (!next_sequence) {
    return Status::failure(next_sequence.error());
  }
  const JournalSequence sequence = next_sequence.value();

  const Status normalized = normalize_journal(journal_, committed_end_);
  if (!normalized.ok()) {
    return normalized;
  }

  const std::vector<std::byte> frame =
      encode_frame(kind, sequence, generation, control_epoch_, incarnation_, payload);

  Status outcome = journal_.append(frame);
  if (outcome.ok()) {
    // The bytes are in the handle but not yet on the device: a death here must
    // leave a store that recovers to the state before this commit.
    faults_.fire(PublishStage::AfterJournalAppendBeforeFlush);
    outcome = journal_.flush();
  }
  if (outcome.ok()) {
    faults_.fire(PublishStage::AfterJournalFlush);
    const Result<std::vector<std::byte>> readback = journal_.read_back(committed_end_, frame.size());
    if (!readback) {
      outcome = Status::failure(readback.error());
    } else {
      std::string reason;
      if (!read_back_matches(readback.value(), frame, limits_, reason)) {
        outcome = Status::failure(ErrorCode::StoreIoError,
                                  "the frame read back from the journal does not match what was written: " + reason);
      }
    }
  }
  if (!outcome.ok()) {
    // Nothing was published, so the frame is not state: the journal goes back to
    // its committed length so that a retry appends onto a verified prefix. If
    // even that repair fails, the next commit truncates the same bytes before it
    // appends, so no unverified byte is ever built upon.
    (void)normalize_journal(journal_, committed_end_);
    return outcome;
  }
  faults_.fire(PublishStage::AfterReadBackVerify);

  const ContentDigest new_head = advance_chain(chain_head_, frame);

  faults_.fire(PublishStage::BeforeManifestPublish);
  const Status published = publish_manifest(journal_ordinal_, sequence, generation, new_head);
  if (!published.ok()) {
    (void)normalize_journal(journal_, committed_end_);
    return published;
  }
  faults_.fire(PublishStage::AfterManifestPublish);

  // The commit point has been passed. Only here does any in-memory state move.
  committed_sequence_ = sequence;
  committed_generation_ = generation;
  chain_head_ = new_head;
  committed_end_ += static_cast<std::uint64_t>(frame.size());

  JournalFrame record;
  record.kind = kind;
  record.sequence = sequence;
  record.generation = generation;
  record.control_epoch = control_epoch_;
  record.incarnation = incarnation_;
  record.payload.assign(payload.begin(), payload.end());
  frames_.push_back(std::move(record));
  return Status::success();
}

// ---------------------------------------------------------------------------
// Compaction
// ---------------------------------------------------------------------------

Status DurableStore::rewrite_with_baseline(RegistryGeneration generation, std::span<const std::byte> payload) {
  if (closed_) {
    return Status::failure(ErrorCode::StoreClosed, "this durable store session is closed");
  }
  if (mode_ != AccessMode::ReadWrite) {
    return Status::failure(ErrorCode::StoreNotWritable, "this session opened the store read-only");
  }
  if (!identity_.has_value()) {
    return Status::failure(ErrorCode::InternalInvariantViolated, "the store identity is not established");
  }
  if (static_cast<std::uint64_t>(payload.size()) > limits_.max_baseline_payload_bytes) {
    return Status::failure(ErrorCode::PayloadTooLarge,
                           "the baseline payload is " + std::to_string(payload.size()) +
                               " bytes, above the baseline limit of " +
                               std::to_string(limits_.max_baseline_payload_bytes) + " bytes");
  }
  if (journal_ordinal_ == std::numeric_limits<std::uint64_t>::max()) {
    return Status::failure(ErrorCode::CounterSaturated, "there is no journal ordinal left to write");
  }

  faults_.fire(PublishStage::BeforeJournalAppend);

  const Result<JournalSequence> next_sequence = advance(committed_sequence_);
  if (!next_sequence) {
    return Status::failure(next_sequence.error());
  }
  const JournalSequence sequence = next_sequence.value();
  const JournalSequence previous_sequence = committed_sequence_;
  const std::string previous_name = identity_->journal_name;
  const std::uint64_t new_ordinal = journal_ordinal_ + 1;
  const std::string new_name = store_layout::journal_file_name(new_ordinal);
  if (new_name.size() > kManifestNameBytes) {
    return Status::failure(ErrorCode::InternalInvariantViolated,
                           "the journal file name is longer than the manifest can hold");
  }
  const std::filesystem::path new_path = root_ / new_name;
  const ContentDigest new_seed = chain_head_;
  const std::vector<std::byte> frame =
      encode_frame(FrameKind::Baseline, sequence, generation, control_epoch_, incarnation_, payload);
  const ContentDigest new_head = advance_chain(new_seed, frame);

  Result<AppendFile> created = AppendFile::create_new(new_path);
  if (!created) {
    return Status::failure(created.error());
  }
  AppendFile replacement = std::move(created).value();

  Status outcome = replacement.append(frame);
  if (outcome.ok()) {
    faults_.fire(PublishStage::AfterJournalAppendBeforeFlush);
    outcome = replacement.flush();
  }
  if (outcome.ok()) {
    faults_.fire(PublishStage::AfterJournalFlush);
    const Result<std::vector<std::byte>> readback = replacement.read_back(0, frame.size());
    if (!readback) {
      outcome = Status::failure(readback.error());
    } else {
      std::string reason;
      if (!read_back_matches(readback.value(), frame, limits_, reason)) {
        outcome = Status::failure(ErrorCode::StoreIoError,
                                  "the baseline frame read back does not match what was written: " + reason);
      }
    }
  }
  if (outcome.ok()) {
    outcome = sync_directory(root_);
  }
  if (!outcome.ok()) {
    (void)replacement.close();
    (void)remove_file(new_path);
    return outcome;
  }
  faults_.fire(PublishStage::AfterReadBackVerify);

  faults_.fire(PublishStage::BeforeManifestPublish);
  // The manifest records the chain seed and the sequence the new journal's first
  // frame follows. Both are the values the baseline frame was actually chained
  // from, so they have to be in place before the publication rather than after
  // it: publishing first would describe a chain the journal does not contain,
  // and every later open would find zero verifiable frames and refuse.
  const JournalSequence previous_base = chain_base_sequence_;
  const ContentDigest previous_seed = chain_seed_;
  chain_seed_ = new_seed;
  chain_base_sequence_ = previous_sequence;
  const Status published = publish_manifest(new_ordinal, sequence, generation, new_head);
  if (!published.ok()) {
    chain_seed_ = previous_seed;
    chain_base_sequence_ = previous_base;
    (void)replacement.close();
    (void)remove_file(new_path);
    return published;
  }
  faults_.fire(PublishStage::AfterManifestPublish);

  // The new journal is authoritative from here on. The previous journal is still
  // intact and is only now removed.
  const Status previous_closed = journal_.close();
  journal_ = std::move(replacement);
  journal_ordinal_ = new_ordinal;
  identity_->journal_name = new_name;
  chain_head_ = new_head;
  committed_sequence_ = sequence;
  committed_generation_ = generation;
  committed_end_ = static_cast<std::uint64_t>(frame.size());
  frames_.clear();
  {
    JournalFrame record;
    record.kind = FrameKind::Baseline;
    record.sequence = sequence;
    record.generation = generation;
    record.control_epoch = control_epoch_;
    record.incarnation = incarnation_;
    record.payload.assign(payload.begin(), payload.end());
    frames_.push_back(std::move(record));
  }
  if (!previous_closed.ok()) {
    report_.notes.push_back("the previous journal handle could not be closed cleanly");
  }
  if (previous_name != new_name) {
    const std::filesystem::path previous_path = root_ / previous_name;
    const Status removed = remove_file(previous_path);
    if (!removed.ok()) {
      report_.notes.push_back("the superseded journal " + previous_name +
                              " could not be removed and will be swept on the next write open");
    }
  }
  return Status::success();
}

}  // namespace detail

// ---------------------------------------------------------------------------
// Access modes and publish stages
// ---------------------------------------------------------------------------

std::string_view to_token(AccessMode mode) noexcept {
  switch (mode) {
    case AccessMode::ReadOnly:
      return "read_only";
    case AccessMode::ReadWrite:
      return "read_write";
    case AccessMode::Unspecified:
      break;
  }
  return "unspecified";
}

std::string_view to_token(PublishStage stage) noexcept {
  switch (stage) {
    case PublishStage::BeforeJournalAppend:
      return "before_journal_append";
    case PublishStage::AfterJournalAppendBeforeFlush:
      return "after_journal_append_before_flush";
    case PublishStage::AfterJournalFlush:
      return "after_journal_flush";
    case PublishStage::AfterReadBackVerify:
      return "after_read_back_verify";
    case PublishStage::BeforeManifestPublish:
      return "before_manifest_publish";
    case PublishStage::AfterManifestPublish:
      return "after_manifest_publish";
    case PublishStage::Unspecified:
      break;
  }
  return "unspecified";
}

bool parse_publish_stage(std::string_view token, PublishStage& out) noexcept {
  if (token == "before_journal_append") {
    out = PublishStage::BeforeJournalAppend;
    return true;
  }
  if (token == "after_journal_append_before_flush") {
    out = PublishStage::AfterJournalAppendBeforeFlush;
    return true;
  }
  if (token == "after_journal_flush") {
    out = PublishStage::AfterJournalFlush;
    return true;
  }
  if (token == "after_read_back_verify") {
    out = PublishStage::AfterReadBackVerify;
    return true;
  }
  if (token == "before_manifest_publish") {
    out = PublishStage::BeforeManifestPublish;
    return true;
  }
  if (token == "after_manifest_publish") {
    out = PublishStage::AfterManifestPublish;
    return true;
  }
  // "unspecified" is deliberately not accepted: a caller parsing a stage is
  // asking which stage a crash happened at, and "no stage" is not an answer.
  return false;
}

// ---------------------------------------------------------------------------
// The durable store layout
// ---------------------------------------------------------------------------

namespace store_layout {

std::string journal_file_name(std::uint64_t ordinal) {
  std::string name{kJournalStem};
  name += std::to_string(ordinal);
  name += std::string{kJournalSuffix};
  return name;
}

bool parse_journal_file_name(std::string_view name, std::uint64_t& ordinal) noexcept {
  const std::string_view stem = kJournalStem;
  const std::string_view suffix = kJournalSuffix;
  if (name.size() <= stem.size() + suffix.size()) {
    return false;
  }
  if (name.substr(0, stem.size()) != stem) {
    return false;
  }
  if (name.substr(name.size() - suffix.size()) != suffix) {
    return false;
  }
  const std::string_view digits = name.substr(stem.size(), name.size() - stem.size() - suffix.size());
  if (digits.empty() || digits.size() > 20) {
    return false;
  }
  if (digits.size() > 1 && digits.front() == '0') {
    return false;
  }
  std::uint64_t value = 0;
  for (const char digit : digits) {
    if (digit < '0' || digit > '9') {
      return false;
    }
    const std::uint64_t numeric = static_cast<std::uint64_t>(digit - '0');
    if (value > (std::numeric_limits<std::uint64_t>::max() - numeric) / 10u) {
      return false;
    }
    value = value * 10u + numeric;
  }
  if (value == 0) {
    return false;
  }
  ordinal = value;
  return true;
}

Status validate_store_root(const std::filesystem::path& root) { return detail::validate_store_root_impl(root); }

}  // namespace store_layout
}  // namespace tenant_registry
