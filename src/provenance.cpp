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

#include "tenant_registry/provenance.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

#include "tenant_registry/clock.hpp"
#include "tenant_registry/digest.hpp"
#include "tenant_registry/errors.hpp"
#include "tenant_registry/ids.hpp"

namespace tenant_registry {

namespace {

struct ProvenanceToken {
  ProvenanceSource source;
  std::string_view token;
};

constexpr ProvenanceToken kProvenanceTokens[] = {
    {ProvenanceSource::Unspecified, "unspecified"},
    {ProvenanceSource::OperatorDeclaration, "operator_declaration"},
    {ProvenanceSource::DirectoryImport, "directory_import"},
    {ProvenanceSource::Feed, "feed"},
    {ProvenanceSource::BootstrapImport, "bootstrap_import"},
    {ProvenanceSource::Reconciliation, "reconciliation"},
    {ProvenanceSource::AutomatedPolicy, "automated_policy"},
    {ProvenanceSource::TestFixture, "test_fixture"},
};

/// The canonical preimage body. Every field is written little-endian with an
/// explicit width or an explicit length, so no two different records can
/// produce the same bytes and no value is ever encoded through its in-memory
/// representation.
void append_u8(std::string& out, std::uint8_t value) { out.push_back(static_cast<char>(value)); }

void append_u64(std::string& out, std::uint64_t value) {
  for (unsigned shift = 0; shift < 64u; shift += 8u) {
    out.push_back(static_cast<char>((value >> shift) & 0xFFu));
  }
}

void append_text(std::string& out, std::string_view value) {
  append_u64(out, static_cast<std::uint64_t>(value.size()));
  out.append(value);
}

}  // namespace

std::string_view to_token(ProvenanceSource source) noexcept {
  for (const ProvenanceToken& entry : kProvenanceTokens) {
    if (entry.source == source) {
      return entry.token;
    }
  }
  return std::string_view{};
}

bool parse_provenance_source(std::string_view token, ProvenanceSource& out) noexcept {
  for (const ProvenanceToken& entry : kProvenanceTokens) {
    if (entry.token == token) {
      out = entry.source;
      return true;
    }
  }
  return false;
}

bool is_known_provenance_source(std::string_view token) noexcept {
  ProvenanceSource source = ProvenanceSource::Unspecified;
  // "unspecified" is a token this build understands but it is not a source, so
  // it is not reported as a known one.
  return parse_provenance_source(token, source) && source != ProvenanceSource::Unspecified;
}

Result<ProvenanceRecord> ProvenanceRecord::create(ProvenanceSource source, SourceId source_id,
                                                  PrincipalId principal, std::optional<Timestamp> declared_at,
                                                  std::string note, std::size_t max_note_bytes) {
  if (source == ProvenanceSource::Unspecified) {
    return Error{ErrorCode::InvalidEnumValue, "provenance source is unspecified"};
  }
  // The identity types can only be produced by their validating factories, so
  // an empty one can only arrive through a decode that already failed; it is
  // still refused here rather than recorded as an anonymous declaration.
  if (source_id.value().empty()) {
    return Error{ErrorCode::InvalidProvenance, "provenance source identity is empty"};
  }
  if (principal.value().empty()) {
    return Error{ErrorCode::InvalidProvenance, "provenance principal identity is empty"};
  }
  if (note.size() > max_note_bytes) {
    return Error{ErrorCode::InvalidProvenance, "provenance note is " + std::to_string(note.size()) +
                                                   " bytes and must be at most " +
                                                   std::to_string(max_note_bytes) + " bytes"};
  }
  if (!note.empty()) {
    // An empty note is legal and stays empty; a note that is present is a text
    // field like any other.
    Result<std::string> validated = validate_text_field(note, max_note_bytes, "provenance note");
    if (!validated) {
      return validated.error();
    }
    note = std::move(validated).value();
  }
  return ProvenanceRecord{source, std::move(source_id), std::move(principal), declared_at, std::move(note)};
}

ContentDigest ProvenanceRecord::digest() const {
  std::string body;
  append_u8(body, static_cast<std::uint8_t>(source_));
  append_text(body, source_id_.value());
  append_text(body, principal_.value());
  // Presence is encoded explicitly: an absent time is not the epoch.
  if (declared_at_.has_value()) {
    append_u8(body, 1);
    append_u64(body, static_cast<std::uint64_t>(declared_at_->unix_milliseconds));
  } else {
    append_u8(body, 0);
  }
  append_text(body, note_);
  return ContentDigest::of(domain_separated("provenance_record", body));
}

std::string ProvenanceRecord::to_text() const {
  std::string out;
  out += "source=";
  out += to_token(source_);
  out += "; source_id=";
  out += source_id_.value();
  out += "; principal=";
  out += principal_.value();
  out += "; declared_at=";
  out += (declared_at_.has_value() ? declared_at_->to_text() : std::string{"absent"});
  out += "; note=";
  out += note_;
  return out;
}

bool operator==(const ProvenanceRecord& lhs, const ProvenanceRecord& rhs) noexcept {
  return lhs.source_ == rhs.source_ && lhs.source_id_ == rhs.source_id_ && lhs.principal_ == rhs.principal_ &&
         lhs.declared_at_ == rhs.declared_at_ && lhs.note_ == rhs.note_;
}

bool operator<(const ProvenanceRecord& lhs, const ProvenanceRecord& rhs) noexcept {
  return std::tie(lhs.source_, lhs.source_id_, lhs.principal_, lhs.declared_at_, lhs.note_) <
         std::tie(rhs.source_, rhs.source_id_, rhs.principal_, rhs.declared_at_, rhs.note_);
}

}  // namespace tenant_registry
