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

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "test_support.hpp"

namespace treg_test {
namespace {

using tenant_registry::ErrorCode;
using tenant_registry::is_known_provenance_source;
using tenant_registry::parse_provenance_source;
using tenant_registry::SourceId;
using tenant_registry::to_token;

SourceId source_id_of(std::string_view text) { return unwrap(SourceId::create(text), "SourceId::create"); }

/// Builds the request without unwrapping it, so a test can assert the exact
/// refusal of a provenance that must not be accepted.
Result<ProvenanceRecord> create_provenance(ProvenanceSource source, std::string_view source_id,
                                           std::string_view principal, std::optional<std::int64_t> declared_at,
                                           std::string_view note, std::size_t max_note_bytes = 512) {
  std::optional<Timestamp> when;
  if (declared_at.has_value()) {
    when = Timestamp{*declared_at};
  }
  return ProvenanceRecord::create(source, source_id_of(source_id), principal_id(principal), when, std::string{note},
                                  max_note_bytes);
}

ProvenanceRecord make_provenance(ProvenanceSource source, std::string_view source_id, std::string_view principal,
                                 std::optional<std::int64_t> declared_at, std::string_view note,
                                 std::size_t max_note_bytes = 512) {
  return unwrap(create_provenance(source, source_id, principal, declared_at, note, max_note_bytes),
                "ProvenanceRecord::create");
}

}  // namespace

TREG_TEST(provenance, create_validation) {
  // The source must be a source this build knows; Unspecified is not one, and a
  // declaration that does not say where it came from is refused rather than
  // recorded as anonymous.
  TREG_CHECK_CODE(create_provenance(ProvenanceSource::Unspecified, "s", "p", std::nullopt, ""),
                  ErrorCode::InvalidEnumValue);

  // A note is a text field: it may be empty, but not unbounded and not a
  // carrier of control bytes.
  TREG_CHECK(create_provenance(ProvenanceSource::TestFixture, "s", "p", std::nullopt, "").has_value());
  TREG_CHECK(
      create_provenance(ProvenanceSource::TestFixture, "s", "p", std::nullopt, std::string(512, 'n')).has_value());
  TREG_CHECK_CODE(create_provenance(ProvenanceSource::TestFixture, "s", "p", std::nullopt, std::string(513, 'n')),
                  ErrorCode::InvalidProvenance);
  TREG_CHECK_CODE(create_provenance(ProvenanceSource::TestFixture, "s", "p", std::nullopt, "line\nbreak"),
                  ErrorCode::InvalidTextForm);
  TREG_CHECK_CODE(create_provenance(ProvenanceSource::TestFixture, "s", "p", std::nullopt, "tab\there"),
                  ErrorCode::InvalidTextForm);

  const ProvenanceRecord record = make_provenance(ProvenanceSource::OperatorDeclaration, "ops-console", "alice", 17,
                                                  "declared by hand");
  TREG_CHECK_EQ(record.source(), ProvenanceSource::OperatorDeclaration);
  TREG_CHECK_EQ(record.source_id().value(), std::string{"ops-console"});
  TREG_CHECK_EQ(record.principal().value(), std::string{"alice"});
  TREG_REQUIRE(record.declared_at().has_value());
  TREG_CHECK_EQ(record.declared_at()->unix_milliseconds, static_cast<std::int64_t>(17));
  TREG_CHECK_EQ(record.note(), std::string{"declared by hand"});

  // A negative reading is a time, not an absence.
  const ProvenanceRecord before_epoch =
      make_provenance(ProvenanceSource::BootstrapImport, "legacy", "carol", -1, "");
  TREG_REQUIRE(before_epoch.declared_at().has_value());
  TREG_CHECK_EQ(before_epoch.declared_at()->unix_milliseconds, static_cast<std::int64_t>(-1));
}

TREG_TEST(provenance, an_absent_time_stays_absent_and_is_never_synthesised) {
  const ProvenanceRecord without_time = provenance_without_time();
  TREG_CHECK(!without_time.declared_at().has_value());
  TREG_CHECK_EQ(without_time.note(), std::string{});
  TREG_CHECK_EQ(without_time.to_text(),
                std::string{"source=test_fixture; source_id=test-source; principal=test-principal; "
                            "declared_at=absent; note="});
  // "absent" is a statement, and it is not the epoch wearing a timestamp.
  const ProvenanceRecord epoch = make_provenance(ProvenanceSource::TestFixture, "test-source", "test-principal", 0, "");
  TREG_REQUIRE(epoch.declared_at().has_value());
  TREG_CHECK_EQ(epoch.declared_at()->unix_milliseconds, static_cast<std::int64_t>(0));
  TREG_CHECK(without_time != epoch);
  TREG_CHECK(without_time.digest() != epoch.digest());
  TREG_CHECK(without_time.to_text() != epoch.to_text());

  // A record with a declared time renders that time and never the word absent.
  const ProvenanceRecord with_time = provenance();
  TREG_REQUIRE(with_time.declared_at().has_value());
  TREG_CHECK_EQ(with_time.to_text(),
                std::string{"source=test_fixture; source_id=test-source; principal=test-principal; declared_at="} +
                    Timestamp{17}.to_text() + "; note=");
  TREG_CHECK(with_time.to_text().find("declared_at=absent") == std::string::npos);
}

TREG_TEST(provenance, note_bounds) {
  const ProvenanceRecord at_bound =
      make_provenance(ProvenanceSource::Reconciliation, "reconciler", "dana", 5, std::string(64, 'x'), 64);
  TREG_CHECK_EQ(at_bound.note().size(), static_cast<std::size_t>(64));
  // One byte over the bound is refused; the bound is enforced against the
  // configured limit rather than a fixed one.
  TREG_CHECK_CODE(create_provenance(ProvenanceSource::Reconciliation, "reconciler", "dana", 5,
                                    std::string(65, 'x'), 64),
                  ErrorCode::InvalidProvenance);
  TREG_CHECK_CODE(create_provenance(ProvenanceSource::Reconciliation, "reconciler", "dana", 5, std::string(1, 'x'), 0),
                  ErrorCode::InvalidProvenance);
  TREG_CHECK_EQ(make_provenance(ProvenanceSource::Feed, "feed-1", "erin", 5, "", 0).note(), std::string{});
}

TREG_TEST(provenance, digest_binds_every_field) {
  const ProvenanceRecord base = make_provenance(ProvenanceSource::Feed, "feed-1", "erin", 17, "note");
  const ProvenanceRecord same = make_provenance(ProvenanceSource::Feed, "feed-1", "erin", 17, "note");
  TREG_CHECK(base == same);
  TREG_CHECK_EQ(base.digest(), same.digest());
  TREG_CHECK(!base.digest().is_zero());

  const ProvenanceRecord other_source = make_provenance(ProvenanceSource::DirectoryImport, "feed-1", "erin", 17, "note");
  const ProvenanceRecord other_source_id = make_provenance(ProvenanceSource::Feed, "feed-2", "erin", 17, "note");
  const ProvenanceRecord other_principal = make_provenance(ProvenanceSource::Feed, "feed-1", "frank", 17, "note");
  const ProvenanceRecord other_time = make_provenance(ProvenanceSource::Feed, "feed-1", "erin", 18, "note");
  const ProvenanceRecord no_time = make_provenance(ProvenanceSource::Feed, "feed-1", "erin", std::nullopt, "note");
  const ProvenanceRecord other_note = make_provenance(ProvenanceSource::Feed, "feed-1", "erin", 17, "other");

  TREG_CHECK(base.digest() != other_source.digest());
  TREG_CHECK(base.digest() != other_source_id.digest());
  TREG_CHECK(base.digest() != other_principal.digest());
  TREG_CHECK(base.digest() != other_time.digest());
  TREG_CHECK(base.digest() != no_time.digest());
  TREG_CHECK(base.digest() != other_note.digest());
  // Two records that differ in a field are different records.
  TREG_CHECK(base != other_source);
  TREG_CHECK(base != other_source_id);
  TREG_CHECK(base != other_principal);
  TREG_CHECK(base != other_time);
  TREG_CHECK(base != no_time);
  TREG_CHECK(base != other_note);

  // The digest is stable for the same content and moves with the content.
  TREG_CHECK_EQ(base.digest().to_text(), same.digest().to_text());
  TREG_CHECK(base.digest().to_text() != other_note.digest().to_text());
}

TREG_TEST(provenance, ordering_and_equality) {
  const ProvenanceRecord base = make_provenance(ProvenanceSource::Feed, "feed-1", "erin", 17, "note");
  const ProvenanceRecord same = make_provenance(ProvenanceSource::Feed, "feed-1", "erin", 17, "note");
  TREG_CHECK(base == same);
  TREG_CHECK(!(base < same));
  TREG_CHECK(!(same < base));
  TREG_CHECK(!(base != same));

  // The source dominates; then the source identity; then the principal; then
  // the time, where an absent time sorts before any declared one; then the note.
  TREG_CHECK(make_provenance(ProvenanceSource::DirectoryImport, "feed-1", "erin", 17, "note") < base);
  TREG_CHECK(make_provenance(ProvenanceSource::OperatorDeclaration, "feed-1", "erin", 17, "note") < base);
  TREG_CHECK(make_provenance(ProvenanceSource::Feed, "feed-0", "erin", 17, "note") < base);
  TREG_CHECK(make_provenance(ProvenanceSource::Feed, "feed-1", "adam", 17, "note") < base);
  TREG_CHECK(make_provenance(ProvenanceSource::Feed, "feed-1", "erin", std::nullopt, "note") < base);
  TREG_CHECK(make_provenance(ProvenanceSource::Feed, "feed-1", "erin", 16, "note") < base);
  TREG_CHECK(base < make_provenance(ProvenanceSource::TestFixture, "feed-1", "erin", 17, "note"));
  TREG_CHECK(base < make_provenance(ProvenanceSource::Feed, "feed-1", "erin", 18, "note"));
  TREG_CHECK(base < make_provenance(ProvenanceSource::Feed, "feed-1", "erin", 17, "zote"));

  // Equality and ordering agree: equal records are never ordered against each
  // other, and a strict order is never reported for equal values.
  if (base == same) {
    TREG_CHECK(!(base < same) && !(same < base));
  }
}

TREG_TEST(provenance, source_tokens_round_trip) {
  struct SourceTokenRow {
    ProvenanceSource source;
    std::string_view token;
  };
  constexpr SourceTokenRow kTokens[] = {
      {ProvenanceSource::Unspecified, "unspecified"},
      {ProvenanceSource::OperatorDeclaration, "operator_declaration"},
      {ProvenanceSource::DirectoryImport, "directory_import"},
      {ProvenanceSource::Feed, "feed"},
      {ProvenanceSource::BootstrapImport, "bootstrap_import"},
      {ProvenanceSource::Reconciliation, "reconciliation"},
      {ProvenanceSource::AutomatedPolicy, "automated_policy"},
      {ProvenanceSource::TestFixture, "test_fixture"},
  };
  for (const SourceTokenRow& row : kTokens) {
    TREG_CHECK_EQ(to_token(row.source), row.token);
    ProvenanceSource parsed = ProvenanceSource::Unspecified;
    TREG_CHECK(parse_provenance_source(row.token, parsed));
    TREG_CHECK_EQ(parsed, row.source);
    // "unspecified" is a token this build understands but it is not a source.
    TREG_CHECK_EQ(is_known_provenance_source(row.token), row.source != ProvenanceSource::Unspecified);
  }
  ProvenanceSource ignored = ProvenanceSource::Feed;
  TREG_CHECK(!parse_provenance_source("", ignored));
  TREG_CHECK(!parse_provenance_source("Feed", ignored));
  TREG_CHECK(!parse_provenance_source("feed ", ignored));
  TREG_CHECK(!parse_provenance_source("manual", ignored));
  TREG_CHECK_EQ(ignored, ProvenanceSource::Feed);
  TREG_CHECK(!is_known_provenance_source(""));
  TREG_CHECK(!is_known_provenance_source("manual"));
  TREG_CHECK_EQ(to_token(static_cast<ProvenanceSource>(99)), std::string_view{});
  // Every source this build calls known can be named in a declaration.
  TREG_CHECK(is_known_provenance_source("operator_declaration"));
  TREG_CHECK(is_known_provenance_source("automated_policy"));
  TREG_CHECK(is_known_provenance_source("test_fixture"));
}

}  // namespace treg_test