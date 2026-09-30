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

#ifndef TENANT_REGISTRY_PROVENANCE_HPP
#define TENANT_REGISTRY_PROVENANCE_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "tenant_registry/clock.hpp"
#include "tenant_registry/digest.hpp"
#include "tenant_registry/errors.hpp"
#include "tenant_registry/ids.hpp"

namespace tenant_registry {

/// Where a declaration came from.
///
/// This is provenance, not authority. A declaration that arrived from a
/// directory import is recorded as such and is exactly as binding as any other,
/// because the registry is the authority for its own canonical state; the
/// external directory is not. Nothing here authenticates anything.
enum class ProvenanceSource : std::uint8_t {
  Unspecified = 0,
  /// An operator or an operator tool declared it.
  OperatorDeclaration = 1,
  /// It was imported from an external directory. The import is evidence about
  /// what that directory said; it is not evidence that the directory is right.
  DirectoryImport = 2,
  /// It arrived on a feed from an adjacent DCCP system.
  Feed = 3,
  /// It was established while bringing a pre-existing facility online.
  BootstrapImport = 4,
  /// It was established by reconciling this registry against another
  /// authority's declared state.
  Reconciliation = 5,
  /// It was established by an automated policy acting on its own.
  AutomatedPolicy = 6,
  /// It was established by a test. Test provenance is a first class value so
  /// that test data can never be mistaken for production data.
  TestFixture = 7,
};

[[nodiscard]] std::string_view to_token(ProvenanceSource source) noexcept;
[[nodiscard]] bool parse_provenance_source(std::string_view token, ProvenanceSource& out) noexcept;
[[nodiscard]] bool is_known_provenance_source(std::string_view token) noexcept;

/// Who declared something, from where, and when.
///
/// The time is optional and stays optional. A declaration with no time is
/// recorded as a declaration with no time; it is never stamped with a
/// synthesized one, and a missing time is never rendered as the Unix epoch.
/// A declaration made before the identity existed, or with a time in the far
/// future, is still a valid declaration of this registry; the clock is not an
/// authority over whether the declaration is current.
class ProvenanceRecord {
 public:
  ProvenanceRecord() = delete;

  [[nodiscard]] static Result<ProvenanceRecord> create(ProvenanceSource source, SourceId source_id,
                                                       PrincipalId principal,
                                                       std::optional<Timestamp> declared_at, std::string note,
                                                       std::size_t max_note_bytes);

  [[nodiscard]] ProvenanceSource source() const noexcept { return source_; }
  [[nodiscard]] const SourceId& source_id() const noexcept { return source_id_; }
  [[nodiscard]] const PrincipalId& principal() const noexcept { return principal_; }
  [[nodiscard]] const std::optional<Timestamp>& declared_at() const noexcept { return declared_at_; }
  [[nodiscard]] const std::string& note() const noexcept { return note_; }

  /// Binds every field of this provenance into one digest. Two provenance
  /// records that differ in any field have different digests.
  [[nodiscard]] ContentDigest digest() const;

  [[nodiscard]] std::string to_text() const;

  friend bool operator==(const ProvenanceRecord& lhs, const ProvenanceRecord& rhs) noexcept;
  friend bool operator<(const ProvenanceRecord& lhs, const ProvenanceRecord& rhs) noexcept;

 private:
  ProvenanceRecord(ProvenanceSource source, SourceId source_id, PrincipalId principal,
                   std::optional<Timestamp> declared_at, std::string note) noexcept
      : source_(source),
        source_id_(std::move(source_id)),
        principal_(std::move(principal)),
        declared_at_(declared_at),
        note_(std::move(note)) {}

  ProvenanceSource source_ = ProvenanceSource::Unspecified;
  SourceId source_id_;
  PrincipalId principal_;
  std::optional<Timestamp> declared_at_;
  std::string note_;
};

}  // namespace tenant_registry

#endif  // TENANT_REGISTRY_PROVENANCE_HPP
