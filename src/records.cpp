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

#include "tenant_registry/records.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>

#include "tenant_registry/digest.hpp"
#include "tenant_registry/errors.hpp"
#include "tenant_registry/ids.hpp"
#include "tenant_registry/lifecycle.hpp"
#include "tenant_registry/metadata.hpp"
#include "tenant_registry/provenance.hpp"

namespace tenant_registry {

namespace {

template <class Enum>
struct EnumToken {
  Enum value;
  std::string_view token;
};

constexpr EnumToken<OwnershipKind> kOwnershipKindTokens[] = {
    {OwnershipKind::Unspecified, "unspecified"},
    {OwnershipKind::Administrative, "administrative"},
    {OwnershipKind::Operational, "operational"},
    {OwnershipKind::Regulatory, "regulatory"},
    {OwnershipKind::DataResidency, "data_residency"},
};

constexpr EnumToken<BindingKind> kBindingKindTokens[] = {
    {BindingKind::Unspecified, "unspecified"},
    {BindingKind::OperatedBy, "operated_by"},
    {BindingKind::Serves, "serves"},
    {BindingKind::ConsumedBy, "consumed_by"},
};

constexpr EnumToken<MembershipRole> kMembershipRoleTokens[] = {
    {MembershipRole::Unspecified, "unspecified"},
    {MembershipRole::Primary, "primary"},
    {MembershipRole::Secondary, "secondary"},
    {MembershipRole::Fallback, "fallback"},
};

constexpr EnumToken<IsolationClass> kIsolationClassTokens[] = {
    {IsolationClass::Unspecified, "unspecified"},
    {IsolationClass::FaultContainment, "fault_containment"},
    {IsolationClass::Administrative, "administrative"},
    {IsolationClass::Regulatory, "regulatory"},
    {IsolationClass::TenantPrivate, "tenant_private"},
};

template <class Enum, std::size_t Size>
std::string_view token_of(const EnumToken<Enum> (&table)[Size], Enum value) noexcept {
  for (const EnumToken<Enum>& entry : table) {
    if (entry.value == value) {
      return entry.token;
    }
  }
  return std::string_view{};
}

template <class Enum, std::size_t Size>
bool parse_token(const EnumToken<Enum> (&table)[Size], std::string_view token, Enum& out) noexcept {
  for (const EnumToken<Enum>& entry : table) {
    if (entry.token == token) {
      out = entry.value;
      return true;
    }
  }
  return false;
}

/// The canonical preimage body: little-endian, explicitly sized or explicitly
/// length prefixed, and never a rendering of a value's memory layout.
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

void append_digest(std::string& out, const ContentDigest& value) {
  const std::array<std::uint8_t, 32>& bytes = value.bytes();
  out.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

/// Validates a note field. An empty note is legal and stays empty, exactly as
/// the header says; a note that carries text is a bounded text field.
Result<std::string> validate_note(std::string_view note, std::size_t max_note_bytes, const char* what) {
  if (note.empty()) {
    return std::string{};
  }
  Result<std::string> validated = validate_text_field(note, max_note_bytes, what);
  if (!validated) {
    return validated.error();
  }
  return validated;
}

}  // namespace

std::string_view to_token(OwnershipKind kind) noexcept { return token_of(kOwnershipKindTokens, kind); }

std::string_view to_token(BindingKind kind) noexcept { return token_of(kBindingKindTokens, kind); }

std::string_view to_token(MembershipRole role) noexcept { return token_of(kMembershipRoleTokens, role); }

std::string_view to_token(IsolationClass isolation_class) noexcept {
  return token_of(kIsolationClassTokens, isolation_class);
}

bool parse_ownership_kind(std::string_view token, OwnershipKind& out) noexcept {
  return parse_token(kOwnershipKindTokens, token, out);
}

bool parse_binding_kind(std::string_view token, BindingKind& out) noexcept {
  return parse_token(kBindingKindTokens, token, out);
}

bool parse_membership_role(std::string_view token, MembershipRole& out) noexcept {
  return parse_token(kMembershipRoleTokens, token, out);
}

bool parse_isolation_class(std::string_view token, IsolationClass& out) noexcept {
  return parse_token(kIsolationClassTokens, token, out);
}

// ---------------------------------------------------------------------------
// Identity helpers
// ---------------------------------------------------------------------------

std::string identity_text(SubjectKind kind, std::string_view value) {
  std::string out{to_token(kind)};
  out += ':';
  out.append(value);
  return out;
}

SubjectKind kind_of(const SubjectRecord& record) noexcept {
  return std::visit(
      [](const auto& value) noexcept -> SubjectKind {
        using Record = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<Record, TenantRecord>) {
          return SubjectKind::Tenant;
        } else if constexpr (std::is_same_v<Record, ServiceRecord>) {
          return SubjectKind::Service;
        } else {
          return SubjectKind::IsolationDomain;
        }
      },
      record);
}

const TenantId& subject_id(const TenantRecord& record) noexcept { return record.id; }

const ServiceId& subject_id(const ServiceRecord& record) noexcept { return record.id; }

const IsolationDomainId& subject_id(const IsolationDomainRecord& record) noexcept { return record.id; }

std::string subject_identity_text(const SubjectRecord& record) {
  return std::visit(
      [](const auto& value) -> std::string {
        using Record = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<Record, TenantRecord>) {
          return identity_text(SubjectKind::Tenant, value.id.value());
        } else if constexpr (std::is_same_v<Record, ServiceRecord>) {
          return identity_text(SubjectKind::Service, value.id.value());
        } else {
          return identity_text(SubjectKind::IsolationDomain, value.id.value());
        }
      },
      record);
}

LifecycleState subject_state(const SubjectRecord& record) noexcept {
  return std::visit([](const auto& value) noexcept { return value.state; }, record);
}

RecordRevision subject_revision(const SubjectRecord& record) noexcept {
  return std::visit([](const auto& value) noexcept { return value.revision; }, record);
}

bool is_terminal(const SubjectRecord& record) noexcept { return is_terminal(subject_state(record)); }

// ---------------------------------------------------------------------------
// Relationship natural keys
// ---------------------------------------------------------------------------

std::string OwnershipEdge::natural_key() const {
  // "|" is outside the identity character set, so the two identities can never
  // run together into one ambiguous key.
  return identity_text(SubjectKind::Tenant, child.value()) + "|" +
         identity_text(SubjectKind::Tenant, parent.value());
}

std::string ServiceBinding::natural_key() const {
  return identity_text(SubjectKind::Service, service.value()) + "|" +
         identity_text(SubjectKind::Tenant, tenant.value());
}

std::string IsolationMembership::natural_key() const {
  return subject.to_text() + "|" + identity_text(SubjectKind::IsolationDomain, domain.value());
}

// ---------------------------------------------------------------------------
// Rebind permit
// ---------------------------------------------------------------------------

Result<RebindPermit> RebindPermit::issue(SubjectKind successor_kind, std::string successor_text,
                                         RegistryGeneration issued_generation, std::string note,
                                         std::size_t max_text_bytes, std::size_t max_note_bytes) {
  if (successor_kind == SubjectKind::Unspecified) {
    return Error{ErrorCode::InvalidIdKind, "a rebind permit must name the kind of its successor identity"};
  }
  if (successor_text.size() > max_text_bytes) {
    return Error{ErrorCode::InvalidIdentity, "rebind permit successor text is " +
                                                 std::to_string(successor_text.size()) +
                                                 " bytes and must be at most " +
                                                 std::to_string(max_text_bytes) + " bytes"};
  }
  Result<std::string> validated = [&successor_kind, &successor_text]() -> Result<std::string> {
    switch (successor_kind) {
      case SubjectKind::Tenant:
        return validate_identity(successor_text, TenantId::rules());
      case SubjectKind::Service:
        return validate_identity(successor_text, ServiceId::rules());
      case SubjectKind::IsolationDomain:
        return validate_identity(successor_text, IsolationDomainId::rules());
      case SubjectKind::Unspecified:
        break;
    }
    return Error{ErrorCode::InvalidIdKind, "a rebind permit must name the kind of its successor identity"};
  }();
  if (!validated) {
    return validated.error();
  }
  successor_text = std::move(validated).value();

  if (note.size() > max_note_bytes) {
    return Error{ErrorCode::InvalidTextForm, "rebind permit note is " + std::to_string(note.size()) +
                                                 " bytes and must be at most " +
                                                 std::to_string(max_note_bytes) + " bytes"};
  }
  Result<std::string> validated_note = validate_note(note, max_note_bytes, "rebind permit note");
  if (!validated_note) {
    return validated_note.error();
  }
  note = std::move(validated_note).value();

  // A permit is always issued unconsumed; consumption is recorded by replacing
  // the record with the copy consumed_at produces.
  return RebindPermit{successor_kind, std::move(successor_text), issued_generation, std::nullopt, std::move(note)};
}

bool RebindPermit::admits(SubjectKind kind, std::string_view text) const noexcept {
  return successor_kind_ == kind && successor_text_ == text;
}

RebindPermit RebindPermit::consumed_at(RegistryGeneration generation) const {
  // A pure copy-with-field operation: the original is untouched, so a permit
  // can only be consumed by committing the copy in its place.
  RebindPermit copy{*this};
  copy.consumed_generation_ = generation;
  return copy;
}

ContentDigest RebindPermit::digest() const {
  std::string body;
  append_u8(body, static_cast<std::uint8_t>(successor_kind_));
  append_text(body, successor_text_);
  append_u64(body, issued_generation_.value());
  if (consumed_generation_.has_value()) {
    append_u8(body, 1);
    append_u64(body, consumed_generation_->value());
  } else {
    append_u8(body, 0);
  }
  append_text(body, note_);
  return ContentDigest::of(domain_separated("rebind_permit", body));
}

std::string RebindPermit::to_text() const {
  std::string out;
  out += "successor=";
  out += to_token(successor_kind_);
  out += ':';
  out += successor_text_;
  out += "; issued_generation=";
  out += std::to_string(issued_generation_.value());
  out += "; consumed_generation=";
  out += (consumed_generation_.has_value() ? std::to_string(consumed_generation_->value()) : std::string{"absent"});
  out += "; note=";
  out += note_;
  return out;
}

bool operator==(const RebindPermit& lhs, const RebindPermit& rhs) noexcept {
  return std::tie(lhs.successor_kind_, lhs.successor_text_, lhs.issued_generation_, lhs.consumed_generation_,
                  lhs.note_) == std::tie(rhs.successor_kind_, rhs.successor_text_, rhs.issued_generation_,
                                         rhs.consumed_generation_, rhs.note_);
}

bool operator<(const RebindPermit& lhs, const RebindPermit& rhs) noexcept {
  return std::tie(lhs.successor_kind_, lhs.successor_text_, lhs.issued_generation_, lhs.consumed_generation_,
                  lhs.note_) < std::tie(rhs.successor_kind_, rhs.successor_text_, rhs.issued_generation_,
                                        rhs.consumed_generation_, rhs.note_);
}

// ---------------------------------------------------------------------------
// Tombstone
// ---------------------------------------------------------------------------

Result<Tombstone> Tombstone::create(RegistryGeneration retired_generation, RegistryGeneration tombstoned_generation,
                                    std::optional<RebindPermit> permit, std::string note,
                                    std::size_t max_note_bytes) {
  if (tombstoned_generation < retired_generation) {
    // The fencing statement cannot predate the withdrawal it fences.
    return Error{ErrorCode::InvalidArgument, "tombstone generation " +
                                                 std::to_string(tombstoned_generation.value()) +
                                                 " precedes the retired generation " +
                                                 std::to_string(retired_generation.value())};
  }
  if (note.size() > max_note_bytes) {
    return Error{ErrorCode::InvalidTextForm, "tombstone note is " + std::to_string(note.size()) +
                                                 " bytes and must be at most " +
                                                 std::to_string(max_note_bytes) + " bytes"};
  }
  Result<std::string> validated_note = validate_note(note, max_note_bytes, "tombstone note");
  if (!validated_note) {
    return validated_note.error();
  }
  note = std::move(validated_note).value();
  return Tombstone{retired_generation, tombstoned_generation, std::move(permit), std::move(note)};
}

Tombstone Tombstone::with_permit(std::optional<RebindPermit> permit) const {
  Tombstone copy{*this};
  copy.permit_ = std::move(permit);
  return copy;
}

ContentDigest Tombstone::digest() const {
  std::string body;
  append_u64(body, retired_generation_.value());
  append_u64(body, tombstoned_generation_.value());
  if (permit_.has_value()) {
    append_u8(body, 1);
    // The permit digest binds every field of the permit, including whether it
    // has been consumed and at which generation.
    append_digest(body, permit_->digest());
  } else {
    append_u8(body, 0);
  }
  append_text(body, note_);
  return ContentDigest::of(domain_separated("tombstone", body));
}

std::string Tombstone::to_text() const {
  std::string out;
  out += "retired_generation=";
  out += std::to_string(retired_generation_.value());
  out += "; tombstoned_generation=";
  out += std::to_string(tombstoned_generation_.value());
  out += "; rebind_permit=";
  out += (permit_.has_value() ? permit_->to_text() : std::string{"absent"});
  out += "; note=";
  out += note_;
  return out;
}

bool operator==(const Tombstone& lhs, const Tombstone& rhs) noexcept {
  return std::tie(lhs.retired_generation_, lhs.tombstoned_generation_, lhs.permit_, lhs.note_) ==
         std::tie(rhs.retired_generation_, rhs.tombstoned_generation_, rhs.permit_, rhs.note_);
}

bool operator<(const Tombstone& lhs, const Tombstone& rhs) noexcept {
  return std::tie(lhs.retired_generation_, lhs.tombstoned_generation_, lhs.permit_, lhs.note_) <
         std::tie(rhs.retired_generation_, rhs.tombstoned_generation_, rhs.permit_, rhs.note_);
}

}  // namespace tenant_registry
