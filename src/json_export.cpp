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

// The canonical JSON form.
//
// Compact, UTF-8 and without a byte order mark, with no trailing newline and
// no insignificant whitespace anywhere. Members appear in the same fixed order
// the text form uses, member names are always quoted lower_snake_case, and a
// member whose value is absent is emitted as the literal null and is still
// emitted, so a reader can always tell that the member exists and is unset.
// Counters are JSON numbers, never strings, because a counter rendered as a
// string can be compared as text with a counter of another kind. The same
// state therefore renders to the same bytes on every run and on every machine.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

#include "tenant_registry/digest.hpp"
#include "tenant_registry/ids.hpp"
#include "tenant_registry/lifecycle.hpp"
#include "tenant_registry/metadata.hpp"
#include "tenant_registry/provenance.hpp"
#include "tenant_registry/records.hpp"
#include "tenant_registry/registry.hpp"
#include "utf8.hpp"

namespace tenant_registry {
namespace {

/// A reserve hint for one rendered record. Nothing is ever truncated to it.
constexpr std::size_t kRecordReserve = 640;

/// Builds one compact JSON object.
///
/// The object is opened by the constructor and closed by finish, members are
/// written in the order the caller emits them, separators carry no whitespace
/// at all, and every string and every member name goes through
/// detail::json_escape. Two writers fed equal values therefore produce
/// identical bytes on every platform.
class JsonObjectWriter {
 public:
  explicit JsonObjectWriter(std::size_t reserve_bytes) {
    out_.reserve(reserve_bytes);
    out_.push_back('{');
  }

  /// Opens one member. The next value written belongs to it.
  void key(std::string_view name) {
    if (!first_member_) {
      out_.push_back(',');
    }
    first_member_ = false;
    out_.push_back('"');
    detail::json_escape(out_, name);
    out_.append("\":");
  }

  void string_value(std::string_view text) {
    out_.push_back('"');
    detail::json_escape(out_, text);
    out_.push_back('"');
  }

  void unsigned_value(std::uint64_t value) { out_.append(std::to_string(value)); }

  void null_value() { out_.append("null"); }

  /// A value that has already been rendered as compact JSON by the type that
  /// owns its layout.
  void raw_value(std::string_view json_text) { out_.append(json_text); }

  /// Closes the object and returns it.
  [[nodiscard]] std::string finish() {
    out_.push_back('}');
    return std::move(out_);
  }

 private:
  std::string out_;
  bool first_member_ = true;
};

// ---------------------------------------------------------------------------
// The shared members. Each helper is the one place its name and its rendering
// are decided, so a field that two records both carry is carried under one
// member name and in one spelling.
// ---------------------------------------------------------------------------

void write_display_name(JsonObjectWriter& writer, const std::optional<std::string>& display_name) {
  writer.key("display_name");
  if (display_name.has_value()) {
    writer.string_value(*display_name);
  } else {
    writer.null_value();
  }
}

void write_retired_generation(JsonObjectWriter& writer, const std::optional<RegistryGeneration>& retired_generation) {
  writer.key("retired_generation");
  if (retired_generation.has_value()) {
    writer.unsigned_value(retired_generation->value());
  } else {
    writer.null_value();
  }
}

void write_tombstone(JsonObjectWriter& writer, const std::optional<Tombstone>& tombstone) {
  writer.key("tombstone");
  if (tombstone.has_value()) {
    writer.string_value(tombstone->to_text());
  } else {
    writer.null_value();
  }
}

/// The permit a tombstone may carry is the one field of a tombstone that is
/// itself a record, so it is rendered through its own text form and never
/// flattened here.
void write_permit(JsonObjectWriter& writer, const std::optional<RebindPermit>& permit) {
  writer.key("permit");
  if (permit.has_value()) {
    writer.string_value(permit->to_text());
  } else {
    writer.null_value();
  }
}

void write_owner(JsonObjectWriter& writer, const std::optional<PrincipalId>& owner) {
  writer.key("owner");
  if (owner.has_value()) {
    writer.string_value(owner->to_text());
  } else {
    writer.null_value();
  }
}

/// The set renders as one member whose keys are the metadata keys, in the
/// canonical key order the set already holds. An empty set is an empty object,
/// never null and never a member that was left out.
void write_metadata(JsonObjectWriter& writer, const TenancyMetadata& metadata) {
  writer.key("metadata");
  if (metadata.empty()) {
    writer.raw_value("{}");
  } else {
    writer.raw_value(metadata.to_json());
  }
}

void write_provenance(JsonObjectWriter& writer, const ProvenanceRecord& provenance) {
  writer.key("provenance");
  writer.string_value(provenance.to_text());
}

void write_origin_digest(JsonObjectWriter& writer, const ContentDigest& origin_digest) {
  writer.key("origin_digest");
  writer.string_value(origin_digest.to_text());
}

void write_created_and_updated(JsonObjectWriter& writer, RegistryGeneration created_generation,
                               RegistryGeneration updated_generation) {
  writer.key("created_generation");
  writer.unsigned_value(created_generation.value());
  writer.key("updated_generation");
  writer.unsigned_value(updated_generation.value());
}

/// The tail of every record that is not an identity record.
void write_relationship_tail(JsonObjectWriter& writer, RegistryGeneration created_generation,
                             RegistryGeneration updated_generation, const ProvenanceRecord& provenance,
                             const ContentDigest& origin_digest) {
  write_created_and_updated(writer, created_generation, updated_generation);
  write_provenance(writer, provenance);
  write_origin_digest(writer, origin_digest);
}

// ---------------------------------------------------------------------------
// One writer per record, in the field order the record declares. It is the
// same order the canonical text form uses.
// ---------------------------------------------------------------------------

void write_members(JsonObjectWriter& writer, const TenantRecord& record) {
  writer.key("identity");
  writer.string_value(identity_text(SubjectKind::Tenant, record.id.value()));
  write_display_name(writer, record.display_name);
  writer.key("state");
  writer.string_value(to_token(record.state));
  writer.key("revision");
  writer.unsigned_value(record.revision.value());
  write_created_and_updated(writer, record.created_generation, record.updated_generation);
  write_retired_generation(writer, record.retired_generation);
  write_tombstone(writer, record.tombstone);
  write_owner(writer, record.owner);
  write_metadata(writer, record.metadata);
  write_provenance(writer, record.provenance);
  write_origin_digest(writer, record.origin_digest);
}

void write_members(JsonObjectWriter& writer, const ServiceRecord& record) {
  writer.key("identity");
  writer.string_value(identity_text(SubjectKind::Service, record.id.value()));
  write_display_name(writer, record.display_name);
  writer.key("state");
  writer.string_value(to_token(record.state));
  writer.key("revision");
  writer.unsigned_value(record.revision.value());
  write_created_and_updated(writer, record.created_generation, record.updated_generation);
  write_retired_generation(writer, record.retired_generation);
  write_tombstone(writer, record.tombstone);
  write_metadata(writer, record.metadata);
  write_provenance(writer, record.provenance);
  write_origin_digest(writer, record.origin_digest);
}

void write_members(JsonObjectWriter& writer, const IsolationDomainRecord& record) {
  writer.key("identity");
  writer.string_value(identity_text(SubjectKind::IsolationDomain, record.id.value()));
  write_display_name(writer, record.display_name);
  writer.key("isolation_class");
  writer.string_value(to_token(record.isolation_class));
  writer.key("state");
  writer.string_value(to_token(record.state));
  writer.key("revision");
  writer.unsigned_value(record.revision.value());
  writer.key("membership_generation");
  writer.unsigned_value(record.membership_generation.value());
  write_created_and_updated(writer, record.created_generation, record.updated_generation);
  write_retired_generation(writer, record.retired_generation);
  write_tombstone(writer, record.tombstone);
  write_metadata(writer, record.metadata);
  write_provenance(writer, record.provenance);
  write_origin_digest(writer, record.origin_digest);
}

void write_members(JsonObjectWriter& writer, const OwnershipEdge& edge) {
  writer.key("child");
  writer.string_value(identity_text(SubjectKind::Tenant, edge.child.value()));
  writer.key("parent");
  writer.string_value(identity_text(SubjectKind::Tenant, edge.parent.value()));
  writer.key("kind");
  writer.string_value(to_token(edge.kind));
  writer.key("state");
  writer.string_value(to_token(edge.state));
  writer.key("revision");
  writer.unsigned_value(edge.revision.value());
  write_relationship_tail(writer, edge.created_generation, edge.updated_generation, edge.provenance,
                          edge.origin_digest);
}

void write_members(JsonObjectWriter& writer, const ServiceBinding& binding) {
  writer.key("service");
  writer.string_value(identity_text(SubjectKind::Service, binding.service.value()));
  writer.key("tenant");
  writer.string_value(identity_text(SubjectKind::Tenant, binding.tenant.value()));
  writer.key("kind");
  writer.string_value(to_token(binding.kind));
  writer.key("state");
  writer.string_value(to_token(binding.state));
  writer.key("revision");
  writer.unsigned_value(binding.revision.value());
  write_relationship_tail(writer, binding.created_generation, binding.updated_generation, binding.provenance,
                          binding.origin_digest);
}

void write_members(JsonObjectWriter& writer, const IsolationMembership& membership) {
  writer.key("subject");
  writer.string_value(membership.subject.to_text());
  writer.key("domain");
  writer.string_value(identity_text(SubjectKind::IsolationDomain, membership.domain.value()));
  writer.key("role");
  writer.string_value(to_token(membership.role));
  writer.key("state");
  writer.string_value(to_token(membership.state));
  writer.key("revision");
  writer.unsigned_value(membership.revision.value());
  write_relationship_tail(writer, membership.created_generation, membership.updated_generation,
                          membership.provenance, membership.origin_digest);
}

void write_members(JsonObjectWriter& writer, const TombstoneRecord& record) {
  writer.key("kind");
  writer.string_value(to_token(record.kind));
  writer.key("identity");
  writer.string_value(identity_text(record.kind, record.identity));
  writer.key("state");
  writer.string_value(to_token(record.state));
  writer.key("revision");
  writer.unsigned_value(record.revision.value());
  writer.key("retired_generation");
  writer.unsigned_value(record.retired_generation.value());
  writer.key("tombstoned_generation");
  writer.unsigned_value(record.tombstoned_generation.value());
  write_permit(writer, record.permit);
  writer.key("note");
  writer.string_value(record.note);
  write_provenance(writer, record.provenance);
  write_origin_digest(writer, record.origin_digest);
}

}  // namespace

std::string to_json(const TenantRecord& record) {
  JsonObjectWriter writer{kRecordReserve};
  write_members(writer, record);
  return writer.finish();
}

std::string to_json(const ServiceRecord& record) {
  JsonObjectWriter writer{kRecordReserve};
  write_members(writer, record);
  return writer.finish();
}

std::string to_json(const IsolationDomainRecord& record) {
  JsonObjectWriter writer{kRecordReserve};
  write_members(writer, record);
  return writer.finish();
}

std::string to_json(const SubjectRecord& record) {
  JsonObjectWriter writer{kRecordReserve};
  writer.key("kind");
  writer.string_value(to_token(kind_of(record)));
  std::visit([&writer](const auto& concrete) { write_members(writer, concrete); }, record);
  return writer.finish();
}

std::string to_json(const OwnershipEdge& edge) {
  JsonObjectWriter writer{kRecordReserve};
  write_members(writer, edge);
  return writer.finish();
}

std::string to_json(const ServiceBinding& binding) {
  JsonObjectWriter writer{kRecordReserve};
  write_members(writer, binding);
  return writer.finish();
}

std::string to_json(const IsolationMembership& membership) {
  JsonObjectWriter writer{kRecordReserve};
  write_members(writer, membership);
  return writer.finish();
}

std::string to_json(const TombstoneRecord& record) {
  JsonObjectWriter writer{kRecordReserve};
  write_members(writer, record);
  return writer.finish();
}

}  // namespace tenant_registry
