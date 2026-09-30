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

// The canonical text form.
//
// One "key=value" pair per line, keys in a fixed order, LF line endings, no
// trailing space, no tab, and exactly one trailing newline. Every field of a
// record is rendered, including the fields that are absent -- an absent
// optional renders as the literal "unset", never as an empty string, never as
// zero and never as "false", because "nothing was declared" and "declared as
// zero" are different answers and this format must not be able to confuse
// them. Every counter line carries the counter's own kind token, so a
// generation can never be misread as a revision or as a domain generation.
// The same state therefore renders to the same bytes on every run, on every
// machine, and whatever order the operations that produced it arrived in.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

#include "tenant_registry/clock.hpp"
#include "tenant_registry/digest.hpp"
#include "tenant_registry/ids.hpp"
#include "tenant_registry/lifecycle.hpp"
#include "tenant_registry/metadata.hpp"
#include "tenant_registry/provenance.hpp"
#include "tenant_registry/records.hpp"
#include "tenant_registry/registry.hpp"

namespace tenant_registry {
namespace {

/// The literal an absent optional renders as.
constexpr std::string_view kUnset = "unset";

/// A reserve hint for one rendered record. Nothing is ever truncated to it.
constexpr std::size_t kRecordReserve = 512;

/// Writes one line at a time. Every renderer in this file writes through this
/// class, so a line is always a key, a single '=', a value, and one LF.
class LineWriter {
 public:
  explicit LineWriter(std::size_t reserve_bytes) { out_.reserve(reserve_bytes); }

  void line(std::string_view key, std::string_view value) {
    out_.append(key);
    out_.push_back('=');
    out_.append(value);
    out_.push_back('\n');
  }

  [[nodiscard]] std::string take() { return std::move(out_); }

 private:
  std::string out_;
};

// ---------------------------------------------------------------------------
// The shared lines. Each helper is the one place its key and its rendering are
// decided, so a field that two records both carry is carried under one key and
// in one spelling.
// ---------------------------------------------------------------------------

void write_display_name(LineWriter& writer, const std::optional<std::string>& display_name) {
  if (display_name.has_value()) {
    writer.line("display_name", *display_name);
  } else {
    writer.line("display_name", kUnset);
  }
}

void write_retired_generation(LineWriter& writer, const std::optional<RegistryGeneration>& retired_generation) {
  if (retired_generation.has_value()) {
    writer.line("retired_generation", retired_generation->to_text());
  } else {
    writer.line("retired_generation", kUnset);
  }
}

void write_tombstone(LineWriter& writer, const std::optional<Tombstone>& tombstone) {
  if (tombstone.has_value()) {
    writer.line("tombstone", tombstone->to_text());
  } else {
    writer.line("tombstone", kUnset);
  }
}

/// The permit a tombstone may carry is the one field of a tombstone that is
/// itself a record, so it is rendered through its own text form and never
/// flattened here.
void write_permit(LineWriter& writer, const std::optional<RebindPermit>& permit) {
  if (permit.has_value()) {
    writer.line("permit", permit->to_text());
  } else {
    writer.line("permit", kUnset);
  }
}

void write_owner(LineWriter& writer, const std::optional<PrincipalId>& owner) {
  if (owner.has_value()) {
    writer.line("owner", owner->to_text());
  } else {
    writer.line("owner", kUnset);
  }
}

/// One line per entry, in the order the set already holds. The set is kept in
/// canonical key order, so the rendering is a property of the value and not of
/// the order a caller supplied the entries in.
void write_metadata(LineWriter& writer, const TenancyMetadata& metadata) {
  std::string key;
  for (const MetadataEntry& entry : metadata.entries()) {
    key.assign("metadata.");
    key.append(entry.key.value());
    writer.line(key, entry.value.to_canonical());
  }
}

void write_provenance(LineWriter& writer, const ProvenanceRecord& provenance) {
  writer.line("provenance", provenance.to_text());
}

void write_origin_digest(LineWriter& writer, const ContentDigest& origin_digest) {
  writer.line("origin_digest", origin_digest.to_text());
}

/// The two generations every record carries. Each line names the counter's own
/// kind, so no two counters can be read as one another.
void write_created_and_updated(LineWriter& writer, RegistryGeneration created_generation,
                               RegistryGeneration updated_generation) {
  writer.line("created_generation", created_generation.to_text());
  writer.line("updated_generation", updated_generation.to_text());
}

/// The tail of every record that is not an identity record.
void write_relationship_tail(LineWriter& writer, RegistryGeneration created_generation,
                             RegistryGeneration updated_generation, const ProvenanceRecord& provenance,
                             const ContentDigest& origin_digest) {
  write_created_and_updated(writer, created_generation, updated_generation);
  write_provenance(writer, provenance);
  write_origin_digest(writer, origin_digest);
}

// ---------------------------------------------------------------------------
// One writer per record, in the field order the record declares. The identity
// records share a head and a tail because they share the fields; the domain
// record carries two extra fields, which are written where the record declares
// them rather than appended at the end.
// ---------------------------------------------------------------------------

void write_lines(LineWriter& writer, const TenantRecord& record) {
  writer.line("identity", identity_text(SubjectKind::Tenant, record.id.value()));
  write_display_name(writer, record.display_name);
  writer.line("state", to_token(record.state));
  writer.line("revision", record.revision.to_text());
  write_created_and_updated(writer, record.created_generation, record.updated_generation);
  write_retired_generation(writer, record.retired_generation);
  write_tombstone(writer, record.tombstone);
  write_owner(writer, record.owner);
  write_metadata(writer, record.metadata);
  write_provenance(writer, record.provenance);
  write_origin_digest(writer, record.origin_digest);
}

void write_lines(LineWriter& writer, const ServiceRecord& record) {
  writer.line("identity", identity_text(SubjectKind::Service, record.id.value()));
  write_display_name(writer, record.display_name);
  writer.line("state", to_token(record.state));
  writer.line("revision", record.revision.to_text());
  write_created_and_updated(writer, record.created_generation, record.updated_generation);
  write_retired_generation(writer, record.retired_generation);
  write_tombstone(writer, record.tombstone);
  write_metadata(writer, record.metadata);
  write_provenance(writer, record.provenance);
  write_origin_digest(writer, record.origin_digest);
}

void write_lines(LineWriter& writer, const IsolationDomainRecord& record) {
  writer.line("identity", identity_text(SubjectKind::IsolationDomain, record.id.value()));
  write_display_name(writer, record.display_name);
  writer.line("isolation_class", to_token(record.isolation_class));
  writer.line("state", to_token(record.state));
  writer.line("revision", record.revision.to_text());
  writer.line("membership_generation", record.membership_generation.to_text());
  write_created_and_updated(writer, record.created_generation, record.updated_generation);
  write_retired_generation(writer, record.retired_generation);
  write_tombstone(writer, record.tombstone);
  write_metadata(writer, record.metadata);
  write_provenance(writer, record.provenance);
  write_origin_digest(writer, record.origin_digest);
}

void write_lines(LineWriter& writer, const OwnershipEdge& edge) {
  writer.line("child", identity_text(SubjectKind::Tenant, edge.child.value()));
  writer.line("parent", identity_text(SubjectKind::Tenant, edge.parent.value()));
  writer.line("kind", to_token(edge.kind));
  writer.line("state", to_token(edge.state));
  writer.line("revision", edge.revision.to_text());
  write_relationship_tail(writer, edge.created_generation, edge.updated_generation, edge.provenance,
                          edge.origin_digest);
}

void write_lines(LineWriter& writer, const ServiceBinding& binding) {
  writer.line("service", identity_text(SubjectKind::Service, binding.service.value()));
  writer.line("tenant", identity_text(SubjectKind::Tenant, binding.tenant.value()));
  writer.line("kind", to_token(binding.kind));
  writer.line("state", to_token(binding.state));
  writer.line("revision", binding.revision.to_text());
  write_relationship_tail(writer, binding.created_generation, binding.updated_generation, binding.provenance,
                          binding.origin_digest);
}

void write_lines(LineWriter& writer, const IsolationMembership& membership) {
  writer.line("subject", membership.subject.to_text());
  writer.line("domain", identity_text(SubjectKind::IsolationDomain, membership.domain.value()));
  writer.line("role", to_token(membership.role));
  writer.line("state", to_token(membership.state));
  writer.line("revision", membership.revision.to_text());
  write_relationship_tail(writer, membership.created_generation, membership.updated_generation,
                          membership.provenance, membership.origin_digest);
}

void write_lines(LineWriter& writer, const TombstoneRecord& record) {
  writer.line("kind", to_token(record.kind));
  writer.line("identity", identity_text(record.kind, record.identity));
  writer.line("state", to_token(record.state));
  writer.line("revision", record.revision.to_text());
  writer.line("retired_generation", record.retired_generation.to_text());
  writer.line("tombstoned_generation", record.tombstoned_generation.to_text());
  write_permit(writer, record.permit);
  writer.line("note", record.note);
  write_provenance(writer, record.provenance);
  write_origin_digest(writer, record.origin_digest);
}

/// Appends a decimal integer, zero padded to at least minimum_digits. The
/// magnitude is taken in unsigned arithmetic, so no input can overflow it, and
/// a year outside [0, 9999] keeps its sign and simply grows past four digits
/// rather than being clamped into a different instant.
void append_padded(std::string& out, std::int64_t value, std::size_t minimum_digits) {
  const bool negative = value < 0;
  const std::uint64_t magnitude =
      negative ? static_cast<std::uint64_t>(-(value + 1)) + 1U : static_cast<std::uint64_t>(value);
  const std::string digits = std::to_string(magnitude);
  if (negative) {
    out.push_back('-');
  }
  for (std::size_t index = digits.size(); index < minimum_digits; ++index) {
    out.push_back('0');
  }
  out.append(digits);
}

}  // namespace

std::string Timestamp::to_text() const {
  constexpr std::int64_t kMillisecondsPerSecond = 1000;
  constexpr std::int64_t kMillisecondsPerMinute = 60 * kMillisecondsPerSecond;
  constexpr std::int64_t kMillisecondsPerHour = 60 * kMillisecondsPerMinute;
  constexpr std::int64_t kMillisecondsPerDay = 24 * kMillisecondsPerHour;

  // Split toward negative infinity. A reading before the epoch then keeps its
  // civil date and its time of day on the same side of midnight, where
  // truncating division would report the previous day and a positive remainder
  // for the same instant.
  std::int64_t days = unix_milliseconds / kMillisecondsPerDay;
  std::int64_t remainder = unix_milliseconds % kMillisecondsPerDay;
  if (remainder < 0) {
    remainder += kMillisecondsPerDay;
    --days;
  }
  const std::int64_t hour = remainder / kMillisecondsPerHour;
  remainder %= kMillisecondsPerHour;
  const std::int64_t minute = remainder / kMillisecondsPerMinute;
  remainder %= kMillisecondsPerMinute;
  const std::int64_t second = remainder / kMillisecondsPerSecond;
  const std::int64_t millisecond = remainder % kMillisecondsPerSecond;

  // Days since 1970-01-01 to a civil date, by the era based projection. It is
  // exact for every instant an int64 reading of milliseconds can name.
  const std::int64_t shifted_days = days + 719468;
  const std::int64_t era = (shifted_days >= 0 ? shifted_days : shifted_days - 146096) / 146097;
  const std::int64_t day_of_era = shifted_days - era * 146097;
  const std::int64_t year_of_era =
      (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
  const std::int64_t day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
  const std::int64_t month_index = (5 * day_of_year + 2) / 153;
  const std::int64_t day = day_of_year - (153 * month_index + 2) / 5 + 1;
  const std::int64_t month = month_index < 10 ? month_index + 3 : month_index - 9;
  const std::int64_t year = year_of_era + era * 400 + (month <= 2 ? 1 : 0);

  // UTC, always, with a fixed number of digits, so two readings sort as text
  // exactly as they sort as instants.
  std::string text;
  text.reserve(24);
  append_padded(text, year, 4U);
  text.push_back('-');
  append_padded(text, month, 2U);
  text.push_back('-');
  append_padded(text, day, 2U);
  text.push_back('T');
  append_padded(text, hour, 2U);
  text.push_back(':');
  append_padded(text, minute, 2U);
  text.push_back(':');
  append_padded(text, second, 2U);
  text.push_back('.');
  append_padded(text, millisecond, 3U);
  text.push_back('Z');
  return text;
}

std::string subject_kind_token(const SubjectRecord& record) { return std::string{to_token(kind_of(record))}; }

std::string to_canonical(const TenantRecord& record) {
  LineWriter writer{kRecordReserve};
  write_lines(writer, record);
  return writer.take();
}

std::string to_canonical(const ServiceRecord& record) {
  LineWriter writer{kRecordReserve};
  write_lines(writer, record);
  return writer.take();
}

std::string to_canonical(const IsolationDomainRecord& record) {
  LineWriter writer{kRecordReserve};
  write_lines(writer, record);
  return writer.take();
}

std::string to_canonical(const SubjectRecord& record) {
  LineWriter writer{kRecordReserve};
  writer.line("kind", subject_kind_token(record));
  std::visit([&writer](const auto& concrete) { write_lines(writer, concrete); }, record);
  return writer.take();
}

std::string to_canonical(const OwnershipEdge& edge) {
  LineWriter writer{kRecordReserve};
  write_lines(writer, edge);
  return writer.take();
}

std::string to_canonical(const ServiceBinding& binding) {
  LineWriter writer{kRecordReserve};
  write_lines(writer, binding);
  return writer.take();
}

std::string to_canonical(const IsolationMembership& membership) {
  LineWriter writer{kRecordReserve};
  write_lines(writer, membership);
  return writer.take();
}

std::string to_canonical(const TombstoneRecord& record) {
  LineWriter writer{kRecordReserve};
  write_lines(writer, record);
  return writer.take();
}

}  // namespace tenant_registry
