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
#include <optional>
#include <string>
#include <vector>

#include "test_support.hpp"

namespace treg_test {
namespace {

using tenant_registry::ErrorCode;
using tenant_registry::IrreversibleAcknowledgement;
using tenant_registry::RebindSuccessor;
using tenant_registry::SetMetadataRequest;
using tenant_registry::TenancyMetadata;
using tenant_registry::TombstoneRequest;

std::vector<std::string> text_lines(const std::string& text) {
  std::vector<std::string> lines;
  std::string current;
  for (const char byte : text) {
    if (byte == '\n') {
      lines.push_back(current);
      current.clear();
    } else {
      current.push_back(byte);
    }
  }
  if (!current.empty()) {
    lines.push_back(current);
  }
  return lines;
}

/// The member names of the canonical text form, in order, with the lines of one
/// metadata set folded into the single member they belong to.
std::vector<std::string> text_members(const std::string& text) {
  std::vector<std::string> members;
  for (const std::string& line : text_lines(text)) {
    const std::size_t separator = line.find('=');
    if (separator == std::string::npos) {
      continue;
    }
    std::string key = line.substr(0, separator);
    if (key.rfind("metadata.", 0) == 0) {
      key = "metadata";
    }
    if (!members.empty() && members.back() == key) {
      continue;
    }
    members.push_back(key);
  }
  return members;
}

/// The names of the top level members of a compact JSON object, in order.
std::vector<std::string> json_members(const std::string& json) {
  std::vector<std::string> members;
  std::size_t depth = 0;
  std::size_t index = 0;
  while (index < json.size()) {
    const char byte = json[index];
    if (byte == '{' || byte == '[') {
      ++depth;
      ++index;
      continue;
    }
    if (byte == '}' || byte == ']') {
      --depth;
      ++index;
      continue;
    }
    if (byte != '"') {
      ++index;
      continue;
    }
    std::string value;
    bool escaped = false;
    std::size_t cursor = index + 1;
    while (cursor < json.size()) {
      const char inner = json[cursor];
      if (escaped) {
        value.push_back(inner);
        escaped = false;
      } else if (inner == '\\') {
        escaped = true;
      } else if (inner == '"') {
        break;
      } else {
        value.push_back(inner);
      }
      ++cursor;
    }
    const std::size_t next = cursor + 1;
    if (depth == 1 && next < json.size() && json[next] == ':') {
      members.push_back(value);
    }
    index = next;
  }
  return members;
}

std::size_t count_substring(const std::string& text, std::string_view needle) {
  std::size_t count = 0;
  std::size_t position = text.find(needle);
  while (position != std::string::npos) {
    ++count;
    position = text.find(needle, position + needle.size());
  }
  return count;
}

bool has_raw_control_byte(const std::string& text) {
  for (const char byte : text) {
    if (static_cast<unsigned char>(byte) < 0x20u) {
      return true;
    }
  }
  return false;
}

/// Every property the canonical text form must have, whatever record it renders.
void check_text_shape(const std::string& text) {
  TREG_CHECK(!text.empty());
  TREG_CHECK_EQ(text.back(), '\n');
  TREG_REQUIRE(text.size() >= 2u);
  TREG_CHECK(text.at(text.size() - 2u) != '\n');
  TREG_CHECK_EQ(text.find('\t'), std::string::npos);
  TREG_CHECK_EQ(text.find("\n\n"), std::string::npos);
  for (const std::string& line : text_lines(text)) {
    TREG_CHECK(!line.empty());
    const std::size_t separator = line.find('=');
    TREG_REQUIRE(separator != std::string::npos);
    TREG_CHECK(separator > 0u);
    const std::string key = line.substr(0, separator);
    TREG_CHECK(key.find(':') == std::string::npos);
    TREG_CHECK(key.find(' ') == std::string::npos);
    TREG_CHECK(line.back() != ' ');
    // The separator is '=' and never ": ": a reader that splits on ": " would
    // read the whole line as a key.
    TREG_CHECK(line.find(": ") == std::string::npos || line.find(": ") > separator);
  }
}

/// Every property the canonical JSON form must have, whatever record it renders.
void check_json_shape(const std::string& json) {
  TREG_CHECK(json.size() > 2u);
  TREG_CHECK_EQ(json.front(), '{');
  TREG_CHECK_EQ(json.back(), '}');
  TREG_CHECK(!has_raw_control_byte(json));
  // No insignificant whitespace: every space in the document is inside a string
  // value, so there is none between two structural characters.
  TREG_CHECK_EQ(json.find(", "), std::string::npos);
  TREG_CHECK_EQ(json.find("{ "), std::string::npos);
  TREG_CHECK_EQ(json.find(" }"), std::string::npos);
}

std::string joined(const std::vector<std::string>& members) {
  std::string out;
  for (const std::string& member : members) {
    if (!out.empty()) {
      out += "|";
    }
    out += member;
  }
  return out;
}

void check_member_order(const std::string& text, const std::string& json) {
  std::vector<std::string> text_order = text_members(text);
  const std::vector<std::string> json_order = json_members(json);
  if (json_order.size() == text_order.size() + 1u) {
    // A record that has no metadata has no line to write for it, while the JSON
    // form still states the member as an empty object.
    for (std::size_t index = 0; index < json_order.size(); ++index) {
      const bool present = index < text_order.size() && text_order.at(index) == "metadata";
      if (json_order.at(index) == "metadata" && !present) {
        text_order.insert(text_order.begin() + static_cast<std::ptrdiff_t>(index), "metadata");
        break;
      }
    }
  }
  TREG_CHECK_EQ(joined(json_order), joined(text_order));
}

TREG_TEST(export, the_text_form_is_one_line_per_field) {
  Harness harness = Harness::ephemeral();
  const TenancyMetadata metadata =
      unwrap(TenancyMetadata::create({entry("region", "eu"), entry("tier", "gold")}, 64, 512), "metadata");
  const TenantRecord tenant = harness.create_tenant("acme", std::optional<std::string>{"Acme"},
                                                   std::optional<PrincipalId>{principal_id("ops")}, metadata);
  const ServiceRecord service =
      harness.create_service("renderer", std::optional<std::string>{"Renderer"}, metadata);
  const IsolationDomainRecord domain = harness.create_domain("zone-a", IsolationClass::Regulatory);
  const TenantRecord related = harness.active_tenant("related");
  require_ok(harness.transition(TenancySubject::of_tenant(tenant.id), tenant.revision, LifecycleState::Active),
             "activate acme");
  require_ok(harness.transition(TenancySubject::of_service(service.id), service.revision, LifecycleState::Active),
             "activate renderer");
  require_ok(harness.transition(TenancySubject::of_isolation_domain(domain.id), domain.revision,
                                LifecycleState::Active),
             "activate zone-a");
  const OwnershipEdge edge = harness.own("related", "acme", OwnershipKind::Operational, LifecycleState::Active);
  const ServiceBinding binding = harness.bind("renderer", "acme", BindingKind::Serves);
  const IsolationMembership membership =
      harness.join(TenancySubject::of_tenant(tenant.id), "zone-a", MembershipRole::Primary);

  const std::vector<std::string> texts{to_canonical(harness.tenant("acme")),
                                       to_canonical(harness.service("renderer")),
                                       to_canonical(harness.domain("zone-a")),
                                       to_canonical(subject_record(harness.tenant("acme"))),
                                       to_canonical(subject_record(harness.service("renderer"))),
                                       to_canonical(subject_record(harness.domain("zone-a"))),
                                       to_canonical(edge),
                                       to_canonical(binding),
                                       to_canonical(membership)};
  for (const std::string& text : texts) {
    check_text_shape(text);
  }

  // One line per field: the two metadata entries add two lines to the single
  // metadata member the JSON form carries.
  check_member_order(texts.at(0), to_json(harness.tenant("acme")));
  TREG_CHECK_EQ(text_lines(texts.at(0)).size(),
                json_members(to_json(harness.tenant("acme"))).size() + 1u);
  check_member_order(texts.at(3), to_json(subject_record(harness.tenant("acme"))));
  check_member_order(texts.at(6), to_json(edge));
  check_member_order(texts.at(7), to_json(binding));
  check_member_order(texts.at(8), to_json(membership));
  TREG_CHECK_EQ(text_lines(texts.at(6)).size(), json_members(to_json(edge)).size());
  TREG_CHECK_EQ(text_lines(texts.at(7)).size(), json_members(to_json(binding)).size());
  TREG_CHECK_EQ(text_lines(texts.at(8)).size(), json_members(to_json(membership)).size());
}

TREG_TEST(export, the_json_form_is_compact_and_escapes_what_it_must) {
  Harness harness = Harness::ephemeral();
  const TenantRecord plain = harness.create_tenant("acme");
  const TenantRecord quoted = harness.create_tenant("quoted", std::optional<std::string>{"a\"b\\c"});

  const std::vector<std::string> documents{to_json(plain), to_json(quoted),
                                           to_json(subject_record(plain)), to_json(subject_record(quoted))};
  for (const std::string& json : documents) {
    check_json_shape(json);
  }
  const std::string escaped = to_json(quoted);
  TREG_CHECK_EQ(count_substring(escaped, "a\\\"b\\\\c"), std::size_t{1});
  TREG_CHECK_EQ(escaped.find("a\"b"), std::string::npos);

  // A rendered record is byte for byte the same every time it is rendered.
  TREG_CHECK_EQ(to_json(quoted), escaped);
  TREG_CHECK_EQ(to_canonical(quoted), to_canonical(quoted));
  TREG_CHECK_EQ(to_json(harness.registry().find_tenant(quoted.id).value()), escaped);
}

TREG_TEST(export, absent_optionals_render_unset_in_text_and_null_in_json) {
  Harness harness = Harness::ephemeral();
  const TenantRecord bare = harness.create_tenant("bare");
  const ServiceRecord service = harness.create_service("renderer");
  const IsolationDomainRecord domain = harness.create_domain("zone-a", IsolationClass::Administrative);

  const std::string tenant_text = to_canonical(bare);
  const std::string tenant_json = to_json(bare);
  for (const char* field : {"display_name", "retired_generation", "tombstone", "owner"}) {
    TREG_CHECK_EQ(count_substring(tenant_text, std::string{field} + "=unset\n"), std::size_t{1});
    TREG_CHECK_EQ(count_substring(tenant_json, std::string{"\""} + field + "\":null"), std::size_t{1});
  }
  TREG_CHECK_EQ(count_substring(tenant_text, "=unset\n"), std::size_t{4});
  TREG_CHECK_EQ(count_substring(tenant_json, ":null"), std::size_t{4});
  TREG_CHECK_EQ(tenant_text.find("display_name=\n"), std::string::npos);
  check_member_order(tenant_text, tenant_json);

  const std::string service_text = to_canonical(service);
  const std::string service_json = to_json(service);
  TREG_CHECK_EQ(count_substring(service_text, "=unset\n"), std::size_t{3});
  TREG_CHECK_EQ(count_substring(service_json, ":null"), std::size_t{3});
  check_member_order(service_text, service_json);

  const std::string domain_text = to_canonical(domain);
  const std::string domain_json = to_json(domain);
  TREG_CHECK_EQ(count_substring(domain_text, "=unset\n"), std::size_t{3});
  TREG_CHECK_EQ(count_substring(domain_json, ":null"), std::size_t{3});
  check_member_order(domain_text, domain_json);

  // An empty metadata set is still a member, and it is an empty object.
  TREG_CHECK_EQ(count_substring(tenant_json, "\"metadata\":{}"), std::size_t{1});
  TREG_CHECK_EQ(count_substring(tenant_text, "metadata."), std::size_t{0});
}

TREG_TEST(export, metadata_renders_one_line_per_entry_and_one_json_object) {
  Harness harness = Harness::ephemeral();
  const TenancyMetadata metadata =
      unwrap(TenancyMetadata::create({entry("tier", "gold"), entry("region", "eu")}, 64, 512), "metadata");
  const CreateTenantOutcome outcome =
      unwrap(harness.registry().create_tenant(CreateTenantRequest{context(harness.generation()),
                                                                 tenant_id("acme"), std::nullopt, std::nullopt,
                                                                 metadata}),
             "create_tenant");

  const std::string text = to_canonical(outcome.record);
  const std::string json = to_json(outcome.record);
  TREG_CHECK_EQ(count_substring(text, "metadata.region=text:2:eu\n"), std::size_t{1});
  TREG_CHECK_EQ(count_substring(text, "metadata.tier=text:4:gold\n"), std::size_t{1});
  TREG_CHECK_EQ(count_substring(json, "\"metadata\":{\"region\":\"eu\",\"tier\":\"gold\"}"), std::size_t{1});
  TREG_CHECK_EQ(json_members(json).back() == "origin_digest", true);
  check_text_shape(text);
  check_json_shape(json);
  check_member_order(text, json);
}

TREG_TEST(export, a_tombstone_and_its_permit_render_every_field) {
  Harness harness = Harness::ephemeral();
  const TenantRecord fenced = harness.create_tenant("fenced", std::optional<std::string>{"Fenced"},
                                                   std::optional<PrincipalId>{principal_id("ops")});
  require_ok(harness.transition(TenancySubject::of_tenant(fenced.id), fenced.revision, LifecycleState::Retired),
             "retire");
  const TenantRecord retired = harness.tenant("fenced");
  unwrap(harness.registry().tombstone(TombstoneRequest{context(harness.generation()),
                                                       TenancySubject::of_tenant(retired.id), retired.revision,
                                                       IrreversibleAcknowledgement::acknowledged(),
                                                       RebindSuccessor{SubjectKind::Tenant, std::string{"fenced"}},
                                                       std::string{"fenced for a successor"}}),
         "tombstone");

  // The identity record carries the tombstone it was fenced with.
  const std::string tenant_text = to_canonical(harness.tenant("fenced"));
  const std::string tenant_json = to_json(harness.tenant("fenced"));
  TREG_CHECK_EQ(count_substring(tenant_text, "retired_generation=generation:"), std::size_t{1});
  TREG_CHECK_EQ(count_substring(tenant_text, "tombstone=retired_generation="), std::size_t{1});
  // Every optional of this record is set, so nothing is unset.
  TREG_CHECK_EQ(count_substring(tenant_text, "=unset\n"), std::size_t{0});
  TREG_CHECK_EQ(count_substring(tenant_json, "\"tombstone\":\"retired_generation="), std::size_t{1});
  check_text_shape(tenant_text);
  check_json_shape(tenant_json);
  check_member_order(tenant_text, tenant_json);

  // The permanent tombstone record of the same identity renders the permit it
  // was fenced with, and a tombstone written without one says so.
  const TombstoneRecord with_permit = unwrap(harness.registry().find_tombstone(SubjectKind::Tenant, "fenced"),
                                            "find_tombstone");
  TREG_CHECK(with_permit.permit.has_value());
  const std::string permit_text = to_canonical(with_permit);
  const std::string permit_json = to_json(with_permit);
  TREG_CHECK_EQ(count_substring(permit_text, "permit=successor=tenant:fenced;"), std::size_t{1});
  // The permit's note and the tombstone's note are two different fields, and
  // both are rendered.
  TREG_CHECK_EQ(count_substring(permit_text, "note=fenced for a successor\n"), std::size_t{2});
  TREG_CHECK_EQ(count_substring(permit_text, "=unset\n"), std::size_t{0});
  check_text_shape(permit_text);
  check_json_shape(permit_json);
  check_member_order(permit_text, permit_json);

  const TenantRecord sealed = harness.create_tenant("sealed");
  require_ok(harness.transition(TenancySubject::of_tenant(sealed.id), sealed.revision, LifecycleState::Retired),
             "retire sealed");
  const TenantRecord sealed_retired = harness.tenant("sealed");
  unwrap(harness.registry().tombstone(TombstoneRequest{context(harness.generation()),
                                                       TenancySubject::of_tenant(sealed_retired.id),
                                                       sealed_retired.revision,
                                                       IrreversibleAcknowledgement::acknowledged(), std::nullopt,
                                                       std::string{"no successor"}}),
         "tombstone");
  const TombstoneRecord without_permit =
      unwrap(harness.registry().find_tombstone(SubjectKind::Tenant, "sealed"), "find_tombstone");
  TREG_CHECK(!without_permit.permit.has_value());
  TREG_CHECK_EQ(count_substring(to_canonical(without_permit), "permit=unset\n"), std::size_t{1});
  TREG_CHECK_EQ(count_substring(to_json(without_permit), "\"permit\":null"), std::size_t{1});
  check_member_order(to_canonical(without_permit), to_json(without_permit));
}

TREG_TEST(export, the_subject_record_carries_its_kind_first) {
  Harness harness = Harness::ephemeral();
  const TenancyMetadata metadata = unwrap(TenancyMetadata::create({entry("region", "eu")}, 64, 512), "metadata");
  const TenantRecord tenant =
      harness.create_tenant("acme", std::nullopt, std::nullopt, metadata);
  const ServiceRecord service = harness.create_service("renderer", std::nullopt, metadata);
  const IsolationDomainRecord domain = harness.create_domain("zone-a", IsolationClass::TenantPrivate);
  unwrap(harness.registry().set_metadata(SetMetadataRequest{context(harness.generation()),
                                                           TenancySubject::of_isolation_domain(domain.id),
                                                           domain.revision, {}, metadata.entries()}),
         "set_metadata");

  const std::vector<SubjectRecord> records{subject_record(harness.tenant("acme")),
                                           subject_record(harness.service("renderer")),
                                           subject_record(harness.domain("zone-a"))};
  const std::vector<std::string> kinds{"tenant", "service", "isolation_domain"};
  for (std::size_t index = 0; index < records.size(); ++index) {
    const std::string text = to_canonical(records.at(index));
    const std::string json = to_json(records.at(index));
    TREG_CHECK_EQ(text.rfind("kind=" + kinds.at(index) + "\n", 0), std::size_t{0});
    TREG_CHECK_EQ(json.rfind("{\"kind\":\"" + kinds.at(index) + "\",", 0), std::size_t{0});
    TREG_CHECK_EQ(subject_kind_token(records.at(index)), kinds.at(index));
    check_text_shape(text);
    check_json_shape(json);
    check_member_order(text, json);
    TREG_CHECK_EQ(text_lines(text).size(), json_members(json).size());
  }
}

}  // namespace
}  // namespace treg_test
