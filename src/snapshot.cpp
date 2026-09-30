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

#include "tenant_registry/snapshot.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "byte_codec.hpp"
#include "canonical_codec.hpp"
#include "sha256.hpp"
#include "utf8.hpp"
#include "tenant_registry/registry.hpp"

namespace tenant_registry {
namespace {

/// The largest snapshot this build will render without being told otherwise.
/// It matches the default RegistryLimits::max_snapshot_bytes, so a snapshot the
/// registry allowed to exist can always be rendered.
constexpr std::size_t kSnapshotRenderLimit = 64u * 1024u * 1024u;

/// Writes the part of the canonical form that describes tenancy state.
///
/// The control epoch, the incarnation, the store identity and the journal
/// position are deliberately NOT part of it. They describe the session that is
/// holding the state, not the state, and including them would mean two
/// registries holding identical tenancy facts could never have the same digest
/// -- which is precisely the comparison a snapshot digest exists to support.
/// They are still reported as fields of the snapshot and are still bound into
/// every mutating decision.
void append_state_header(detail::ByteWriter& writer, const RegistrySnapshot& snapshot) {
  writer.u64(snapshot.generation.value());
}

}  // namespace

std::size_t RegistrySnapshot::record_count() const noexcept {
  return tenants.size() + services.size() + isolation_domains.size() + ownership_edges.size() +
         service_bindings.size() + isolation_memberships.size() + tombstones.size();
}

std::string RegistrySnapshot::to_canonical_bytes() const {
  detail::ByteWriter writer{kSnapshotRenderLimit};
  append_state_header(writer, *this);

  writer.u32(static_cast<std::uint32_t>(tenants.size()));
  for (const auto& record : tenants) {
    detail::encode(writer, record);
  }
  writer.u32(static_cast<std::uint32_t>(services.size()));
  for (const auto& record : services) {
    detail::encode(writer, record);
  }
  writer.u32(static_cast<std::uint32_t>(isolation_domains.size()));
  for (const auto& record : isolation_domains) {
    detail::encode(writer, record);
  }
  writer.u32(static_cast<std::uint32_t>(ownership_edges.size()));
  for (const auto& record : ownership_edges) {
    detail::encode(writer, record);
  }
  writer.u32(static_cast<std::uint32_t>(service_bindings.size()));
  for (const auto& record : service_bindings) {
    detail::encode(writer, record);
  }
  writer.u32(static_cast<std::uint32_t>(isolation_memberships.size()));
  for (const auto& record : isolation_memberships) {
    detail::encode(writer, record);
  }
  writer.u32(static_cast<std::uint32_t>(tombstones.size()));
  for (const auto& record : tombstones) {
    detail::encode(writer, record);
  }
  writer.u32(static_cast<std::uint32_t>(domain_generations.size()));
  for (const auto& [domain, membership_generation] : domain_generations) {
    writer.length_prefixed(domain.value());
    writer.u64(membership_generation.value());
  }

  const auto& bytes = writer.bytes();
  return std::string{reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

ContentDigest RegistrySnapshot::digest() const {
  const std::string canonical = to_canonical_bytes();
  detail::Sha256 hasher;
  hasher.update(detail::canonical_preimage(detail::kSnapshotDigestDomain, ""));
  hasher.update(canonical);
  return hasher.finish();
}

std::optional<DomainGeneration> RegistrySnapshot::domain_generation(const IsolationDomainId& id) const {
  for (const auto& [domain, membership_generation] : domain_generations) {
    if (domain == id) {
      return membership_generation;
    }
  }
  return std::nullopt;
}

std::string RegistrySnapshot::to_json() const {
  std::string out;
  out.append("{\"generation\":").append(std::to_string(generation.value())).append(",\"control_epoch\":");
  out.append(std::to_string(control_epoch.value())).append(",\"incarnation\":");
  out.append(std::to_string(incarnation.value())).append(",\"store_id\":");
  if (store_id.has_value()) {
    out.append("\"").append(store_id->to_text()).append("\"");
  } else {
    out.append("null");
  }
  out.append(",\"committed_sequence\":").append(std::to_string(committed_sequence.value()));

  const auto emit = [&out](const char* name, const auto& collection) {
    out.append(",\"").append(name).append("\":[");
    bool first = true;
    for (const auto& record : collection) {
      if (!first) {
        out.append(",");
      }
      first = false;
      out.append(tenant_registry::to_json(record));
    }
    out.append("]");
  };

  emit("tenants", tenants);
  emit("services", services);
  emit("isolation_domains", isolation_domains);
  emit("ownership_edges", ownership_edges);
  emit("service_bindings", service_bindings);
  emit("isolation_memberships", isolation_memberships);
  emit("tombstones", tombstones);

  out.append(",\"domain_generations\":[");
  bool first = true;
  for (const auto& [domain, membership_generation] : domain_generations) {
    if (!first) {
      out.append(",");
    }
    first = false;
    out.append("{\"domain\":\"").append(domain.value()).append("\",\"membership_generation\":");
    out.append(std::to_string(membership_generation.value())).append("}");
  }
  out.append("]}");
  return out;
}

std::string RegistrySnapshot::to_text() const {
  std::string out;
  out.append("registry snapshot\n");
  out.append("  generation         : ").append(std::to_string(generation.value())).append("\n");
  out.append("  control_epoch      : ").append(std::to_string(control_epoch.value())).append("\n");
  out.append("  incarnation        : ").append(std::to_string(incarnation.value())).append("\n");
  out.append("  committed_sequence : ").append(std::to_string(committed_sequence.value())).append("\n");
  out.append("  store_id           : ");
  out.append(store_id.has_value() ? store_id->to_text() : std::string{"unset"}).append("\n");
  out.append("  tenants            : ").append(std::to_string(tenants.size())).append("\n");
  out.append("  services           : ").append(std::to_string(services.size())).append("\n");
  out.append("  isolation_domains  : ").append(std::to_string(isolation_domains.size())).append("\n");
  out.append("  ownership_edges    : ").append(std::to_string(ownership_edges.size())).append("\n");
  out.append("  service_bindings   : ").append(std::to_string(service_bindings.size())).append("\n");
  out.append("  memberships        : ").append(std::to_string(isolation_memberships.size())).append("\n");
  out.append("  tombstones         : ").append(std::to_string(tombstones.size())).append("\n");
  out.append("  digest             : ").append(digest().to_text()).append("\n");
  return out;
}

ContentDigest Explanation::digest() const {
  detail::ByteWriter writer{kSnapshotRenderLimit};
  detail::encode(writer, subject);
  std::visit([&writer](const auto& stored) { detail::encode(writer, stored); }, record);
  writer.optional(owner, [&](const PrincipalId& principal) { writer.length_prefixed(principal.value()); });
  writer.u32(static_cast<std::uint32_t>(owned_by.size()));
  for (const auto& edge : owned_by) {
    detail::encode(writer, edge);
  }
  writer.u32(static_cast<std::uint32_t>(ownership_lineage.size()));
  for (const auto& ancestor : ownership_lineage) {
    writer.length_prefixed(ancestor.value());
  }
  writer.u32(static_cast<std::uint32_t>(owns.size()));
  for (const auto& edge : owns) {
    detail::encode(writer, edge);
  }
  writer.u32(static_cast<std::uint32_t>(bindings.size()));
  for (const auto& binding : bindings) {
    detail::encode(writer, binding);
  }
  writer.u32(static_cast<std::uint32_t>(memberships.size()));
  for (const auto& membership : memberships) {
    detail::encode(writer, membership);
  }
  writer.u32(static_cast<std::uint32_t>(domain_generations.size()));
  for (const auto& [domain, membership_generation] : domain_generations) {
    writer.length_prefixed(domain.value());
    writer.u64(membership_generation.value());
  }
  writer.optional(outstanding_rebind_permit,
                  [&](const RebindPermit& permit) { detail::encode(writer, permit); });
  writer.u64(generation.value());
  writer.u64(control_epoch.value());
  writer.u64(incarnation.value());
  writer.u32(static_cast<std::uint32_t>(unknowns.size()));
  for (const auto& unknown : unknowns) {
    writer.length_prefixed(unknown);
  }

  detail::Sha256 hasher;
  hasher.update(detail::canonical_preimage(detail::kSnapshotDigestDomain, "explanation"));
  const auto& bytes = writer.bytes();
  hasher.update(std::span<const std::byte>{bytes.data(), bytes.size()});
  return hasher.finish();
}

std::string Explanation::to_json() const {
  std::string out;
  out.append("{\"subject\":\"").append(subject.to_text()).append("\",\"record\":");
  out.append(tenant_registry::to_json(record)).append(",\"owner\":");
  out.append(owner.has_value() ? "\"" + owner->value() + "\"" : std::string{"null"});

  const auto emit = [&out](const char* name, const auto& collection) {
    out.append(",\"").append(name).append("\":[");
    bool first = true;
    for (const auto& item : collection) {
      if (!first) {
        out.append(",");
      }
      first = false;
      out.append(tenant_registry::to_json(item));
    }
    out.append("]");
  };
  emit("owned_by", owned_by);

  out.append(",\"ownership_lineage\":[");
  bool first_lineage = true;
  for (const auto& ancestor : ownership_lineage) {
    if (!first_lineage) {
      out.append(",");
    }
    first_lineage = false;
    out.append("\"").append(ancestor.value()).append("\"");
  }
  out.append("]");

  emit("owns", owns);
  emit("bindings", bindings);
  emit("memberships", memberships);

  out.append(",\"domain_generations\":[");
  bool first = true;
  for (const auto& [domain, membership_generation] : domain_generations) {
    if (!first) {
      out.append(",");
    }
    first = false;
    out.append("{\"domain\":\"").append(domain.value()).append("\",\"membership_generation\":");
    out.append(std::to_string(membership_generation.value())).append("}");
  }
  out.append("],\"outstanding_rebind_permit\":");
  if (outstanding_rebind_permit.has_value()) {
    // The permit is rendered as a quoted string. Emitting its text unquoted
    // would produce a document that is not JSON at all, which is worse than
    // useless: a consumer would fail on a state the registry considers normal.
    std::string escaped;
    detail::json_escape(escaped, outstanding_rebind_permit->to_text());
    out.append("\"").append(escaped).append("\"");
  } else {
    out.append("null");
  }

  out.append(",\"generation\":").append(std::to_string(generation.value()));
  out.append(",\"control_epoch\":").append(std::to_string(control_epoch.value()));
  out.append(",\"incarnation\":").append(std::to_string(incarnation.value()));
  out.append(",\"unknowns\":[");
  first = true;
  for (const auto& unknown : unknowns) {
    if (!first) {
      out.append(",");
    }
    first = false;
    out.append("\"").append(unknown).append("\"");
  }
  out.append("]}");
  return out;
}

std::string Explanation::to_text() const {
  std::string out;
  out.append("subject   : ").append(subject.to_text()).append("\n");
  out.append("generation: ").append(std::to_string(generation.value())).append("\n");
  out.append("epoch     : ").append(std::to_string(control_epoch.value())).append("\n");
  out.append("incarn    : ").append(std::to_string(incarnation.value())).append("\n");
  out.append("owner     : ").append(owner.has_value() ? owner->value() : std::string{"unset"}).append("\n");
  out.append("owned_by  : ").append(std::to_string(owned_by.size())).append("\n");
  out.append("owns      : ").append(std::to_string(owns.size())).append("\n");
  out.append("bindings  : ").append(std::to_string(bindings.size())).append("\n");
  out.append("memberships: ").append(std::to_string(memberships.size())).append("\n");
  out.append("rebind    : ");
  out.append(outstanding_rebind_permit.has_value() ? outstanding_rebind_permit->to_text()
                                                   : std::string{"unset"})
      .append("\n");
  out.append("record    :\n").append(tenant_registry::to_canonical(record)).append("\n");
  if (unknowns.empty()) {
    out.append("unknowns  : none\n");
  } else {
    for (const auto& unknown : unknowns) {
      out.append("unknown   : ").append(unknown).append("\n");
    }
  }
  out.append("digest    : ").append(digest().to_text()).append("\n");
  return out;
}

std::string RegistryStats::to_text() const {
  std::string out;
  out.append("generation         : ").append(std::to_string(generation.value())).append("\n");
  out.append("control_epoch      : ").append(std::to_string(control_epoch.value())).append("\n");
  out.append("incarnation        : ").append(std::to_string(incarnation.value())).append("\n");
  out.append("committed_sequence : ").append(std::to_string(committed_sequence.value())).append("\n");
  out.append("store_id           : ");
  out.append(store_id.has_value() ? store_id->to_text() : std::string{"unset"}).append("\n");
  out.append("tenants            : ").append(std::to_string(tenants)).append("\n");
  out.append("services           : ").append(std::to_string(services)).append("\n");
  out.append("isolation_domains  : ").append(std::to_string(isolation_domains)).append("\n");
  out.append("ownership_edges    : ").append(std::to_string(ownership_edges)).append("\n");
  out.append("service_bindings   : ").append(std::to_string(service_bindings)).append("\n");
  out.append("memberships        : ").append(std::to_string(isolation_memberships)).append("\n");

  const auto emit = [&out](const char* name, const std::vector<StateCount>& counts) {
    out.append(name).append(":\n");
    for (const auto& entry : counts) {
      out.append("  ").append(to_token(entry.state)).append(" = ").append(std::to_string(entry.count)).append("\n");
    }
  };
  emit("tenants_by_state", tenants_by_state);
  emit("services_by_state", services_by_state);
  emit("domains_by_state", domains_by_state);
  return out;
}

}  // namespace tenant_registry
