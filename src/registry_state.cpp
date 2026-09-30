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

#include "registry_state.hpp"

#include <algorithm>
#include <cstddef>
#include <optional>
#include <set>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "tenant_registry/lifecycle.hpp"
#include "tenant_registry/records.hpp"

namespace tenant_registry {
namespace detail {
namespace {

constexpr char kSeparator = '|';

[[nodiscard]] std::string join(std::string_view prefix, std::string_view value) {
  std::string out;
  out.reserve(prefix.size() + value.size());
  out.append(prefix);
  out.append(value);
  return out;
}

[[nodiscard]] std::string join3(std::string_view prefix, std::string_view a, std::string_view b) {
  std::string out;
  out.reserve(prefix.size() + a.size() + b.size() + 1);
  out.append(prefix);
  out.append(a);
  out.push_back(kSeparator);
  out.append(b);
  return out;
}

}  // namespace

bool RegistryState::starts_with(std::string_view text, std::string_view prefix) noexcept {
  return text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0;
}

std::string identity_key(SubjectKind kind, std::string_view value) {
  switch (kind) {
    case SubjectKind::Tenant:
      return join("tenant:", value);
    case SubjectKind::Service:
      return join("service:", value);
    case SubjectKind::IsolationDomain:
      return join("isolation_domain:", value);
    case SubjectKind::Unspecified:
      break;
  }
  return std::string{};
}

std::string tenant_key(std::string_view value) { return join("tenant:", value); }
std::string service_key(std::string_view value) { return join("service:", value); }
std::string domain_key(std::string_view value) { return join("isolation_domain:", value); }

std::string ownership_key(std::string_view child, std::string_view parent) {
  return join3("ownership:", child, parent);
}

std::string binding_key(std::string_view service, std::string_view tenant, BindingKind kind) {
  std::string out;
  out.reserve(service.size() + tenant.size() + 24);
  out.append("binding:");
  out.append(service);
  out.push_back(kSeparator);
  out.append(tenant);
  out.push_back(kSeparator);
  out.append(to_token(kind));
  return out;
}

std::string membership_key(const TenancySubject& subject, const IsolationDomainId& domain) {
  return join3("membership:", subject.to_text(), domain.value());
}

std::string tombstone_key(SubjectKind kind, std::string_view value) {
  // This must produce exactly the string canonical_key(TombstoneRecord) builds.
  // Two builders exist only because the mutation path asks the question before
  // it has a record; if they ever disagree, a tombstone is written under one key
  // and looked for under another, which refuses a valid operation and then makes
  // the store unreadable. A test compares them for every kind.
  std::string out;
  out.reserve(value.size() + 32);
  out.append("tombstone:");
  switch (kind) {
    case SubjectKind::Tenant:
      out.append("tenant");
      break;
    case SubjectKind::Service:
      out.append("service");
      break;
    case SubjectKind::IsolationDomain:
      out.append("isolation_domain");
      break;
    case SubjectKind::Unspecified:
      return std::string{};
  }
  out.push_back(':');
  out.append(value);
  return out;
}

std::string_view key_prefix(RecordKind kind) noexcept {
  switch (kind) {
    case RecordKind::Tenant:
      return "tenant:";
    case RecordKind::Service:
      return "service:";
    case RecordKind::IsolationDomain:
      return "isolation_domain:";
    case RecordKind::OwnershipEdge:
      return "ownership:";
    case RecordKind::ServiceBinding:
      return "binding:";
    case RecordKind::IsolationMembership:
      return "membership:";
    case RecordKind::Tombstone:
      return "tombstone:";
    case RecordKind::Unspecified:
      break;
  }
  return std::string_view{};
}

RecordKind kind_of_key(std::string_view key) noexcept {
  constexpr RecordKind kKinds[] = {RecordKind::Tenant,          RecordKind::Service,
                                   RecordKind::IsolationDomain, RecordKind::OwnershipEdge,
                                   RecordKind::ServiceBinding,  RecordKind::IsolationMembership,
                                   RecordKind::Tombstone};
  for (const auto kind : kKinds) {
    const auto prefix = key_prefix(kind);
    if (RegistryState::starts_with(key, prefix)) {
      return kind;
    }
  }
  return RecordKind::Unspecified;
}

std::string ownership_child_prefix(std::string_view child) {
  return join3("ownership:", child, "");
}

std::string binding_service_prefix(std::string_view service) {
  return join3("binding:", service, "");
}

std::string membership_subject_prefix(const TenancySubject& subject) {
  return join3("membership:", subject.to_text(), "");
}

RegistryState::RegistryState(RegistryLimits limits_in) : limits(std::move(limits_in)) {
  generation = RegistryGeneration::initial();
}

std::size_t RegistryState::kind_index(RecordKind kind) noexcept {
  // The table is sized to the number of record kinds plus the unspecified slot.
  constexpr std::size_t kKindSlots = 8;
  const auto value = static_cast<std::size_t>(kind);
  return value < kKindSlots ? value : 0;
}

std::uint64_t RegistryState::count(RecordKind kind) const noexcept { return counts_[kind_index(kind)]; }

const AnyRecord* RegistryState::find(std::string_view key) const noexcept {
  const auto it = records.find(std::string{key});
  return it == records.end() ? nullptr : &it->second;
}

const TenantRecord* RegistryState::find_tenant(const TenantId& id) const noexcept {
  const auto* record = find(tenant_key(id.value()));
  if (record == nullptr) {
    return nullptr;
  }
  return std::get_if<TenantRecord>(record);
}

const ServiceRecord* RegistryState::find_service(const ServiceId& id) const noexcept {
  const auto* record = find(service_key(id.value()));
  if (record == nullptr) {
    return nullptr;
  }
  return std::get_if<ServiceRecord>(record);
}

const IsolationDomainRecord* RegistryState::find_domain(const IsolationDomainId& id) const noexcept {
  const auto* record = find(domain_key(id.value()));
  if (record == nullptr) {
    return nullptr;
  }
  return std::get_if<IsolationDomainRecord>(record);
}

const OwnershipEdge* RegistryState::find_ownership(std::string_view child, std::string_view parent) const noexcept {
  const auto* record = find(ownership_key(child, parent));
  if (record == nullptr) {
    return nullptr;
  }
  return std::get_if<OwnershipEdge>(record);
}

const ServiceBinding* RegistryState::find_binding(std::string_view service, std::string_view tenant,
                                                  BindingKind kind) const noexcept {
  const auto* record = find(binding_key(service, tenant, kind));
  if (record == nullptr) {
    return nullptr;
  }
  return std::get_if<ServiceBinding>(record);
}

const IsolationMembership* RegistryState::find_membership(const TenancySubject& subject,
                                                          const IsolationDomainId& domain) const noexcept {
  const auto* record = find(membership_key(subject, domain));
  if (record == nullptr) {
    return nullptr;
  }
  return std::get_if<IsolationMembership>(record);
}

std::optional<TombstoneRecord> RegistryState::find_tombstone(SubjectKind kind, std::string_view value) const {
  if (kind == SubjectKind::Unspecified) {
    return std::nullopt;
  }
  const auto key = tombstone_key(kind, value);
  if (key.empty()) {
    return std::nullopt;
  }
  if (const auto* stored = find(key); stored != nullptr) {
    if (const auto* tombstone = std::get_if<TombstoneRecord>(stored); tombstone != nullptr) {
      return *tombstone;
    }
  }
  // A tombstoned identity that has not been reused yet lives in the identity
  // map with state Tombstoned. Projecting it here means that "is this identity
  // fenced" has exactly one answer, before and after a permitted rebind.
  const auto* identity = find(identity_key(kind, value));
  if (identity == nullptr) {
    return std::nullopt;
  }
  return std::visit(
      [](const auto& stored) -> std::optional<TombstoneRecord> {
        using Stored = std::decay_t<decltype(stored)>;
        if constexpr (std::is_same_v<Stored, TenantRecord> || std::is_same_v<Stored, ServiceRecord> ||
                      std::is_same_v<Stored, IsolationDomainRecord>) {
          if (!stored.tombstone.has_value()) {
            return std::nullopt;
          }
          SubjectKind stored_kind = SubjectKind::Tenant;
          if constexpr (std::is_same_v<Stored, ServiceRecord>) {
            stored_kind = SubjectKind::Service;
          } else if constexpr (std::is_same_v<Stored, IsolationDomainRecord>) {
            stored_kind = SubjectKind::IsolationDomain;
          }
          const auto& tombstone = *stored.tombstone;
          return TombstoneRecord{stored_kind,
                                 std::string{stored.id.value()},
                                 LifecycleState::Tombstoned,
                                 stored.revision,
                                 tombstone.retired_generation(),
                                 tombstone.tombstoned_generation(),
                                 tombstone.rebind_permit(),
                                 tombstone.note(),
                                 stored.provenance,
                                 stored.origin_digest};
        } else {
          return std::nullopt;
        }
      },
      *identity);
}

void RegistryState::apply(AnyRecord record) {
  const std::string key = canonical_key(record);
  const auto it = records.find(key);
  if (it == records.end()) {
    ++counts_[kind_index(kind_of(record))];
    if (const auto* edge = std::get_if<OwnershipEdge>(&record); edge != nullptr) {
      ++children_of_[std::string{edge->parent.value()}];
    }
    records.emplace(key, std::move(record));
    return;
  }
  // A replacement keeps the canonical key, and for an ownership edge the key
  // contains both endpoints, so the parent cannot have changed and the index
  // stays correct without being touched.
  it->second = std::move(record);
}

bool RegistryState::erase(std::string_view key) {
  const auto it = records.find(std::string{key});
  if (it == records.end()) {
    return false;
  }
  --counts_[kind_index(kind_of(it->second))];
  if (const auto* edge = std::get_if<OwnershipEdge>(&it->second); edge != nullptr) {
    const auto found = children_of_.find(std::string{edge->parent.value()});
    if (found != children_of_.end()) {
      if (found->second <= 1) {
        children_of_.erase(found);
      } else {
        --found->second;
      }
    }
  }
  records.erase(it);
  return true;
}

std::uint64_t RegistryState::child_count(std::string_view parent) const noexcept {
  const auto found = children_of_.find(std::string{parent});
  return found == children_of_.end() ? 0 : found->second;
}

void RegistryState::reset() {
  records.clear();
  ledger.clear();
  children_of_.clear();
  counts_.fill(0);
  generation = RegistryGeneration::initial();
}

std::string RegistryState::shape_text() const {
  std::string out;
  out.append("generation=").append(std::to_string(generation.value()));
  out.append(" tenants=").append(std::to_string(count(RecordKind::Tenant)));
  out.append(" services=").append(std::to_string(count(RecordKind::Service)));
  out.append(" isolation_domains=").append(std::to_string(count(RecordKind::IsolationDomain)));
  out.append(" ownership_edges=").append(std::to_string(count(RecordKind::OwnershipEdge)));
  out.append(" service_bindings=").append(std::to_string(count(RecordKind::ServiceBinding)));
  out.append(" isolation_memberships=").append(std::to_string(count(RecordKind::IsolationMembership)));
  out.append(" ledger=").append(std::to_string(ledger.size()));
  return out;
}

Status RegistryState::validate(std::string& detail) const {
  // The order of these checks is the order of the diagnostics. Two runs over
  // the same state therefore produce the same first refusal.

  // One slot per record kind including the unspecified slot, which is the same
  // sizing rule RegistryState::counts_ uses. A narrower table would index past
  // its end as soon as a new record kind is added.
  std::array<std::uint64_t, 8> derived{};
  for (const auto& [key, record] : records) {
    const auto kind = kind_of(record);
    if (kind == RecordKind::Unspecified) {
      detail = "a record has no kind";
      return Status::failure(ErrorCode::InternalInvariantViolated, detail);
    }
    if (canonical_key(record) != key) {
      detail = "record " + key + " is stored under a key its own canonical form disagrees with";
      return Status::failure(ErrorCode::InternalInvariantViolated, detail);
    }
    ++derived[static_cast<std::size_t>(kind)];
  }
  for (std::size_t index = 0; index < derived.size(); ++index) {
    if (derived[index] != counts_[index]) {
      detail = "record counts disagree with the stored map for kind index " + std::to_string(index);
      return Status::failure(ErrorCode::InternalInvariantViolated, detail);
    }
  }

  // The children index is derived state, so it is re-derived here and compared.
  // An index that had drifted from the map would let a bound be enforced
  // against a number that is not true.
  {
    std::map<std::string, std::uint64_t> expected_children;
    for (const auto& [key, record] : records) {
      (void)key;
      if (const auto* edge = std::get_if<OwnershipEdge>(&record); edge != nullptr) {
        ++expected_children[std::string{edge->parent.value()}];
      }
    }
    if (expected_children.size() != children_of_.size()) {
      detail = "the children index holds a different number of owners than the record map";
      return Status::failure(ErrorCode::InternalInvariantViolated, detail);
    }
    for (const auto& [parent, count] : expected_children) {
      if (child_count(parent) != count) {
        detail = "the children index disagrees with the record map for " + parent;
        return Status::failure(ErrorCode::InternalInvariantViolated, detail);
      }
    }
  }

  // Identity records.
  for (const auto& [key, record] : records) {
    const auto kind = kind_of(record);
    if (kind == RecordKind::Tenant) {
      const auto& tenant = std::get<TenantRecord>(record);
      if (tenant.revision.value() < 1) {
        detail = "tenant " + key + " has revision zero";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
      if (tenant.updated_generation < tenant.created_generation) {
        detail = "tenant " + key + " was updated before it was created";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
      const bool retired = tenant.state == LifecycleState::Retired || tenant.state == LifecycleState::Tombstoned;
      if (retired != tenant.retired_generation.has_value()) {
        detail = "tenant " + key + " has a retirement generation that disagrees with its state";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
      const bool tombstoned = tenant.state == LifecycleState::Tombstoned;
      if (tombstoned != tenant.tombstone.has_value()) {
        detail = "tenant " + key + " has a tombstone that disagrees with its state";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
      if (tenant.state == LifecycleState::Unspecified) {
        detail = "tenant " + key + " has no lifecycle state";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
    } else if (kind == RecordKind::Service) {
      const auto& service = std::get<ServiceRecord>(record);
      if (service.revision.value() < 1) {
        detail = "service " + key + " has revision zero";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
      if (service.updated_generation < service.created_generation) {
        detail = "service " + key + " was updated before it was created";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
      const bool retired = service.state == LifecycleState::Retired || service.state == LifecycleState::Tombstoned;
      if (retired != service.retired_generation.has_value()) {
        detail = "service " + key + " has a retirement generation that disagrees with its state";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
      const bool tombstoned = service.state == LifecycleState::Tombstoned;
      if (tombstoned != service.tombstone.has_value()) {
        detail = "service " + key + " has a tombstone that disagrees with its state";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
      if (service.state == LifecycleState::Unspecified) {
        detail = "service " + key + " has no lifecycle state";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
    } else if (kind == RecordKind::IsolationDomain) {
      const auto& domain = std::get<IsolationDomainRecord>(record);
      if (domain.revision.value() < 1) {
        detail = "isolation domain " + key + " has revision zero";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
      if (domain.isolation_class == IsolationClass::Unspecified) {
        detail = "isolation domain " + key + " has no declared isolation class";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
      if (domain.updated_generation < domain.created_generation) {
        detail = "isolation domain " + key + " was updated before it was created";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
      const bool retired = domain.state == LifecycleState::Retired || domain.state == LifecycleState::Tombstoned;
      if (retired != domain.retired_generation.has_value()) {
        detail = "isolation domain " + key + " has a retirement generation that disagrees with its state";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
      const bool tombstoned = domain.state == LifecycleState::Tombstoned;
      if (tombstoned != domain.tombstone.has_value()) {
        detail = "isolation domain " + key + " has a tombstone that disagrees with its state";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
    }
  }

  // Relationships must never dangle.
  for (const auto& [key, record] : records) {
    const auto kind = kind_of(record);
    if (kind == RecordKind::OwnershipEdge) {
      const auto& edge = std::get<OwnershipEdge>(record);
      const auto* child = find_tenant(edge.child);
      if (child == nullptr) {
        detail = "ownership edge " + key + " names a child tenant that does not exist";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
      const auto* parent = find_tenant(edge.parent);
      if (parent == nullptr) {
        detail = "ownership edge " + key + " names a parent tenant that does not exist";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
      if (is_terminal(child->state) || is_terminal(parent->state)) {
        detail = "ownership edge " + key + " involves a tenant that can never move again";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
      if (edge.state == LifecycleState::Unspecified || edge.state == LifecycleState::Tombstoned) {
        detail = "ownership edge " + key + " has a state a relationship may not have";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
      if (edge.revision.value() < 1) {
        detail = "ownership edge " + key + " has revision zero";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
      if (edge.child == edge.parent) {
        detail = "ownership edge " + key + " is its own parent";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
    } else if (kind == RecordKind::ServiceBinding) {
      const auto& binding = std::get<ServiceBinding>(record);
      if (find_service(binding.service) == nullptr) {
        detail = "service binding " + key + " names a service that does not exist";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
      if (find_tenant(binding.tenant) == nullptr) {
        detail = "service binding " + key + " names a tenant that does not exist";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
      if (binding.state == LifecycleState::Unspecified || binding.state == LifecycleState::Tombstoned) {
        detail = "service binding " + key + " has a state a relationship may not have";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
      if (binding.kind == BindingKind::Unspecified) {
        detail = "service binding " + key + " has no declared kind";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
      if (binding.revision.value() < 1) {
        detail = "service binding " + key + " has revision zero";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
    } else if (kind == RecordKind::IsolationMembership) {
      const auto& membership = std::get<IsolationMembership>(record);
      const auto subject_key = identity_key(membership.subject.kind(), membership.subject.identity_value());
      if (find(subject_key) == nullptr) {
        detail = "isolation membership " + key + " names a subject that does not exist";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
      if (find_domain(membership.domain) == nullptr) {
        detail = "isolation membership " + key + " names a domain that does not exist";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
      if (membership.state == MembershipState::Unspecified || membership.state == MembershipState::Withdrawn) {
        detail = "isolation membership " + key + " is stored in a state that must not be stored";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
      if (membership.role == MembershipRole::Unspecified) {
        detail = "isolation membership " + key + " has no declared role";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
      if (membership.revision.value() < 1) {
        detail = "isolation membership " + key + " has revision zero";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
    }
  }

  // Tombstones are permanent records. Their own key must agree with their
  // contents, their state must be Tombstoned, and an identity may never be both
  // fenced and live at the same time.
  for (const auto& [key, record] : records) {
    if (kind_of(record) != RecordKind::Tombstone) {
      continue;
    }
    const auto& tombstone = std::get<TombstoneRecord>(record);
    if (tombstone.kind == SubjectKind::Unspecified) {
      detail = "tombstone " + key + " names no identity kind";
      return Status::failure(ErrorCode::StoreCorrupt, detail);
    }
    if (tombstone_key(tombstone.kind, tombstone.identity) != key) {
      detail = "tombstone " + key + " is stored under a key its own identity disagrees with";
      return Status::failure(ErrorCode::StoreCorrupt, detail);
    }
    if (tombstone.state != LifecycleState::Tombstoned) {
      detail = "tombstone " + key + " is not in the tombstoned state";
      return Status::failure(ErrorCode::StoreCorrupt, detail);
    }
    if (tombstone.revision.value() < 1) {
      detail = "tombstone " + key + " has revision zero";
      return Status::failure(ErrorCode::StoreCorrupt, detail);
    }
    if (tombstone.retired_generation.value() < 1 ||
        tombstone.tombstoned_generation < tombstone.retired_generation) {
      detail = "tombstone " + key + " has retirement and tombstone generations that cannot both be true";
      return Status::failure(ErrorCode::StoreCorrupt, detail);
    }
    if (tombstone.permit.has_value()) {
      const auto& permit = *tombstone.permit;
      if (permit.successor_kind() != tombstone.kind || !permit.consumed()) {
        detail = "tombstone " + key + " carries a permit that was not consumed for this identity";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
    }
  }

  // An identity is either live or fenced -- with exactly one exception, which is
  // the handover the rebind design is built on. When a permit is consumed, the
  // tombstone is moved to its permanent record and a fresh successor record
  // takes the identity's place, so from that moment the identity IS both live
  // and fenced, and the tombstone is the only remaining proof that it was once
  // fenced. That coexistence is legal precisely because the consumed permit
  // records it; any other coexistence is corruption and stays refused.
  for (const auto& [key, record] : records) {
    if (kind_of(record) != RecordKind::Tombstone) {
      continue;
    }
    const auto& tombstone = std::get<TombstoneRecord>(record);
    const bool handed_over = tombstone.permit.has_value() && tombstone.permit->consumed();
    if (!handed_over && find(identity_key(tombstone.kind, tombstone.identity)) != nullptr) {
      detail = "identity " + identity_key(tombstone.kind, tombstone.identity) +
               " is both live and fenced by tombstone " + key +
               " without a consumed rebind permit to record the handover";
      return Status::failure(ErrorCode::StoreCorrupt, detail);
    }
  }

  // At most one in-force binding per service and kind.
  {
    std::set<std::string> seen;
    for (const auto& [key, record] : records) {
      if (kind_of(record) != RecordKind::ServiceBinding) {
        continue;
      }
      const auto& binding = std::get<ServiceBinding>(record);
      if (!is_in_force(binding.state)) {
        continue;
      }
      std::string marker = binding.service.value();
      marker.push_back(kSeparator);
      marker.append(to_token(binding.kind));
      if (!seen.insert(marker).second) {
        detail = "service " + binding.service.value() + " has more than one in-force " +
                 std::string{to_token(binding.kind)} + " binding";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
    }
  }

  // At most one in-force administrative owner per child.
  {
    std::set<std::string> seen;
    for (const auto& [key, record] : records) {
      if (kind_of(record) != RecordKind::OwnershipEdge) {
        continue;
      }
      const auto& edge = std::get<OwnershipEdge>(record);
      if (!is_in_force(edge.state) || edge.kind != OwnershipKind::Administrative) {
        continue;
      }
      if (!seen.insert(edge.child.value()).second) {
        detail = "tenant " + edge.child.value() + " has more than one in-force administrative owner";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
    }
  }

  // At most one in-force primary membership per subject.
  {
    std::set<std::string> seen;
    for (const auto& [key, record] : records) {
      if (kind_of(record) != RecordKind::IsolationMembership) {
        continue;
      }
      const auto& membership = std::get<IsolationMembership>(record);
      if (membership.state != MembershipState::Bound || membership.role != MembershipRole::Primary) {
        continue;
      }
      const auto key_text = identity_key(membership.subject.kind(), membership.subject.identity_value());
      if (!seen.insert(key_text).second) {
        detail = "subject " + key_text + " has more than one in-force primary isolation domain";
        return Status::failure(ErrorCode::StoreCorrupt, detail);
      }
    }
  }

  // The ownership graph must be acyclic. The walk is a single depth first pass
  // over the parent adjacency, so it is linear in the number of edges and
  // cannot be made to recurse without bound by a crafted state.
  {
    std::map<std::string, std::vector<std::string>> parents_of;
    for (const auto& [key, record] : records) {
      if (kind_of(record) != RecordKind::OwnershipEdge) {
        continue;
      }
      const auto& edge = std::get<OwnershipEdge>(record);
      parents_of[tenant_key(edge.child.value())].push_back(tenant_key(edge.parent.value()));
    }
    std::map<std::string, int> colour;  // 0 unvisited, 1 on the stack, 2 finished
    std::vector<std::pair<std::string, std::size_t>> stack;
    for (const auto& [key, record] : records) {
      if (kind_of(record) != RecordKind::Tenant) {
        continue;
      }
      const std::string root = tenant_key(std::get<TenantRecord>(record).id.value());
      if (colour[root] == 2) {
        continue;
      }
      colour[root] = 1;
      stack.emplace_back(root, 0);
      while (!stack.empty()) {
        auto& [node, index] = stack.back();
        const auto found = parents_of.find(node);
        if (found == parents_of.end() || index >= found->second.size()) {
          colour[node] = 2;
          stack.pop_back();
          continue;
        }
        const std::string& next = found->second[index];
        ++index;
        const int state = colour[next];
        if (state == 1) {
          detail = "the ownership graph contains a cycle through " + next;
          return Status::failure(ErrorCode::StoreCorrupt, detail);
        }
        if (state == 2) {
          continue;
        }
        colour[next] = 1;
        stack.emplace_back(next, 0);
      }
    }
  }

  // The idempotency ledger is derived from the log, so every entry must look
  // like something the log could have produced.
  for (const auto& [key, entry] : ledger) {
    if (entry.key.value() != key) {
      detail = "idempotency ledger entry " + key + " is stored under a key that disagrees with its own";
      return Status::failure(ErrorCode::InternalInvariantViolated, detail);
    }
    if (entry.primary_key.empty()) {
      detail = "idempotency ledger entry " + key + " names no subject";
      return Status::failure(ErrorCode::StoreCorrupt, detail);
    }
    if (entry.generation.value() < 1) {
      detail = "idempotency ledger entry " + key + " has generation zero";
      return Status::failure(ErrorCode::StoreCorrupt, detail);
    }
    if (entry.outcome_payload.size() > limits.max_idempotency_outcome_bytes) {
      detail = "idempotency ledger entry " + key + " carries too much outcome content";
      return Status::failure(ErrorCode::StoreCorrupt, detail);
    }
    if (entry.sequence.value() < 1) {
      detail = "idempotency ledger entry " + key + " has sequence zero";
      return Status::failure(ErrorCode::StoreCorrupt, detail);
    }
  }

  // Counts against the limits.
  const std::pair<RecordKind, std::uint64_t> bounded[] = {
      {RecordKind::Tenant, limits.max_tenants},
      {RecordKind::Service, limits.max_services},
      {RecordKind::IsolationDomain, limits.max_isolation_domains},
      {RecordKind::OwnershipEdge, limits.max_ownership_edges},
      {RecordKind::ServiceBinding, limits.max_service_bindings},
      {RecordKind::IsolationMembership, limits.max_isolation_memberships},
  };
  for (const auto& [kind, bound] : bounded) {
    if (count(kind) > bound) {
      detail = std::string{"the stored state holds "} + std::to_string(count(kind)) + " " +
               std::string{key_prefix(kind)} + " records, above the configured limit of " + std::to_string(bound);
      return Status::failure(ErrorCode::LimitExceeded, detail);
    }
  }

  if (ledger.size() > limits.max_idempotency_entries) {
    detail = "the idempotency ledger holds more entries than the configured limit";
    return Status::failure(ErrorCode::LimitExceeded, detail);
  }

  detail.clear();
  return Status::success();
}

}  // namespace detail
}  // namespace tenant_registry
