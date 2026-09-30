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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <type_traits>
#include <variant>
#include <vector>

#include "canonical_codec.hpp"
#include "registry_internal.hpp"
#include "registry_state.hpp"
#include "tenant_registry/lifecycle.hpp"
#include "tenant_registry/registry.hpp"

namespace tenant_registry {

using detail::AnyRecord;
using detail::RecordKind;
using detail::RegistryState;

namespace detail {
namespace {

/// The page size a query actually uses: the caller's limit, or the configured
/// default when the caller did not state one. A caller may never ask for more
/// than the configured maximum, and asking for more is refused rather than
/// silently reduced, because a silently reduced page looks like a complete one.
[[nodiscard]] Result<std::size_t> effective_limit(std::size_t requested, const RegistryLimits& limits) {
  if (requested == 0) {
    return limits.default_listing_limit;
  }
  if (requested > limits.max_listing_limit) {
    return Error{ErrorCode::ListingLimitExceeded,
                 "the requested page size " + std::to_string(requested) +
                     " is above the configured maximum of " + std::to_string(limits.max_listing_limit)};
  }
  return requested;
}

/// Streams one record kind, applies a filter, applies an opaque cursor and
/// collects at most limit summaries.
///
/// total_matched counts every record of that kind that passes the filter,
/// whether or not it fits in the page, so a caller can tell "that is all there
/// is" from "that is all that fitted".
template <class Summary, class Filter, class Extract>
[[nodiscard]] Page<Summary> scan(const RegistryState& state, RecordKind kind, std::size_t limit,
                                 const std::optional<std::string>& cursor, Filter filter, Extract extract) {
  Page<Summary> page;
  const std::string_view prefix = key_prefix(kind);
  bool skipping = cursor.has_value();
  std::optional<std::string> last_key;

  for (auto it = state.records.lower_bound(std::string{prefix}); it != state.records.end(); ++it) {
    if (!RegistryState::starts_with(it->first, prefix)) {
      break;
    }
    if (!filter(it->second)) {
      continue;
    }
    ++page.total_matched;
    if (skipping) {
      if (it->first == *cursor) {
        skipping = false;
      }
      continue;
    }
    if (page.items.size() < limit) {
      page.items.push_back(extract(it->second));
      last_key = it->first;
    } else {
      page.truncated = true;
    }
  }

  if (page.truncated && last_key.has_value()) {
    page.next_cursor = std::move(last_key);
  } else {
    page.next_cursor.reset();
  }
  return page;
}

[[nodiscard]] bool tenant_matches(const RegistryState& state, const TenantRecord& tenant,
                                  const TenantQuery& query) {
  if (query.state.has_value() && tenant.state != *query.state) {
    return false;
  }
  if (query.owner.has_value()) {
    if (!tenant.owner.has_value() || !(*tenant.owner == *query.owner)) {
      return false;
    }
  }
  if (query.member_of_domain.has_value()) {
    const auto membership = state.find_membership(TenancySubject::of_tenant(tenant.id), *query.member_of_domain);
    if (membership == nullptr || membership->state == MembershipState::Withdrawn) {
      return false;
    }
    if (query.member_state.has_value() && membership->state != *query.member_state) {
      return false;
    }
  } else if (query.member_state.has_value()) {
    return false;
  }
  if (query.child_of.has_value()) {
    if (state.find_ownership(tenant.id.value(), query.child_of->value()) == nullptr) {
      return false;
    }
  }
  if (query.parent_of.has_value()) {
    bool found = false;
    state.for_each_prefix(ownership_child_prefix(query.parent_of->value()), [&](const AnyRecord& stored) {
      const auto& edge = std::get<OwnershipEdge>(stored);
      if (edge.child.value() == query.parent_of->value() && edge.parent.value() == tenant.id.value()) {
        found = true;
        return false;
      }
      return true;
    });
    if (!found) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] bool service_matches(const RegistryState& state, const ServiceRecord& service,
                                   const ServiceQuery& query) {
  if (query.state.has_value() && service.state != *query.state) {
    return false;
  }
  if (query.bound_to_tenant.has_value() || query.binding_kind.has_value()) {
    bool found = false;
    state.for_each_prefix(binding_service_prefix(service.id.value()), [&](const AnyRecord& stored) {
      const auto& binding = std::get<ServiceBinding>(stored);
      if (binding.service.value() != service.id.value()) {
        return true;
      }
      if (query.bound_to_tenant.has_value() && !(binding.tenant == *query.bound_to_tenant)) {
        return true;
      }
      if (query.binding_kind.has_value() && binding.kind != *query.binding_kind) {
        return true;
      }
      found = true;
      return false;
    });
    if (!found) {
      return false;
    }
  }
  if (query.member_of_domain.has_value()) {
    if (state.find_membership(TenancySubject::of_service(service.id), *query.member_of_domain) == nullptr) {
      return false;
    }
  }
  return true;
}

}  // namespace
}  // namespace detail

// ---------------------------------------------------------------------------
// Traversal direction tokens
// ---------------------------------------------------------------------------

std::string_view to_token(TraversalDirection direction) noexcept {
  switch (direction) {
    case TraversalDirection::Ancestors:
      return "ancestors";
    case TraversalDirection::Descendants:
      return "descendants";
    case TraversalDirection::Unspecified:
      break;
  }
  return "unspecified";
}

bool parse_traversal_direction(std::string_view token, TraversalDirection& out) noexcept {
  if (token == "ancestors") {
    out = TraversalDirection::Ancestors;
    return true;
  }
  if (token == "descendants") {
    out = TraversalDirection::Descendants;
    return true;
  }
  // "unspecified" is deliberately not accepted as a direction: walking in an
  // unspecified direction would be a wider answer than the caller asked for.
  return false;
}

// ---------------------------------------------------------------------------
// Point lookups
// ---------------------------------------------------------------------------

Result<TenantRecord> TenantRegistry::find_tenant(const TenantId& id) const {
  if (core_ == nullptr || core_->closed) {
    return Error{ErrorCode::StoreClosed, core_ == nullptr ? "this registry session has been moved from"
                                                          : "this registry session has been closed"};
  }
  auto guard = core_->lock();
  const auto* record = core_->state.find_tenant(id);
  if (record == nullptr) {
    return Error{ErrorCode::NotFound, "tenant " + id.value() + " is not registered"};
  }
  return *record;
}

Result<ServiceRecord> TenantRegistry::find_service(const ServiceId& id) const {
  if (core_ == nullptr || core_->closed) {
    return Error{ErrorCode::StoreClosed, core_ == nullptr ? "this registry session has been moved from"
                                                          : "this registry session has been closed"};
  }
  auto guard = core_->lock();
  const auto* record = core_->state.find_service(id);
  if (record == nullptr) {
    return Error{ErrorCode::NotFound, "service " + id.value() + " is not registered"};
  }
  return *record;
}

Result<IsolationDomainRecord> TenantRegistry::find_isolation_domain(const IsolationDomainId& id) const {
  if (core_ == nullptr || core_->closed) {
    return Error{ErrorCode::StoreClosed, core_ == nullptr ? "this registry session has been moved from"
                                                          : "this registry session has been closed"};
  }
  auto guard = core_->lock();
  const auto* record = core_->state.find_domain(id);
  if (record == nullptr) {
    return Error{ErrorCode::NotFound, "isolation domain " + id.value() + " is not registered"};
  }
  return *record;
}

Result<IsolationDomainRecord> TenantRegistry::find_isolation_domain(
    const IsolationDomainId& id, const DomainGeneration& expected_membership_generation) const {
  if (core_ == nullptr || core_->closed) {
    return Error{ErrorCode::StoreClosed, core_ == nullptr ? "this registry session has been moved from"
                                                          : "this registry session has been closed"};
  }
  auto guard = core_->lock();
  const auto* record = core_->state.find_domain(id);
  if (record == nullptr) {
    return Error{ErrorCode::NotFound, "isolation domain " + id.value() + " is not registered"};
  }
  if (record->membership_generation != expected_membership_generation) {
    return Error{ErrorCode::StaleDomainGeneration,
                 "the caller cached membership generation " +
                     std::to_string(expected_membership_generation.value()) + " of isolation domain " + id.value() +
                     " but that domain is at generation " +
                     std::to_string(record->membership_generation.value()) +
                     "; the cached membership set is fenced and must be re-read"};
  }
  return *record;
}

Result<SubjectRecord> TenantRegistry::find_subject(const TenancySubject& subject) const {
  if (core_ == nullptr || core_->closed) {
    return Error{ErrorCode::StoreClosed, core_ == nullptr ? "this registry session has been moved from"
                                                          : "this registry session has been closed"};
  }
  auto guard = core_->lock();
  const auto* record = core_->state.find(detail::identity_key(subject.kind(), subject.identity_value()));
  if (record == nullptr) {
    return Error{ErrorCode::NotFound, subject.to_text() + " is not registered"};
  }
  if (const auto* tenant = std::get_if<TenantRecord>(record); tenant != nullptr) {
    return SubjectRecord{*tenant};
  }
  if (const auto* service = std::get_if<ServiceRecord>(record); service != nullptr) {
    return SubjectRecord{*service};
  }
  if (const auto* domain = std::get_if<IsolationDomainRecord>(record); domain != nullptr) {
    return SubjectRecord{*domain};
  }
  return Error{ErrorCode::InternalInvariantViolated, subject.to_text() + " is not an identity record"};
}

Result<TombstoneRecord> TenantRegistry::find_tombstone(SubjectKind kind, std::string_view identity) const {
  if (core_ == nullptr || core_->closed) {
    return Error{ErrorCode::StoreClosed, core_ == nullptr ? "this registry session has been moved from"
                                                          : "this registry session has been closed"};
  }
  if (kind == SubjectKind::Unspecified) {
    return Error{ErrorCode::InvalidIdKind, "the identity kind is unspecified"};
  }
  if (const auto text = detail::check_identity_text(kind, identity); !text.ok()) {
    return text.error();
  }
  auto guard = core_->lock();
  auto tombstone = core_->state.find_tombstone(kind, identity);
  if (!tombstone.has_value()) {
    return Error{ErrorCode::NotFound,
                 identity_text(kind, identity) + " has never been tombstoned, so no rebind policy exists for it"};
  }
  return std::move(tombstone).value();
}

// ---------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------

Result<Page<TenantSummary>> TenantRegistry::list_tenants(const TenantQuery& query) const {
  if (core_ == nullptr || core_->closed) {
    return Error{ErrorCode::StoreClosed, core_ == nullptr ? "this registry session has been moved from"
                                                          : "this registry session has been closed"};
  }
  const RegistryLimits limits = core_->limits;
  auto limit = detail::effective_limit(query.limit, limits);
  if (!limit) {
    return limit.error();
  }
  auto guard = core_->lock();
  const RegistryState& state = core_->state;
  return detail::scan<TenantSummary>(
      state, detail::RecordKind::Tenant, limit.value(), query.cursor,
      [&](const detail::AnyRecord& stored) {
        return detail::tenant_matches(state, std::get<TenantRecord>(stored), query);
      },
      [](const detail::AnyRecord& stored) {
        const auto& tenant = std::get<TenantRecord>(stored);
        return TenantSummary{tenant.id, tenant.display_name, tenant.state, tenant.revision};
      });
}

Result<Page<ServiceSummary>> TenantRegistry::list_services(const ServiceQuery& query) const {
  if (core_ == nullptr || core_->closed) {
    return Error{ErrorCode::StoreClosed, core_ == nullptr ? "this registry session has been moved from"
                                                          : "this registry session has been closed"};
  }
  const RegistryLimits limits = core_->limits;
  auto limit = detail::effective_limit(query.limit, limits);
  if (!limit) {
    return limit.error();
  }
  auto guard = core_->lock();
  const RegistryState& state = core_->state;
  return detail::scan<ServiceSummary>(
      state, detail::RecordKind::Service, limit.value(), query.cursor,
      [&](const detail::AnyRecord& stored) {
        return detail::service_matches(state, std::get<ServiceRecord>(stored), query);
      },
      [](const detail::AnyRecord& stored) {
        const auto& service = std::get<ServiceRecord>(stored);
        return ServiceSummary{service.id, service.display_name, service.state, service.revision};
      });
}

Result<Page<DomainSummary>> TenantRegistry::list_isolation_domains(const DomainQuery& query) const {
  if (core_ == nullptr || core_->closed) {
    return Error{ErrorCode::StoreClosed, core_ == nullptr ? "this registry session has been moved from"
                                                          : "this registry session has been closed"};
  }
  const RegistryLimits limits = core_->limits;
  auto limit = detail::effective_limit(query.limit, limits);
  if (!limit) {
    return limit.error();
  }
  auto guard = core_->lock();
  return detail::scan<DomainSummary>(
      core_->state, detail::RecordKind::IsolationDomain, limit.value(), query.cursor,
      [&](const detail::AnyRecord& stored) {
        const auto& domain = std::get<IsolationDomainRecord>(stored);
        if (query.state.has_value() && domain.state != *query.state) {
          return false;
        }
        if (query.isolation_class.has_value() && domain.isolation_class != *query.isolation_class) {
          return false;
        }
        return true;
      },
      [](const detail::AnyRecord& stored) {
        const auto& domain = std::get<IsolationDomainRecord>(stored);
        return DomainSummary{domain.id,          domain.display_name, domain.isolation_class,
                             domain.state,       domain.revision,     domain.membership_generation};
      });
}

Result<Page<MembershipSummary>> TenantRegistry::list_isolation_memberships(const MembershipQuery& query) const {
  if (core_ == nullptr || core_->closed) {
    return Error{ErrorCode::StoreClosed, core_ == nullptr ? "this registry session has been moved from"
                                                          : "this registry session has been closed"};
  }
  const RegistryLimits limits = core_->limits;
  auto limit = detail::effective_limit(query.limit, limits);
  if (!limit) {
    return limit.error();
  }
  auto guard = core_->lock();
  return detail::scan<MembershipSummary>(
      core_->state, detail::RecordKind::IsolationMembership, limit.value(), query.cursor,
      [&](const detail::AnyRecord& stored) {
        const auto& membership = std::get<IsolationMembership>(stored);
        if (query.domain.has_value() && !(membership.domain == *query.domain)) {
          return false;
        }
        if (query.subject.has_value() && !(membership.subject == *query.subject)) {
          return false;
        }
        if (query.state.has_value() && membership.state != *query.state) {
          return false;
        }
        if (query.role.has_value() && membership.role != *query.role) {
          return false;
        }
        return true;
      },
      [](const detail::AnyRecord& stored) {
        const auto& membership = std::get<IsolationMembership>(stored);
        return MembershipSummary{membership.subject, membership.domain, membership.role, membership.state,
                                 membership.revision};
      });
}

Result<Page<OwnershipEdge>> TenantRegistry::list_ownership(const OwnershipQuery& query) const {
  if (core_ == nullptr || core_->closed) {
    return Error{ErrorCode::StoreClosed, core_ == nullptr ? "this registry session has been moved from"
                                                          : "this registry session has been closed"};
  }
  const RegistryLimits limits = core_->limits;
  auto limit = detail::effective_limit(query.limit, limits);
  if (!limit) {
    return limit.error();
  }
  auto guard = core_->lock();
  return detail::scan<OwnershipEdge>(
      core_->state, detail::RecordKind::OwnershipEdge, limit.value(), query.cursor,
      [&](const detail::AnyRecord& stored) {
        const auto& edge = std::get<OwnershipEdge>(stored);
        if (query.child.has_value() && !(edge.child == *query.child)) {
          return false;
        }
        if (query.parent.has_value() && !(edge.parent == *query.parent)) {
          return false;
        }
        if (query.kind.has_value() && edge.kind != *query.kind) {
          return false;
        }
        if (query.state.has_value() && edge.state != *query.state) {
          return false;
        }
        return true;
      },
      [](const detail::AnyRecord& stored) { return std::get<OwnershipEdge>(stored); });
}

Result<Page<ServiceBinding>> TenantRegistry::list_service_bindings(const BindingQuery& query) const {
  if (core_ == nullptr || core_->closed) {
    return Error{ErrorCode::StoreClosed, core_ == nullptr ? "this registry session has been moved from"
                                                          : "this registry session has been closed"};
  }
  const RegistryLimits limits = core_->limits;
  auto limit = detail::effective_limit(query.limit, limits);
  if (!limit) {
    return limit.error();
  }
  auto guard = core_->lock();
  return detail::scan<ServiceBinding>(
      core_->state, detail::RecordKind::ServiceBinding, limit.value(), query.cursor,
      [&](const detail::AnyRecord& stored) {
        const auto& binding = std::get<ServiceBinding>(stored);
        if (query.service.has_value() && !(binding.service == *query.service)) {
          return false;
        }
        if (query.tenant.has_value() && !(binding.tenant == *query.tenant)) {
          return false;
        }
        if (query.kind.has_value() && binding.kind != *query.kind) {
          return false;
        }
        if (query.state.has_value() && binding.state != *query.state) {
          return false;
        }
        return true;
      },
      [](const detail::AnyRecord& stored) { return std::get<ServiceBinding>(stored); });
}

// ---------------------------------------------------------------------------
// Traversal
// ---------------------------------------------------------------------------

Result<OwnershipTraversal> TenantRegistry::traverse_ownership(const OwnershipTraversalRequest& request) const {
  if (core_ == nullptr || core_->closed) {
    return Error{ErrorCode::StoreClosed, core_ == nullptr ? "this registry session has been moved from"
                                                          : "this registry session has been closed"};
  }
  const RegistryLimits limits = core_->limits;
  if (request.direction != TraversalDirection::Ancestors &&
      request.direction != TraversalDirection::Descendants) {
    return Error{ErrorCode::InvalidEnumValue,
                 "a traversal must declare its direction; walking in an unspecified direction would be a wider "
                 "answer than the caller asked for"};
  }
  const std::size_t max_depth = request.max_depth == 0 ? limits.max_traversal_depth : request.max_depth;
  if (max_depth > limits.max_traversal_depth) {
    return Error{ErrorCode::TraversalLimitExceeded,
                 "the requested traversal depth " + std::to_string(request.max_depth) +
                     " is above the configured maximum of " + std::to_string(limits.max_traversal_depth)};
  }
  const std::size_t max_results = request.max_results == 0 ? limits.max_traversal_results : request.max_results;
  if (max_results > limits.max_traversal_results) {
    return Error{ErrorCode::TraversalLimitExceeded,
                 "the requested traversal result bound " + std::to_string(request.max_results) +
                     " is above the configured maximum of " + std::to_string(limits.max_traversal_results)};
  }

  auto guard = core_->lock();
  const RegistryState& state = core_->state;
  if (state.find_tenant(request.start) == nullptr) {
    return Error{ErrorCode::NotFound, "tenant " + request.start.value() + " is not registered"};
  }

  OwnershipTraversal traversal{request.start, request.direction, {}, {}, 0, false, false};
  std::set<std::string> visited;
  visited.insert(request.start.value());
  std::set<std::string> frontier;
  frontier.insert(request.start.value());

  for (std::size_t depth = 1; depth <= max_depth; ++depth) {
    std::vector<OwnershipStep> level;
    std::set<std::string> next_frontier;
    bool limit_hit = false;

    state.for_each_kind(detail::RecordKind::OwnershipEdge, [&](const detail::AnyRecord& stored) {
      const auto& edge = std::get<OwnershipEdge>(stored);
      if (request.kind.has_value() && edge.kind != *request.kind) {
        return true;
      }
      if (request.only_state.has_value() && edge.state != *request.only_state) {
        return true;
      }
      if (!is_in_force(edge.state)) {
        return true;
      }
      const std::string& anchor =
          request.direction == TraversalDirection::Descendants ? edge.parent.value() : edge.child.value();
      if (frontier.find(anchor) == frontier.end()) {
        return true;
      }
      const TenantId& from = request.direction == TraversalDirection::Descendants ? edge.parent : edge.child;
      const TenantId& to = request.direction == TraversalDirection::Descendants ? edge.child : edge.parent;
      if (level.size() >= max_results) {
        limit_hit = true;
        return false;
      }
      level.push_back(OwnershipStep{from, to, edge.kind, edge.state, depth});
      if (visited.find(to.value()) == visited.end()) {
        visited.insert(to.value());
        next_frontier.insert(to.value());
        traversal.reached.push_back(to);
      }
      return true;
    });

    std::stable_sort(level.begin(), level.end(), [](const OwnershipStep& lhs, const OwnershipStep& rhs) {
      if (lhs.from != rhs.from) {
        return lhs.from < rhs.from;
      }
      if (lhs.to != rhs.to) {
        return lhs.to < rhs.to;
      }
      return to_token(lhs.kind) < to_token(rhs.kind);
    });
    for (const auto& step : level) {
      traversal.steps.push_back(step);
    }
    traversal.max_depth_reached = depth;

    if (limit_hit) {
      traversal.truncated = true;
      traversal.depth_limited = true;
      return traversal;
    }
    if (next_frontier.empty()) {
      return traversal;
    }
    frontier = std::move(next_frontier);
    if (depth == max_depth) {
      traversal.truncated = true;
      traversal.depth_limited = true;
      return traversal;
    }
  }
  return traversal;
}

Result<std::vector<IsolationDomainId>> TenantRegistry::isolation_domains_of(const TenancySubject& subject) const {
  if (core_ == nullptr || core_->closed) {
    return Error{ErrorCode::StoreClosed, core_ == nullptr ? "this registry session has been moved from"
                                                          : "this registry session has been closed"};
  }
  if (subject.kind() == SubjectKind::IsolationDomain) {
    return Error{ErrorCode::InvalidIdKind,
                 "an isolation domain is not a member of another isolation domain"};
  }
  auto guard = core_->lock();
  if (core_->state.find(detail::identity_key(subject.kind(), subject.identity_value())) == nullptr) {
    return Error{ErrorCode::NotFound, subject.to_text() + " is not registered"};
  }
  std::vector<IsolationDomainId> domains;
  core_->state.for_each_prefix(detail::membership_subject_prefix(subject), [&](const detail::AnyRecord& stored) {
    const auto& membership = std::get<IsolationMembership>(stored);
    if (membership.subject == subject && is_in_force(membership.state)) {
      domains.push_back(membership.domain);
    }
    return true;
  });
  return domains;
}

Result<std::vector<TenancySubject>> TenantRegistry::members_of(const IsolationDomainId& domain,
                                                              std::size_t limit) const {
  if (core_ == nullptr || core_->closed) {
    return Error{ErrorCode::StoreClosed, core_ == nullptr ? "this registry session has been moved from"
                                                          : "this registry session has been closed"};
  }
  const RegistryLimits limits = core_->limits;
  auto effective = detail::effective_limit(limit, limits);
  if (!effective) {
    return effective.error();
  }
  auto guard = core_->lock();
  if (core_->state.find_domain(domain) == nullptr) {
    return Error{ErrorCode::NotFound, "isolation domain " + domain.value() + " is not registered"};
  }
  std::vector<TenancySubject> subjects;
  bool truncated = false;
  core_->state.for_each_kind(detail::RecordKind::IsolationMembership, [&](const detail::AnyRecord& stored) {
    const auto& membership = std::get<IsolationMembership>(stored);
    if (!(membership.domain == domain) || !is_in_force(membership.state)) {
      return true;
    }
    if (subjects.size() >= effective.value()) {
      truncated = true;
      return false;
    }
    subjects.push_back(membership.subject);
    return true;
  });
  if (truncated) {
    return Error{ErrorCode::ListingLimitExceeded,
                 "isolation domain " + domain.value() + " holds more in-force members than the requested bound of " +
                     std::to_string(effective.value()) +
                     "; the answer is refused rather than silently truncated"};
  }
  return subjects;
}

// ---------------------------------------------------------------------------
// Explanation, statistics and snapshot
// ---------------------------------------------------------------------------

Result<Explanation> TenantRegistry::explain(const TenancySubject& subject, const ExplainOptions& options) const {
  if (core_ == nullptr || core_->closed) {
    return Error{ErrorCode::StoreClosed, core_ == nullptr ? "this registry session has been moved from"
                                                          : "this registry session has been closed"};
  }
  if (options.max_lineage_depth > core_->limits.max_ownership_depth) {
    return Error{ErrorCode::TraversalLimitExceeded,
                 "the requested lineage depth is above the configured ownership depth limit"};
  }
  auto guard = core_->lock();
  const RegistryState& state = core_->state;
  const std::string key = detail::identity_key(subject.kind(), subject.identity_value());
  const detail::AnyRecord* raw = state.find(key);
  if (raw == nullptr) {
    return Error{ErrorCode::NotFound, subject.to_text() + " is not registered"};
  }

  const auto* tenant_record = std::get_if<TenantRecord>(raw);
  const auto* service_record = std::get_if<ServiceRecord>(raw);
  const auto* domain_record = std::get_if<IsolationDomainRecord>(raw);
  if (tenant_record == nullptr && service_record == nullptr && domain_record == nullptr) {
    return Error{ErrorCode::InternalInvariantViolated,
                 subject.to_text() + " is stored under an identity key but is not an identity record"};
  }
  SubjectRecord record = tenant_record != nullptr
                             ? SubjectRecord{*tenant_record}
                             : (service_record != nullptr ? SubjectRecord{*service_record}
                                                          : SubjectRecord{*domain_record});

  Explanation explanation{subject,
                          record,
                          std::nullopt,
                          {},
                          {},
                          {},
                          {},
                          {},
                          {},
                          std::nullopt,
                          state.generation,
                          core_->control_epoch,
                          core_->incarnation,
                          {}};

  if (const auto* tenant = std::get_if<TenantRecord>(&record); tenant != nullptr) {
    explanation.owner = tenant->owner;
    if (!tenant->display_name.has_value()) {
      explanation.unknowns.emplace_back("display_name: unset");
    }
    if (!tenant->owner.has_value()) {
      explanation.unknowns.emplace_back("owner_principal: unset");
    }
  }
  if (const auto* service = std::get_if<ServiceRecord>(&record); service != nullptr) {
    if (!service->display_name.has_value()) {
      explanation.unknowns.emplace_back("display_name: unset");
    }
  }
  if (const auto* domain = std::get_if<IsolationDomainRecord>(&record); domain != nullptr) {
    if (!domain->display_name.has_value()) {
      explanation.unknowns.emplace_back("display_name: unset");
    }
  }

  if (subject.kind() == SubjectKind::Tenant) {
    state.for_each_prefix(detail::ownership_child_prefix(subject.identity_value()),
                          [&](const detail::AnyRecord& stored) {
                            const auto& edge = std::get<OwnershipEdge>(stored);
                            if (edge.child.value() == subject.identity_value()) {
                              explanation.owned_by.push_back(edge);
                            }
                            return true;
                          });
    // The lineage walk is bounded and reports its own truncation.
    std::string node{subject.identity_value()};
    std::set<std::string> seen;
    seen.insert(node);
    for (std::size_t depth = 0; depth < options.max_lineage_depth; ++depth) {
      const OwnershipEdge* next = nullptr;
      state.for_each_prefix(detail::ownership_child_prefix(node), [&](const detail::AnyRecord& stored) {
        const auto& edge = std::get<OwnershipEdge>(stored);
        if (edge.child.value() == node && is_in_force(edge.state) &&
            edge.kind == OwnershipKind::Administrative) {
          next = &edge;
          return false;
        }
        return true;
      });
      if (next == nullptr) {
        break;
      }
      if (seen.find(next->parent.value()) != seen.end()) {
        explanation.unknowns.emplace_back("ownership_lineage: stops at a cycle through " + next->parent.value());
        break;
      }
      seen.insert(next->parent.value());
      explanation.ownership_lineage.push_back(next->parent);
      node = next->parent.value();
      if (depth + 1 == options.max_lineage_depth) {
        explanation.unknowns.emplace_back("ownership_lineage: truncated at the configured depth of " +
                                          std::to_string(options.max_lineage_depth));
      }
    }
    if (explanation.owned_by.empty() && explanation.ownership_lineage.empty()) {
      explanation.unknowns.emplace_back("ownership: no owner is declared for this tenant");
    }
  }

  state.for_each_kind(detail::RecordKind::OwnershipEdge, [&](const detail::AnyRecord& stored) {
    const auto& edge = std::get<OwnershipEdge>(stored);
    if (edge.parent.value() == subject.identity_value() && subject.kind() == SubjectKind::Tenant) {
      explanation.owns.push_back(edge);
    }
    return true;
  });

  state.for_each_kind(detail::RecordKind::ServiceBinding, [&](const detail::AnyRecord& stored) {
    const auto& binding = std::get<ServiceBinding>(stored);
    const bool matches = subject.kind() == SubjectKind::Service
                             ? binding.service.value() == subject.identity_value()
                             : binding.tenant.value() == subject.identity_value();
    if (matches) {
      explanation.bindings.push_back(binding);
    }
    return true;
  });

  state.for_each_prefix(detail::membership_subject_prefix(subject), [&](const detail::AnyRecord& stored) {
    const auto& membership = std::get<IsolationMembership>(stored);
    if (membership.subject == subject) {
      explanation.memberships.push_back(membership);
    }
    return true;
  });
  for (const auto& membership : explanation.memberships) {
    const auto* domain = state.find_domain(membership.domain);
    if (domain != nullptr) {
      explanation.domain_generations.emplace_back(domain->id, domain->membership_generation);
    }
  }
  if (explanation.memberships.empty()) {
    explanation.unknowns.emplace_back(
        "isolation_memberships: none recorded; isolation is declared, never inferred from a name or a label");
  }
  if (explanation.bindings.empty()) {
    explanation.unknowns.emplace_back("service_bindings: none recorded");
  }

  const auto tombstone = state.find_tombstone(subject.kind(), subject.identity_value());
  if (tombstone.has_value()) {
    if (tombstone->permit.has_value() && !tombstone->permit->consumed()) {
      explanation.outstanding_rebind_permit = tombstone->permit;
    }
    explanation.unknowns.emplace_back("identity: fenced by a tombstone written at generation " +
                                      std::to_string(tombstone->tombstoned_generation.value()));
  }

  if (!options.include_metadata) {
    explanation.unknowns.emplace_back("metadata: not requested");
  } else {
    const bool empty = std::visit(
        [](const auto& stored) -> bool {
          using Stored = std::decay_t<decltype(stored)>;
          if constexpr (std::is_same_v<Stored, TombstoneRecord>) {
            return true;
          } else {
            return stored.metadata.empty();
          }
        },
        record);
    if (empty) {
      explanation.unknowns.emplace_back("metadata: no key has ever been recorded for this subject");
    }
  }

  return explanation;
}

RegistryStats TenantRegistry::stats() const {
  auto guard = core_->lock();
  const RegistryState& state = core_->state;

  RegistryStats result{state.generation,
                       core_->control_epoch,
                       core_->incarnation,
                       core_->store.has_value() ? core_->store->identity().has_value()
                                                     ? std::optional<ContentDigest>{core_->store->identity()->id}
                                                     : std::nullopt
                                               : std::nullopt,
                       core_->sequence,
                       state.count(detail::RecordKind::Tenant),
                       state.count(detail::RecordKind::Service),
                       state.count(detail::RecordKind::IsolationDomain),
                       state.count(detail::RecordKind::OwnershipEdge),
                       state.count(detail::RecordKind::ServiceBinding),
                       state.count(detail::RecordKind::IsolationMembership),
                       {},
                       {},
                       {}};

  const auto tally = [&](detail::RecordKind kind, std::vector<StateCount>& out) {
    std::uint64_t buckets[7] = {0, 0, 0, 0, 0, 0, 0};
    state.for_each_kind(kind, [&](const detail::AnyRecord& stored) {
      const auto value = static_cast<std::size_t>(detail::identity_state(stored));
      if (value < 7) {
        ++buckets[value];
      }
      return true;
    });
    for (std::size_t index = 1; index < 7; ++index) {
      if (buckets[index] != 0) {
        out.push_back(StateCount{static_cast<LifecycleState>(index), buckets[index]});
      }
    }
  };
  tally(detail::RecordKind::Tenant, result.tenants_by_state);
  tally(detail::RecordKind::Service, result.services_by_state);
  tally(detail::RecordKind::IsolationDomain, result.domains_by_state);
  return result;
}

namespace detail {

RegistrySnapshot build_snapshot(const RegistryCore& core) {
  const RegistryState& state = core.state;

  RegistrySnapshot snapshot{state.generation,
                            core.control_epoch,
                            core.incarnation,
                            std::nullopt,
                            core.sequence,
                            {},
                            {},
                            {},
                            {},
                            {},
                            {},
                            {},
                            {}};
  if (core.store.has_value() && core.store->identity().has_value()) {
    snapshot.store_id = core.store->identity()->id;
  }

  for (const auto& [key, record] : state.records) {
    (void)key;
    if (const auto* tenant = std::get_if<TenantRecord>(&record); tenant != nullptr) {
      snapshot.tenants.push_back(*tenant);
    } else if (const auto* service = std::get_if<ServiceRecord>(&record); service != nullptr) {
      snapshot.services.push_back(*service);
    } else if (const auto* domain = std::get_if<IsolationDomainRecord>(&record); domain != nullptr) {
      snapshot.isolation_domains.push_back(*domain);
    } else if (const auto* edge = std::get_if<OwnershipEdge>(&record); edge != nullptr) {
      snapshot.ownership_edges.push_back(*edge);
    } else if (const auto* binding = std::get_if<ServiceBinding>(&record); binding != nullptr) {
      snapshot.service_bindings.push_back(*binding);
    } else if (const auto* membership = std::get_if<IsolationMembership>(&record); membership != nullptr) {
      snapshot.isolation_memberships.push_back(*membership);
    } else if (const auto* tombstone = std::get_if<TombstoneRecord>(&record); tombstone != nullptr) {
      snapshot.tombstones.push_back(*tombstone);
    }
  }
  for (const auto& domain : snapshot.isolation_domains) {
    snapshot.domain_generations.emplace_back(domain.id, domain.membership_generation);
  }
  return snapshot;
}

}  // namespace detail

RegistrySnapshot TenantRegistry::snapshot() const {
  auto guard = core_->lock();
  return detail::build_snapshot(*core_);
}

Result<std::string> TenantRegistry::export_json() const {
  const RegistrySnapshot current = snapshot();
  const std::string rendered = current.to_json();
  if (rendered.size() > core_->limits.max_snapshot_bytes) {
    return Error{ErrorCode::PayloadTooLarge,
                 "the JSON export of this state is larger than the configured snapshot limit; it is refused rather "
                 "than truncated"};
  }
  return rendered;
}

// ---------------------------------------------------------------------------
// Compaction
// ---------------------------------------------------------------------------

Status TenantRegistry::compact() {
  if (core_ == nullptr) {
    return Status::failure(ErrorCode::StoreClosed, "this registry session has been moved from");
  }
  auto guard = core_->lock();
  if (const auto writable = detail::ensure_writable(*core_); !writable.ok()) {
    return writable;
  }
  if (!core_->durable || !core_->store.has_value()) {
    return Status::success();
  }

  const RegistrySnapshot current = detail::build_snapshot(*core_);
  detail::BaselinePayload payload{current.generation,
                                  current.tenants,
                                  current.services,
                                  current.isolation_domains,
                                  current.ownership_edges,
                                  current.service_bindings,
                                  current.isolation_memberships,
                                  current.tombstones,
                                  current.domain_generations,
                                  {}};
  for (const auto& [key, entry] : core_->state.ledger) {
    (void)key;
    payload.ledger.push_back(entry);
  }

  detail::ByteWriter writer{core_->limits.max_baseline_payload_bytes};
  detail::encode(writer, payload);
  if (writer.overflowed()) {
    return Status::failure(ErrorCode::PayloadTooLarge,
                           "the state does not fit in the configured baseline payload limit, so compaction is "
                           "refused rather than writing a partial snapshot");
  }
  const auto& bytes = writer.bytes();
  const auto status = core_->store->rewrite_with_baseline(core_->state.generation,
                                                          std::span<const std::byte>{bytes.data(), bytes.size()});
  if (!status.ok()) {
    return status;
  }
  // The baseline frame occupies one journal position of its own, so the
  // session's committed position and recovery report have to follow it.
  // Without this the next commit would write one sequence into its payload and
  // another into its frame header, and the store would refuse to reopen.
  core_->sequence = core_->store->committed_sequence();
  core_->report = core_->store->recovery_report();
  return Status::success();
}

}  // namespace tenant_registry
