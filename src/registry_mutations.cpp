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
#include <type_traits>
#include <utility>
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

/// What the identity admission check decided.
struct IdentityAdmission {
  /// The permanent tombstone to write in the same commit that reuses an
  /// identity. Absent unless a rebind permit was consumed.
  std::optional<TombstoneRecord> capture;
  /// True when a fenced record is being deleted as part of this commit.
  bool reuse = false;
};

/// True when the value is one of the enumerators this build defines.
///
/// A value cast from an out-of-range integer would otherwise be accepted,
/// stored, and then refused by the decoder on the next read: one request would
/// permanently poison a durable store. Every enum that arrives from a caller is
/// checked with this before it is used.
template <class Enum>
[[nodiscard]] bool is_defined(Enum value, Enum first, Enum last) noexcept {
  return value >= first && value <= last;
}

[[nodiscard]] std::uint64_t capacity_bound(const RegistryLimits& limits, RecordKind kind) noexcept {
  switch (kind) {
    case RecordKind::Tenant:
      return limits.max_tenants;
    case RecordKind::Service:
      return limits.max_services;
    case RecordKind::IsolationDomain:
      return limits.max_isolation_domains;
    case RecordKind::OwnershipEdge:
      return limits.max_ownership_edges;
    case RecordKind::ServiceBinding:
      return limits.max_service_bindings;
    case RecordKind::IsolationMembership:
      return limits.max_isolation_memberships;
    case RecordKind::Tombstone:
    case RecordKind::Unspecified:
      break;
  }
  return 0;
}

[[nodiscard]] Status ensure_capacity(const RegistryCore& core, RecordKind kind, std::uint64_t adding) {
  const std::uint64_t bound = capacity_bound(core.limits, kind);
  if (bound == 0) {
    return Status::success();
  }
  const std::uint64_t current = core.state.count(kind);
  if (adding > bound || current > bound - adding) {
    return Status::failure(ErrorCode::LimitExceeded,
                           "the registry already holds " + std::to_string(current) + " " +
                               std::string{key_prefix(kind)} + " records and may hold at most " +
                               std::to_string(bound));
  }
  return Status::success();
}

[[nodiscard]] Status check_metadata(const TenancyMetadata& metadata, const RegistryLimits& limits) {
  if (metadata.size() > limits.max_metadata_entries_per_record) {
    return Status::failure(ErrorCode::LimitExceeded,
                           "the metadata set holds " + std::to_string(metadata.size()) +
                               " entries, above the configured limit of " +
                               std::to_string(limits.max_metadata_entries_per_record));
  }
  for (const auto& entry : metadata.entries()) {
    if (entry.key.value().size() > limits.max_metadata_key_bytes) {
      return Status::failure(ErrorCode::InvalidMetadata, "a metadata key is longer than the configured limit");
    }
    const auto* text = entry.value.text_if();
    const auto* token = entry.value.token_if();
    const std::size_t length = text != nullptr ? text->size() : (token != nullptr ? token->size() : 0);
    if (length > limits.max_metadata_value_bytes) {
      return Status::failure(ErrorCode::InvalidMetadata,
                             "the metadata value for key " + std::string{entry.key.value()} +
                                 " is longer than the configured limit");
    }
  }
  return Status::success();
}

/// The identity admission check.
///
/// An identity that was retired is never reusable. An identity that was
/// tombstoned is reusable exactly once, and only when the tombstone names that
/// exact identity as its permitted successor. Everything else is refused with
/// the reason that fits, so a caller can tell "this already exists" apart from
/// "this was fenced forever" apart from "the permit for this was already used".
[[nodiscard]] Result<IdentityAdmission> admit_identity(const RegistryState& state, SubjectKind kind,
                                                       std::string_view text, RegistryGeneration next_generation) {
  const std::string subject = identity_text(kind, text);
  const std::string key = identity_key(kind, text);
  const AnyRecord* existing = state.find(key);

  if (existing == nullptr) {
    if (state.find(tombstone_key(kind, text)) != nullptr) {
      return Error{ErrorCode::RebindPermitConsumed,
                   subject +
                       " has already been rebound once; a tombstone permits exactly one successor and that permit "
                       "has been consumed"};
    }
    return IdentityAdmission{};
  }

  const LifecycleState current = identity_state(*existing);
  if (current == LifecycleState::Retired) {
    Error error{ErrorCode::IdentityRetired,
                subject +
                    " was retired and may not be reused; tombstoning it with an explicit rebind permit is the only "
                    "way an identity can be taken over"};
    error.add_suppressed("the retired record sits at revision " +
                         std::to_string(revision_of(*existing).value()));
    return error;
  }
  if (current != LifecycleState::Tombstoned) {
    Error error{ErrorCode::IdentityAlreadyExists,
                subject + " already exists in state " + std::string{to_token(current)}};
    if (const auto permanent = state.find_tombstone(kind, text);
        permanent.has_value() && permanent->permit.has_value() && permanent->permit->consumed()) {
      error.add_suppressed("this identity was taken over by consuming the rebind permit issued at generation " +
                           std::to_string(permanent->permit->issued_generation().value()) +
                           "; the permanent tombstone remains");
    }
    return error;
  }

  const auto tombstone = state.find_tombstone(kind, text);
  if (!tombstone.has_value() || !tombstone->permit.has_value()) {
    return Error{ErrorCode::IdentityTombstoned,
                 subject + " is tombstoned and no rebind permit was issued for it"};
  }
  const RebindPermit& permit = *tombstone->permit;
  if (permit.consumed()) {
    return Error{ErrorCode::RebindPermitConsumed,
                 subject + " is tombstoned and the rebind permit issued for it was already consumed at generation " +
                     std::to_string(permit.consumed_generation()->value())};
  }
  if (!permit.admits(kind, text)) {
    Error error{ErrorCode::IdentityTombstoned,
                subject + " is tombstoned and the outstanding rebind permit does not name it as the successor"};
    error.add_suppressed("the outstanding permit names '" + permit.successor_text() + "'");
    return error;
  }

  IdentityAdmission admission;
  admission.reuse = true;
  admission.capture = TombstoneRecord{kind,
                                      std::string{text},
                                      LifecycleState::Tombstoned,
                                      tombstone->revision,
                                      tombstone->retired_generation,
                                      tombstone->tombstoned_generation,
                                      std::optional<RebindPermit>{permit.consumed_at(next_generation)},
                                      tombstone->note,
                                      tombstone->provenance,
                                      tombstone->origin_digest};
  return admission;
}

[[nodiscard]] Status require_expected_revision(RecordRevision actual, RecordRevision expected,
                                               std::string_view subject) {
  if (actual != expected) {
    return Status::failure(ErrorCode::StaleRecordRevision,
                           std::string{subject} + " is at revision " + std::to_string(actual.value()) +
                               " but the request asserts revision " + std::to_string(expected.value()));
  }
  return Status::success();
}

[[nodiscard]] Status require_changeable(const AnyRecord& record, std::string_view subject) {
  const LifecycleState state = identity_state(record);
  if (is_terminal(state)) {
    return Status::failure(ErrorCode::TerminalStateReached,
                           std::string{subject} + " is in state " + std::string{to_token(state)} +
                               " and can never be changed again");
  }
  return Status::success();
}

/// Counts the ownership edges a tenant is an endpoint of: the children it owns
/// and the owners above it. Both are relationships that must be gone before the
/// tenant can leave, and neither can be found by a key prefix, because the two
/// ends of an edge are not the same field.
struct OwnershipDependents {
  std::uint64_t children = 0;
  std::uint64_t owners = 0;
  std::string first_example;
};

[[nodiscard]] OwnershipDependents ownership_dependents(const RegistryState& state, std::string_view text) {
  OwnershipDependents counts;
  state.for_each_kind(RecordKind::OwnershipEdge, [&](const AnyRecord& stored) {
    const auto& edge = std::get<OwnershipEdge>(stored);
    if (edge.parent.value() == text) {
      ++counts.children;
      if (counts.first_example.empty()) {
        counts.first_example = "ownership edge over child " + edge.child.value();
      }
    }
    if (edge.child.value() == text) {
      ++counts.owners;
      if (counts.first_example.empty()) {
        counts.first_example = "ownership edge to owner " + edge.parent.value();
      }
    }
    return true;
  });
  return counts;
}

/// Counts what still refers to a subject. A refusal names what is in the way
/// rather than only that something is.
[[nodiscard]] std::string live_dependent_report(const RegistryState& state, SubjectKind kind,
                                                std::string_view text) {
  std::uint64_t children = 0;
  std::uint64_t owners = 0;
  std::uint64_t bindings = 0;
  std::uint64_t memberships = 0;
  std::string first_example;

  if (kind == SubjectKind::Tenant) {
    const OwnershipDependents counted = ownership_dependents(state, text);
    children = counted.children;
    owners = counted.owners;
    first_example = counted.first_example;
    state.for_each_kind(RecordKind::ServiceBinding, [&](const AnyRecord& stored) {
      const auto& binding = std::get<ServiceBinding>(stored);
      if (binding.tenant.value() == text) {
        ++bindings;
        if (first_example.empty()) {
          first_example = "service binding of " + binding.service.value();
        }
      }
      return true;
    });
  } else if (kind == SubjectKind::Service) {
    state.for_each_prefix(binding_service_prefix(text), [&](const AnyRecord& stored) {
      ++bindings;
      if (first_example.empty()) {
        first_example = "service binding of " + std::get<ServiceBinding>(stored).service.value();
      }
      return true;
    });
  }

  const std::string subject_key =
      kind == SubjectKind::IsolationDomain ? std::string{} : identity_key(kind, text);
  state.for_each_kind(RecordKind::IsolationMembership, [&](const AnyRecord& stored) {
    const auto& membership = std::get<IsolationMembership>(stored);
    const bool matches =
        kind == SubjectKind::IsolationDomain
            ? membership.domain.value() == text
            : identity_key(membership.subject.kind(), membership.subject.identity_value()) == subject_key;
    if (matches) {
      ++memberships;
      if (first_example.empty()) {
        first_example = "isolation membership in " + membership.domain.value();
      }
    }
    return true;
  });

  std::string out;
  out.append("children=").append(std::to_string(children));
  out.append(" owners=").append(std::to_string(owners));
  out.append(" service_bindings=").append(std::to_string(bindings));
  out.append(" isolation_memberships=").append(std::to_string(memberships));
  if (!first_example.empty()) {
    out.append(" first=").append(first_example);
  }
  return out;
}

[[nodiscard]] bool has_live_dependents(const RegistryState& state, SubjectKind kind, std::string_view text) {
  if (kind == SubjectKind::Tenant) {
    bool found = false;
    state.for_each_kind(RecordKind::OwnershipEdge, [&](const AnyRecord& stored) {
      const auto& edge = std::get<OwnershipEdge>(stored);
      if (edge.parent.value() == text || edge.child.value() == text) {
        found = true;
        return false;
      }
      return true;
    });
    if (found) {
      return true;
    }
    state.for_each_kind(RecordKind::ServiceBinding, [&](const AnyRecord& stored) {
      if (std::get<ServiceBinding>(stored).tenant.value() == text) {
        found = true;
        return false;
      }
      return true;
    });
    if (found) {
      return true;
    }
  } else if (kind == SubjectKind::Service) {
    bool found = false;
    state.for_each_prefix(binding_service_prefix(text), [&](const AnyRecord&) {
      found = true;
      return false;
    });
    if (found) {
      return true;
    }
  }

  const std::string subject_key =
      kind == SubjectKind::IsolationDomain ? std::string{} : identity_key(kind, text);
  bool found = false;
  state.for_each_kind(RecordKind::IsolationMembership, [&](const AnyRecord& stored) {
    const auto& membership = std::get<IsolationMembership>(stored);
    const bool matches =
        kind == SubjectKind::IsolationDomain
            ? membership.domain.value() == text
            : identity_key(membership.subject.kind(), membership.subject.identity_value()) == subject_key;
    if (matches) {
      found = true;
      return false;
    }
    return true;
  });
  return found;
}

/// Walks up from the prospective parent following in-force ownership edges and
/// refuses when the walk reaches the prospective child. The walk is bounded by
/// the configured ownership depth, so a crafted graph cannot make it run
/// without end, and reaching the bound is itself a refusal rather than a
/// silent "probably fine".
[[nodiscard]] Status check_acyclic_added_edge(const RegistryState& state, const TenantId& child,
                                              const TenantId& parent, const RegistryLimits& limits) {
  if (child == parent) {
    return Status::failure(ErrorCode::SelfReference, "tenant " + child.value() + " cannot own itself");
  }
  std::string node = parent.value();
  std::size_t depth = 0;
  while (true) {
    if (node == child.value()) {
      return Status::failure(ErrorCode::OwnershipCycle,
                             "adding an ownership edge from " + child.value() + " to " + parent.value() +
                                 " would create a cycle through " + node);
    }
    if (depth >= limits.max_ownership_depth) {
      return Status::failure(ErrorCode::OwnershipDepthExceeded,
                             "the ownership chain above " + parent.value() +
                                 " is deeper than the configured limit of " +
                                 std::to_string(limits.max_ownership_depth));
    }
    bool advanced = false;
    std::string next;
    state.for_each_prefix(ownership_child_prefix(node), [&](const AnyRecord& stored) {
      const auto& edge = std::get<OwnershipEdge>(stored);
      if (edge.child.value() == node && is_in_force(edge.state)) {
        next = edge.parent.value();
        advanced = true;
        return false;
      }
      return true;
    });
    if (!advanced) {
      return Status::success();
    }
    ++depth;
    node = std::move(next);
  }
}

[[nodiscard]] Result<const AnyRecord*> require_record(const RegistryState& state, std::string_view key,
                                                      const char* what) {
  const AnyRecord* record = state.find(key);
  if (record == nullptr) {
    return Error{ErrorCode::NotFound, std::string{what} + " " + std::string{key} + " is not registered"};
  }
  return record;
}

[[nodiscard]] Result<const AnyRecord*> require_identity(const RegistryState& state, SubjectKind kind,
                                                        std::string_view text, const char* what) {
  return require_record(state, identity_key(kind, text), what);
}

[[nodiscard]] Status require_in_force_target(const AnyRecord& record, std::string_view subject) {
  const LifecycleState state = identity_state(record);
  if (!admits_relationship_target(state)) {
    return Status::failure(ErrorCode::ReferenceTerminal,
                           std::string{subject} + " is in state " + std::string{to_token(state)} +
                               " and can never be the target of a new relationship");
  }
  return Status::success();
}

[[nodiscard]] Status require_admits_new_relationships(const AnyRecord& record, std::string_view subject) {
  const LifecycleState state = identity_state(record);
  if (!admits_new_relationships(state)) {
    return Status::failure(ErrorCode::ReferenceNotYetLive,
                           std::string{subject} + " is in state " + std::string{to_token(state)} +
                               " and may not be the source of a new relationship");
  }
  return Status::success();
}

/// Copies whichever identity record a variant holds into a SubjectRecord.
[[nodiscard]] SubjectRecord as_subject(const AnyRecord& record) {
  if (const auto* tenant = std::get_if<TenantRecord>(&record); tenant != nullptr) {
    return SubjectRecord{*tenant};
  }
  if (const auto* service = std::get_if<ServiceRecord>(&record); service != nullptr) {
    return SubjectRecord{*service};
  }
  return SubjectRecord{std::get<IsolationDomainRecord>(record)};
}

}  // namespace
}  // namespace detail

// ---------------------------------------------------------------------------
// Creating identities
// ---------------------------------------------------------------------------

Result<CreateTenantOutcome> TenantRegistry::create_tenant(const CreateTenantRequest& request) {
  if (core_ == nullptr) {
    return Error{ErrorCode::StoreClosed, "this registry session has been moved from"};
  }
  const RegistryLimits limits = core_->limits;
  auto display_name = detail::check_optional_text(request.display_name, limits.max_display_name_bytes, "display name");
  if (!display_name) {
    return display_name.error();
  }
  if (const auto provenance = detail::check_provenance(request.context.actor, limits); !provenance.ok()) {
    return provenance.error();
  }
  if (const auto metadata = detail::check_metadata(request.metadata, limits); !metadata.ok()) {
    return metadata.error();
  }
  const RequestDigest digest = detail::request_digest(request);

  auto guard = core_->lock();
  auto resolution = detail::resolve_context(*core_, OperationKind::CreateTenant, digest, request.context);
  if (!resolution) {
    return resolution.error();
  }
  if (resolution.value().replay) {
    auto stored = detail::decode_outcome(*resolution.value().entry, limits);
    if (!stored) {
      return stored.error();
    }
    const auto* tenant = std::get_if<TenantRecord>(&stored.value());
    if (tenant == nullptr) {
      return Error{ErrorCode::InternalInvariantViolated,
                   "the idempotency ledger holds an outcome of the wrong kind for this request"};
    }
    return CreateTenantOutcome{resolution.value().receipt, *tenant};
  }

  const auto next_generation = advance(core_->state.generation);
  if (!next_generation) {
    return next_generation.error();
  }
  auto admission =
      detail::admit_identity(core_->state, SubjectKind::Tenant, request.id.value(), next_generation.value());
  if (!admission) {
    return admission.error();
  }
  const std::uint64_t adding = admission.value().reuse ? 0u : 1u;
  if (const auto capacity = detail::ensure_capacity(*core_, RecordKind::Tenant, adding); !capacity.ok()) {
    return capacity.error();
  }

  const TenantRecord record{request.id,
                            display_name.value(),
                            LifecycleState::Declared,
                            RecordRevision::from_value(1),
                            next_generation.value(),
                            next_generation.value(),
                            std::nullopt,
                            std::nullopt,
                            request.owner,
                            request.metadata,
                            request.context.actor,
                            digest};

  detail::PendingCommit pending;
  pending.operation = OperationKind::CreateTenant;
  pending.request_digest = digest;
  pending.idempotency_key = request.context.idempotency_key;
  pending.primary_key = detail::canonical_key(record);
  pending.primary_revision = record.revision;
  pending.deletes.push_back(detail::tenant_key(record.id.value()));
  pending.upserts.push_back(detail::AnyRecord{record});
  if (admission.value().capture.has_value()) {
    pending.upserts.push_back(detail::AnyRecord{*admission.value().capture});
  }
  pending.outcome_payload = detail::outcome_of(detail::AnyRecord{record});

  auto receipt = detail::apply_commit(*core_, std::move(pending));
  if (!receipt) {
    return receipt.error();
  }
  return CreateTenantOutcome{receipt.value(), record};
}

Result<CreateServiceOutcome> TenantRegistry::create_service(const CreateServiceRequest& request) {
  if (core_ == nullptr) {
    return Error{ErrorCode::StoreClosed, "this registry session has been moved from"};
  }
  const RegistryLimits limits = core_->limits;
  auto display_name = detail::check_optional_text(request.display_name, limits.max_display_name_bytes, "display name");
  if (!display_name) {
    return display_name.error();
  }
  if (const auto provenance = detail::check_provenance(request.context.actor, limits); !provenance.ok()) {
    return provenance.error();
  }
  if (const auto metadata = detail::check_metadata(request.metadata, limits); !metadata.ok()) {
    return metadata.error();
  }
  const RequestDigest digest = detail::request_digest(request);

  auto guard = core_->lock();
  auto resolution = detail::resolve_context(*core_, OperationKind::CreateService, digest, request.context);
  if (!resolution) {
    return resolution.error();
  }
  if (resolution.value().replay) {
    auto stored = detail::decode_outcome(*resolution.value().entry, limits);
    if (!stored) {
      return stored.error();
    }
    const auto* service = std::get_if<ServiceRecord>(&stored.value());
    if (service == nullptr) {
      return Error{ErrorCode::InternalInvariantViolated,
                   "the idempotency ledger holds an outcome of the wrong kind for this request"};
    }
    return CreateServiceOutcome{resolution.value().receipt, *service};
  }

  const auto next_generation = advance(core_->state.generation);
  if (!next_generation) {
    return next_generation.error();
  }
  auto admission =
      detail::admit_identity(core_->state, SubjectKind::Service, request.id.value(), next_generation.value());
  if (!admission) {
    return admission.error();
  }
  const std::uint64_t adding = admission.value().reuse ? 0u : 1u;
  if (const auto capacity = detail::ensure_capacity(*core_, RecordKind::Service, adding); !capacity.ok()) {
    return capacity.error();
  }

  const ServiceRecord record{request.id,
                             display_name.value(),
                             LifecycleState::Declared,
                             RecordRevision::from_value(1),
                             next_generation.value(),
                             next_generation.value(),
                             std::nullopt,
                             std::nullopt,
                             request.metadata,
                             request.context.actor,
                             digest};

  detail::PendingCommit pending;
  pending.operation = OperationKind::CreateService;
  pending.request_digest = digest;
  pending.idempotency_key = request.context.idempotency_key;
  pending.primary_key = detail::canonical_key(record);
  pending.primary_revision = record.revision;
  pending.deletes.push_back(detail::service_key(record.id.value()));
  pending.upserts.push_back(detail::AnyRecord{record});
  if (admission.value().capture.has_value()) {
    pending.upserts.push_back(detail::AnyRecord{*admission.value().capture});
  }
  pending.outcome_payload = detail::outcome_of(detail::AnyRecord{record});

  auto receipt = detail::apply_commit(*core_, std::move(pending));
  if (!receipt) {
    return receipt.error();
  }
  return CreateServiceOutcome{receipt.value(), record};
}

Result<CreateIsolationDomainOutcome> TenantRegistry::create_isolation_domain(
    const CreateIsolationDomainRequest& request) {
  if (core_ == nullptr) {
    return Error{ErrorCode::StoreClosed, "this registry session has been moved from"};
  }
  const RegistryLimits limits = core_->limits;
  if (request.isolation_class == IsolationClass::Unspecified) {
    return Error{ErrorCode::MissingRequiredField,
                 "an isolation domain must declare why its members are isolated; the class is not implied by a name"};
  }
  if (!detail::is_defined(request.isolation_class, IsolationClass::FaultContainment, IsolationClass::TenantPrivate)) {
    return Error{ErrorCode::InvalidEnumValue, "the isolation class is not one this build defines"};
  }
  auto display_name = detail::check_optional_text(request.display_name, limits.max_display_name_bytes, "display name");
  if (!display_name) {
    return display_name.error();
  }
  if (const auto provenance = detail::check_provenance(request.context.actor, limits); !provenance.ok()) {
    return provenance.error();
  }
  if (const auto metadata = detail::check_metadata(request.metadata, limits); !metadata.ok()) {
    return metadata.error();
  }
  const RequestDigest digest = detail::request_digest(request);

  auto guard = core_->lock();
  auto resolution = detail::resolve_context(*core_, OperationKind::CreateIsolationDomain, digest, request.context);
  if (!resolution) {
    return resolution.error();
  }
  if (resolution.value().replay) {
    auto stored = detail::decode_outcome(*resolution.value().entry, limits);
    if (!stored) {
      return stored.error();
    }
    const auto* domain = std::get_if<IsolationDomainRecord>(&stored.value());
    if (domain == nullptr) {
      return Error{ErrorCode::InternalInvariantViolated,
                   "the idempotency ledger holds an outcome of the wrong kind for this request"};
    }
    return CreateIsolationDomainOutcome{resolution.value().receipt, *domain};
  }

  const auto next_generation = advance(core_->state.generation);
  if (!next_generation) {
    return next_generation.error();
  }
  auto admission = detail::admit_identity(core_->state, SubjectKind::IsolationDomain, request.id.value(),
                                          next_generation.value());
  if (!admission) {
    return admission.error();
  }
  const std::uint64_t adding = admission.value().reuse ? 0u : 1u;
  if (const auto capacity = detail::ensure_capacity(*core_, RecordKind::IsolationDomain, adding); !capacity.ok()) {
    return capacity.error();
  }

  const IsolationDomainRecord record{request.id,
                                     display_name.value(),
                                     request.isolation_class,
                                     LifecycleState::Declared,
                                     RecordRevision::from_value(1),
                                     DomainGeneration::initial(),
                                     next_generation.value(),
                                     next_generation.value(),
                                     std::nullopt,
                                     std::nullopt,
                                     request.metadata,
                                     request.context.actor,
                                     digest};

  detail::PendingCommit pending;
  pending.operation = OperationKind::CreateIsolationDomain;
  pending.request_digest = digest;
  pending.idempotency_key = request.context.idempotency_key;
  pending.primary_key = detail::canonical_key(record);
  pending.primary_revision = record.revision;
  pending.deletes.push_back(detail::domain_key(record.id.value()));
  pending.upserts.push_back(detail::AnyRecord{record});
  if (admission.value().capture.has_value()) {
    pending.upserts.push_back(detail::AnyRecord{*admission.value().capture});
  }
  pending.outcome_payload = detail::outcome_of(detail::AnyRecord{record});

  auto receipt = detail::apply_commit(*core_, std::move(pending));
  if (!receipt) {
    return receipt.error();
  }
  return CreateIsolationDomainOutcome{receipt.value(), record};
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

Result<TransitionSubjectOutcome> TenantRegistry::transition_subject(const TransitionSubjectRequest& request) {
  if (core_ == nullptr) {
    return Error{ErrorCode::StoreClosed, "this registry session has been moved from"};
  }
  const RegistryLimits limits = core_->limits;
  const SubjectKind kind = request.subject.kind();
  if (kind == SubjectKind::Unspecified) {
    return Error{ErrorCode::InvalidIdKind, "the subject kind is unspecified"};
  }
  if (request.target == LifecycleState::Unspecified) {
    return Error{ErrorCode::InvalidEnumValue, "the target lifecycle state is unspecified"};
  }
  if (request.target == LifecycleState::Tombstoned) {
    return Error{ErrorCode::IrreversibleActionNotAcknowledged,
                 "tombstoning is irreversible and is not reachable through an ordinary lifecycle transition; use the "
                 "tombstone operation, which requires an explicit acknowledgement and records a rebind policy"};
  }
  if (const auto provenance = detail::check_provenance(request.context.actor, limits); !provenance.ok()) {
    return provenance.error();
  }
  const RequestDigest digest = detail::request_digest(request);

  auto guard = core_->lock();
  auto resolution = detail::resolve_context(*core_, OperationKind::TransitionSubject, digest, request.context);
  if (!resolution) {
    return resolution.error();
  }
  if (resolution.value().replay) {
    auto stored = detail::decode_outcome(*resolution.value().entry, limits);
    if (!stored) {
      return stored.error();
    }
    return TransitionSubjectOutcome{resolution.value().receipt, detail::as_subject(stored.value())};
  }

  const std::string text{request.subject.identity_value()};
  const std::string subject_token = identity_text(kind, text);
  auto found = detail::require_identity(core_->state, kind, text, "subject");
  if (!found) {
    return found.error();
  }
  const AnyRecord& current = *found.value();
  const RecordRevision revision = detail::revision_of(current);
  if (const auto check = detail::require_expected_revision(revision, request.expected_revision, subject_token);
      !check.ok()) {
    return check.error();
  }
  const LifecycleState from = detail::identity_state(current);
  if (from == request.target) {
    Error error{ErrorCode::LifecycleStateUnchanged,
                subject_token + " is already in state " + std::string{to_token(from)}};
    error.add_suppressed(std::string{"legal targets from here: "} + std::string{legal_targets_text(from)});
    return error;
  }
  if (!is_legal_transition(from, request.target)) {
    Error error{ErrorCode::LifecycleTransitionIllegal,
                subject_token + " cannot move from " + std::string{to_token(from)} + " to " +
                    std::string{to_token(request.target)}};
    error.add_suppressed(std::string{"legal targets from "} + std::string{to_token(from)} + ": " +
                         std::string{legal_targets_text(from)});
    return error;
  }
  if (request.target == LifecycleState::Retiring && detail::has_live_dependents(core_->state, kind, text)) {
    Error error{ErrorCode::HasLiveDependents,
                subject_token +
                    " cannot begin retirement while records still refer to it; remove them first, then retire"};
    error.add_suppressed(detail::live_dependent_report(core_->state, kind, text));
    return error;
  }

  const auto next_generation = advance(core_->state.generation);
  if (!next_generation) {
    return next_generation.error();
  }
  const auto next_revision = advance(revision);
  if (!next_revision) {
    return next_revision.error();
  }
  const bool retiring = request.target == LifecycleState::Retired;

  AnyRecord updated = std::visit(
      [&](const auto& stored) -> AnyRecord {
        using Stored = std::decay_t<decltype(stored)>;
        if constexpr (std::is_same_v<Stored, TenantRecord> || std::is_same_v<Stored, ServiceRecord> ||
                      std::is_same_v<Stored, IsolationDomainRecord>) {
          auto copy = stored;
          copy.state = request.target;
          copy.revision = next_revision.value();
          copy.updated_generation = next_generation.value();
          if (retiring) {
            copy.retired_generation = next_generation.value();
          }
          return AnyRecord{std::move(copy)};
        } else {
          return AnyRecord{stored};
        }
      },
      current);

  detail::PendingCommit pending;
  pending.operation = OperationKind::TransitionSubject;
  pending.request_digest = digest;
  pending.idempotency_key = request.context.idempotency_key;
  pending.primary_key = detail::canonical_key(updated);
  pending.primary_revision = next_revision.value();
  pending.upserts.push_back(updated);
  pending.outcome_payload = detail::outcome_of(updated);

  auto receipt = detail::apply_commit(*core_, std::move(pending));
  if (!receipt) {
    return receipt.error();
  }
  return TransitionSubjectOutcome{receipt.value(), detail::as_subject(updated)};
}

// ---------------------------------------------------------------------------
// Ownership principal and metadata
// ---------------------------------------------------------------------------

Result<MutationReceipt> TenantRegistry::set_owner(const SetOwnerRequest& request) {
  if (core_ == nullptr) {
    return Error{ErrorCode::StoreClosed, "this registry session has been moved from"};
  }
  const RegistryLimits limits = core_->limits;
  if (const auto provenance = detail::check_provenance(request.context.actor, limits); !provenance.ok()) {
    return provenance.error();
  }
  const RequestDigest digest = detail::request_digest(request);

  auto guard = core_->lock();
  auto resolution = detail::resolve_context(*core_, OperationKind::SetOwner, digest, request.context);
  if (!resolution) {
    return resolution.error();
  }
  if (resolution.value().replay) {
    return resolution.value().receipt;
  }

  const std::string subject_token = identity_text(SubjectKind::Tenant, request.tenant.value());
  auto found = detail::require_identity(core_->state, SubjectKind::Tenant, request.tenant.value(), "tenant");
  if (!found) {
    return found.error();
  }
  const auto& tenant = std::get<TenantRecord>(*found.value());
  if (const auto check = detail::require_expected_revision(tenant.revision, request.expected_revision, subject_token);
      !check.ok()) {
    return check.error();
  }
  if (const auto changeable = detail::require_changeable(*found.value(), subject_token); !changeable.ok()) {
    return changeable.error();
  }

  const auto next_generation = advance(core_->state.generation);
  if (!next_generation) {
    return next_generation.error();
  }
  const auto next_revision = advance(tenant.revision);
  if (!next_revision) {
    return next_revision.error();
  }

  TenantRecord updated = tenant;
  updated.owner = request.owner;
  updated.revision = next_revision.value();
  updated.updated_generation = next_generation.value();

  detail::PendingCommit pending;
  pending.operation = OperationKind::SetOwner;
  pending.request_digest = digest;
  pending.idempotency_key = request.context.idempotency_key;
  pending.primary_key = detail::canonical_key(updated);
  pending.primary_revision = next_revision.value();
  pending.upserts.push_back(detail::AnyRecord{updated});
  pending.outcome_payload = detail::outcome_of(detail::AnyRecord{updated});

  return detail::apply_commit(*core_, std::move(pending));
}

Result<SetMetadataOutcome> TenantRegistry::set_metadata(const SetMetadataRequest& request) {
  if (core_ == nullptr) {
    return Error{ErrorCode::StoreClosed, "this registry session has been moved from"};
  }
  const RegistryLimits limits = core_->limits;
  const SubjectKind kind = request.subject.kind();
  if (kind == SubjectKind::Unspecified) {
    return Error{ErrorCode::InvalidIdKind, "the subject kind is unspecified"};
  }
  if (const auto provenance = detail::check_provenance(request.context.actor, limits); !provenance.ok()) {
    return provenance.error();
  }
  const RequestDigest digest = detail::request_digest(request);

  auto guard = core_->lock();
  auto resolution = detail::resolve_context(*core_, OperationKind::SetMetadata, digest, request.context);
  if (!resolution) {
    return resolution.error();
  }
  if (resolution.value().replay) {
    auto stored = detail::decode_outcome(*resolution.value().entry, limits);
    if (!stored) {
      return stored.error();
    }
    return SetMetadataOutcome{resolution.value().receipt, detail::as_subject(stored.value())};
  }

  const std::string text{request.subject.identity_value()};
  const std::string subject_token = identity_text(kind, text);
  auto found = detail::require_identity(core_->state, kind, text, "subject");
  if (!found) {
    return found.error();
  }
  const AnyRecord& current = *found.value();
  if (const auto check = detail::require_expected_revision(detail::revision_of(current), request.expected_revision,
                                                           subject_token);
      !check.ok()) {
    return check.error();
  }
  if (const auto changeable = detail::require_changeable(current, subject_token); !changeable.ok()) {
    return changeable.error();
  }

  const auto next_generation = advance(core_->state.generation);
  if (!next_generation) {
    return next_generation.error();
  }
  const auto next_revision = advance(detail::revision_of(current));
  if (!next_revision) {
    return next_revision.error();
  }

  Status outcome = Status::success();
  AnyRecord updated = std::visit(
      [&](const auto& stored) -> AnyRecord {
        using Stored = std::decay_t<decltype(stored)>;
        if constexpr (std::is_same_v<Stored, TenantRecord> || std::is_same_v<Stored, ServiceRecord> ||
                      std::is_same_v<Stored, IsolationDomainRecord>) {
          auto copy = stored;
          for (const auto& key : request.remove_keys) {
            // Removing a key that was never present is not an error: the caller
            // asked for the key to be absent, and after this it is.
            (void)copy.metadata.erase(key);
          }
          for (const auto& entry : request.put_entries) {
            const auto put = copy.metadata.put(entry.key, entry.value, limits.max_metadata_entries_per_record);
            if (!put.ok() && outcome.ok()) {
              outcome = put;
            }
          }
          if (outcome.ok()) {
            outcome = detail::check_metadata(copy.metadata, limits);
          }
          copy.revision = next_revision.value();
          copy.updated_generation = next_generation.value();
          return AnyRecord{std::move(copy)};
        } else {
          return AnyRecord{stored};
        }
      },
      current);
  if (!outcome.ok()) {
    return outcome.error();
  }

  detail::PendingCommit pending;
  pending.operation = OperationKind::SetMetadata;
  pending.request_digest = digest;
  pending.idempotency_key = request.context.idempotency_key;
  pending.primary_key = detail::canonical_key(updated);
  pending.primary_revision = next_revision.value();
  pending.upserts.push_back(updated);
  pending.outcome_payload = detail::outcome_of(updated);

  auto receipt = detail::apply_commit(*core_, std::move(pending));
  if (!receipt) {
    return receipt.error();
  }
  return SetMetadataOutcome{receipt.value(), detail::as_subject(updated)};
}

// ---------------------------------------------------------------------------
// Tombstone
// ---------------------------------------------------------------------------

Result<TombstoneOutcome> TenantRegistry::tombstone(const TombstoneRequest& request) {
  if (core_ == nullptr) {
    return Error{ErrorCode::StoreClosed, "this registry session has been moved from"};
  }
  const RegistryLimits limits = core_->limits;
  const SubjectKind kind = request.subject.kind();
  if (kind == SubjectKind::Unspecified) {
    return Error{ErrorCode::InvalidIdKind, "the subject kind is unspecified"};
  }
  if (!request.acknowledgement.is_acknowledged()) {
    return Error{ErrorCode::IrreversibleActionNotAcknowledged,
                 "tombstoning an identity cannot be undone and requires an explicit acknowledgement in the request"};
  }
  if (request.note.size() > limits.max_provenance_note_bytes) {
    return Error{ErrorCode::InvalidProvenance, "the tombstone note is longer than the configured limit"};
  }
  if (request.rebind.has_value()) {
    if (request.rebind->kind != kind) {
      return Error{ErrorCode::InvalidIdKind,
                   "a rebind permit must name a successor of the same kind as the identity it fences"};
    }
    if (const auto text = detail::check_identity_text(request.rebind->kind, request.rebind->text); !text.ok()) {
      return text.error();
    }
  }
  if (const auto provenance = detail::check_provenance(request.context.actor, limits); !provenance.ok()) {
    return provenance.error();
  }
  const RequestDigest digest = detail::request_digest(request);

  auto guard = core_->lock();
  auto resolution = detail::resolve_context(*core_, OperationKind::Tombstone, digest, request.context);
  if (!resolution) {
    return resolution.error();
  }
  if (resolution.value().replay) {
    auto stored = detail::decode_outcome(*resolution.value().entry, limits);
    if (!stored) {
      return stored.error();
    }
    return TombstoneOutcome{resolution.value().receipt, detail::as_subject(stored.value())};
  }

  const std::string text{request.subject.identity_value()};
  const std::string subject_token = identity_text(kind, text);
  auto found = detail::require_identity(core_->state, kind, text, "subject");
  if (!found) {
    return found.error();
  }
  const AnyRecord& current = *found.value();
  if (const auto check = detail::require_expected_revision(detail::revision_of(current), request.expected_revision,
                                                           subject_token);
      !check.ok()) {
    return check.error();
  }
  const LifecycleState from = detail::identity_state(current);
  if (from != LifecycleState::Retired) {
    Error error{ErrorCode::LifecycleTransitionIllegal,
                subject_token + " is in state " + std::string{to_token(from)} +
                    "; an identity is tombstoned from Retired and from nothing else"};
    error.add_suppressed(std::string{"legal targets from "} + std::string{to_token(from)} + ": " +
                         std::string{legal_targets_text(from)});
    return error;
  }
  if (detail::has_live_dependents(core_->state, kind, text)) {
    Error error{ErrorCode::HasLiveDependents,
                subject_token + " still has records referring to it and cannot be fenced yet"};
    error.add_suppressed(detail::live_dependent_report(core_->state, kind, text));
    return error;
  }

  const auto next_generation = advance(core_->state.generation);
  if (!next_generation) {
    return next_generation.error();
  }
  const auto next_revision = advance(detail::revision_of(current));
  if (!next_revision) {
    return next_revision.error();
  }

  std::optional<RebindPermit> permit;
  if (request.rebind.has_value()) {
    auto issued = RebindPermit::issue(request.rebind->kind, request.rebind->text, next_generation.value(), request.note,
                                      limits.max_identity_bytes, limits.max_provenance_note_bytes);
    if (!issued) {
      return issued.error();
    }
    permit = std::move(issued).value();
  }

  const RegistryGeneration retired_generation = std::visit(
      [](const auto& stored) -> RegistryGeneration {
        using Stored = std::decay_t<decltype(stored)>;
        if constexpr (std::is_same_v<Stored, TenantRecord> || std::is_same_v<Stored, ServiceRecord> ||
                      std::is_same_v<Stored, IsolationDomainRecord>) {
          return stored.retired_generation.value_or(RegistryGeneration::initial());
        } else {
          return RegistryGeneration::initial();
        }
      },
      current);

  auto tombstone_value =
      Tombstone::create(retired_generation, next_generation.value(), permit, request.note,
                        limits.max_provenance_note_bytes);
  if (!tombstone_value) {
    return tombstone_value.error();
  }

  AnyRecord updated = std::visit(
      [&](const auto& stored) -> AnyRecord {
        using Stored = std::decay_t<decltype(stored)>;
        if constexpr (std::is_same_v<Stored, TenantRecord> || std::is_same_v<Stored, ServiceRecord> ||
                      std::is_same_v<Stored, IsolationDomainRecord>) {
          auto copy = stored;
          copy.state = LifecycleState::Tombstoned;
          copy.revision = next_revision.value();
          copy.updated_generation = next_generation.value();
          copy.retired_generation = retired_generation;
          copy.tombstone = tombstone_value.value();
          return AnyRecord{std::move(copy)};
        } else {
          return AnyRecord{stored};
        }
      },
      current);

  detail::PendingCommit pending;
  pending.operation = OperationKind::Tombstone;
  pending.request_digest = digest;
  pending.idempotency_key = request.context.idempotency_key;
  pending.primary_key = detail::canonical_key(updated);
  pending.primary_revision = next_revision.value();
  pending.upserts.push_back(updated);
  pending.outcome_payload = detail::outcome_of(updated);

  auto receipt = detail::apply_commit(*core_, std::move(pending));
  if (!receipt) {
    return receipt.error();
  }
  return TombstoneOutcome{receipt.value(), detail::as_subject(updated)};
}


// ---------------------------------------------------------------------------
// Relationships
// ---------------------------------------------------------------------------

Result<PutOwnershipOutcome> TenantRegistry::put_ownership(const PutOwnershipRequest& request) {
  if (core_ == nullptr) {
    return Error{ErrorCode::StoreClosed, "this registry session has been moved from"};
  }
  const RegistryLimits limits = core_->limits;
  if (request.kind == OwnershipKind::Unspecified) {
    return Error{ErrorCode::MissingRequiredField,
                 "an ownership relationship must declare its kind; the kind is not inferred from a name"};
  }
  if (!detail::is_defined(request.kind, OwnershipKind::Administrative, OwnershipKind::DataResidency)) {
    return Error{ErrorCode::InvalidEnumValue, "the ownership kind is not one this build defines"};
  }
  if (request.initial_state != LifecycleState::Declared && request.initial_state != LifecycleState::Active) {
    return Error{ErrorCode::InvalidEnumValue,
                 "a new ownership relationship starts Declared or Active; every other state is reached by transition"};
  }
  if (const auto provenance = detail::check_provenance(request.context.actor, limits); !provenance.ok()) {
    return provenance.error();
  }
  const RequestDigest digest = detail::request_digest(request);

  auto guard = core_->lock();
  auto resolution = detail::resolve_context(*core_, OperationKind::PutOwnership, digest, request.context);
  if (!resolution) {
    return resolution.error();
  }
  if (resolution.value().replay) {
    auto stored = detail::decode_outcome(*resolution.value().entry, limits);
    if (!stored) {
      return stored.error();
    }
    const auto* edge = std::get_if<OwnershipEdge>(&stored.value());
    if (edge == nullptr) {
      return Error{ErrorCode::InternalInvariantViolated,
                   "the idempotency ledger holds an outcome of the wrong kind for this request"};
    }
    return PutOwnershipOutcome{resolution.value().receipt, *edge};
  }

  const std::string child_token = identity_text(SubjectKind::Tenant, request.child.value());
  const std::string parent_token = identity_text(SubjectKind::Tenant, request.parent.value());
  auto child = detail::require_identity(core_->state, SubjectKind::Tenant, request.child.value(), "tenant");
  if (!child) {
    return child.error();
  }
  auto parent = detail::require_identity(core_->state, SubjectKind::Tenant, request.parent.value(), "tenant");
  if (!parent) {
    return parent.error();
  }
  if (const auto check = detail::require_in_force_target(*parent.value(), parent_token); !check.ok()) {
    return check.error();
  }
  if (const auto check = detail::require_admits_new_relationships(*child.value(), child_token); !check.ok()) {
    return check.error();
  }
  if (const auto acyclic = detail::check_acyclic_added_edge(core_->state, request.child, request.parent, limits);
      !acyclic.ok()) {
    return acyclic.error();
  }

  const OwnershipEdge* existing = core_->state.find_ownership(request.child.value(), request.parent.value());
  if (existing == nullptr && request.expected_revision.has_value()) {
    return Error{ErrorCode::StaleRecordRevision,
                 "the request asserts that the ownership relationship " + child_token + " -> " + parent_token +
                     " exists at revision " + std::to_string(request.expected_revision->value()) +
                     ", but no such relationship exists"};
  }
  if (existing != nullptr && !request.expected_revision.has_value()) {
    return Error{ErrorCode::DuplicateRelationship,
                 "the ownership relationship " + child_token + " -> " + parent_token +
                     " already exists at revision " + std::to_string(existing->revision.value()) +
                     "; supply expected_revision to change it"};
  }
  if (existing != nullptr) {
    if (const auto check = detail::require_expected_revision(existing->revision, *request.expected_revision,
                                                             child_token + " -> " + parent_token);
        !check.ok()) {
      return check.error();
    }
  }

  if (request.initial_state == LifecycleState::Active && request.kind == OwnershipKind::Administrative) {
    bool conflict = false;
    std::string holder;
    core_->state.for_each_prefix(detail::ownership_child_prefix(request.child.value()),
                                 [&](const detail::AnyRecord& stored) {
                                   const auto& edge = std::get<OwnershipEdge>(stored);
                                   if (edge.child.value() == request.child.value() && edge.kind == OwnershipKind::Administrative &&
                                       is_in_force(edge.state) && edge.parent.value() != request.parent.value()) {
                                     conflict = true;
                                     holder = edge.parent.value();
                                     return false;
                                   }
                                   return true;
                                 });
    if (conflict) {
      return Error{ErrorCode::BindingConflict,
                   child_token + " already has an in-force administrative owner, " + holder +
                       "; a tenant has exactly one accountable owner at a time"};
    }
  }

  if (existing == nullptr) {
    if (const auto capacity = detail::ensure_capacity(*core_, detail::RecordKind::OwnershipEdge, 1u);
        !capacity.ok()) {
      return capacity.error();
    }
    // The canonical key is "ownership:<child>|<parent>", so the children of a
    // tenant are not a key prefix. The count is therefore maintained with the
    // record map instead of being derived: a scan here would make declaring one
    // edge cost the whole registry.
    const std::uint64_t owned = core_->state.child_count(request.parent.value());
    if (owned >= limits.max_children_per_tenant) {
      return Error{ErrorCode::LimitExceeded,
                   parent_token + " already owns " + std::to_string(owned) +
                       " tenants, which is the configured limit"};
    }
  }

  const auto next_generation = advance(core_->state.generation);
  if (!next_generation) {
    return next_generation.error();
  }

  RecordRevision revision = RecordRevision::from_value(1);
  RegistryGeneration created = next_generation.value();
  if (existing != nullptr) {
    const auto next_revision = advance(existing->revision);
    if (!next_revision) {
      return next_revision.error();
    }
    revision = next_revision.value();
    created = existing->created_generation;
  }

  const OwnershipEdge edge{request.child,
                           request.parent,
                           request.kind,
                           request.initial_state,
                           revision,
                           created,
                           next_generation.value(),
                           request.context.actor,
                           digest};

  detail::PendingCommit pending;
  pending.operation = OperationKind::PutOwnership;
  pending.request_digest = digest;
  pending.idempotency_key = request.context.idempotency_key;
  pending.primary_key = detail::canonical_key(edge);
  pending.primary_revision = revision;
  pending.upserts.push_back(detail::AnyRecord{edge});
  pending.outcome_payload = detail::outcome_of(detail::AnyRecord{edge});

  auto receipt = detail::apply_commit(*core_, std::move(pending));
  if (!receipt) {
    return receipt.error();
  }
  return PutOwnershipOutcome{receipt.value(), edge};
}

Result<MutationReceipt> TenantRegistry::remove_ownership(const RemoveOwnershipRequest& request) {
  if (core_ == nullptr) {
    return Error{ErrorCode::StoreClosed, "this registry session has been moved from"};
  }
  const RegistryLimits limits = core_->limits;
  if (const auto provenance = detail::check_provenance(request.context.actor, limits); !provenance.ok()) {
    return provenance.error();
  }
  const RequestDigest digest = detail::request_digest(request);

  auto guard = core_->lock();
  auto resolution = detail::resolve_context(*core_, OperationKind::RemoveOwnership, digest, request.context);
  if (!resolution) {
    return resolution.error();
  }
  if (resolution.value().replay) {
    return resolution.value().receipt;
  }

  const OwnershipEdge* edge = core_->state.find_ownership(request.child.value(), request.parent.value());
  const std::string token = identity_text(SubjectKind::Tenant, request.child.value()) + " -> " +
                            identity_text(SubjectKind::Tenant, request.parent.value());
  if (edge == nullptr) {
    return Error{ErrorCode::RelationshipAbsent, "the ownership relationship " + token + " does not exist"};
  }
  if (const auto check = detail::require_expected_revision(edge->revision, request.expected_revision, token);
      !check.ok()) {
    return check.error();
  }

  const auto next_generation = advance(core_->state.generation);
  if (!next_generation) {
    return next_generation.error();
  }

  detail::PendingCommit pending;
  pending.operation = OperationKind::RemoveOwnership;
  pending.request_digest = digest;
  pending.idempotency_key = request.context.idempotency_key;
  pending.primary_key = detail::ownership_key(request.child.value(), request.parent.value());
  pending.primary_revision = edge->revision;
  pending.deletes.push_back(pending.primary_key);

  return detail::apply_commit(*core_, std::move(pending));
}

Result<MutationReceipt> TenantRegistry::transition_ownership(const TransitionOwnershipRequest& request) {
  if (core_ == nullptr) {
    return Error{ErrorCode::StoreClosed, "this registry session has been moved from"};
  }
  const RegistryLimits limits = core_->limits;
  if (request.target == LifecycleState::Unspecified || request.target == LifecycleState::Tombstoned) {
    return Error{ErrorCode::InvalidEnumValue,
                 "an ownership relationship moves between Declared, Active, Suspended, Retiring and Retired only"};
  }
  if (const auto provenance = detail::check_provenance(request.context.actor, limits); !provenance.ok()) {
    return provenance.error();
  }
  const RequestDigest digest = detail::request_digest(request);

  auto guard = core_->lock();
  auto resolution = detail::resolve_context(*core_, OperationKind::TransitionOwnership, digest, request.context);
  if (!resolution) {
    return resolution.error();
  }
  if (resolution.value().replay) {
    return resolution.value().receipt;
  }

  const OwnershipEdge* edge = core_->state.find_ownership(request.child.value(), request.parent.value());
  const std::string token = identity_text(SubjectKind::Tenant, request.child.value()) + " -> " +
                            identity_text(SubjectKind::Tenant, request.parent.value());
  if (edge == nullptr) {
    return Error{ErrorCode::RelationshipAbsent, "the ownership relationship " + token + " does not exist"};
  }
  if (const auto check = detail::require_expected_revision(edge->revision, request.expected_revision, token);
      !check.ok()) {
    return check.error();
  }
  if (edge->state == request.target) {
    return Error{ErrorCode::LifecycleStateUnchanged, token + " is already in state " +
                                                          std::string{to_token(edge->state)}};
  }
  if (!is_legal_transition(edge->state, request.target)) {
    Error error{ErrorCode::LifecycleTransitionIllegal,
                token + " cannot move from " + std::string{to_token(edge->state)} + " to " +
                    std::string{to_token(request.target)}};
    error.add_suppressed(std::string{"legal targets from "} + std::string{to_token(edge->state)} + ": " +
                         std::string{legal_targets_text(edge->state)});
    return error;
  }
  if (request.target == LifecycleState::Active && edge->kind == OwnershipKind::Administrative) {
    // Bringing an edge into force has to satisfy exactly the rule that creating
    // one in force satisfies. Checking it only on creation would let a caller
    // reach a state this registry refuses to store, which is a corruption path
    // reachable through a legal operation.
    bool conflict = false;
    std::string holder;
    core_->state.for_each_prefix(detail::ownership_child_prefix(request.child.value()),
                                 [&](const detail::AnyRecord& stored) {
                                   const auto& other = std::get<OwnershipEdge>(stored);
                                   if (other.child.value() == request.child.value() &&
                                       other.kind == OwnershipKind::Administrative && is_in_force(other.state) &&
                                       other.parent.value() != request.parent.value()) {
                                     conflict = true;
                                     holder = other.parent.value();
                                     return false;
                                   }
                                   return true;
                                 });
    if (conflict) {
      return Error{ErrorCode::BindingConflict,
                   identity_text(SubjectKind::Tenant, request.child.value()) +
                       " already has an in-force administrative owner, " + holder +
                       "; a tenant has exactly one accountable owner at a time"};
    }
  }

  const auto next_generation = advance(core_->state.generation);
  if (!next_generation) {
    return next_generation.error();
  }
  const auto next_revision = advance(edge->revision);
  if (!next_revision) {
    return next_revision.error();
  }

  OwnershipEdge updated = *edge;
  updated.state = request.target;
  updated.revision = next_revision.value();
  updated.updated_generation = next_generation.value();

  detail::PendingCommit pending;
  pending.operation = OperationKind::TransitionOwnership;
  pending.request_digest = digest;
  pending.idempotency_key = request.context.idempotency_key;
  pending.primary_key = detail::canonical_key(updated);
  pending.primary_revision = next_revision.value();
  pending.upserts.push_back(detail::AnyRecord{updated});

  return detail::apply_commit(*core_, std::move(pending));
}

Result<PutServiceBindingOutcome> TenantRegistry::put_service_binding(const PutServiceBindingRequest& request) {
  if (core_ == nullptr) {
    return Error{ErrorCode::StoreClosed, "this registry session has been moved from"};
  }
  const RegistryLimits limits = core_->limits;
  if (request.kind == BindingKind::Unspecified) {
    return Error{ErrorCode::MissingRequiredField, "a service binding must declare its kind"};
  }
  if (!detail::is_defined(request.kind, BindingKind::OperatedBy, BindingKind::ConsumedBy)) {
    return Error{ErrorCode::InvalidEnumValue, "the binding kind is not one this build defines"};
  }
  if (request.initial_state != LifecycleState::Declared && request.initial_state != LifecycleState::Active) {
    return Error{ErrorCode::InvalidEnumValue,
                 "a new service binding starts Declared or Active; every other state is reached by transition"};
  }
  if (const auto provenance = detail::check_provenance(request.context.actor, limits); !provenance.ok()) {
    return provenance.error();
  }
  const RequestDigest digest = detail::request_digest(request);

  auto guard = core_->lock();
  auto resolution = detail::resolve_context(*core_, OperationKind::PutServiceBinding, digest, request.context);
  if (!resolution) {
    return resolution.error();
  }
  if (resolution.value().replay) {
    auto stored = detail::decode_outcome(*resolution.value().entry, limits);
    if (!stored) {
      return stored.error();
    }
    const auto* binding = std::get_if<ServiceBinding>(&stored.value());
    if (binding == nullptr) {
      return Error{ErrorCode::InternalInvariantViolated,
                   "the idempotency ledger holds an outcome of the wrong kind for this request"};
    }
    return PutServiceBindingOutcome{resolution.value().receipt, *binding};
  }

  const std::string service_token = identity_text(SubjectKind::Service, request.service.value());
  const std::string tenant_token = identity_text(SubjectKind::Tenant, request.tenant.value());
  auto service = detail::require_identity(core_->state, SubjectKind::Service, request.service.value(), "service");
  if (!service) {
    return service.error();
  }
  auto tenant = detail::require_identity(core_->state, SubjectKind::Tenant, request.tenant.value(), "tenant");
  if (!tenant) {
    return tenant.error();
  }
  if (const auto check = detail::require_admits_new_relationships(*service.value(), service_token); !check.ok()) {
    return check.error();
  }
  if (const auto check = detail::require_in_force_target(*tenant.value(), tenant_token); !check.ok()) {
    return check.error();
  }

  const std::string key = detail::binding_key(request.service.value(), request.tenant.value(), request.kind);
  const ServiceBinding* existing = core_->state.find_binding(request.service.value(), request.tenant.value(),
                                                             request.kind);
  if (existing == nullptr && request.expected_revision.has_value()) {
    return Error{ErrorCode::StaleRecordRevision,
                 "the request asserts that the " + std::string{to_token(request.kind)} + " binding of " +
                     service_token + " to " + tenant_token + " exists at revision " +
                     std::to_string(request.expected_revision->value()) + ", but no such binding exists"};
  }
  if (existing != nullptr && !request.expected_revision.has_value()) {
    return Error{ErrorCode::DuplicateRelationship,
                 "the " + std::string{to_token(request.kind)} + " binding of " + service_token + " to " +
                     tenant_token + " already exists at revision " + std::to_string(existing->revision.value()) +
                     "; supply expected_revision to change it"};
  }
  if (existing != nullptr) {
    if (const auto check = detail::require_expected_revision(existing->revision, *request.expected_revision, key);
        !check.ok()) {
      return check.error();
    }
  }

  if (request.initial_state == LifecycleState::Active) {
    const ServiceBinding* in_force = nullptr;
    core_->state.for_each_prefix(detail::binding_service_prefix(request.service.value()),
                                 [&](const detail::AnyRecord& stored) {
                                   const auto& binding = std::get<ServiceBinding>(stored);
                                   if (binding.service.value() == request.service.value() &&
                                       binding.kind == request.kind && is_in_force(binding.state) &&
                                       binding.tenant.value() != request.tenant.value()) {
                                     in_force = &binding;
                                     return false;
                                   }
                                   return true;
                                 });
    if (in_force != nullptr) {
      return Error{ErrorCode::BindingConflict,
                   service_token + " already has an in-force " + std::string{to_token(request.kind)} +
                       " binding to " + in_force->tenant.value() +
                       "; two in-force bindings of one kind would be two answers to one question"};
    }
  }

  if (existing == nullptr) {
    if (const auto capacity = detail::ensure_capacity(*core_, detail::RecordKind::ServiceBinding, 1u);
        !capacity.ok()) {
      return capacity.error();
    }
    std::size_t count = 0;
    core_->state.for_each_prefix(detail::binding_service_prefix(request.service.value()),
                                 [&](const detail::AnyRecord&) {
                                   ++count;
                                   return true;
                                 });
    if (count >= limits.max_bindings_per_service) {
      return Error{ErrorCode::LimitExceeded,
                   service_token + " already holds " + std::to_string(count) +
                       " bindings, which is the configured limit"};
    }
  }

  const auto next_generation = advance(core_->state.generation);
  if (!next_generation) {
    return next_generation.error();
  }

  RecordRevision revision = RecordRevision::from_value(1);
  RegistryGeneration created = next_generation.value();
  if (existing != nullptr) {
    const auto next_revision = advance(existing->revision);
    if (!next_revision) {
      return next_revision.error();
    }
    revision = next_revision.value();
    created = existing->created_generation;
  }

  const ServiceBinding binding{request.service,
                               request.tenant,
                               request.kind,
                               request.initial_state,
                               revision,
                               created,
                               next_generation.value(),
                               request.context.actor,
                               digest};

  detail::PendingCommit pending;
  pending.operation = OperationKind::PutServiceBinding;
  pending.request_digest = digest;
  pending.idempotency_key = request.context.idempotency_key;
  pending.primary_key = detail::canonical_key(binding);
  pending.primary_revision = revision;
  pending.upserts.push_back(detail::AnyRecord{binding});
  pending.outcome_payload = detail::outcome_of(detail::AnyRecord{binding});

  auto receipt = detail::apply_commit(*core_, std::move(pending));
  if (!receipt) {
    return receipt.error();
  }
  return PutServiceBindingOutcome{receipt.value(), binding};
}

Result<MutationReceipt> TenantRegistry::remove_service_binding(const RemoveServiceBindingRequest& request) {
  if (core_ == nullptr) {
    return Error{ErrorCode::StoreClosed, "this registry session has been moved from"};
  }
  const RegistryLimits limits = core_->limits;
  if (request.kind == BindingKind::Unspecified) {
    return Error{ErrorCode::MissingRequiredField, "a service binding must declare its kind"};
  }
  if (!detail::is_defined(request.kind, BindingKind::OperatedBy, BindingKind::ConsumedBy)) {
    return Error{ErrorCode::InvalidEnumValue, "the binding kind is not one this build defines"};
  }
  if (const auto provenance = detail::check_provenance(request.context.actor, limits); !provenance.ok()) {
    return provenance.error();
  }
  const RequestDigest digest = detail::request_digest(request);

  auto guard = core_->lock();
  auto resolution = detail::resolve_context(*core_, OperationKind::RemoveServiceBinding, digest, request.context);
  if (!resolution) {
    return resolution.error();
  }
  if (resolution.value().replay) {
    return resolution.value().receipt;
  }

  const std::string key =
      detail::binding_key(request.service.value(), request.tenant.value(), request.kind);
  const ServiceBinding* binding = core_->state.find_binding(request.service.value(), request.tenant.value(),
                                                             request.kind);
  if (binding == nullptr) {
    return Error{ErrorCode::RelationshipAbsent, "the binding " + key + " does not exist"};
  }
  if (const auto check = detail::require_expected_revision(binding->revision, request.expected_revision, key);
      !check.ok()) {
    return check.error();
  }

  const auto next_generation = advance(core_->state.generation);
  if (!next_generation) {
    return next_generation.error();
  }

  detail::PendingCommit pending;
  pending.operation = OperationKind::RemoveServiceBinding;
  pending.request_digest = digest;
  pending.idempotency_key = request.context.idempotency_key;
  pending.primary_key = key;
  pending.primary_revision = binding->revision;
  pending.deletes.push_back(key);

  return detail::apply_commit(*core_, std::move(pending));
}

Result<MutationReceipt> TenantRegistry::transition_service_binding(
    const TransitionServiceBindingRequest& request) {
  if (core_ == nullptr) {
    return Error{ErrorCode::StoreClosed, "this registry session has been moved from"};
  }
  const RegistryLimits limits = core_->limits;
  if (request.kind == BindingKind::Unspecified) {
    return Error{ErrorCode::MissingRequiredField, "a service binding must declare its kind"};
  }
  if (!detail::is_defined(request.kind, BindingKind::OperatedBy, BindingKind::ConsumedBy)) {
    return Error{ErrorCode::InvalidEnumValue, "the binding kind is not one this build defines"};
  }
  if (!detail::is_defined(request.target, LifecycleState::Declared, LifecycleState::Tombstoned)) {
    return Error{ErrorCode::InvalidEnumValue, "the binding target state is not one this build defines"};
  }
  if (request.target == LifecycleState::Unspecified || request.target == LifecycleState::Tombstoned) {
    return Error{ErrorCode::InvalidEnumValue,
                 "a service binding moves between Declared, Active, Suspended, Retiring and Retired only"};
  }
  if (const auto provenance = detail::check_provenance(request.context.actor, limits); !provenance.ok()) {
    return provenance.error();
  }
  const RequestDigest digest = detail::request_digest(request);

  auto guard = core_->lock();
  auto resolution = detail::resolve_context(*core_, OperationKind::TransitionServiceBinding, digest, request.context);
  if (!resolution) {
    return resolution.error();
  }
  if (resolution.value().replay) {
    return resolution.value().receipt;
  }

  const std::string key =
      detail::binding_key(request.service.value(), request.tenant.value(), request.kind);
  const ServiceBinding* binding = core_->state.find_binding(request.service.value(), request.tenant.value(),
                                                             request.kind);
  if (binding == nullptr) {
    return Error{ErrorCode::RelationshipAbsent, "the binding " + key + " does not exist"};
  }
  if (const auto check = detail::require_expected_revision(binding->revision, request.expected_revision, key);
      !check.ok()) {
    return check.error();
  }
  if (binding->state == request.target) {
    return Error{ErrorCode::LifecycleStateUnchanged,
                 key + " is already in state " + std::string{to_token(binding->state)}};
  }
  if (!is_legal_transition(binding->state, request.target)) {
    Error error{ErrorCode::LifecycleTransitionIllegal,
                key + " cannot move from " + std::string{to_token(binding->state)} + " to " +
                    std::string{to_token(request.target)}};
    error.add_suppressed(std::string{"legal targets from "} + std::string{to_token(binding->state)} + ": " +
                         std::string{legal_targets_text(binding->state)});
    return error;
  }
  if (request.target == LifecycleState::Active) {
    const ServiceBinding* in_force = nullptr;
    core_->state.for_each_prefix(detail::binding_service_prefix(request.service.value()),
                                 [&](const detail::AnyRecord& stored) {
                                   const auto& other = std::get<ServiceBinding>(stored);
                                   if (other.service.value() == request.service.value() &&
                                       other.kind == request.kind && is_in_force(other.state) &&
                                       other.tenant.value() != request.tenant.value()) {
                                     in_force = &other;
                                     return false;
                                   }
                                   return true;
                                 });
    if (in_force != nullptr) {
      return Error{ErrorCode::BindingConflict,
                   identity_text(SubjectKind::Service, request.service.value()) +
                       " already has an in-force " + std::string{to_token(request.kind)} + " binding to " +
                       in_force->tenant.value()};
    }
  }

  const auto next_generation = advance(core_->state.generation);
  if (!next_generation) {
    return next_generation.error();
  }
  const auto next_revision = advance(binding->revision);
  if (!next_revision) {
    return next_revision.error();
  }

  ServiceBinding updated = *binding;
  updated.state = request.target;
  updated.revision = next_revision.value();
  updated.updated_generation = next_generation.value();

  detail::PendingCommit pending;
  pending.operation = OperationKind::TransitionServiceBinding;
  pending.request_digest = digest;
  pending.idempotency_key = request.context.idempotency_key;
  pending.primary_key = detail::canonical_key(updated);
  pending.primary_revision = next_revision.value();
  pending.upserts.push_back(detail::AnyRecord{updated});

  return detail::apply_commit(*core_, std::move(pending));
}

// ---------------------------------------------------------------------------
// Isolation membership
//
// Every membership change advances the membership generation of the domain it
// touches, and every membership request must state the generation it saw. A
// consumer that cached membership of a domain is therefore fenced the moment
// that domain changes, without having to re-read the whole registry.
// ---------------------------------------------------------------------------

Result<PutIsolationMembershipOutcome> TenantRegistry::put_isolation_membership(
    const PutIsolationMembershipRequest& request) {
  if (core_ == nullptr) {
    return Error{ErrorCode::StoreClosed, "this registry session has been moved from"};
  }
  const RegistryLimits limits = core_->limits;
  const SubjectKind kind = request.subject.kind();
  if (kind == SubjectKind::Unspecified) {
    return Error{ErrorCode::InvalidIdKind, "the subject kind is unspecified"};
  }
  if (kind == SubjectKind::IsolationDomain) {
    return Error{ErrorCode::InvalidIdKind,
                 "an isolation domain is not a member of another isolation domain; isolation membership is declared "
                 "for tenants and services only"};
  }
  if (request.role == MembershipRole::Unspecified) {
    return Error{ErrorCode::MissingRequiredField,
                 "an isolation membership must declare its role; isolation is never inferred from a name or a label"};
  }
  if (!detail::is_defined(request.role, MembershipRole::Primary, MembershipRole::Fallback)) {
    return Error{ErrorCode::InvalidEnumValue, "the membership role is not one this build defines"};
  }
  if (request.initial_state != MembershipState::Proposed && request.initial_state != MembershipState::Bound) {
    return Error{ErrorCode::InvalidEnumValue,
                 "a new isolation membership starts Proposed or Bound; every other state is reached by transition"};
  }
  if (const auto provenance = detail::check_provenance(request.context.actor, limits); !provenance.ok()) {
    return provenance.error();
  }
  const RequestDigest digest = detail::request_digest(request);

  auto guard = core_->lock();
  auto resolution =
      detail::resolve_context(*core_, OperationKind::PutIsolationMembership, digest, request.context);
  if (!resolution) {
    return resolution.error();
  }
  if (resolution.value().replay) {
    auto stored = detail::decode_outcome(*resolution.value().entry, limits);
    if (!stored) {
      return stored.error();
    }
    const auto* membership = std::get_if<IsolationMembership>(&stored.value());
    if (membership == nullptr) {
      return Error{ErrorCode::InternalInvariantViolated,
                   "the idempotency ledger holds an outcome of the wrong kind for this request"};
    }
    const auto* domain = core_->state.find_domain(request.domain);
    const DomainGeneration generation =
        domain != nullptr ? domain->membership_generation : DomainGeneration::initial();
    return PutIsolationMembershipOutcome{resolution.value().receipt, *membership, generation};
  }

  const std::string subject_token = identity_text(kind, request.subject.identity_value());
  const std::string domain_token = identity_text(SubjectKind::IsolationDomain, request.domain.value());
  auto subject = detail::require_identity(core_->state, kind, request.subject.identity_value(), "subject");
  if (!subject) {
    return subject.error();
  }
  auto domain = detail::require_identity(core_->state, SubjectKind::IsolationDomain, request.domain.value(),
                                         "isolation domain");
  if (!domain) {
    return domain.error();
  }
  const auto& domain_record = std::get<IsolationDomainRecord>(*domain.value());
  if (domain_record.membership_generation != request.expected_domain_generation) {
    return Error{ErrorCode::StaleDomainGeneration,
                 "the request was composed against membership generation " +
                     std::to_string(request.expected_domain_generation.value()) + " of " + domain_token +
                     " but that domain is at generation " +
                     std::to_string(domain_record.membership_generation.value()) +
                     "; re-read the domain before changing its membership"};
  }

  const IsolationMembership* existing =
      core_->state.find_membership(request.subject, request.domain);
  if (existing != nullptr && !request.expected_revision.has_value()) {
    return Error{ErrorCode::DuplicateRelationship,
                 subject_token + " already has a membership in " + domain_token + " at revision " +
                     std::to_string(existing->revision.value()) +
                     "; supply expected_revision to change it"};
  }
  if (existing == nullptr && request.expected_revision.has_value()) {
    return Error{ErrorCode::StaleRecordRevision,
                 "the request asserts that " + subject_token + " is a member of " + domain_token +
                     " at revision " + std::to_string(request.expected_revision->value()) +
                     ", but no such membership exists"};
  }
  if (existing != nullptr) {
    const std::string token = subject_token + " in " + domain_token;
    if (const auto check = detail::require_expected_revision(existing->revision, *request.expected_revision, token);
        !check.ok()) {
      return check.error();
    }
    if (existing->state != request.initial_state) {
      Error error{ErrorCode::LifecycleTransitionIllegal,
                  token + " is in state " + std::string{to_token(existing->state)} +
                      "; changing a membership state is a transition, not a re-declaration"};
      error.add_suppressed(std::string{"use the membership transition operation to reach "} +
                           std::string{to_token(request.initial_state)});
      return error;
    }
  } else {
    if (const auto check = detail::require_admits_new_relationships(*subject.value(), subject_token); !check.ok()) {
      return check.error();
    }
    if (const auto check = detail::require_admits_new_relationships(*domain.value(), domain_token); !check.ok()) {
      return check.error();
    }
    if (const auto capacity = detail::ensure_capacity(*core_, detail::RecordKind::IsolationMembership, 1u);
        !capacity.ok()) {
      return capacity.error();
    }
    std::size_t domain_count = 0;
    core_->state.for_each_prefix("membership:", [&](const detail::AnyRecord& stored) {
      if (std::get<IsolationMembership>(stored).domain == request.domain) {
        ++domain_count;
      }
      return true;
    });
    if (domain_count >= limits.max_memberships_per_domain) {
      return Error{ErrorCode::LimitExceeded,
                   domain_token + " already holds " + std::to_string(domain_count) +
                       " memberships, which is the configured limit"};
    }
    std::size_t subject_count = 0;
    core_->state.for_each_prefix(detail::membership_subject_prefix(request.subject),
                                 [&](const detail::AnyRecord&) {
                                   ++subject_count;
                                   return true;
                                 });
    if (subject_count >= limits.max_memberships_per_subject) {
      return Error{ErrorCode::LimitExceeded,
                   subject_token + " already holds " + std::to_string(subject_count) +
                       " isolation memberships, which is the configured limit"};
    }
  }

  if (request.role == MembershipRole::Primary && request.initial_state == MembershipState::Bound) {
    bool conflict = false;
    std::string holder;
    core_->state.for_each_prefix(detail::membership_subject_prefix(request.subject),
                                 [&](const detail::AnyRecord& stored) {
                                   const auto& membership = std::get<IsolationMembership>(stored);
                                   if (membership.role == MembershipRole::Primary &&
                                       membership.state == MembershipState::Bound &&
                                       !(membership.domain == request.domain)) {
                                     conflict = true;
                                     holder = membership.domain.value();
                                     return false;
                                   }
                                   return true;
                                 });
    if (conflict) {
      return Error{ErrorCode::MembershipRoleConflict,
                   subject_token + " is already an in-force primary member of " + holder +
                       "; a subject has exactly one primary isolation domain at a time"};
    }
  }

  const auto next_generation = advance(core_->state.generation);
  if (!next_generation) {
    return next_generation.error();
  }
  const auto next_domain_generation = advance(domain_record.membership_generation);
  if (!next_domain_generation) {
    return next_domain_generation.error();
  }

  RecordRevision revision = RecordRevision::from_value(1);
  RegistryGeneration created = next_generation.value();
  if (existing != nullptr) {
    const auto next_revision = advance(existing->revision);
    if (!next_revision) {
      return next_revision.error();
    }
    revision = next_revision.value();
    created = existing->created_generation;
  }

  const IsolationMembership membership{request.subject,
                                       request.domain,
                                       request.role,
                                       request.initial_state,
                                       revision,
                                       created,
                                       next_generation.value(),
                                       request.context.actor,
                                       digest};

  IsolationDomainRecord updated_domain = domain_record;
  const auto domain_revision = advance(domain_record.revision);
  if (!domain_revision) {
    return domain_revision.error();
  }
  updated_domain.membership_generation = next_domain_generation.value();
  updated_domain.revision = domain_revision.value();
  updated_domain.updated_generation = next_generation.value();

  detail::PendingCommit pending;
  pending.operation = OperationKind::PutIsolationMembership;
  pending.request_digest = digest;
  pending.idempotency_key = request.context.idempotency_key;
  pending.primary_key = detail::canonical_key(membership);
  pending.primary_revision = revision;
  pending.upserts.push_back(detail::AnyRecord{membership});
  pending.upserts.push_back(detail::AnyRecord{updated_domain});
  pending.domain_generations.emplace_back(request.domain, next_domain_generation.value());
  pending.outcome_payload = detail::outcome_of(detail::AnyRecord{membership});

  auto receipt = detail::apply_commit(*core_, std::move(pending));
  if (!receipt) {
    return receipt.error();
  }
  return PutIsolationMembershipOutcome{receipt.value(), membership, next_domain_generation.value()};
}

Result<TransitionIsolationMembershipOutcome> TenantRegistry::transition_isolation_membership(
    const TransitionIsolationMembershipRequest& request) {
  if (core_ == nullptr) {
    return Error{ErrorCode::StoreClosed, "this registry session has been moved from"};
  }
  const RegistryLimits limits = core_->limits;
  const SubjectKind kind = request.subject.kind();
  if (kind == SubjectKind::Unspecified) {
    return Error{ErrorCode::InvalidIdKind, "the subject kind is unspecified"};
  }
  if (kind == SubjectKind::IsolationDomain) {
    return Error{ErrorCode::InvalidIdKind,
                 "an isolation domain is not a member of another isolation domain"};
  }
  if (request.target == MembershipState::Unspecified) {
    return Error{ErrorCode::InvalidEnumValue, "the target membership state is unspecified"};
  }
  if (const auto provenance = detail::check_provenance(request.context.actor, limits); !provenance.ok()) {
    return provenance.error();
  }
  const RequestDigest digest = detail::request_digest(request);

  auto guard = core_->lock();
  auto resolution =
      detail::resolve_context(*core_, OperationKind::TransitionIsolationMembership, digest, request.context);
  if (!resolution) {
    return resolution.error();
  }
  if (resolution.value().replay) {
    auto stored = detail::decode_outcome(*resolution.value().entry, limits);
    if (!stored) {
      return stored.error();
    }
    const auto* membership = std::get_if<IsolationMembership>(&stored.value());
    if (membership == nullptr) {
      return Error{ErrorCode::InternalInvariantViolated,
                   "the idempotency ledger holds an outcome of the wrong kind for this request"};
    }
    const auto* domain = core_->state.find_domain(request.domain);
    const DomainGeneration generation =
        domain != nullptr ? domain->membership_generation : DomainGeneration::initial();
    return TransitionIsolationMembershipOutcome{resolution.value().receipt, *membership, generation};
  }

  const std::string subject_token = identity_text(kind, request.subject.identity_value());
  const std::string domain_token = identity_text(SubjectKind::IsolationDomain, request.domain.value());
  auto domain = detail::require_identity(core_->state, SubjectKind::IsolationDomain, request.domain.value(),
                                         "isolation domain");
  if (!domain) {
    return domain.error();
  }
  const auto& domain_record = std::get<IsolationDomainRecord>(*domain.value());
  if (domain_record.membership_generation != request.expected_domain_generation) {
    return Error{ErrorCode::StaleDomainGeneration,
                 "the request was composed against membership generation " +
                     std::to_string(request.expected_domain_generation.value()) + " of " + domain_token +
                     " but that domain is at generation " +
                     std::to_string(domain_record.membership_generation.value())};
  }

  const IsolationMembership* membership = core_->state.find_membership(request.subject, request.domain);
  const std::string token = subject_token + " in " + domain_token;
  if (membership == nullptr) {
    return Error{ErrorCode::DomainMembershipAbsent, token + " is not a member of that domain"};
  }
  if (const auto check = detail::require_expected_revision(membership->revision, request.expected_revision, token);
      !check.ok()) {
    return check.error();
  }
  if (membership->state == request.target) {
    return Error{ErrorCode::LifecycleStateUnchanged,
                 token + " is already in membership state " + std::string{to_token(membership->state)}};
  }
  if (!is_legal_membership_transition(membership->state, request.target)) {
    Error error{ErrorCode::LifecycleTransitionIllegal,
                token + " cannot move from " + std::string{to_token(membership->state)} + " to " +
                    std::string{to_token(request.target)}};
    return error;
  }
  if (request.target == MembershipState::Bound && membership->role == MembershipRole::Primary) {
    bool conflict = false;
    std::string holder;
    core_->state.for_each_prefix(detail::membership_subject_prefix(request.subject),
                                 [&](const detail::AnyRecord& stored) {
                                   const auto& other = std::get<IsolationMembership>(stored);
                                   if (other.role == MembershipRole::Primary &&
                                       other.state == MembershipState::Bound &&
                                       !(other.domain == request.domain)) {
                                     conflict = true;
                                     holder = other.domain.value();
                                     return false;
                                   }
                                   return true;
                                 });
    if (conflict) {
      return Error{ErrorCode::MembershipRoleConflict,
                   subject_token + " is already an in-force primary member of " + holder};
    }
  }

  const auto next_generation = advance(core_->state.generation);
  if (!next_generation) {
    return next_generation.error();
  }
  const auto next_revision = advance(membership->revision);
  if (!next_revision) {
    return next_revision.error();
  }
  const auto next_domain_generation = advance(domain_record.membership_generation);
  if (!next_domain_generation) {
    return next_domain_generation.error();
  }

  IsolationMembership updated = *membership;
  updated.state = request.target;
  updated.revision = next_revision.value();
  updated.updated_generation = next_generation.value();

  IsolationDomainRecord updated_domain = domain_record;
  const auto domain_revision = advance(domain_record.revision);
  if (!domain_revision) {
    return domain_revision.error();
  }
  updated_domain.membership_generation = next_domain_generation.value();
  updated_domain.revision = domain_revision.value();
  updated_domain.updated_generation = next_generation.value();

  detail::PendingCommit pending;
  pending.operation = OperationKind::TransitionIsolationMembership;
  pending.request_digest = digest;
  pending.idempotency_key = request.context.idempotency_key;
  pending.primary_key = detail::membership_key(request.subject, request.domain);
  pending.primary_revision = next_revision.value();
  if (request.target == MembershipState::Withdrawn) {
    // Withdrawal is terminal: the record leaves the state, exactly as
    // lifecycle.hpp documents. Storing it in a withdrawn state would both
    // contradict that rule and make the store unreadable, because a withdrawn
    // membership is a state the state validator refuses. The commit log still
    // records that the withdrawal happened and who asked for it.
    pending.deletes.push_back(pending.primary_key);
  } else {
    pending.upserts.push_back(detail::AnyRecord{updated});
  }
  pending.upserts.push_back(detail::AnyRecord{updated_domain});
  pending.domain_generations.emplace_back(request.domain, next_domain_generation.value());
  pending.outcome_payload = detail::outcome_of(detail::AnyRecord{updated});

  auto receipt = detail::apply_commit(*core_, std::move(pending));
  if (!receipt) {
    return receipt.error();
  }
  return TransitionIsolationMembershipOutcome{receipt.value(), updated, next_domain_generation.value()};
}

Result<MutationReceipt> TenantRegistry::remove_isolation_membership(
    const RemoveIsolationMembershipRequest& request) {
  if (core_ == nullptr) {
    return Error{ErrorCode::StoreClosed, "this registry session has been moved from"};
  }
  const RegistryLimits limits = core_->limits;
  const SubjectKind kind = request.subject.kind();
  if (kind == SubjectKind::Unspecified) {
    return Error{ErrorCode::InvalidIdKind, "the subject kind is unspecified"};
  }
  if (kind == SubjectKind::IsolationDomain) {
    return Error{ErrorCode::InvalidIdKind,
                 "an isolation domain is not a member of another isolation domain"};
  }
  if (const auto provenance = detail::check_provenance(request.context.actor, limits); !provenance.ok()) {
    return provenance.error();
  }
  const RequestDigest digest = detail::request_digest(request);

  auto guard = core_->lock();
  auto resolution =
      detail::resolve_context(*core_, OperationKind::RemoveIsolationMembership, digest, request.context);
  if (!resolution) {
    return resolution.error();
  }
  if (resolution.value().replay) {
    return resolution.value().receipt;
  }

  const std::string subject_token = identity_text(kind, request.subject.identity_value());
  const std::string domain_token = identity_text(SubjectKind::IsolationDomain, request.domain.value());
  auto domain = detail::require_identity(core_->state, SubjectKind::IsolationDomain, request.domain.value(),
                                         "isolation domain");
  if (!domain) {
    return domain.error();
  }
  const auto& domain_record = std::get<IsolationDomainRecord>(*domain.value());
  if (domain_record.membership_generation != request.expected_domain_generation) {
    return Error{ErrorCode::StaleDomainGeneration,
                 "the request was composed against membership generation " +
                     std::to_string(request.expected_domain_generation.value()) + " of " + domain_token +
                     " but that domain is at generation " +
                     std::to_string(domain_record.membership_generation.value())};
  }

  const IsolationMembership* membership = core_->state.find_membership(request.subject, request.domain);
  const std::string token = subject_token + " in " + domain_token;
  if (membership == nullptr) {
    return Error{ErrorCode::DomainMembershipAbsent, token + " is not a member of that domain"};
  }
  if (const auto check = detail::require_expected_revision(membership->revision, request.expected_revision, token);
      !check.ok()) {
    return check.error();
  }

  const auto next_generation = advance(core_->state.generation);
  if (!next_generation) {
    return next_generation.error();
  }
  const auto next_domain_generation = advance(domain_record.membership_generation);
  if (!next_domain_generation) {
    return next_domain_generation.error();
  }

  IsolationDomainRecord updated_domain = domain_record;
  const auto domain_revision = advance(domain_record.revision);
  if (!domain_revision) {
    return domain_revision.error();
  }
  updated_domain.membership_generation = next_domain_generation.value();
  updated_domain.revision = domain_revision.value();
  updated_domain.updated_generation = next_generation.value();

  detail::PendingCommit pending;
  pending.operation = OperationKind::RemoveIsolationMembership;
  pending.request_digest = digest;
  pending.idempotency_key = request.context.idempotency_key;
  pending.primary_key = detail::membership_key(request.subject, request.domain);
  pending.primary_revision = membership->revision;
  pending.deletes.push_back(pending.primary_key);
  pending.upserts.push_back(detail::AnyRecord{updated_domain});
  pending.domain_generations.emplace_back(request.domain, next_domain_generation.value());

  return detail::apply_commit(*core_, std::move(pending));
}

}  // namespace tenant_registry
