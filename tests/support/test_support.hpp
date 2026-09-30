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

#ifndef TENANT_REGISTRY_TESTS_SUPPORT_TEST_SUPPORT_HPP
#define TENANT_REGISTRY_TESTS_SUPPORT_TEST_SUPPORT_HPP

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <variant>
#include <string_view>
#include <utility>
#include <vector>

#include "tenant_registry/tenant_registry.hpp"
#include "test_harness.hpp"

namespace treg_test {

using tenant_registry::BindingKind;
using tenant_registry::ContentDigest;
using tenant_registry::ControlEpoch;
using tenant_registry::CreateIsolationDomainOutcome;
using tenant_registry::CreateIsolationDomainRequest;
using tenant_registry::CreateServiceOutcome;
using tenant_registry::CreateServiceRequest;
using tenant_registry::CreateTenantOutcome;
using tenant_registry::CreateTenantRequest;
using tenant_registry::DomainGeneration;
using tenant_registry::EphemeralOptions;
using tenant_registry::FixedClock;
using tenant_registry::IdempotencyKey;
using tenant_registry::Incarnation;
using tenant_registry::IsolationClass;
using tenant_registry::IsolationDomainId;
using tenant_registry::IsolationDomainRecord;
using tenant_registry::IsolationMembership;
using tenant_registry::LifecycleState;
using tenant_registry::MembershipRole;
using tenant_registry::MembershipState;
using tenant_registry::MetadataEntry;
using tenant_registry::MetadataKey;
using tenant_registry::MetadataValue;
using tenant_registry::MutationContext;
using tenant_registry::MutationReceipt;
using tenant_registry::OwnershipEdge;
using tenant_registry::OwnershipKind;
using tenant_registry::PrincipalId;
using tenant_registry::ProvenanceRecord;
using tenant_registry::ProvenanceSource;
using tenant_registry::PublishStage;
using tenant_registry::RecordRevision;
using tenant_registry::RegistryGeneration;
using tenant_registry::RegistryLimits;
using tenant_registry::RegistryOpenRequest;
using tenant_registry::PutIsolationMembershipRequest;
using tenant_registry::PutOwnershipRequest;
using tenant_registry::PutServiceBindingRequest;
using tenant_registry::RegistrySnapshot;
using tenant_registry::RemoveIsolationMembershipRequest;
using tenant_registry::RemoveOwnershipRequest;
using tenant_registry::RemoveServiceBindingRequest;
using tenant_registry::Result;
using tenant_registry::SetMetadataRequest;
using tenant_registry::SetOwnerRequest;
using tenant_registry::TombstoneRequest;
using tenant_registry::TransitionIsolationMembershipRequest;
using tenant_registry::TransitionOwnershipRequest;
using tenant_registry::TransitionServiceBindingRequest;
using tenant_registry::TransitionSubjectRequest;
using tenant_registry::ServiceBinding;
using tenant_registry::ServiceId;
using tenant_registry::ServiceRecord;
using tenant_registry::Status;
using tenant_registry::SubjectKind;
using tenant_registry::SubjectRecord;
using tenant_registry::BindingQuery;
using tenant_registry::DomainQuery;
using tenant_registry::ExplainOptions;
using tenant_registry::Explanation;
using tenant_registry::MembershipQuery;
using tenant_registry::OwnershipQuery;
using tenant_registry::OwnershipTraversal;
using tenant_registry::OwnershipTraversalRequest;
using tenant_registry::RegistryStats;
using tenant_registry::ServiceQuery;
using tenant_registry::TenancySubject;
using tenant_registry::TenantId;
using tenant_registry::TenantQuery;
using tenant_registry::TenantRecord;
using tenant_registry::TenantRegistry;
using tenant_registry::Timestamp;
using tenant_registry::TombstoneRecord;
using tenant_registry::TraversalDirection;

/// Fails the current test by throwing; the harness reports it as an exception.
[[noreturn]] inline void fail_now(std::string message) { throw std::runtime_error{std::move(message)}; }

template <class T>
T unwrap(Result<T> result, std::string_view what) {
  if (!result) {
    fail_now(std::string{what} + " was refused with " + std::string{tenant_registry::to_token(result.error().code())} +
             ": " + result.error().detail());
  }
  return std::move(result).value();
}

inline void require_ok(Status status, std::string_view what) {
  if (!status.ok()) {
    fail_now(std::string{what} + " was refused with " + std::string{tenant_registry::to_token(status.code())} + ": " +
             status.error().detail());
  }
}

inline TenantId tenant_id(std::string_view text) { return unwrap(TenantId::create(text), "TenantId::create"); }
inline ServiceId service_id(std::string_view text) { return unwrap(ServiceId::create(text), "ServiceId::create"); }
inline IsolationDomainId domain_id(std::string_view text) {
  return unwrap(IsolationDomainId::create(text), "IsolationDomainId::create");
}
inline PrincipalId principal_id(std::string_view text) {
  return unwrap(PrincipalId::create(text), "PrincipalId::create");
}
inline MetadataKey metadata_key(std::string_view text) {
  return unwrap(MetadataKey::create(text), "MetadataKey::create");
}
inline IdempotencyKey idempotency_key(std::string_view text) {
  return unwrap(IdempotencyKey::create(text), "IdempotencyKey::create");
}

inline SubjectRecord subject_record(const TenantRecord& record) { return SubjectRecord{record}; }
inline SubjectRecord subject_record(const ServiceRecord& record) { return SubjectRecord{record}; }
inline SubjectRecord subject_record(const IsolationDomainRecord& record) { return SubjectRecord{record}; }

inline LifecycleState state_of(const SubjectRecord& record) {
  return std::visit([](const auto& stored) { return stored.state; }, record);
}
inline RecordRevision revision_of(const SubjectRecord& record) {
  return std::visit([](const auto& stored) { return stored.revision; }, record);
}

inline ProvenanceRecord provenance(std::string_view source_id = "test-source",
                                   std::string_view principal = "test-principal", std::int64_t when = 17,
                                   std::string_view note = {}) {
  return unwrap(ProvenanceRecord::create(ProvenanceSource::TestFixture, unwrap(tenant_registry::SourceId::create(source_id), "SourceId::create"),
                                         principal_id(principal), std::optional<Timestamp>{Timestamp{when}},
                                         std::string{note}, 512),
                "ProvenanceRecord::create");
}

inline ProvenanceRecord provenance_without_time(std::string_view source_id = "test-source",
                                               std::string_view principal = "test-principal") {
  return unwrap(ProvenanceRecord::create(ProvenanceSource::TestFixture,
                                         unwrap(tenant_registry::SourceId::create(source_id), "SourceId::create"),
                                         principal_id(principal), std::nullopt, std::string{}, 512),
                "ProvenanceRecord::create");
}

inline MutationContext context(RegistryGeneration expected, std::optional<IdempotencyKey> key = std::nullopt,
                               ProvenanceRecord actor = provenance()) {
  return MutationContext{expected, std::move(key), std::move(actor)};
}

inline TenancySubject tenant_subject(std::string_view text) {
  return TenancySubject::of_tenant(tenant_id(text));
}
inline TenancySubject service_subject(std::string_view text) {
  return TenancySubject::of_service(service_id(text));
}

inline MetadataEntry entry(std::string_view key, std::string_view value) {
  return MetadataEntry{metadata_key(key), unwrap(MetadataValue::text(std::string{value}, 512), "MetadataValue::text")};
}

/// A registry plus the small conveniences every test needs. Helpers that are
/// expected to succeed throw on rejection, so a broken precondition shows up as
/// a failed test rather than as a silently different registry.
class Harness {
 public:
  explicit Harness(TenantRegistry registry) : registry_(std::move(registry)) {}

  static Harness ephemeral(RegistryLimits limits = RegistryLimits{}, std::int64_t clock = 1'700'000'000'000) {
    EphemeralOptions options;
    options.limits = limits;
    options.clock = std::make_shared<FixedClock>(clock);
    return Harness{unwrap(TenantRegistry::open_ephemeral(options), "open_ephemeral")};
  }

  static Harness durable(const std::filesystem::path& root, RegistryLimits limits = RegistryLimits{},
                         tenant_registry::StoreOptions store = {}, bool read_only = false,
                         std::int64_t clock = 1'700'000'000'000) {
    RegistryOpenRequest request;
    request.root = root;
    request.mode = read_only ? tenant_registry::AccessMode::ReadOnly : tenant_registry::AccessMode::ReadWrite;
    request.store = std::move(store);
    request.store.limits = limits;
    request.clock = std::make_shared<FixedClock>(clock);
    return Harness{unwrap(TenantRegistry::open(request), "open")};
  }

  [[nodiscard]] TenantRegistry& registry() noexcept { return registry_; }
  [[nodiscard]] const TenantRegistry& registry() const noexcept { return registry_; }
  [[nodiscard]] RegistryGeneration generation() const { return registry_.generation(); }
  [[nodiscard]] RegistrySnapshot snapshot() const { return registry_.snapshot(); }
  [[nodiscard]] RegistryLimits limits() const { return registry_.limits(); }

  [[nodiscard]] TenantRecord tenant(std::string_view text) const {
    return unwrap(registry_.find_tenant(tenant_id(text)), "find_tenant");
  }
  [[nodiscard]] ServiceRecord service(std::string_view text) const {
    return unwrap(registry_.find_service(service_id(text)), "find_service");
  }
  [[nodiscard]] IsolationDomainRecord domain(std::string_view text) const {
    return unwrap(registry_.find_isolation_domain(domain_id(text)), "find_isolation_domain");
  }
  [[nodiscard]] RecordRevision revision_of_tenant(std::string_view text) const { return tenant(text).revision; }
  [[nodiscard]] DomainGeneration domain_generation(std::string_view text) const {
    return domain(text).membership_generation;
  }

  TenantRecord create_tenant(std::string_view text, std::optional<std::string> display_name = std::nullopt,
                             std::optional<PrincipalId> owner = std::nullopt,
                             tenant_registry::TenancyMetadata metadata = {}) {
    const CreateTenantRequest request{context(registry_.generation()), tenant_id(text), std::move(display_name),
                                      std::move(owner), std::move(metadata)};
    return unwrap(registry_.create_tenant(request), "create_tenant").record;
  }

  ServiceRecord create_service(std::string_view text, std::optional<std::string> display_name = std::nullopt,
                               tenant_registry::TenancyMetadata metadata = {}) {
    const CreateServiceRequest request{context(registry_.generation()), service_id(text), std::move(display_name),
                                       std::move(metadata)};
    return unwrap(registry_.create_service(request), "create_service").record;
  }

  IsolationDomainRecord create_domain(std::string_view text, IsolationClass isolation_class = IsolationClass::FaultContainment) {
    const CreateIsolationDomainRequest request{context(registry_.generation()), domain_id(text), isolation_class,
                                              std::nullopt, tenant_registry::TenancyMetadata{}};
    return unwrap(registry_.create_isolation_domain(request), "create_isolation_domain").record;
  }

  /// Creates a tenant and admits it, which is what almost every test wants.
  /// Admits an identity. The outcome carries a tagged subject because one
  /// operation serves all three kinds, so the concrete alternative is picked
  /// out here rather than at every call site.
  TenantRecord active_tenant(std::string_view text, std::optional<PrincipalId> owner = std::nullopt) {
    const TenantRecord created = create_tenant(text, std::nullopt, std::move(owner));
    const auto outcome = unwrap(registry_.transition_subject(transition_request(
                                    TenancySubject::of_tenant(created.id), created.revision,
                                    LifecycleState::Active)),
                                "transition_subject");
    const auto* record = std::get_if<TenantRecord>(&outcome.record);
    if (record == nullptr) {
      fail_now("transition_subject answered with a subject of the wrong kind");
    }
    return *record;
  }

  ServiceRecord active_service(std::string_view text) {
    const ServiceRecord created = create_service(text);
    const auto outcome = unwrap(registry_.transition_subject(transition_request(
                                    TenancySubject::of_service(created.id), created.revision,
                                    LifecycleState::Active)),
                                "transition_subject");
    const auto* record = std::get_if<ServiceRecord>(&outcome.record);
    if (record == nullptr) {
      fail_now("transition_subject answered with a subject of the wrong kind");
    }
    return *record;
  }

  IsolationDomainRecord active_domain(std::string_view text,
                                      IsolationClass isolation_class = IsolationClass::FaultContainment) {
    const IsolationDomainRecord created = create_domain(text, isolation_class);
    const auto outcome = unwrap(registry_.transition_subject(transition_request(
                                    TenancySubject::of_isolation_domain(created.id), created.revision,
                                    LifecycleState::Active)),
                                "transition_subject");
    const auto* record = std::get_if<IsolationDomainRecord>(&outcome.record);
    if (record == nullptr) {
      fail_now("transition_subject answered with a subject of the wrong kind");
    }
    return *record;
  }

  [[nodiscard]] tenant_registry::TransitionSubjectRequest transition_request(TenancySubject subject,
                                                                            RecordRevision revision,
                                                                            LifecycleState target) const {
    return tenant_registry::TransitionSubjectRequest{context(registry_.generation()), std::move(subject), revision,
                                                     target};
  }

  Status transition(const TenancySubject& subject, RecordRevision revision, LifecycleState target) {
    auto outcome = registry_.transition_subject(transition_request(subject, revision, target));
    if (!outcome) {
      return Status::failure(outcome.error());
    }
    return Status::success();
  }

  TenantId retire_tenant(std::string_view text) {
    const TenantRecord current = tenant(text);
    const TenancySubject subject = TenancySubject::of_tenant(current.id);
    require_ok(transition(subject, current.revision, LifecycleState::Retiring), "retire to Retiring");
    const TenantRecord retiring = tenant(text);
    require_ok(transition(subject, retiring.revision, LifecycleState::Retired), "retire to Retired");
    return current.id;
  }

  void tombstone(std::string_view text, bool with_rebind, std::string_view note = {}) {
    const TenantRecord current = tenant(text);
    std::optional<tenant_registry::RebindSuccessor> rebind;
    if (with_rebind) {
      rebind = tenant_registry::RebindSuccessor{SubjectKind::Tenant, std::string{text}};
    }
    const tenant_registry::TombstoneRequest request{context(registry_.generation()),
                                                    TenancySubject::of_tenant(current.id),
                                                    current.revision,
                                                    tenant_registry::IrreversibleAcknowledgement::acknowledged(),
                                                    std::move(rebind),
                                                    std::string{note}};
    unwrap(registry_.tombstone(request), "tombstone");
  }

  OwnershipEdge own(std::string_view child, std::string_view parent,
                    OwnershipKind kind = OwnershipKind::Administrative,
                    LifecycleState state = LifecycleState::Active) {
    const tenant_registry::PutOwnershipRequest request{context(registry_.generation()), tenant_id(child),
                                                       tenant_id(parent), kind, state, std::nullopt};
    return unwrap(registry_.put_ownership(request), "put_ownership").edge;
  }

  ServiceBinding bind(std::string_view service, std::string_view tenant,
                      BindingKind kind = BindingKind::OperatedBy,
                      LifecycleState state = LifecycleState::Active) {
    const tenant_registry::PutServiceBindingRequest request{context(registry_.generation()), service_id(service),
                                                            tenant_id(tenant), kind, state, std::nullopt};
    return unwrap(registry_.put_service_binding(request), "put_service_binding").binding;
  }

  IsolationMembership join(const TenancySubject& subject, std::string_view domain,
                           MembershipRole role = MembershipRole::Primary,
                           MembershipState state = MembershipState::Bound) {
    const tenant_registry::PutIsolationMembershipRequest request{context(registry_.generation()), subject,
                                                                 domain_id(domain), role, state,
                                                                 domain_generation(domain), std::nullopt};
    return unwrap(registry_.put_isolation_membership(request), "put_isolation_membership").membership;
  }

 private:
  TenantRegistry registry_;
};

/// A deterministic pseudo random generator, so every randomized test is
/// reproducible from the seed it prints.
class Rng {
 public:
  explicit Rng(std::uint64_t seed) : state_(seed == 0 ? 0x9E3779B97F4A7C15ull : seed) {}

  [[nodiscard]] std::uint64_t next() {
    // SplitMix64: small, fast, and identical on every platform.
    state_ += 0x9E3779B97F4A7C15ull;
    std::uint64_t value = state_;
    value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ull;
    value = (value ^ (value >> 27)) * 0x94D049BB133111EBull;
    return value ^ (value >> 31);
  }

  [[nodiscard]] std::uint32_t below(std::uint32_t bound) {
    return bound == 0 ? 0 : static_cast<std::uint32_t>(next() % bound);
  }

  [[nodiscard]] bool chance(std::uint32_t numerator, std::uint32_t denominator) {
    return below(denominator) < numerator;
  }

 private:
  std::uint64_t state_;
};

inline std::string seed_text(std::uint64_t seed) { return "seed=" + std::to_string(seed); }

}  // namespace treg_test

#endif  // TENANT_REGISTRY_TESTS_SUPPORT_TEST_SUPPORT_HPP
