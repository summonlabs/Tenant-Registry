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

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "test_support.hpp"

namespace {

using tenant_registry::AccessMode;
using tenant_registry::BindingKind;
using tenant_registry::CreateIsolationDomainRequest;
using tenant_registry::CreateServiceRequest;
using tenant_registry::CreateTenantOutcome;
using tenant_registry::CreateTenantRequest;
using tenant_registry::DomainGeneration;
using tenant_registry::EphemeralOptions;
using tenant_registry::ErrorClass;
using tenant_registry::ErrorCode;
using tenant_registry::FixedClock;
using tenant_registry::IsolationClass;
using tenant_registry::IrreversibleAcknowledgement;
using tenant_registry::LifecycleState;
using tenant_registry::MembershipRole;
using tenant_registry::MembershipState;
using tenant_registry::MutationContext;
using tenant_registry::OwnershipKind;
using tenant_registry::PutIsolationMembershipRequest;
using tenant_registry::PutOwnershipRequest;
using tenant_registry::PutServiceBindingRequest;
using tenant_registry::RecordRevision;
using tenant_registry::RebindSuccessor;
using tenant_registry::RegistryGeneration;
using tenant_registry::RegistryOpenRequest;
using tenant_registry::RegistrySnapshot;
using tenant_registry::Result;
using tenant_registry::RemoveOwnershipRequest;
using tenant_registry::Status;
using tenant_registry::SubjectKind;
using tenant_registry::TenancyMetadata;
using tenant_registry::TenancySubject;
using tenant_registry::TenantRecord;
using tenant_registry::TenantRegistry;
using tenant_registry::TombstoneOutcome;
using tenant_registry::TombstoneRecord;
using tenant_registry::TombstoneRequest;
using tenant_registry::TransitionSubjectRequest;
using tenant_registry::classify;

MutationContext context(RegistryGeneration generation) {
  return MutationContext{generation, std::nullopt,
                         treg_test::provenance("tombstone-suite", "fencing-principal", 17,
                                               "declared by the tombstone suite")};
}

/// The registry under test plus the exact operations this suite needs. Every
/// helper is a step a caller could take; none of them reaches into state.
class Fixture {
 public:
  explicit Fixture(TenantRegistry registry) : registry_(std::move(registry)) {}

  static Fixture ephemeral() {
    EphemeralOptions options;
    options.clock = std::make_shared<FixedClock>(1'700'000'000'000);
    return Fixture{std::move(TenantRegistry::open_ephemeral(options).value())};
  }

  [[nodiscard]] TenantRegistry& registry() noexcept { return registry_; }
  [[nodiscard]] RegistryGeneration generation() const { return registry_.generation(); }

  /// Creates a tenant and admits it, which is the state a tenant must be in
  /// before it can begin to be withdrawn.
  TenantRecord admit(std::string_view text) {
    TREG_REQUIRE_OK(registry_.create_tenant(CreateTenantRequest{context(registry_.generation()),
                                                                treg_test::tenant_id(text), std::nullopt, std::nullopt,
                                                                TenancyMetadata{}}));
    TREG_REQUIRE(transition(TenancySubject::of_tenant(treg_test::tenant_id(text)), tenant(text).revision,
                            LifecycleState::Active)
                     .ok());
    return tenant(text);
  }

  TenantRecord create_tenant(std::string_view text) {
    return registry_
        .create_tenant(CreateTenantRequest{context(registry_.generation()), treg_test::tenant_id(text), std::nullopt,
                                           std::nullopt, TenancyMetadata{}})
        .value()
        .record;
  }

  tenant_registry::ServiceRecord create_service(std::string_view text) {
    return registry_
        .create_service(CreateServiceRequest{context(registry_.generation()), treg_test::service_id(text),
                                            std::nullopt, TenancyMetadata{}})
        .value()
        .record;
  }

  tenant_registry::IsolationDomainRecord create_domain(std::string_view text) {
    return registry_
        .create_isolation_domain(CreateIsolationDomainRequest{context(registry_.generation()),
                                                              treg_test::domain_id(text),
                                                              IsolationClass::FaultContainment, std::nullopt,
                                                              TenancyMetadata{}})
        .value()
        .record;
  }

  Status transition(const TenancySubject& subject, RecordRevision revision, LifecycleState target) {
    auto outcome = registry_.transition_subject(
        TransitionSubjectRequest{context(registry_.generation()), subject, revision, target});
    if (!outcome) {
      return Status::failure(outcome.error());
    }
    return Status::success();
  }

  Status retire(std::string_view text) {
    const TenancySubject subject = TenancySubject::of_tenant(treg_test::tenant_id(text));
    const Status to_retiring = transition(subject, tenant(text).revision, LifecycleState::Retiring);
    if (!to_retiring.ok()) {
      return to_retiring;
    }
    return transition(subject, tenant(text).revision, LifecycleState::Retired);
  }

  [[nodiscard]] TenantRecord tenant(std::string_view text) const {
    return registry_.find_tenant(treg_test::tenant_id(text)).value();
  }

  Result<TombstoneOutcome> tombstone(std::string_view text, bool acknowledged,
                                     std::optional<RebindSuccessor> rebind, std::string note) {
    return registry_.tombstone(TombstoneRequest{context(registry_.generation()),
                                                TenancySubject::of_tenant(treg_test::tenant_id(text)),
                                                tenant(text).revision,
                                                acknowledged ? IrreversibleAcknowledgement::acknowledged()
                                                             : IrreversibleAcknowledgement{},
                                                std::move(rebind), std::move(note)});
  }

  Result<TombstoneOutcome> fence(std::string_view text, std::string_view note = "fenced forever") {
    return tombstone(text, true, std::nullopt, std::string{note});
  }

  Result<CreateTenantOutcome> recreate(std::string_view text) {
    return registry_.create_tenant(CreateTenantRequest{context(registry_.generation()),
                                                       treg_test::tenant_id(text), std::nullopt, std::nullopt,
                                                       TenancyMetadata{}});
  }

  [[nodiscard]] RegistrySnapshot snapshot() const { return registry_.snapshot(); }

 private:
  TenantRegistry registry_;
};

class TempTree {
 public:
  explicit TempTree(std::filesystem::path root) : root_(std::move(root)) {}
  ~TempTree() { remove(); }

  TempTree(const TempTree&) = delete;
  TempTree& operator=(const TempTree&) = delete;

  [[nodiscard]] const std::filesystem::path& path() const noexcept { return root_; }

 private:
  void remove() noexcept {
    std::error_code error;
    std::filesystem::remove_all(root_, error);
  }

  std::filesystem::path root_;
};

RegistryOpenRequest open_request(const std::filesystem::path& root, AccessMode mode) {
  RegistryOpenRequest request;
  request.root = root;
  request.mode = mode;
  request.clock = std::make_shared<FixedClock>(1'700'000'000'000);
  return request;
}

/// Admits a tenant, retires it and fences it, which is the only legal way to
/// reach a tombstone.
void retire_and_fence(Fixture& fixture, std::string_view text) {
  if (fixture.tenant(text).state == LifecycleState::Declared) {
    TREG_REQUIRE(fixture
                     .transition(TenancySubject::of_tenant(treg_test::tenant_id(text)),
                                 fixture.tenant(text).revision, LifecycleState::Active)
                     .ok());
  }
  TREG_REQUIRE(fixture.retire(text).ok());
  TREG_REQUIRE(fixture.fence(text).has_value());
}

}  // namespace

// ---------------------------------------------------------------------------
// Retired is the end of reuse; tombstoned is the end of everything.
// ---------------------------------------------------------------------------

TREG_TEST(tombstone, a_retired_identity_can_never_be_recreated) {
  Fixture fixture = Fixture::ephemeral();
  fixture.admit("acme");
  TREG_REQUIRE(fixture.retire("acme").ok());
  const RegistryGeneration retired_at = fixture.generation();
  const std::string before = fixture.snapshot().digest().to_text();

  const auto refused = fixture.recreate("acme");
  TREG_CHECK_CODE(refused, ErrorCode::IdentityRetired);
  if (!refused) {
    TREG_CHECK_EQ(classify(refused.error().code()), ErrorClass::Identity);
    TREG_CHECK(!refused.error().suppressed().empty());
  }

  // The refusal is evidence about a state, not a change to one.
  TREG_CHECK_EQ(fixture.generation(), retired_at);
  TREG_CHECK_EQ(fixture.snapshot().digest().to_text(), before);
  TREG_CHECK_EQ(fixture.tenant("acme").state, LifecycleState::Retired);
}

TREG_TEST(tombstone, fencing_requires_the_retired_state_and_an_acknowledgement) {
  Fixture fixture = Fixture::ephemeral();
  TREG_REQUIRE_OK(fixture.recreate("acme"));
  const RegistryGeneration declared_at = fixture.generation();
  const std::string before = fixture.snapshot().digest().to_text();

  // A declaration is not a retirement, and an acknowledgement does not make it
  // one: the state is the authority, not the caller's intent.
  const auto too_early = fixture.tombstone("acme", true, std::nullopt, "fenced");
  TREG_CHECK_CODE(too_early, ErrorCode::LifecycleTransitionIllegal);
  TREG_CHECK_EQ(fixture.generation(), declared_at);

  TREG_REQUIRE(fixture.transition(TenancySubject::of_tenant(treg_test::tenant_id("acme")),
                                  fixture.tenant("acme").revision, LifecycleState::Active)
                   .ok());
  const auto active_attempt = fixture.tombstone("acme", true, std::nullopt, "fenced");
  TREG_CHECK_CODE(active_attempt, ErrorCode::LifecycleTransitionIllegal);
  TREG_CHECK_EQ(fixture.tenant("acme").state, LifecycleState::Active);

  TREG_REQUIRE(fixture.retire("acme").ok());
  const RegistryGeneration retired_at = fixture.generation();
  const std::string retired_digest = fixture.snapshot().digest().to_text();

  // Irreversibility needs an explicit statement, per request, every time.
  const auto unacknowledged = fixture.tombstone("acme", false, std::nullopt, "fenced");
  TREG_CHECK_CODE(unacknowledged, ErrorCode::IrreversibleActionNotAcknowledged);
  TREG_CHECK_EQ(fixture.generation(), retired_at);
  TREG_CHECK_EQ(fixture.snapshot().digest().to_text(), retired_digest);

  // Tombstoned is not reachable through an ordinary lifecycle transition
  // either, so no transition table mistake can fence an identity.
  const auto through_transition = fixture.transition(TenancySubject::of_tenant(treg_test::tenant_id("acme")),
                                                     fixture.tenant("acme").revision, LifecycleState::Tombstoned);
  TREG_CHECK_STATUS(through_transition, ErrorCode::IrreversibleActionNotAcknowledged);
  TREG_CHECK_EQ(fixture.snapshot().digest().to_text(), retired_digest);

  const auto fenced = fixture.fence("acme");
  TREG_REQUIRE_OK(fenced);
  TREG_CHECK_EQ(fenced.value().receipt.operation, tenant_registry::OperationKind::Tombstone);
  TREG_CHECK_EQ(std::get<tenant_registry::TenantRecord>(fenced.value().record).state,
                LifecycleState::Tombstoned);
  TREG_CHECK_EQ(fixture.generation(), RegistryGeneration::from_value(retired_at.value() + 1));
  TREG_CHECK(fixture.snapshot().digest().to_text() != retired_digest);
}

TREG_TEST(tombstone, fencing_requires_the_exact_revision_and_a_registered_subject) {
  Fixture fixture = Fixture::ephemeral();
  fixture.admit("acme");
  TREG_REQUIRE(fixture.retire("acme").ok());
  const RegistryGeneration retired_at = fixture.generation();
  const std::string before = fixture.snapshot().digest().to_text();

  const auto wrong_revision = fixture.registry().tombstone(TombstoneRequest{
      context(fixture.generation()), TenancySubject::of_tenant(treg_test::tenant_id("acme")),
      RecordRevision::from_value(99), IrreversibleAcknowledgement::acknowledged(), std::nullopt,
      std::string{"fenced"}});
  TREG_CHECK_CODE(wrong_revision, ErrorCode::StaleRecordRevision);

  const auto missing = fixture.registry().tombstone(TombstoneRequest{
      context(fixture.generation()), TenancySubject::of_tenant(treg_test::tenant_id("ghost")),
      RecordRevision::from_value(1), IrreversibleAcknowledgement::acknowledged(), std::nullopt,
      std::string{"fenced"}});
  TREG_CHECK_CODE(missing, ErrorCode::NotFound);

  // A rebind permit may only name a successor of the same kind as the identity
  // it fences; a permit for a service cannot free a tenant identity.
  const auto wrong_kind = fixture.tombstone("acme", true, RebindSuccessor{SubjectKind::Service, "acme"}, "fenced");
  TREG_CHECK_CODE(wrong_kind, ErrorCode::InvalidIdKind);

  // A permit whose successor text is not a legal identity is refused as a
  // malformed request rather than stored as a promise that can never be kept.
  const auto bad_successor = fixture.tombstone("acme", true, RebindSuccessor{SubjectKind::Tenant, "no trailing-"},
                                               "fenced");
  TREG_CHECK_CODE(bad_successor, ErrorCode::InvalidIdentity);

  TREG_CHECK_EQ(fixture.generation(), retired_at);
  TREG_CHECK_EQ(fixture.snapshot().digest().to_text(), before);
  TREG_CHECK_EQ(fixture.tenant("acme").state, LifecycleState::Retired);
}

TREG_TEST(tombstone, a_tombstoned_identity_can_never_be_recreated_without_a_permit) {
  Fixture fixture = Fixture::ephemeral();
  TREG_REQUIRE_OK(fixture.recreate("acme"));
  TREG_REQUIRE(fixture.transition(TenancySubject::of_tenant(treg_test::tenant_id("acme")),
                                  fixture.tenant("acme").revision, LifecycleState::Active)
                   .ok());
  TREG_REQUIRE(fixture.retire("acme").ok());
  const RegistryGeneration retired_at = fixture.tenant("acme").retired_generation.value();
  TREG_REQUIRE(fixture.fence("acme").has_value());
  const RegistryGeneration fenced_at = fixture.generation();

  // The fenced record is still readable, and it is readable as fenced.
  TREG_CHECK_EQ(fixture.tenant("acme").state, LifecycleState::Tombstoned);
  TREG_CHECK(fixture.tenant("acme").tombstone.has_value());

  const auto tombstone = fixture.registry().find_tombstone(SubjectKind::Tenant, "acme");
  TREG_REQUIRE_OK(tombstone);
  TREG_CHECK_EQ(tombstone.value().kind, SubjectKind::Tenant);
  TREG_CHECK_EQ(tombstone.value().identity, std::string{"acme"});
  TREG_CHECK_EQ(tombstone.value().state, LifecycleState::Tombstoned);
  TREG_CHECK_EQ(tombstone.value().retired_generation, retired_at);
  TREG_CHECK_EQ(tombstone.value().tombstoned_generation, fenced_at);
  TREG_CHECK(!tombstone.value().permit.has_value());
  TREG_CHECK_EQ(tombstone.value().note, std::string{"fenced forever"});

  const std::string before = fixture.snapshot().digest().to_text();
  const auto refused = fixture.recreate("acme");
  TREG_CHECK_CODE(refused, ErrorCode::IdentityTombstoned);
  TREG_CHECK_EQ(fixture.generation(), fenced_at);
  TREG_CHECK_EQ(fixture.snapshot().digest().to_text(), before);

  // An identity that was never fenced has no tombstone at all, and asking for
  // one is refused rather than answered with an empty record.
  TREG_CHECK_CODE(fixture.registry().find_tombstone(SubjectKind::Tenant, "never-fenced"), ErrorCode::NotFound);
}

// ---------------------------------------------------------------------------
// Retirement needs the identity to be free of live dependents.
// ---------------------------------------------------------------------------

TREG_TEST(tombstone, a_tenant_with_a_live_dependent_cannot_be_retired) {
  Fixture fixture = Fixture::ephemeral();
  TREG_REQUIRE_OK(fixture.recreate("parent"));
  TREG_REQUIRE_OK(fixture.recreate("child"));
  TREG_REQUIRE(fixture.transition(TenancySubject::of_tenant(treg_test::tenant_id("parent")),
                                  fixture.tenant("parent").revision, LifecycleState::Active)
                   .ok());
  TREG_REQUIRE(fixture.transition(TenancySubject::of_tenant(treg_test::tenant_id("child")),
                                  fixture.tenant("child").revision, LifecycleState::Active)
                   .ok());

  const auto edge = fixture.registry().put_ownership(PutOwnershipRequest{
      context(fixture.generation()), treg_test::tenant_id("child"), treg_test::tenant_id("parent"),
      OwnershipKind::Administrative, LifecycleState::Active, std::nullopt});
  TREG_REQUIRE_OK(edge);
  const RegistryGeneration with_edge = fixture.generation();
  const std::string before = fixture.snapshot().digest().to_text();

  // A child of the tenant is a dependent of the tenant: the owner cannot be
  // withdrawn while somebody is still owned through it.
  const auto parent_blocked = fixture.retire("parent");
  TREG_CHECK_STATUS(parent_blocked, ErrorCode::HasLiveDependents);
  if (!parent_blocked.ok()) {
    TREG_CHECK(!parent_blocked.error().suppressed().empty());
  }
  // And the relationship is a dependent in both directions: the child cannot
  // walk away from its owner by retiring either.
  const auto child_blocked = fixture.retire("child");
  TREG_CHECK_STATUS(child_blocked, ErrorCode::HasLiveDependents);

  // Fencing is only reachable from Retired, and retirement is exactly what the
  // live child blocks, so there is no path by which a tenant that still has a
  // child reaches a tombstone.
  TREG_CHECK_CODE(fixture.fence("parent"), ErrorCode::LifecycleTransitionIllegal);
  TREG_CHECK_CODE(fixture.fence("child"), ErrorCode::LifecycleTransitionIllegal);

  TREG_CHECK_EQ(fixture.generation(), with_edge);
  TREG_CHECK_EQ(fixture.snapshot().digest().to_text(), before);

  // Once the relationship is gone the retirement is legal, which shows the
  // refusal was about the dependent and not about the tenant.
  TREG_REQUIRE_OK(fixture.registry().remove_ownership(RemoveOwnershipRequest{
      context(fixture.generation()), treg_test::tenant_id("child"), treg_test::tenant_id("parent"),
      edge.value().edge.revision}));
  TREG_CHECK(fixture.retire("parent").ok());

  // A service binding is a dependent too.
  TREG_REQUIRE_OK(fixture.recreate("bound"));
  TREG_REQUIRE(fixture.transition(TenancySubject::of_tenant(treg_test::tenant_id("bound")),
                                  fixture.tenant("bound").revision, LifecycleState::Active)
                   .ok());
  const auto service = fixture.create_service("renderer");
  TREG_REQUIRE(fixture.transition(TenancySubject::of_service(service.id), service.revision, LifecycleState::Active)
                   .ok());
  TREG_REQUIRE_OK(fixture.registry().put_service_binding(PutServiceBindingRequest{
      context(fixture.generation()), service.id, treg_test::tenant_id("bound"), BindingKind::OperatedBy,
      LifecycleState::Active, std::nullopt}));
  TREG_CHECK_STATUS(fixture.retire("bound"), ErrorCode::HasLiveDependents);

  // An isolation membership is a dependent as well.
  TREG_REQUIRE_OK(fixture.recreate("member"));
  TREG_REQUIRE(fixture.transition(TenancySubject::of_tenant(treg_test::tenant_id("member")),
                                  fixture.tenant("member").revision, LifecycleState::Active)
                   .ok());
  const auto domain = fixture.create_domain("zone-a");
  TREG_REQUIRE(fixture.transition(TenancySubject::of_isolation_domain(domain.id), domain.revision,
                                  LifecycleState::Active)
                   .ok());
  TREG_REQUIRE_OK(fixture.registry().put_isolation_membership(PutIsolationMembershipRequest{
      context(fixture.generation()), TenancySubject::of_tenant(treg_test::tenant_id("member")), domain.id,
      MembershipRole::Primary, MembershipState::Bound, DomainGeneration::initial(), std::nullopt}));
  TREG_CHECK_STATUS(fixture.retire("member"), ErrorCode::HasLiveDependents);
}

// ---------------------------------------------------------------------------
// A rebind permit frees one identity for exactly one successor.
// ---------------------------------------------------------------------------

TREG_TEST(tombstone, a_rebind_permit_admits_the_identity_exactly_once) {
  Fixture fixture = Fixture::ephemeral();
  fixture.admit("acme");
  TREG_REQUIRE(fixture.retire("acme").ok());

  const auto fenced = fixture.tombstone("acme", true, RebindSuccessor{SubjectKind::Tenant, "acme"},
                                        "the successor may take this identity");
  TREG_REQUIRE_OK(fenced);
  const RegistryGeneration fenced_at = fenced.value().receipt.generation;
  TREG_CHECK_EQ(fixture.tenant("acme").state, LifecycleState::Tombstoned);

  // The permit names exactly this identity, so exactly this identity may be
  // taken over -- once.
  const auto adopted = fixture.recreate("acme");
  TREG_REQUIRE_OK(adopted);
  TREG_CHECK_EQ(adopted.value().record.state, LifecycleState::Declared);
  TREG_CHECK_EQ(adopted.value().record.revision, RecordRevision::from_value(1));
  TREG_CHECK_EQ(adopted.value().record.created_generation,
                RegistryGeneration::from_value(fenced_at.value() + 1));
  TREG_CHECK(adopted.value().record.tombstone.has_value() == false);

  // The permanent tombstone is kept, with the permit marked consumed at the
  // generation that consumed it. It is the only remaining proof that this
  // identity was once fenced forever.
  const RegistrySnapshot snapshot = fixture.snapshot();
  TREG_REQUIRE(snapshot.tombstones.size() == 1);
  const TombstoneRecord& permanent = snapshot.tombstones.front();
  TREG_CHECK_EQ(permanent.kind, SubjectKind::Tenant);
  TREG_CHECK_EQ(permanent.identity, std::string{"acme"});
  TREG_CHECK_EQ(permanent.state, LifecycleState::Tombstoned);
  TREG_REQUIRE(permanent.permit.has_value());
  TREG_CHECK(permanent.permit->consumed());
  TREG_CHECK_EQ(permanent.permit->successor_text(), std::string{"acme"});
  TREG_CHECK_EQ(permanent.permit->successor_kind(), SubjectKind::Tenant);
  TREG_CHECK(permanent.permit->consumed_generation().has_value());
  if (permanent.permit->consumed_generation().has_value()) {
    TREG_CHECK_EQ(*permanent.permit->consumed_generation(), adopted.value().receipt.generation);
  }
  TREG_CHECK_EQ(permanent.note, std::string{"the successor may take this identity"});

  // The public lookup answers the same question as the snapshot: the record is
  // reachable whether it is still in the identity map or was superseded by a
  // permitted rebind.
  const auto looked_up = fixture.registry().find_tombstone(SubjectKind::Tenant, "acme");
  TREG_REQUIRE_OK(looked_up);
  TREG_CHECK_EQ(looked_up.value().identity, std::string{"acme"});
  TREG_CHECK_EQ(looked_up.value().tombstoned_generation, fenced_at);
  TREG_REQUIRE(looked_up.value().permit.has_value());
  TREG_CHECK(looked_up.value().permit->consumed());
  TREG_CHECK_EQ(to_canonical(looked_up.value()), to_canonical(permanent));

  // A permit is consumed at most once. The accurate answer to a later attempt
  // is that the identity exists -- it exists as the successor the permit
  // admitted -- and the refusal has to say that a permit was spent, so the
  // caller is not left thinking the identity was never fenced.
  const auto again = fixture.recreate("acme");
  TREG_CHECK_CODE(again, ErrorCode::IdentityAlreadyExists);
  if (!again) {
    TREG_CHECK(!again.error().suppressed().empty());
    bool mentions_permit = false;
    for (const std::string& note : again.error().suppressed()) {
      if (note.find("rebind permit") != std::string::npos &&
          note.find("permanent tombstone") != std::string::npos) {
        mentions_permit = true;
      }
    }
    TREG_CHECK(mentions_permit);
  }
  TREG_CHECK_EQ(fixture.tenant("acme").revision, RecordRevision::from_value(1));
}

TREG_TEST(tombstone, a_rebind_permit_that_names_another_successor_does_not_admit_the_identity) {
  Fixture fixture = Fixture::ephemeral();
  fixture.admit("acme");
  TREG_REQUIRE(fixture.retire("acme").ok());
  TREG_REQUIRE_OK(fixture.tombstone("acme", true, RebindSuccessor{SubjectKind::Tenant, "successor"}, "handover"));
  const RegistryGeneration fenced_at = fixture.generation();

  // The permit names a different successor, so it does not free this identity.
  const auto refused = fixture.recreate("acme");
  TREG_CHECK_CODE(refused, ErrorCode::IdentityTombstoned);
  if (!refused) {
    TREG_CHECK(!refused.error().suppressed().empty());
  }
  TREG_CHECK_EQ(fixture.generation(), fenced_at);
  TREG_CHECK_EQ(fixture.tenant("acme").state, LifecycleState::Tombstoned);

  // The named successor is a different identity, and it was never fenced, so
  // it is created as an ordinary new identity.
  const auto successor = fixture.recreate("successor");
  TREG_REQUIRE_OK(successor);
  TREG_CHECK_EQ(successor.value().record.created_generation, RegistryGeneration::from_value(fenced_at.value() + 1));
  TREG_CHECK_EQ(fixture.tenant("acme").state, LifecycleState::Tombstoned);
}

// ---------------------------------------------------------------------------
// A consumed permit is a durable fact, so it has to survive a restart.
// ---------------------------------------------------------------------------

TREG_TEST(tombstone, a_consumed_rebind_permit_survives_a_durable_close_and_reopen) {
  const TempTree tree{treg_test::make_temp_directory("tombstone-rebind-reopen")};
  RegistryGeneration fenced_at = RegistryGeneration::initial();
  RegistryGeneration adopted_at = RegistryGeneration::initial();

  {
    auto opened = TenantRegistry::open(open_request(tree.path(), AccessMode::ReadWrite));
    TREG_REQUIRE_OK(opened);
    Fixture fixture{std::move(opened).value()};
    fixture.admit("acme");
    TREG_REQUIRE(fixture.retire("acme").ok());
    const auto fenced = fixture.tombstone("acme", true, RebindSuccessor{SubjectKind::Tenant, "acme"},
                                          "the successor may take this identity");
    TREG_REQUIRE_OK(fenced);
    fenced_at = fenced.value().receipt.generation;
    const auto adopted = fixture.recreate("acme");
    TREG_REQUIRE_OK(adopted);
    adopted_at = adopted.value().receipt.generation;
    TREG_REQUIRE(fixture.registry().close().ok());
  }

  {
    auto reopened = TenantRegistry::open(open_request(tree.path(), AccessMode::ReadWrite));
    TREG_REQUIRE_OK(reopened);
    Fixture fixture{std::move(reopened).value()};
    TREG_CHECK_EQ(fixture.generation(), adopted_at);

    // The permit was consumed before the restart, and the restart does not
    // forgive it: the record that proves the identity was fenced is still there
    // and still says the one permitted successor has already taken it.
    const auto tombstone = fixture.registry().find_tombstone(SubjectKind::Tenant, "acme");
    TREG_REQUIRE_OK(tombstone);
    TREG_CHECK_EQ(tombstone.value().kind, SubjectKind::Tenant);
    TREG_CHECK_EQ(tombstone.value().tombstoned_generation, fenced_at);
    TREG_REQUIRE(tombstone.value().permit.has_value());
    TREG_CHECK(tombstone.value().permit->consumed());
    TREG_REQUIRE(tombstone.value().permit->consumed_generation().has_value());
    TREG_CHECK_EQ(*tombstone.value().permit->consumed_generation(), adopted_at);

    const RegistrySnapshot snapshot = fixture.snapshot();
    TREG_REQUIRE(snapshot.tombstones.size() == 1);
    TREG_CHECK(snapshot.tombstones.front().permit.has_value());
    TREG_CHECK(snapshot.tombstones.front().permit->consumed());

    // The successor the permit admitted is live, and the handover is not
    // repeatable after the restart either.
    TREG_CHECK_EQ(fixture.tenant("acme").state, LifecycleState::Declared);
    TREG_CHECK_EQ(fixture.tenant("acme").created_generation, adopted_at);
    TREG_CHECK_CODE(fixture.recreate("acme"), ErrorCode::IdentityAlreadyExists);
    TREG_REQUIRE(fixture.registry().close().ok());
  }
}

// ---------------------------------------------------------------------------
// A permanent statement has to survive a restart.
// ---------------------------------------------------------------------------

TREG_TEST(tombstone, a_tombstone_survives_a_durable_close_and_reopen) {
  const TempTree tree{treg_test::make_temp_directory("tombstone-reopen")};
  RegistryGeneration fenced_at = RegistryGeneration::initial();

  {
    auto opened = TenantRegistry::open(open_request(tree.path(), AccessMode::ReadWrite));
    TREG_REQUIRE_OK(opened);
    Fixture fixture{std::move(opened).value()};
    fixture.admit("acme");
    retire_and_fence(fixture, "acme");
    fenced_at = fixture.generation();
    TREG_REQUIRE(fixture.registry().close().ok());
  }

  {
    auto reopened = TenantRegistry::open(open_request(tree.path(), AccessMode::ReadWrite));
    TREG_REQUIRE_OK(reopened);
    Fixture fixture{std::move(reopened).value()};
    TREG_CHECK_EQ(fixture.generation(), fenced_at);

    const auto tombstone = fixture.registry().find_tombstone(SubjectKind::Tenant, "acme");
    TREG_REQUIRE_OK(tombstone);
    TREG_CHECK_EQ(tombstone.value().identity, std::string{"acme"});
    TREG_CHECK_EQ(tombstone.value().tombstoned_generation, fenced_at);
    TREG_CHECK_EQ(fixture.tenant("acme").state, LifecycleState::Tombstoned);

    const auto refused = fixture.recreate("acme");
    TREG_CHECK_CODE(refused, ErrorCode::IdentityTombstoned);
    TREG_CHECK_EQ(fixture.generation(), fenced_at);

    // A fenced identity stays fenced for the life of the store: the closure is
    // what makes it a tombstone rather than a deletion.
    const auto still_fenced = fixture.registry().find_tombstone(SubjectKind::Tenant, "acme");
    TREG_REQUIRE_OK(still_fenced);
    TREG_CHECK_EQ(still_fenced.value().note, std::string{"fenced forever"});
    TREG_REQUIRE(fixture.registry().close().ok());
  }
}