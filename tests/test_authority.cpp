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
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
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
using tenant_registry::ContentDigest;
using tenant_registry::ControlEpoch;
using tenant_registry::CreateIsolationDomainRequest;
using tenant_registry::CreateServiceRequest;
using tenant_registry::CreateTenantRequest;
using tenant_registry::DomainGeneration;
using tenant_registry::EphemeralOptions;
using tenant_registry::ErrorClass;
using tenant_registry::ErrorCode;
using tenant_registry::FixedClock;
using tenant_registry::IdempotencyKey;
using tenant_registry::Incarnation;
using tenant_registry::IsolationClass;
using tenant_registry::IsolationDomainId;
using tenant_registry::IrreversibleAcknowledgement;
using tenant_registry::JournalSequence;
using tenant_registry::LifecycleState;
using tenant_registry::MembershipRole;
using tenant_registry::MembershipState;
using tenant_registry::MutationContext;
using tenant_registry::OwnershipKind;
using tenant_registry::PutIsolationMembershipRequest;
using tenant_registry::PutOwnershipRequest;
using tenant_registry::PutServiceBindingRequest;
using tenant_registry::RecordRevision;
using tenant_registry::RegistryGeneration;
using tenant_registry::RegistryOpenRequest;
using tenant_registry::RemoveIsolationMembershipRequest;
using tenant_registry::RemoveOwnershipRequest;
using tenant_registry::RemoveServiceBindingRequest;
using tenant_registry::ServiceId;
using tenant_registry::SetMetadataRequest;
using tenant_registry::SetOwnerRequest;
using tenant_registry::StoreRecoveryReport;
using tenant_registry::SubjectKind;
using tenant_registry::TenantQuery;
using tenant_registry::TenancyMetadata;
using tenant_registry::TenancySubject;
using tenant_registry::TenantId;
using tenant_registry::TenantRecord;
using tenant_registry::TenantRegistry;
using tenant_registry::TombstoneRequest;
using tenant_registry::TransitionIsolationMembershipRequest;
using tenant_registry::TransitionOwnershipRequest;
using tenant_registry::TransitionServiceBindingRequest;
using tenant_registry::TransitionSubjectRequest;
using tenant_registry::advance;
using tenant_registry::classify;

// ---------------------------------------------------------------------------
// Local declarations.
//
// The shared helpers build their actor from a default ProvenanceRecord whose
// note is empty, and a record carrying an empty note cannot be decoded back
// (the codec re-validates every text field on the way in). Every request in
// this suite therefore states its actor explicitly with a note that survives a
// round trip, so a test that fails here fails for the property under test and
// not for the shape of its own fixture.
// ---------------------------------------------------------------------------

MutationContext context(RegistryGeneration generation, std::optional<IdempotencyKey> key = std::nullopt) {
  return MutationContext{generation, std::move(key),
                         treg_test::provenance("authority-suite", "authority-principal", 17,
                                               "declared by the authority suite")};
}

CreateTenantRequest tenant_request(RegistryGeneration generation, std::string_view text) {
  return CreateTenantRequest{context(generation), treg_test::tenant_id(text), std::nullopt, std::nullopt,
                             TenancyMetadata{}};
}

/// Removes a directory tree when the test leaves the scope, including on an
/// aborted test. If an ordinary removal fails the tree is retried through the
/// Windows long path prefix, which is the only way to reach a path that the
/// ordinary MAX_PATH limit hides.
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
    if (!std::filesystem::exists(root_, error)) {
      return;
    }
#if defined(_WIN32)
    std::error_code absolute_error;
    const std::filesystem::path absolute = std::filesystem::absolute(root_, absolute_error);
    if (!absolute_error) {
      // "\\?\" disables the MAX_PATH limit, so a tree that was never reachable
      // through an ordinary path is still removable.
      std::filesystem::remove_all(std::filesystem::path{L"\\\\?\\" + absolute.wstring()}, error);
    }
#endif
  }

  std::filesystem::path root_;
};

/// The durable state of a store rendered as one string: every file name, and
/// the digest of every file's bytes. Two fingerprints differ exactly when
/// something about the store changed, so a refusal that claims to change
/// nothing can be held to that claim.
std::string store_fingerprint(const std::filesystem::path& root) {
  std::vector<std::string> names;
  std::error_code error;
  for (const std::filesystem::directory_entry& entry : std::filesystem::directory_iterator(root, error)) {
    if (entry.is_regular_file(error)) {
      names.push_back(entry.path().filename().string());
    }
  }
  std::sort(names.begin(), names.end());
  std::string out;
  for (const std::string& name : names) {
    std::ifstream input{root / name, std::ios::binary};
    const std::string bytes{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    out += name;
    out += '=';
    out += ContentDigest::of(bytes).to_text();
    out += ';';
  }
  return out;
}

RegistryOpenRequest open_request(const std::filesystem::path& root, AccessMode mode) {
  RegistryOpenRequest request;
  request.root = root;
  request.mode = mode;
  request.clock = std::make_shared<FixedClock>(1'700'000'000'000);
  return request;
}

/// Every mutating entry point of the public API, in one place, each carrying a
/// request that is well formed apart from the reason it must be refused. This
/// exists so that "every mutation is refused" is checked exhaustively rather
/// than on the three operations a test happened to remember.
void expect_every_mutation_refused(TenantRegistry& registry, ErrorCode expected) {
  const RegistryGeneration generation = registry.generation();
  const TenantId first = treg_test::tenant_id("alpha");
  const TenantId second = treg_test::tenant_id("beta");
  const ServiceId service = treg_test::service_id("renderer");
  const IsolationDomainId domain = treg_test::domain_id("zone-a");
  const TenancySubject subject = TenancySubject::of_tenant(first);
  const RecordRevision revision = RecordRevision::initial();
  const DomainGeneration domain_generation = DomainGeneration::initial();

  TREG_CHECK_CODE(registry.create_tenant(CreateTenantRequest{context(generation), first, std::nullopt, std::nullopt,
                                                             TenancyMetadata{}}),
                  expected);
  TREG_CHECK_CODE(registry.create_service(
                      CreateServiceRequest{context(generation), service, std::nullopt, TenancyMetadata{}}),
                  expected);
  TREG_CHECK_CODE(registry.create_isolation_domain(CreateIsolationDomainRequest{
                      context(generation), domain, IsolationClass::FaultContainment, std::nullopt, TenancyMetadata{}}),
                  expected);
  TREG_CHECK_CODE(registry.transition_subject(
                      TransitionSubjectRequest{context(generation), subject, revision, LifecycleState::Active}),
                  expected);
  TREG_CHECK_CODE(registry.set_owner(SetOwnerRequest{context(generation), first, revision, std::nullopt}), expected);
  TREG_CHECK_CODE(registry.set_metadata(SetMetadataRequest{context(generation), subject, revision, {}, {}}), expected);
  TREG_CHECK_CODE(registry.put_ownership(PutOwnershipRequest{context(generation), first, second,
                                                             OwnershipKind::Administrative, LifecycleState::Active,
                                                             std::nullopt}),
                  expected);
  TREG_CHECK_CODE(registry.remove_ownership(RemoveOwnershipRequest{context(generation), first, second, revision}),
                  expected);
  TREG_CHECK_CODE(registry.transition_ownership(TransitionOwnershipRequest{context(generation), first, second, revision,
                                                                          LifecycleState::Active}),
                  expected);
  TREG_CHECK_CODE(registry.put_service_binding(PutServiceBindingRequest{context(generation), service, first,
                                                                       BindingKind::OperatedBy, LifecycleState::Active,
                                                                       std::nullopt}),
                  expected);
  TREG_CHECK_CODE(registry.remove_service_binding(RemoveServiceBindingRequest{context(generation), service, first,
                                                                             BindingKind::OperatedBy, revision}),
                  expected);
  TREG_CHECK_CODE(registry.transition_service_binding(TransitionServiceBindingRequest{
                      context(generation), service, first, BindingKind::OperatedBy, revision, LifecycleState::Active}),
                  expected);
  TREG_CHECK_CODE(registry.put_isolation_membership(PutIsolationMembershipRequest{
                      context(generation), subject, domain, MembershipRole::Primary, MembershipState::Bound,
                      domain_generation, std::nullopt}),
                  expected);
  TREG_CHECK_CODE(registry.transition_isolation_membership(TransitionIsolationMembershipRequest{
                      context(generation), subject, domain, revision, domain_generation, MembershipState::Bound}),
                  expected);
  TREG_CHECK_CODE(registry.remove_isolation_membership(RemoveIsolationMembershipRequest{
                      context(generation), subject, domain, revision, domain_generation}),
                  expected);
  TREG_CHECK_CODE(registry.tombstone(TombstoneRequest{context(generation), subject, revision,
                                                      IrreversibleAcknowledgement::acknowledged(), std::nullopt,
                                                      std::string{"fenced"}}),
                  expected);
  TREG_CHECK_STATUS(registry.flush(), expected);
  TREG_CHECK_STATUS(registry.compact(), expected);
}

}  // namespace

// ---------------------------------------------------------------------------
// Fencing: a request composed against a generation the registry has left is
// refused and changes nothing at all.
// ---------------------------------------------------------------------------

TREG_TEST(authority, a_stale_generation_is_refused_naming_both_generations) {
  EphemeralOptions options;
  options.clock = std::make_shared<FixedClock>(1'700'000'000'000);
  TenantRegistry registry = std::move(TenantRegistry::open_ephemeral(options).value());

  TREG_REQUIRE_OK(registry.create_tenant(tenant_request(registry.generation(), "acme")));
  const RegistryGeneration current = registry.generation();
  const TenantRecord acme = registry.find_tenant(treg_test::tenant_id("acme")).value();
  const std::string before = registry.snapshot().digest().to_text();

  // The generation is the fence: a caller that states a generation the registry
  // has moved past is telling the truth about a state that no longer exists.
  const auto stale_create = registry.create_tenant(tenant_request(RegistryGeneration::initial(), "beta"));
  TREG_CHECK_CODE(stale_create, ErrorCode::StaleGeneration);
  if (!stale_create) {
    TREG_CHECK_EQ(classify(stale_create.error().code()), ErrorClass::Staleness);
    // The refusal has to name both numbers, because "you are stale" without
    // "you said 0 and it is 1" is not actionable.
    TREG_CHECK(stale_create.error().detail().find("generation 0") != std::string::npos);
    TREG_CHECK(stale_create.error().detail().find("generation 1") != std::string::npos);
  }

  const auto stale_transition =
      registry.transition_subject(TransitionSubjectRequest{context(RegistryGeneration::initial()),
                                                           TenancySubject::of_tenant(acme.id), acme.revision,
                                                           LifecycleState::Active});
  TREG_CHECK_CODE(stale_transition, ErrorCode::StaleGeneration);

  const auto stale_tombstone =
      registry.tombstone(TombstoneRequest{context(RegistryGeneration::from_value(current.value() - 1)),
                                          TenancySubject::of_tenant(acme.id), acme.revision,
                                          IrreversibleAcknowledgement::acknowledged(), std::nullopt,
                                          std::string{"fenced"}});
  TREG_CHECK_CODE(stale_tombstone, ErrorCode::StaleGeneration);

  TREG_CHECK_EQ(registry.generation(), current);
  TREG_CHECK_EQ(registry.snapshot().digest().to_text(), before);
  TREG_CHECK(!registry.find_tenant(treg_test::tenant_id("beta")).has_value());
  TREG_CHECK_EQ(registry.find_tenant(treg_test::tenant_id("acme")).value().state, LifecycleState::Declared);
}

TREG_TEST(authority, staleness_is_decided_before_revision_and_before_existence) {
  EphemeralOptions options;
  options.clock = std::make_shared<FixedClock>(1'700'000'000'000);
  TenantRegistry registry = std::move(TenantRegistry::open_ephemeral(options).value());

  TREG_REQUIRE_OK(registry.create_tenant(tenant_request(registry.generation(), "acme")));
  const TenantRecord acme = registry.find_tenant(treg_test::tenant_id("acme")).value();
  const std::string before = registry.snapshot().digest().to_text();

  // Wrong generation *and* wrong revision: the generation question is answered
  // first, so the caller learns the larger fact before the smaller one.
  const auto both_wrong = registry.transition_subject(TransitionSubjectRequest{
      context(RegistryGeneration::initial()), TenancySubject::of_tenant(acme.id),
      RecordRevision::from_value(99), LifecycleState::Active});
  TREG_CHECK_CODE(both_wrong, ErrorCode::StaleGeneration);

  // Wrong generation and a subject that does not exist at all: still stale.
  const auto missing = registry.transition_subject(TransitionSubjectRequest{
      context(RegistryGeneration::initial()), TenancySubject::of_tenant(treg_test::tenant_id("ghost")),
      RecordRevision::initial(), LifecycleState::Active});
  TREG_CHECK_CODE(missing, ErrorCode::StaleGeneration);

  // With the right generation the same two requests are refused for their own
  // reasons, which is what makes the ordering above observable.
  const auto revision_wrong = registry.transition_subject(TransitionSubjectRequest{
      context(registry.generation()), TenancySubject::of_tenant(acme.id), RecordRevision::from_value(99),
      LifecycleState::Active});
  TREG_CHECK_CODE(revision_wrong, ErrorCode::StaleRecordRevision);

  const auto absent = registry.transition_subject(TransitionSubjectRequest{
      context(registry.generation()), TenancySubject::of_tenant(treg_test::tenant_id("ghost")),
      RecordRevision::initial(), LifecycleState::Active});
  TREG_CHECK_CODE(absent, ErrorCode::NotFound);

  TREG_CHECK_EQ(registry.snapshot().digest().to_text(), before);
}

// ---------------------------------------------------------------------------
// Authority: control epoch and incarnation are published, and taking control
// of a durable store advances both.
// ---------------------------------------------------------------------------

TREG_TEST(authority, control_epoch_and_incarnation_advance_across_a_reopen) {
  const TempTree tree{treg_test::make_temp_directory("authority-reopen")};

  ControlEpoch first_epoch = ControlEpoch::initial();
  Incarnation first_incarnation = Incarnation::initial();
  ContentDigest store_id;
  RegistryGeneration generation_after_first_session = RegistryGeneration::initial();
  JournalSequence sequence_after_first_session = JournalSequence::initial();

  {
    auto opened = TenantRegistry::open(open_request(tree.path(), AccessMode::ReadWrite));
    TREG_REQUIRE_OK(opened);
    TenantRegistry registry = std::move(opened).value();
    TREG_REQUIRE(registry.store_identity().has_value());

    first_epoch = registry.control_epoch();
    first_incarnation = registry.incarnation();
    store_id = registry.store_identity()->id;
    TREG_CHECK_EQ(registry.access_mode(), AccessMode::ReadWrite);
    TREG_CHECK(registry.durable());

    TREG_REQUIRE_OK(registry.create_tenant(tenant_request(registry.generation(), "acme")));
    generation_after_first_session = registry.generation();
    sequence_after_first_session = registry.committed_sequence();
    // A store that is being created is created under its first writer's control,
    // so the epoch it publishes is already past the initial value.
    TREG_CHECK(first_epoch.value() >= 1);
    TREG_REQUIRE(registry.close().ok());
    TREG_CHECK(!registry.valid());
  }

  {
    auto reopened = TenantRegistry::open(open_request(tree.path(), AccessMode::ReadWrite));
    TREG_REQUIRE_OK(reopened);
    TenantRegistry registry = std::move(reopened).value();

    // Taking control is the act that fences every authority the previous
    // writer held, so the epoch advances by exactly one and the incarnation is
    // strictly newer.
    TREG_CHECK_EQ(registry.control_epoch(), ControlEpoch::from_value(first_epoch.value() + 1));
    TREG_CHECK(registry.incarnation().value() > first_incarnation.value());
    TREG_CHECK_EQ(registry.store_identity()->id, store_id);
    TREG_CHECK_EQ(registry.generation(), generation_after_first_session);
    TREG_CHECK_EQ(registry.committed_sequence(), sequence_after_first_session);

    const StoreRecoveryReport report = registry.recovery_report();
    TREG_CHECK(report.previous_control_epoch.has_value());
    if (report.previous_control_epoch.has_value()) {
      TREG_CHECK_EQ(*report.previous_control_epoch, first_epoch);
    }
    TREG_CHECK_EQ(report.control_epoch, registry.control_epoch());
    TREG_CHECK_EQ(report.incarnation, registry.incarnation());
    TREG_CHECK(!report.store_created);
    TREG_CHECK(report.frames_replayed >= 1);
    TREG_CHECK_EQ(report.committed_generation, generation_after_first_session);
    TREG_CHECK(!report.read_only);

    // The state that was committed under the old authority is still the state.
    TREG_CHECK(registry.find_tenant(treg_test::tenant_id("acme")).has_value());
    TREG_REQUIRE(registry.close().ok());
  }
}

// ---------------------------------------------------------------------------
// A read-only session holds no authority at all.
// ---------------------------------------------------------------------------

TREG_TEST(authority, a_read_only_session_refuses_every_mutation_and_changes_nothing) {
  const TempTree tree{treg_test::make_temp_directory("authority-readonly")};

  auto writer = TenantRegistry::open(open_request(tree.path(), AccessMode::ReadWrite));
  TREG_REQUIRE_OK(writer);
  TenantRegistry writing = std::move(writer).value();
  TREG_REQUIRE_OK(writing.create_tenant(tenant_request(writing.generation(), "acme")));
  const RegistryGeneration committed = writing.generation();
  const std::string fingerprint = store_fingerprint(tree.path());

  // A read-only session does not take the writer lock, so it can coexist with
  // the writer; what it cannot do is change anything.
  auto reader = TenantRegistry::open(open_request(tree.path(), AccessMode::ReadOnly));
  TREG_REQUIRE_OK(reader);
  TenantRegistry reading = std::move(reader).value();
  TREG_CHECK_EQ(reading.access_mode(), AccessMode::ReadOnly);
  TREG_CHECK_EQ(reading.generation(), committed);
  TREG_CHECK(reading.recovery_report().read_only);

  expect_every_mutation_refused(reading, ErrorCode::StoreNotWritable);

  // Even a request that is stale as well as unauthorized is refused for the
  // writability reason: authority is decided before staleness.
  const auto stale = reading.create_tenant(tenant_request(RegistryGeneration::initial(), "beta"));
  TREG_CHECK_CODE(stale, ErrorCode::StoreNotWritable);

  TREG_CHECK_EQ(reading.generation(), committed);
  TREG_CHECK_EQ(store_fingerprint(tree.path()), fingerprint);
  TREG_CHECK(reading.find_tenant(treg_test::tenant_id("acme")).has_value());
  TREG_CHECK(!reading.find_tenant(treg_test::tenant_id("beta")).has_value());
  TREG_REQUIRE(writing.close().ok());
}

// ---------------------------------------------------------------------------
// A closed session is closed whatever it could do before.
// ---------------------------------------------------------------------------

TREG_TEST(authority, a_closed_session_refuses_every_mutation_with_store_closed) {
  const TempTree tree{treg_test::make_temp_directory("authority-closed")};

  auto opened = TenantRegistry::open(open_request(tree.path(), AccessMode::ReadWrite));
  TREG_REQUIRE_OK(opened);
  TenantRegistry registry = std::move(opened).value();
  TREG_REQUIRE_OK(registry.create_tenant(tenant_request(registry.generation(), "acme")));
  const RegistryGeneration committed = registry.generation();
  const std::string fingerprint = store_fingerprint(tree.path());

  TREG_REQUIRE(registry.close().ok());
  TREG_CHECK(!registry.valid());

  expect_every_mutation_refused(registry, ErrorCode::StoreClosed);

  // Closing twice is not an error. A closed session refuses to answer at all --
  // every entry point reports StoreClosed rather than relying on the caller
  // honouring a precondition -- and the state it protected is still there.
  TREG_CHECK(registry.close().ok());
  TREG_CHECK_EQ(registry.generation(), committed);
  TREG_CHECK_CODE(registry.find_tenant(treg_test::tenant_id("acme")), ErrorCode::StoreClosed);
  TREG_CHECK_CODE(registry.find_tombstone(SubjectKind::Tenant, "acme"), ErrorCode::StoreClosed);
  TREG_CHECK_CODE(registry.list_tenants(TenantQuery{}), ErrorCode::StoreClosed);
  // The entry points that cannot refuse keep answering from the state the
  // closed session was protecting, so closing is not the same as forgetting.
  const auto exported = registry.export_json();
  TREG_REQUIRE(exported.has_value());
  TREG_CHECK(exported.value().find("acme") != std::string::npos);
  TREG_CHECK_EQ(registry.snapshot().tenants.size(), static_cast<std::size_t>(1));
  TREG_CHECK_EQ(store_fingerprint(tree.path()), fingerprint);
}

// ---------------------------------------------------------------------------
// Counters: reported exactly, advanced by exactly one, and never wrapped.
// ---------------------------------------------------------------------------

TREG_TEST(authority, counters_are_reported_exactly_and_saturate_instead_of_wrapping) {
  constexpr std::uint64_t kMaximum = 0xFFFFFFFFFFFFFFFFull;

  // The only legal answer at the maximum is a refusal, so a saturated counter
  // can never silently become a small one and make stale state look current.
  TREG_CHECK_CODE(advance(RegistryGeneration::from_value(kMaximum)), ErrorCode::CounterSaturated);
  TREG_CHECK_CODE(advance(RecordRevision::from_value(kMaximum)), ErrorCode::CounterSaturated);
  TREG_CHECK_CODE(advance(DomainGeneration::from_value(kMaximum)), ErrorCode::CounterSaturated);
  TREG_CHECK_CODE(advance(ControlEpoch::from_value(kMaximum)), ErrorCode::CounterSaturated);
  TREG_CHECK_CODE(advance(JournalSequence::from_value(kMaximum)), ErrorCode::CounterSaturated);

  // A counter reports the value it was built with, without reinterpretation.
  TREG_CHECK_EQ(RegistryGeneration::from_value(kMaximum).value(), kMaximum);
  TREG_CHECK_EQ(RegistryGeneration::from_value(kMaximum).to_text(), std::string{"generation:18446744073709551615"});
  TREG_CHECK_EQ(advance(RegistryGeneration::from_value(41)).value(), RegistryGeneration::from_value(42));
  TREG_CHECK(RegistryGeneration::initial().is_initial());
  TREG_CHECK_EQ(RegistryGeneration::initial().value(), static_cast<std::uint64_t>(0));
  TREG_CHECK(RecordRevision::initial().is_initial());
  TREG_CHECK(ControlEpoch::initial().is_initial());
  TREG_CHECK(Incarnation::initial().is_initial());
  TREG_CHECK(JournalSequence::initial().is_initial());
  TREG_CHECK(DomainGeneration::initial().is_initial());

  EphemeralOptions options;
  options.clock = std::make_shared<FixedClock>(1'700'000'000'000);
  TenantRegistry registry = std::move(TenantRegistry::open_ephemeral(options).value());
  TREG_CHECK(registry.generation().is_initial());
  TREG_CHECK_EQ(registry.committed_sequence(), JournalSequence::initial());

  RegistryGeneration expected = RegistryGeneration::initial();
  for (int index = 0; index < 5; ++index) {
    const std::string name = "counter-" + std::to_string(index);
    const auto created = registry.create_tenant(tenant_request(registry.generation(), name));
    TREG_REQUIRE_OK(created);
    expected = advance(expected).value();
    TREG_CHECK_EQ(created.value().receipt.generation, expected);
    TREG_CHECK_EQ(created.value().record.created_generation, expected);
    TREG_CHECK_EQ(created.value().record.updated_generation, expected);
    TREG_CHECK_EQ(created.value().record.revision, RecordRevision::from_value(1));
  }
  TREG_CHECK_EQ(registry.generation(), expected);
  TREG_CHECK_EQ(registry.snapshot().generation, expected);

  const TenantRecord first = registry.find_tenant(treg_test::tenant_id("counter-0")).value();
  TREG_CHECK_EQ(first.revision, RecordRevision::from_value(1));
  TREG_REQUIRE_OK(registry.transition_subject(TransitionSubjectRequest{
      context(registry.generation()), TenancySubject::of_tenant(first.id), first.revision, LifecycleState::Active}));
  TREG_CHECK_EQ(registry.find_tenant(treg_test::tenant_id("counter-0")).value().revision,
                RecordRevision::from_value(2));
}