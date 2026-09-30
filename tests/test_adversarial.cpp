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
using tenant_registry::CreateTenantRequest;
using tenant_registry::DomainGeneration;
using tenant_registry::EphemeralOptions;
using tenant_registry::ErrorClass;
using tenant_registry::ErrorCode;
using tenant_registry::FixedClock;
using tenant_registry::IdempotencyKey;
using tenant_registry::IsolationClass;
using tenant_registry::IsolationDomainId;
using tenant_registry::PrincipalId;
using tenant_registry::ServiceId;
using tenant_registry::LifecycleState;
using tenant_registry::MembershipRole;
using tenant_registry::MembershipState;
using tenant_registry::MetadataEntry;
using tenant_registry::MetadataKey;
using tenant_registry::MetadataValue;
using tenant_registry::MutationContext;
using tenant_registry::OwnershipKind;
using tenant_registry::OwnershipQuery;
using tenant_registry::ProvenanceRecord;
using tenant_registry::ProvenanceSource;
using tenant_registry::PutIsolationMembershipRequest;
using tenant_registry::PutOwnershipRequest;
using tenant_registry::PutServiceBindingRequest;
using tenant_registry::RecordRevision;
using tenant_registry::RegistryGeneration;
using tenant_registry::RegistryOpenRequest;
using tenant_registry::SourceId;
using tenant_registry::TenancyMetadata;
using tenant_registry::TenantId;
using tenant_registry::TenantRecord;
using tenant_registry::TenancySubject;
using tenant_registry::TenantRegistry;
using tenant_registry::Timestamp;
using tenant_registry::TransitionSubjectRequest;
using tenant_registry::is_valid_utf8;

MutationContext context(RegistryGeneration generation, std::optional<IdempotencyKey> key = std::nullopt) {
  return MutationContext{generation, std::move(key),
                         treg_test::provenance("adversarial-suite", "hostile-principal", 17,
                                               "declared by the adversarial suite")};
}

/// The registry under test, plus the digest of its state. Every hostile input
/// is compared against the digest taken before it, so "refused" and "did not
/// change anything" are two separate assertions.
class Env {
 public:
  Env() : registry_(open_ephemeral_registry()) {}

  [[nodiscard]] TenantRegistry& registry() noexcept { return registry_; }
  [[nodiscard]] RegistryGeneration generation() const { return registry_.generation(); }
  [[nodiscard]] std::string digest() const { return registry_.snapshot().digest().to_text(); }

  void seed() {
    TREG_REQUIRE_OK(registry_.create_tenant(CreateTenantRequest{context(registry_.generation()),
                                                               treg_test::tenant_id("acme"), std::nullopt,
                                                               std::nullopt, TenancyMetadata{}}));
    TREG_REQUIRE_OK(registry_.create_service(CreateServiceRequest{context(registry_.generation()),
                                                                 treg_test::service_id("renderer"), std::nullopt,
                                                                 TenancyMetadata{}}));
    TREG_REQUIRE_OK(registry_.create_isolation_domain(CreateIsolationDomainRequest{
        context(registry_.generation()), treg_test::domain_id("zone-a"), IsolationClass::FaultContainment,
        std::nullopt, TenancyMetadata{}}));
  }

 private:
  static TenantRegistry open_ephemeral_registry() {
    EphemeralOptions options;
    options.clock = std::make_shared<FixedClock>(1'700'000'000'000);
    return std::move(TenantRegistry::open_ephemeral(options).value());
  }

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

CreateTenantRequest tenant_request(RegistryGeneration generation, std::string_view text,
                                   std::optional<std::string> display_name = std::nullopt,
                                   TenancyMetadata metadata = {}) {
  return CreateTenantRequest{context(generation), treg_test::tenant_id(text), std::move(display_name), std::nullopt,
                             std::move(metadata)};
}

std::string overlong_sequence() {
  std::string bytes;
  bytes.push_back(static_cast<char>(0xC0));
  bytes.push_back(static_cast<char>(0x80));
  return bytes;
}

std::string lone_surrogate() {
  std::string bytes;
  bytes.push_back(static_cast<char>(0xED));
  bytes.push_back(static_cast<char>(0xA0));
  bytes.push_back(static_cast<char>(0x80));
  return bytes;
}

std::string truncated_sequence() {
  std::string bytes;
  bytes.push_back(static_cast<char>(0xE2));
  bytes.push_back(static_cast<char>(0x82));
  return bytes;
}

}  // namespace

// ---------------------------------------------------------------------------
// Identity: the bound is exact and the form is exact.
// ---------------------------------------------------------------------------

TREG_TEST(adversarial, identity_length_and_form_bounds_are_exact) {
  Env env;
  env.seed();
  const RegistryGeneration committed = env.generation();
  const std::string before = env.digest();

  // An identity reaches a request only through its validating builder, so the
  // bound is enforced where the identity is made: a request carrying an
  // over-long or ill-formed identity is not a request this API can express.
  const std::string at_bound(128, 'a');
  const std::string over_bound(129, 'a');
  TREG_CHECK_CODE(TenantId::create(over_bound), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(ServiceId::create(over_bound), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(IsolationDomainId::create(over_bound), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(PrincipalId::create(over_bound), ErrorCode::InvalidIdentity);
  // The metadata key has its own, smaller bound.
  TREG_CHECK_CODE(MetadataKey::create(std::string(97, 'k')), ErrorCode::InvalidIdentity);
  TREG_REQUIRE_OK(MetadataKey::create(std::string(96, 'k')));

  // The form is exact: one leading separator, one trailing separator, a token
  // that is nothing but a separator, an inner space and the empty string are
  // each refused, and none of them is trimmed into a legal identity.
  for (const std::string& hostile : {std::string{"_acme"}, std::string{"acme-"}, std::string{":"},
                                     std::string{"ac me"}, std::string{}}) {
    TREG_CHECK_CODE(TenantId::create(hostile), ErrorCode::InvalidIdentity);
    TREG_CHECK_CODE(ServiceId::create(hostile), ErrorCode::InvalidIdentity);
    TREG_CHECK_CODE(IsolationDomainId::create(hostile), ErrorCode::InvalidIdentity);
  }

  // Refusals at the builder cannot have touched the registry.
  TREG_CHECK_EQ(env.generation(), committed);
  TREG_CHECK_EQ(env.digest(), before);

  // Exactly the bound is legal, and it is legal all the way through a request.
  const auto accepted = TenantId::create(at_bound);
  TREG_REQUIRE_OK(accepted);
  TREG_REQUIRE_OK(env.registry().create_tenant(CreateTenantRequest{
      context(env.generation()), accepted.value(), std::nullopt, std::nullopt, TenancyMetadata{}}));
  TREG_CHECK(env.registry().find_tenant(accepted.value()).has_value());
  TREG_CHECK_EQ(env.generation(), RegistryGeneration::from_value(committed.value() + 1));
  TREG_CHECK(env.digest() != before);
}

TREG_TEST(adversarial, non_utf8_and_control_bytes_are_refused_in_text_fields) {
  Env env;
  env.seed();
  const std::string before = env.digest();
  const std::string overlong = overlong_sequence();
  const std::string surrogate = lone_surrogate();
  const std::string truncated = truncated_sequence();

  // The predicate itself has to say no, or every field below is only
  // accidentally safe.
  TREG_CHECK(!is_valid_utf8(overlong));
  TREG_CHECK(!is_valid_utf8(surrogate));
  TREG_CHECK(!is_valid_utf8(truncated));
  TREG_CHECK(is_valid_utf8("plain ascii"));
  TREG_CHECK(is_valid_utf8("\xC3\xA9"));  // U+00E9, a well formed two byte sequence

  // An identity refuses malformed bytes as a malformed identity rather than
  // storing them and discovering the problem at decode time. This happens at
  // the identity builder, because no request can carry an identity that has
  // not been through it.
  TREG_CHECK_CODE(TenantId::create(overlong), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(TenantId::create(surrogate), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(TenantId::create(truncated), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(IsolationDomainId::create(surrogate), ErrorCode::InvalidIdentity);

  // A text field refuses them as malformed text.
  TREG_CHECK_CODE(env.registry().create_tenant(tenant_request(env.generation(), "text-a", overlong)),
                  ErrorCode::InvalidUtf8);
  TREG_CHECK_CODE(env.registry().create_tenant(tenant_request(env.generation(), "text-b", surrogate)),
                  ErrorCode::InvalidUtf8);
  TREG_CHECK_CODE(env.registry().create_tenant(tenant_request(env.generation(), "text-c", truncated)),
                  ErrorCode::InvalidUtf8);

  // Control bytes are legal UTF-8 and illegal here: a record that can carry a
  // terminal instruction is a record no log or export can be trusted to render.
  const std::string delete_byte(1, static_cast<char>(0x7F));
  TREG_CHECK_CODE(env.registry().create_tenant(tenant_request(env.generation(), "text-d", delete_byte)),
                  ErrorCode::InvalidTextForm);
  std::string with_nul{"a"};
  with_nul.push_back('\0');
  with_nul += "b";
  TREG_CHECK_CODE(env.registry().create_tenant(tenant_request(env.generation(), "text-e", with_nul)),
                  ErrorCode::InvalidTextForm);
  std::string with_unit_separator{"a"};
  with_unit_separator.push_back(static_cast<char>(0x1F));
  with_unit_separator += "b";
  const auto bad_value = MetadataValue::text(with_unit_separator, 512);
  TREG_CHECK_CODE(bad_value, ErrorCode::InvalidTextForm);

  // The identity with an embedded NUL is refused for its byte set, before any
  // question of text form arises.
  std::string identity_with_nul{"ac"};
  identity_with_nul.push_back('\0');
  identity_with_nul += "me";
  TREG_CHECK_CODE(TenantId::create(identity_with_nul), ErrorCode::InvalidIdentity);

  TREG_CHECK_EQ(env.digest(), before);
}

TREG_TEST(adversarial, display_name_bounds_are_exact) {
  Env env;
  env.seed();
  const std::string before = env.digest();

  const std::string at_bound(256, 'd');
  TREG_REQUIRE_OK(env.registry().create_tenant(tenant_request(env.generation(), "name-at-bound", at_bound)));
  const std::string over_bound(257, 'd');
  TREG_CHECK_CODE(env.registry().create_tenant(tenant_request(env.generation(), "name-over-bound", over_bound)),
                  ErrorCode::InvalidTextForm);
  TREG_CHECK_CODE(env.registry().create_tenant(tenant_request(env.generation(), "name-empty", std::string{})),
                  ErrorCode::InvalidTextForm);

  TREG_CHECK(!env.registry().find_tenant(treg_test::tenant_id("name-over-bound")).has_value());
  TREG_CHECK(!env.registry().find_tenant(treg_test::tenant_id("name-empty")).has_value());
  TREG_CHECK(env.digest() != before);
}

// ---------------------------------------------------------------------------
// Bounded containers: the bound is a bound, not a hint.
// ---------------------------------------------------------------------------

TREG_TEST(adversarial, metadata_bounds_are_exact) {
  Env env;
  env.seed();
  const std::string before = env.digest();

  std::vector<MetadataEntry> at_bound;
  for (std::size_t index = 0; index < 64; ++index) {
    at_bound.push_back(MetadataEntry{treg_test::metadata_key("key-" + std::to_string(index)),
                                     MetadataValue::integer(static_cast<std::int64_t>(index))});
  }
  const auto exact = TenancyMetadata::create(std::move(at_bound), 64, 512);
  TREG_REQUIRE_OK(exact);
  TREG_REQUIRE_OK(env.registry().create_tenant(
      tenant_request(env.generation(), "meta-exact", std::nullopt, exact.value())));

  // One entry more than the configured maximum is refused, and nothing is
  // stored: an absurd number of entries cannot be made to fit by asking twice.
  std::vector<MetadataEntry> over_bound;
  for (std::size_t index = 0; index < 65; ++index) {
    over_bound.push_back(MetadataEntry{treg_test::metadata_key("key-" + std::to_string(index)),
                                       MetadataValue::integer(static_cast<std::int64_t>(index))});
  }
  const auto too_many = TenancyMetadata::create(std::move(over_bound), 65, 512);
  TREG_REQUIRE_OK(too_many);
  TREG_CHECK_CODE(env.registry().create_tenant(
                      tenant_request(env.generation(), "meta-too-many", std::nullopt, too_many.value())),
                  ErrorCode::LimitExceeded);

  // An absurd payload: a value far beyond the per-value bound is refused by the
  // request check, and a value beyond the builder's own bound never becomes a
  // value at all.
  const auto huge = MetadataValue::text(std::string(4096, 'x'), 4096);
  TREG_REQUIRE_OK(huge);
  const auto huge_set = TenancyMetadata::create(
      {MetadataEntry{treg_test::metadata_key("huge"), huge.value()}}, 8, 4096);
  TREG_REQUIRE_OK(huge_set);
  TREG_CHECK_CODE(env.registry().create_tenant(
                      tenant_request(env.generation(), "meta-huge", std::nullopt, huge_set.value())),
                  ErrorCode::InvalidMetadata);
  TREG_CHECK_CODE(MetadataValue::text(std::string(600, 'y'), 512), ErrorCode::InvalidTextForm);

  // Duplicate keys would make the meaning of a declaration depend on the order
  // it was written in, so they are refused rather than resolved.
  const auto duplicated = TenancyMetadata::create(
      {MetadataEntry{treg_test::metadata_key("dup"), MetadataValue::integer(1)},
       MetadataEntry{treg_test::metadata_key("dup"), MetadataValue::integer(2)}},
      8, 64);
  TREG_CHECK_CODE(duplicated, ErrorCode::InvalidMetadata);

  TREG_CHECK(!env.registry().find_tenant(treg_test::tenant_id("meta-too-many")).has_value());
  TREG_CHECK(!env.registry().find_tenant(treg_test::tenant_id("meta-huge")).has_value());
  TREG_CHECK(env.digest() != before);
}

TREG_TEST(adversarial, idempotency_key_bounds_are_exact) {
  Env env;
  env.seed();
  const std::string before = env.digest();

  // Eight bytes is the shortest key and sixty four the longest; both are legal
  // and both actually work, so the bound is not an off by one in either
  // direction.
  const std::string shortest(8, 'k');
  const std::string longest(64, 'k');
  TREG_REQUIRE_OK(IdempotencyKey::create(shortest));
  TREG_REQUIRE_OK(IdempotencyKey::create(longest));

  const CreateTenantRequest short_request{context(env.generation(), IdempotencyKey::create(shortest).value()),
                                          treg_test::tenant_id("short-key"), std::nullopt, std::nullopt,
                                          TenancyMetadata{}};
  TREG_REQUIRE_OK(env.registry().create_tenant(short_request));
  const CreateTenantRequest long_request{context(env.generation(), IdempotencyKey::create(longest).value()),
                                         treg_test::tenant_id("long-key"), std::nullopt, std::nullopt,
                                         TenancyMetadata{}};
  TREG_REQUIRE_OK(env.registry().create_tenant(long_request));
  const auto replay = env.registry().create_tenant(short_request);
  TREG_REQUIRE_OK(replay);
  TREG_CHECK(replay.value().receipt.replayed);

  TREG_CHECK_CODE(IdempotencyKey::create(std::string(7, 'k')), ErrorCode::IdempotencyKeyMalformed);
  TREG_CHECK_CODE(IdempotencyKey::create(std::string(65, 'k')), ErrorCode::IdempotencyKeyMalformed);
  TREG_CHECK_CODE(IdempotencyKey::create("short!key"), ErrorCode::IdempotencyKeyMalformed);
  TREG_CHECK_CODE(IdempotencyKey::create("key-with-trailing-"), ErrorCode::IdempotencyKeyMalformed);
  TREG_CHECK(!env.registry().find_tenant(treg_test::tenant_id(std::string(65, 'k'))).has_value());
  TREG_CHECK(env.digest() != before);
}

// ---------------------------------------------------------------------------
// Enumerations: a value this build does not define is not a value.
// ---------------------------------------------------------------------------

TREG_TEST(adversarial, out_of_range_enum_values_are_refused_and_change_nothing) {
  Env env;
  env.seed();
  const RegistryGeneration committed = env.generation();
  const std::string before = env.digest();

  // Each of these would be written as one byte and refused by the decoder on
  // the next read, so accepting one would permanently poison a durable store.
  TREG_CHECK_CODE(env.registry().create_isolation_domain(CreateIsolationDomainRequest{
                      context(env.generation()), treg_test::domain_id("bad-class"),
                      static_cast<IsolationClass>(99), std::nullopt, TenancyMetadata{}}),
                  ErrorCode::InvalidEnumValue);
  TREG_CHECK_CODE(env.registry().put_ownership(PutOwnershipRequest{
                      context(env.generation()), treg_test::tenant_id("acme"), treg_test::tenant_id("acme"),
                      static_cast<OwnershipKind>(99), LifecycleState::Active, std::nullopt}),
                  ErrorCode::InvalidEnumValue);
  TREG_CHECK_CODE(env.registry().put_service_binding(PutServiceBindingRequest{
                      context(env.generation()), treg_test::service_id("renderer"), treg_test::tenant_id("acme"),
                      static_cast<BindingKind>(99), LifecycleState::Active, std::nullopt}),
                  ErrorCode::InvalidEnumValue);
  TREG_CHECK_CODE(env.registry().put_isolation_membership(PutIsolationMembershipRequest{
                      context(env.generation()), TenancySubject::of_tenant(treg_test::tenant_id("acme")),
                      treg_test::domain_id("zone-a"), static_cast<MembershipRole>(99), MembershipState::Bound,
                      DomainGeneration::initial(), std::nullopt}),
                  ErrorCode::InvalidEnumValue);

  // An actor whose provenance source is not one this build defines is refused
  // too, and the record never reaches the journal.
  const auto hostile_actor = ProvenanceRecord::create(static_cast<ProvenanceSource>(99),
                                                      treg_test::unwrap(SourceId::create("hostile-source"),
                                                                        "SourceId::create"),
                                                      treg_test::principal_id("hostile-principal"),
                                                      std::optional<Timestamp>{Timestamp{17}},
                                                      std::string{"undefined source"}, 512);
  TREG_REQUIRE_OK(hostile_actor);
  TREG_CHECK_CODE(env.registry().create_tenant(CreateTenantRequest{
                      MutationContext{env.generation(), std::nullopt, hostile_actor.value()},
                      treg_test::tenant_id("bad-source"), std::nullopt, std::nullopt, TenancyMetadata{}}),
                  ErrorCode::InvalidEnumValue);

  // An out-of-range lifecycle target is refused as an illegal transition,
  // because the state machine has no such destination to offer.
  TREG_CHECK_CODE(env.registry().transition_subject(TransitionSubjectRequest{
                      context(env.generation()), TenancySubject::of_tenant(treg_test::tenant_id("acme")),
                      RecordRevision::from_value(1), static_cast<LifecycleState>(200)}),
                  ErrorCode::LifecycleTransitionIllegal);
  TREG_CHECK_CODE(env.registry().put_ownership(PutOwnershipRequest{
                      context(env.generation()), treg_test::tenant_id("acme"), treg_test::tenant_id("acme"),
                      OwnershipKind::Administrative, static_cast<LifecycleState>(88), std::nullopt}),
                  ErrorCode::InvalidEnumValue);

  TREG_CHECK_EQ(env.generation(), committed);
  TREG_CHECK_EQ(env.digest(), before);
  TREG_CHECK(!env.registry().find_isolation_domain(treg_test::domain_id("bad-class")).has_value());
}

// ---------------------------------------------------------------------------
// Fencing: the maximum generation is stale, not special.
// ---------------------------------------------------------------------------

TREG_TEST(adversarial, a_maximum_generation_is_stale_and_changes_nothing) {
  Env env;
  env.seed();
  const RegistryGeneration committed = env.generation();
  const std::string before = env.digest();

  const auto refused = env.registry().create_tenant(
      CreateTenantRequest{context(RegistryGeneration::from_value(0xFFFFFFFFFFFFFFFFull)),
                          treg_test::tenant_id("max-generation"), std::nullopt, std::nullopt, TenancyMetadata{}});
  TREG_CHECK_CODE(refused, ErrorCode::StaleGeneration);
  if (!refused) {
    TREG_CHECK_EQ(classify(refused.error().code()), ErrorClass::Staleness);
    TREG_CHECK(refused.error().detail().find("18446744073709551615") != std::string::npos);
  }
  TREG_CHECK_EQ(env.generation(), committed);
  TREG_CHECK_EQ(env.digest(), before);
  TREG_CHECK(!env.registry().find_tenant(treg_test::tenant_id("max-generation")).has_value());
}

TREG_TEST(adversarial, a_battery_of_hostile_requests_leaves_the_digest_untouched) {
  Env env;
  env.seed();
  const RegistryGeneration committed = env.generation();
  const std::string before = env.digest();

  const std::vector<std::string> hostile_identities = {
      std::string{},        overlong_sequence(), lone_surrogate(),  truncated_sequence(),
      "_leading",           "trailing_",         ":",              "ac me",
      std::string(129, 'z')};
  for (const std::string& identity : hostile_identities) {
    TREG_CHECK_CODE(TenantId::create(identity), ErrorCode::InvalidIdentity);
    TREG_CHECK_EQ(env.digest(), before);
  }

  const std::vector<std::string> hostile_names = {overlong_sequence(), lone_surrogate(), truncated_sequence(),
                                                  std::string(257, 'n'), std::string(1, static_cast<char>(0x7F))};
  for (std::size_t index = 0; index < hostile_names.size(); ++index) {
    const auto refused = env.registry().create_tenant(
        tenant_request(env.generation(), "hostile-name-" + std::to_string(index), hostile_names[index]));
    TREG_CHECK(!refused.has_value());
    TREG_CHECK_EQ(env.digest(), before);
  }

  TREG_CHECK_EQ(env.generation(), committed);
  TREG_CHECK_EQ(env.digest(), before);
}

// ---------------------------------------------------------------------------
// Bounds that only exist once state exists.
// ---------------------------------------------------------------------------

TREG_TEST(adversarial, a_children_bound_is_enforced_on_every_new_child) {
  EphemeralOptions options;
  options.clock = std::make_shared<FixedClock>(1'700'000'000'000);
  options.limits.max_children_per_tenant = 2;
  TenantRegistry registry = std::move(TenantRegistry::open_ephemeral(options).value());

  // One parent that will be pushed to its bound, one tenant that will be used
  // to show the bound belongs to a parent and not to the registry.
  const auto parent = registry.create_tenant(tenant_request(registry.generation(), "parent"));
  TREG_REQUIRE_OK(parent);
  TREG_REQUIRE_OK(registry.transition_subject(TransitionSubjectRequest{
      context(registry.generation()), TenancySubject::of_tenant(parent.value().record.id),
      parent.value().record.revision, LifecycleState::Active}));
  const auto other_parent = registry.create_tenant(tenant_request(registry.generation(), "other-parent"));
  TREG_REQUIRE_OK(other_parent);
  TREG_REQUIRE_OK(registry.transition_subject(TransitionSubjectRequest{
      context(registry.generation()), TenancySubject::of_tenant(other_parent.value().record.id),
      other_parent.value().record.revision, LifecycleState::Active}));
  for (const char* name : {"child-one", "child-two", "child-three", "other-child"}) {
    const auto child = registry.create_tenant(tenant_request(registry.generation(), name));
    TREG_REQUIRE_OK(child);
    TREG_REQUIRE_OK(registry.transition_subject(TransitionSubjectRequest{
        context(registry.generation()), TenancySubject::of_tenant(child.value().record.id),
        child.value().record.revision, LifecycleState::Active}));
  }

  // Two children fit exactly.
  TREG_REQUIRE_OK(registry.put_ownership(PutOwnershipRequest{
      context(registry.generation()), treg_test::tenant_id("child-one"), parent.value().record.id,
      OwnershipKind::Administrative, LifecycleState::Active, std::nullopt}));
  TREG_REQUIRE_OK(registry.put_ownership(PutOwnershipRequest{
      context(registry.generation()), treg_test::tenant_id("child-two"), parent.value().record.id,
      OwnershipKind::Administrative, LifecycleState::Active, std::nullopt}));

  const RegistryGeneration at_bound = registry.generation();
  const std::string before = registry.snapshot().digest().to_text();
  const OwnershipQuery children_of_parent{std::nullopt, std::optional<TenantId>{parent.value().record.id},
                                          std::nullopt, std::nullopt, 0, std::nullopt};
  TREG_REQUIRE(registry.list_ownership(children_of_parent).value().total_matched == 2);

  // The third child is above the configured maximum. The bound counts the
  // children the tenant already owns, so it has to fire on the child that
  // crosses it and not on some later one.
  TREG_CHECK_CODE(registry.put_ownership(PutOwnershipRequest{
                      context(registry.generation()), treg_test::tenant_id("child-three"),
                      parent.value().record.id, OwnershipKind::Operational, LifecycleState::Active, std::nullopt}),
                  ErrorCode::LimitExceeded);
  TREG_CHECK_EQ(registry.generation(), at_bound);
  TREG_CHECK_EQ(registry.snapshot().digest().to_text(), before);
  TREG_CHECK_EQ(registry.list_ownership(children_of_parent).value().total_matched,
                static_cast<std::size_t>(2));

  // The bound is per parent: another tenant, at the same limits, still takes a
  // child, so the refusal above was about this parent's bound and nothing else.
  const OwnershipQuery children_of_other{std::nullopt, std::optional<TenantId>{other_parent.value().record.id},
                                         std::nullopt, std::nullopt, 0, std::nullopt};
  TREG_CHECK_EQ(registry.list_ownership(children_of_other).value().total_matched, static_cast<std::size_t>(0));
  TREG_REQUIRE_OK(registry.put_ownership(PutOwnershipRequest{
      context(registry.generation()), treg_test::tenant_id("other-child"), other_parent.value().record.id,
      OwnershipKind::Administrative, LifecycleState::Active, std::nullopt}));
  TREG_CHECK_EQ(registry.list_ownership(children_of_other).value().total_matched, static_cast<std::size_t>(1));
  TREG_CHECK_EQ(registry.list_ownership(children_of_parent).value().total_matched,
                static_cast<std::size_t>(2));
}

// ---------------------------------------------------------------------------
// The hostile input is refused; the registry keeps working across a restart.
// ---------------------------------------------------------------------------

TREG_TEST(adversarial, a_valid_request_after_a_restart_is_accepted) {
  const TempTree tree{treg_test::make_temp_directory("adversarial-reopen")};
  std::string digest_before_close;

  {
    auto opened = TenantRegistry::open(open_request(tree.path(), AccessMode::ReadWrite));
    TREG_REQUIRE_OK(opened);
    TenantRegistry registry = std::move(opened).value();
    TREG_REQUIRE_OK(registry.create_tenant(CreateTenantRequest{context(registry.generation()),
                                                              treg_test::tenant_id("before-restart"),
                                                              std::nullopt, std::nullopt, TenancyMetadata{}}));

    // A hostile request against the live store is refused, and the refusal
    // leaves nothing behind that a restart could resurrect.
    TREG_CHECK_CODE(registry.create_isolation_domain(CreateIsolationDomainRequest{
                        context(registry.generation()), treg_test::domain_id("bad-class"),
                        static_cast<IsolationClass>(99), std::nullopt, TenancyMetadata{}}),
                    ErrorCode::InvalidEnumValue);
    TREG_CHECK_CODE(TenantId::create(std::string(129, 'q')), ErrorCode::InvalidIdentity);
    TREG_CHECK_CODE(registry.create_tenant(
                        tenant_request(registry.generation(), "over-long-name", std::string(257, 'n'))),
                    ErrorCode::InvalidTextForm);
    TREG_CHECK_CODE(registry.create_tenant(
                        tenant_request(registry.generation(), "control-byte-name",
                                       std::string(1, static_cast<char>(0x7F)))),
                    ErrorCode::InvalidTextForm);
    digest_before_close = registry.snapshot().digest().to_text();
    TREG_REQUIRE(registry.close().ok());
  }

  {
    auto reopened = TenantRegistry::open(open_request(tree.path(), AccessMode::ReadWrite));
    TREG_REQUIRE_OK(reopened);
    TenantRegistry registry = std::move(reopened).value();
    TREG_CHECK_EQ(registry.snapshot().digest().to_text(), digest_before_close);
    TREG_CHECK_EQ(registry.generation(), RegistryGeneration::from_value(1));

    // The store accepted nothing hostile, so an ordinary request at the new
    // session's generation is accepted and lands on top of the old state.
    const auto accepted = registry.create_tenant(CreateTenantRequest{context(registry.generation()),
                                                                    treg_test::tenant_id("after-restart"),
                                                                    std::nullopt, std::nullopt, TenancyMetadata{}});
    TREG_REQUIRE_OK(accepted);
    TREG_CHECK(!accepted.value().receipt.replayed);
    TREG_CHECK_EQ(registry.generation(), RegistryGeneration::from_value(2));
    TREG_CHECK(registry.find_tenant(treg_test::tenant_id("before-restart")).has_value());
    TREG_CHECK(registry.find_tenant(treg_test::tenant_id("after-restart")).has_value());
    TREG_REQUIRE(registry.close().ok());
  }
}