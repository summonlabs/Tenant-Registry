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
#include <optional>
#include <string>
#include <string_view>

#include "test_support.hpp"

namespace treg_test {
namespace {

using tenant_registry::ContentDigest;
using tenant_registry::CreateTenantOutcome;
using tenant_registry::ErrorCode;
using tenant_registry::IdentityRules;
using tenant_registry::OperationKind;
using tenant_registry::TenancyMetadata;
using tenant_registry::validate_identity;

const CreateTenantRequest tenant_request(const TenantRegistry& registry, std::string_view id,
                                         std::optional<std::string> display_name, std::optional<PrincipalId> owner,
                                         TenancyMetadata metadata) {
  return CreateTenantRequest{context(registry.generation()), tenant_id(id), std::move(display_name),
                             std::move(owner), std::move(metadata)};
}

const CreateServiceRequest service_request(const TenantRegistry& registry, std::string_view id,
                                           std::optional<std::string> display_name, TenancyMetadata metadata) {
  return CreateServiceRequest{context(registry.generation()), service_id(id), std::move(display_name),
                              std::move(metadata)};
}

const CreateIsolationDomainRequest domain_request(const TenantRegistry& registry, std::string_view id,
                                                  IsolationClass isolation_class,
                                                  std::optional<std::string> display_name,
                                                  TenancyMetadata metadata) {
  return CreateIsolationDomainRequest{context(registry.generation()), domain_id(id), isolation_class,
                                      std::move(display_name), std::move(metadata)};
}

TREG_TEST(registry_create, a_tenant_declaration_binds_every_field_of_the_record) {
  Harness harness = Harness::ephemeral();
  const TenantId id = tenant_id("acme");
  const PrincipalId owner = principal_id("ops-owner");
  const TenancyMetadata metadata =
      unwrap(TenancyMetadata::create({entry("region", "eu"), entry("tier", "gold")}, 64, 512), "metadata");
  const ProvenanceRecord actor = provenance("declaration-source", "declaring-principal", 4242, "declared");
  const RegistryGeneration before = harness.generation();

  const CreateTenantRequest request{context(before, std::nullopt, actor), id,
                                    std::optional<std::string>{"Acme Facility"}, std::optional<PrincipalId>{owner},
                                    metadata};
  const CreateTenantOutcome outcome = unwrap(harness.registry().create_tenant(request), "create_tenant");
  const TenantRecord& record = outcome.record;

  // A declaration is a reservation: it exists and confers nothing.
  TREG_CHECK_EQ(record.state, LifecycleState::Declared);
  TREG_CHECK_EQ(record.revision.value(), 1u);
  TREG_CHECK_EQ(record.created_generation, outcome.receipt.generation);
  TREG_CHECK_EQ(record.updated_generation, outcome.receipt.generation);
  TREG_CHECK_EQ(outcome.receipt.generation.value(), before.value() + 1);
  TREG_CHECK_EQ(harness.generation().value(), before.value() + 1);
  TREG_CHECK(!record.retired_generation.has_value());
  TREG_CHECK(!record.tombstone.has_value());

  // The record is bound to the exact declaration that produced it.
  TREG_CHECK_EQ(record.provenance, actor);
  TREG_CHECK_EQ(record.origin_digest, outcome.receipt.request_digest);
  TREG_CHECK(!record.origin_digest.is_zero());
  TREG_CHECK_EQ(outcome.receipt.operation, OperationKind::CreateTenant);
  TREG_CHECK(!outcome.receipt.replayed);

  TREG_CHECK(record.display_name.has_value());
  TREG_CHECK_EQ(*record.display_name, "Acme Facility");
  TREG_CHECK(record.owner.has_value());
  TREG_CHECK_EQ(*record.owner, owner);
  TREG_CHECK_EQ(record.metadata, metadata);
  TREG_CHECK_EQ(record.metadata.size(), 2u);
  TREG_CHECK_EQ(record.metadata.entries().at(0).key.value(), "region");
  TREG_CHECK_EQ(record.metadata.entries().at(1).key.value(), "tier");
  TREG_CHECK_EQ(to_canonical(harness.tenant("acme")), to_canonical(record));
}

TREG_TEST(registry_create, an_absent_display_name_stays_absent) {
  Harness harness = Harness::ephemeral();
  const CreateTenantOutcome quiet =
      unwrap(harness.registry().create_tenant(tenant_request(harness.registry(), "quiet", std::nullopt,
                                                            std::nullopt, TenancyMetadata{})),
             "create_tenant");
  TREG_CHECK(!quiet.record.display_name.has_value());
  TREG_CHECK(!quiet.record.owner.has_value());
  TREG_CHECK(quiet.record.metadata.empty());

  // "Nothing was declared" and "declared as the empty string" must not look alike.
  const std::string text = to_canonical(quiet.record);
  TREG_CHECK(text.find("display_name=unset\n") != std::string::npos);
  TREG_CHECK(text.find("display_name=\n") == std::string::npos);

  const RegistryGeneration before = harness.generation();
  TREG_CHECK_CODE(harness.registry().create_tenant(tenant_request(harness.registry(), "blank",
                                                                 std::optional<std::string>{std::string{}},
                                                                 std::nullopt, TenancyMetadata{})),
                  ErrorCode::InvalidTextForm);
  TREG_CHECK_EQ(harness.generation(), before);
  TREG_CHECK_CODE(harness.registry().find_tenant(tenant_id("blank")), ErrorCode::NotFound);
}

TREG_TEST(registry_create, service_and_domain_declarations_bind_their_fields) {
  Harness harness = Harness::ephemeral();
  const TenancyMetadata metadata = unwrap(TenancyMetadata::create({entry("rack", "r7")}, 64, 512), "metadata");
  const ProvenanceRecord actor =
      provenance_without_time("declaration-source", "declaring-principal");

  const CreateServiceRequest service{context(harness.generation(), std::nullopt, actor), service_id("renderer"),
                                     std::optional<std::string>{"Renderer"}, metadata};
  const CreateServiceOutcome created_service = unwrap(harness.registry().create_service(service), "create_service");
  TREG_CHECK_EQ(created_service.record.state, LifecycleState::Declared);
  TREG_CHECK_EQ(created_service.record.revision.value(), 1u);
  TREG_CHECK_EQ(created_service.record.created_generation, created_service.record.updated_generation);
  TREG_CHECK_EQ(created_service.record.created_generation, created_service.receipt.generation);
  TREG_CHECK_EQ(created_service.record.provenance, actor);
  TREG_CHECK_EQ(created_service.record.origin_digest, created_service.receipt.request_digest);
  TREG_CHECK_EQ(created_service.record.display_name.value_or(std::string{}), "Renderer");
  TREG_CHECK_EQ(created_service.record.metadata, metadata);
  TREG_CHECK(!created_service.record.retired_generation.has_value());
  TREG_CHECK(!created_service.record.tombstone.has_value());

  const CreateIsolationDomainRequest domain{context(harness.generation()), domain_id("zone-a"),
                                            IsolationClass::FaultContainment,
                                            std::optional<std::string>{"Zone A"}, TenancyMetadata{}};
  const CreateIsolationDomainOutcome created_domain =
      unwrap(harness.registry().create_isolation_domain(domain), "create_isolation_domain");
  TREG_CHECK_EQ(created_domain.record.state, LifecycleState::Declared);
  TREG_CHECK_EQ(created_domain.record.isolation_class, IsolationClass::FaultContainment);
  TREG_CHECK_EQ(created_domain.record.revision.value(), 1u);
  TREG_CHECK_EQ(created_domain.record.membership_generation, DomainGeneration::initial());
  TREG_CHECK_EQ(created_domain.record.created_generation, created_domain.record.updated_generation);
  TREG_CHECK_EQ(created_domain.record.created_generation, created_domain.receipt.generation);
  TREG_CHECK_EQ(created_domain.record.origin_digest, created_domain.receipt.request_digest);
  TREG_CHECK_EQ(to_canonical(harness.domain("zone-a")), to_canonical(created_domain.record));
}

TREG_TEST(registry_create, every_isolation_class_is_accepted_and_kept) {
  Harness harness = Harness::ephemeral();
  const IsolationClass classes[] = {IsolationClass::FaultContainment, IsolationClass::Administrative,
                                    IsolationClass::Regulatory, IsolationClass::TenantPrivate};
  const std::string_view names[] = {"fault", "admin", "regulatory", "tenant"};
  for (std::size_t index = 0; index < 4; ++index) {
    const CreateIsolationDomainOutcome outcome =
        unwrap(harness.registry().create_isolation_domain(domain_request(
                   harness.registry(), names[index], classes[index], std::nullopt, TenancyMetadata{})),
               "create_isolation_domain");
    TREG_CHECK_EQ(outcome.record.isolation_class, classes[index]);
    TREG_CHECK_EQ(outcome.record.state, LifecycleState::Declared);
  }
  TREG_CHECK_EQ(harness.snapshot().isolation_domains.size(), 4u);
  TREG_CHECK_EQ(harness.domain("regulatory").isolation_class, IsolationClass::Regulatory);
}

TREG_TEST(registry_create, duplicate_identities_are_refused) {
  Harness harness = Harness::ephemeral();
  const RegistryGeneration before = harness.generation();
  const RegistrySnapshot before_snapshot = harness.snapshot();

  unwrap(harness.registry().create_tenant(tenant_request(harness.registry(), "acme",
                                                         std::optional<std::string>{"Acme"}, std::nullopt,
                                                         TenancyMetadata{})),
         "create_tenant");
  const auto duplicate_tenant = harness.registry().create_tenant(
      tenant_request(harness.registry(), "acme", std::nullopt, std::nullopt, TenancyMetadata{}));
  TREG_CHECK_CODE(duplicate_tenant, ErrorCode::IdentityAlreadyExists);
  TREG_CHECK(duplicate_tenant.error().detail().find("tenant:acme") != std::string::npos);
  TREG_CHECK(duplicate_tenant.error().detail().find("declared") != std::string::npos);

  unwrap(harness.registry().create_service(service_request(harness.registry(), "renderer", std::nullopt,
                                                           TenancyMetadata{})),
         "create_service");
  TREG_CHECK_CODE(harness.registry().create_service(
                      service_request(harness.registry(), "renderer", std::nullopt, TenancyMetadata{})),
                  ErrorCode::IdentityAlreadyExists);

  unwrap(harness.registry().create_isolation_domain(domain_request(harness.registry(), "zone",
                                                                   IsolationClass::Administrative, std::nullopt,
                                                                   TenancyMetadata{})),
         "create_isolation_domain");
  TREG_CHECK_CODE(harness.registry().create_isolation_domain(domain_request(
                      harness.registry(), "zone", IsolationClass::Regulatory, std::nullopt, TenancyMetadata{})),
                  ErrorCode::IdentityAlreadyExists);

  // The refusals happened after three accepted declarations and changed nothing else.
  TREG_CHECK_EQ(harness.generation().value(), before.value() + 3);
  TREG_CHECK_EQ(harness.snapshot().record_count(), before_snapshot.record_count() + 3);
  TREG_CHECK_EQ(harness.generation(), harness.snapshot().generation);
}

TREG_TEST(registry_create, an_identity_that_is_not_a_valid_token_is_refused_at_the_boundary) {
  const IdentityRules& rules = TenantId::rules();
  TREG_CHECK_CODE(validate_identity(std::string_view{}, rules), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(validate_identity("-leading", rules), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(validate_identity("trailing-", rules), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(validate_identity("has space", rules), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(validate_identity("has/slash", rules), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(validate_identity(std::string(129, 'a'), rules), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(validate_identity("\xC3\x28", rules), ErrorCode::InvalidIdentity);
  TREG_CHECK(validate_identity("a.b:c_d-1", rules).has_value());

  // The same rules guard every identity type, and a malformed one never becomes a request.
  TREG_CHECK_CODE(validate_identity("has space", ServiceId::rules()), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(validate_identity("has space", IsolationDomainId::rules()), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(TenantId::create("has space"), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(ServiceId::create("has space"), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(IsolationDomainId::create("has space"), ErrorCode::InvalidIdentity);
  TREG_CHECK_EQ(TenantId::rules().max_length, std::size_t{128});

  Harness harness = Harness::ephemeral();
  TREG_CHECK_EQ(harness.snapshot().record_count(), std::size_t{0});
  TREG_CHECK_EQ(harness.generation(), RegistryGeneration::initial());
}

TREG_TEST(registry_create, an_isolation_domain_without_a_class_is_refused) {
  Harness harness = Harness::ephemeral();
  const RegistryGeneration before = harness.generation();
  const RegistrySnapshot before_snapshot = harness.snapshot();

  const CreateIsolationDomainRequest request{context(before), domain_id("classless"), IsolationClass::Unspecified,
                                             std::optional<std::string>{"Classless"}, TenancyMetadata{}};
  TREG_CHECK_CODE(harness.registry().create_isolation_domain(request), ErrorCode::MissingRequiredField);
  TREG_CHECK_EQ(harness.generation(), before);
  TREG_CHECK_EQ(harness.snapshot().record_count(), before_snapshot.record_count());
  TREG_CHECK_EQ(harness.snapshot().digest(), before_snapshot.digest());
  TREG_CHECK_CODE(harness.registry().find_isolation_domain(domain_id("classless")), ErrorCode::NotFound);
}

TREG_TEST(registry_create, the_origin_digest_binds_the_exact_declaration) {
  Harness first = Harness::ephemeral();
  Harness second = Harness::ephemeral();
  Harness third = Harness::ephemeral();

  const auto declare = [](Harness& harness, std::string_view display) {
    const CreateTenantOutcome outcome =
        unwrap(harness.registry().create_tenant(tenant_request(harness.registry(), "same",
                                                              std::optional<std::string>{std::string{display}},
                                                              std::nullopt, TenancyMetadata{})),
               "create_tenant");
    TREG_CHECK_EQ(outcome.record.origin_digest, outcome.receipt.request_digest);
    return outcome.record.origin_digest;
  };

  const ContentDigest one = declare(first, "One");
  const ContentDigest repeat = declare(second, "One");
  const ContentDigest other = declare(third, "Two");
  TREG_CHECK_EQ(one, repeat);
  TREG_CHECK(one != other);
}

}  // namespace
}  // namespace treg_test
