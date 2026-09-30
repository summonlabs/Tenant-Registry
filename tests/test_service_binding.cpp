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
#include <vector>

#include "test_support.hpp"

namespace treg_test {
namespace {

using tenant_registry::BindingQuery;
using tenant_registry::ErrorCode;
using tenant_registry::Explanation;
using tenant_registry::OperationKind;
using tenant_registry::Page;
using tenant_registry::PutServiceBindingOutcome;
using tenant_registry::PutServiceBindingRequest;
using tenant_registry::RemoveServiceBindingRequest;
using tenant_registry::ServiceQuery;
using tenant_registry::ServiceSummary;
using tenant_registry::TenancyMetadata;
using tenant_registry::TransitionServiceBindingRequest;

PutServiceBindingRequest binding_request(const TenantRegistry& registry, const ServiceId& service,
                                        const TenantId& tenant, BindingKind kind, LifecycleState initial_state,
                                        std::optional<RecordRevision> expected_revision = std::nullopt) {
  return PutServiceBindingRequest{context(registry.generation()), service, tenant, kind, initial_state,
                                  expected_revision};
}

PutServiceBindingOutcome bind(Harness& harness, const ServiceId& service, const TenantId& tenant, BindingKind kind,
                              LifecycleState initial_state,
                              std::optional<RecordRevision> expected_revision = std::nullopt) {
  return unwrap(harness.registry().put_service_binding(
                    binding_request(harness.registry(), service, tenant, kind, initial_state, expected_revision)),
                "put_service_binding");
}

std::string binding_kinds_text(const std::vector<ServiceBinding>& bindings) {
  std::string out;
  for (const ServiceBinding& binding : bindings) {
    if (!out.empty()) {
      out += ",";
    }
    out += to_token(binding.kind);
  }
  return out;
}

TREG_TEST(service_binding, a_binding_is_put_transitioned_and_removed) {
  Harness harness = Harness::ephemeral();
  const ServiceRecord service = harness.active_service("renderer");
  const TenantRecord tenant = harness.active_tenant("acme");
  const RegistryGeneration before = harness.generation();

  const PutServiceBindingOutcome created =
      bind(harness, service.id, tenant.id, BindingKind::OperatedBy, LifecycleState::Active);
  const ServiceBinding& binding = created.binding;
  TREG_CHECK_EQ(binding.service, service.id);
  TREG_CHECK_EQ(binding.tenant, tenant.id);
  TREG_CHECK_EQ(binding.kind, BindingKind::OperatedBy);
  TREG_CHECK_EQ(binding.state, LifecycleState::Active);
  TREG_CHECK_EQ(binding.revision.value(), 1u);
  TREG_CHECK_EQ(binding.created_generation, created.receipt.generation);
  TREG_CHECK_EQ(binding.updated_generation, created.receipt.generation);
  TREG_CHECK_EQ(created.receipt.operation, OperationKind::PutServiceBinding);
  TREG_CHECK_EQ(created.receipt.generation.value(), before.value() + 1);
  TREG_CHECK_EQ(binding.origin_digest, created.receipt.request_digest);
  TREG_CHECK_EQ(binding.natural_key(), std::string{"service:renderer|tenant:acme"});
  TREG_REQUIRE(harness.snapshot().service_bindings.size() == 1u);
  TREG_CHECK_EQ(to_canonical(harness.snapshot().service_bindings.at(0)), to_canonical(binding));

  const auto suspended = harness.registry().transition_service_binding(
      TransitionServiceBindingRequest{context(harness.generation()), service.id, tenant.id, BindingKind::OperatedBy,
                                      RecordRevision::from_value(1), LifecycleState::Suspended});
  TREG_REQUIRE_OK(suspended);
  TREG_CHECK_EQ(suspended.value().revision.value(), 2u);
  TREG_CHECK_EQ(harness.snapshot().service_bindings.at(0).state, LifecycleState::Suspended);

  const auto removed = harness.registry().remove_service_binding(
      RemoveServiceBindingRequest{context(harness.generation()), service.id, tenant.id, BindingKind::OperatedBy,
                                  RecordRevision::from_value(2)});
  TREG_REQUIRE_OK(removed);
  TREG_CHECK(harness.snapshot().service_bindings.empty());
  TREG_CHECK(harness.registry().list_service_bindings(BindingQuery{}).value().items.empty());
  TREG_CHECK_CODE(harness.registry().remove_service_binding(
                      RemoveServiceBindingRequest{context(harness.generation()), service.id, tenant.id,
                                                  BindingKind::OperatedBy, RecordRevision::from_value(2)}),
                  ErrorCode::RelationshipAbsent);
  TREG_CHECK_CODE(harness.registry().transition_service_binding(
                      TransitionServiceBindingRequest{context(harness.generation()), service.id, tenant.id,
                                                      BindingKind::OperatedBy, RecordRevision::from_value(2),
                                                      LifecycleState::Active}),
                  ErrorCode::RelationshipAbsent);
}

TREG_TEST(service_binding, the_kind_is_part_of_the_identity_of_a_binding) {
  Harness harness = Harness::ephemeral();
  const ServiceRecord service = harness.active_service("renderer");
  const TenantRecord tenant = harness.active_tenant("acme");

  // The same pair may answer several different questions at once.
  bind(harness, service.id, tenant.id, BindingKind::OperatedBy, LifecycleState::Active);
  bind(harness, service.id, tenant.id, BindingKind::Serves, LifecycleState::Active);
  bind(harness, service.id, tenant.id, BindingKind::ConsumedBy, LifecycleState::Active);
  TREG_CHECK_EQ(harness.snapshot().service_bindings.size(), 3u);
  TREG_CHECK_EQ(binding_kinds_text(harness.snapshot().service_bindings),
                std::string{"consumed_by,operated_by,serves"});
  TREG_CHECK_EQ(to_token(BindingKind::OperatedBy), "operated_by");
  TREG_CHECK_EQ(to_token(BindingKind::Serves), "serves");
  TREG_CHECK_EQ(to_token(BindingKind::ConsumedBy), "consumed_by");

  // Removing one leaves the others, and the pair's natural key is the pair.
  const auto removed = harness.registry().remove_service_binding(
      RemoveServiceBindingRequest{context(harness.generation()), service.id, tenant.id, BindingKind::Serves,
                                  RecordRevision::from_value(1)});
  TREG_REQUIRE_OK(removed);
  TREG_CHECK_EQ(harness.snapshot().service_bindings.size(), 2u);
  TREG_CHECK_EQ(binding_kinds_text(harness.snapshot().service_bindings), std::string{"consumed_by,operated_by"});

  const auto missing_kind = harness.registry().remove_service_binding(
      RemoveServiceBindingRequest{context(harness.generation()), service.id, tenant.id, BindingKind::Unspecified,
                                  RecordRevision::from_value(1)});
  TREG_CHECK_CODE(missing_kind, ErrorCode::MissingRequiredField);
  TREG_CHECK_EQ(harness.snapshot().service_bindings.size(), 2u);
}

TREG_TEST(service_binding, at_most_one_in_force_binding_per_service_and_kind) {
  Harness harness = Harness::ephemeral();
  const ServiceRecord service = harness.active_service("renderer");
  const TenantRecord first = harness.active_tenant("first");
  const TenantRecord second = harness.active_tenant("second");
  const TenantRecord third = harness.active_tenant("third");

  bind(harness, service.id, first.id, BindingKind::OperatedBy, LifecycleState::Active);
  const auto conflict =
      harness.registry().put_service_binding(binding_request(harness.registry(), service.id, second.id,
                                                            BindingKind::OperatedBy, LifecycleState::Active));
  TREG_CHECK_CODE(conflict, ErrorCode::BindingConflict);
  TREG_CHECK(conflict.error().detail().find("first") != std::string::npos);
  TREG_CHECK_EQ(harness.snapshot().service_bindings.size(), 1u);

  // A binding that is not in force is allowed to exist; making it in force is not.
  const ServiceBinding declared =
      bind(harness, service.id, second.id, BindingKind::OperatedBy, LifecycleState::Declared).binding;
  const auto late_conflict = harness.registry().transition_service_binding(
      TransitionServiceBindingRequest{context(harness.generation()), service.id, second.id, BindingKind::OperatedBy,
                                      declared.revision, LifecycleState::Active});
  TREG_CHECK_CODE(late_conflict, ErrorCode::BindingConflict);
  TREG_CHECK(late_conflict.error().detail().find("first") != std::string::npos);

  // The conflict is per kind, so other kinds are unaffected.
  bind(harness, service.id, second.id, BindingKind::Serves, LifecycleState::Active);
  bind(harness, service.id, third.id, BindingKind::ConsumedBy, LifecycleState::Active);
  TREG_CHECK_EQ(harness.snapshot().service_bindings.size(), 4u);

  // Re-declaring the same binding without asserting a revision is a duplicate.
  const auto duplicate = harness.registry().put_service_binding(
      binding_request(harness.registry(), service.id, first.id, BindingKind::OperatedBy, LifecycleState::Active));
  TREG_CHECK_CODE(duplicate, ErrorCode::DuplicateRelationship);
  const auto stale =
      harness.registry().put_service_binding(binding_request(harness.registry(), service.id, first.id,
                                                            BindingKind::OperatedBy, LifecycleState::Active,
                                                            RecordRevision::from_value(4)));
  TREG_CHECK_CODE(stale, ErrorCode::StaleRecordRevision);
  TREG_CHECK(stale.error().detail().find("revision 1") != std::string::npos);
  TREG_CHECK(stale.error().detail().find("revision 4") != std::string::npos);
}

TREG_TEST(service_binding, a_binding_from_a_non_active_service_is_refused) {
  Harness harness = Harness::ephemeral();
  const TenantRecord tenant = harness.active_tenant("acme");
  const ServiceRecord declared = harness.create_service("declared-service");
  const ServiceRecord suspended_service = harness.active_service("suspended-service");
  const ServiceRecord retiring_service = harness.active_service("retiring-service");

  require_ok(harness.transition(TenancySubject::of_service(suspended_service.id), suspended_service.revision,
                                LifecycleState::Suspended),
             "suspend service");
  require_ok(harness.transition(TenancySubject::of_service(retiring_service.id), retiring_service.revision,
                                LifecycleState::Retiring),
             "retire service");

  const ServiceId services[] = {declared.id, suspended_service.id, retiring_service.id};
  for (const ServiceId& service : services) {
    TREG_CHECK_CODE(harness.registry().put_service_binding(binding_request(
                        harness.registry(), service, tenant.id, BindingKind::OperatedBy, LifecycleState::Active)),
                    ErrorCode::ReferenceNotYetLive);
  }
  TREG_CHECK(harness.snapshot().service_bindings.empty());
}

TREG_TEST(service_binding, a_binding_to_a_tenant_that_cannot_receive_one_is_refused) {
  Harness harness = Harness::ephemeral();
  const ServiceRecord service = harness.active_service("renderer");
  const TenantRecord suspended_tenant = harness.active_tenant("suspended-tenant");
  const TenantRecord retiring_tenant = harness.active_tenant("retiring-tenant");
  const TenantRecord declared_tenant = harness.create_tenant("declared-tenant");

  require_ok(harness.transition(TenancySubject::of_tenant(suspended_tenant.id), suspended_tenant.revision,
                                LifecycleState::Suspended),
             "suspend tenant");
  require_ok(harness.transition(TenancySubject::of_tenant(retiring_tenant.id), retiring_tenant.revision,
                                LifecycleState::Retiring),
             "retire tenant");

  // A suspended tenant may still be named: suspension is recoverable.
  bind(harness, service.id, suspended_tenant.id, BindingKind::Serves, LifecycleState::Active);
  TREG_CHECK_CODE(harness.registry().put_service_binding(binding_request(
                      harness.registry(), service.id, retiring_tenant.id, BindingKind::Serves,
                      LifecycleState::Active)),
                  ErrorCode::ReferenceTerminal);
  TREG_CHECK_CODE(harness.registry().put_service_binding(binding_request(
                      harness.registry(), service.id, declared_tenant.id, BindingKind::Serves,
                      LifecycleState::Active)),
                  ErrorCode::ReferenceTerminal);
  TREG_CHECK_EQ(harness.snapshot().service_bindings.size(), 1u);
}

TREG_TEST(service_binding, listing_and_explanation_agree_with_the_records) {
  Harness harness = Harness::ephemeral();
  const ServiceRecord renderer = harness.active_service("renderer");
  const ServiceRecord storage = harness.active_service("storage");
  const TenantRecord acme = harness.active_tenant("acme");
  const TenantRecord other = harness.active_tenant("other");

  bind(harness, renderer.id, acme.id, BindingKind::OperatedBy, LifecycleState::Active);
  bind(harness, renderer.id, other.id, BindingKind::Serves, LifecycleState::Active);
  bind(harness, storage.id, acme.id, BindingKind::Serves, LifecycleState::Declared);

  const Page<ServiceBinding> all =
      unwrap(harness.registry().list_service_bindings(BindingQuery{}), "list_service_bindings");
  TREG_CHECK_EQ(all.total_matched, std::size_t{3});
  TREG_CHECK_EQ(all.items.size(), 3u);
  TREG_CHECK_EQ(all.items.at(0).service.value(), "renderer");
  TREG_CHECK_EQ(all.items.at(0).tenant.value(), "acme");
  TREG_CHECK_EQ(all.items.at(1).service.value(), "renderer");
  TREG_CHECK_EQ(all.items.at(1).tenant.value(), "other");
  TREG_CHECK_EQ(all.items.at(2).service.value(), "storage");

  const Page<ServiceBinding> of_renderer =
      unwrap(harness.registry().list_service_bindings(BindingQuery{.service = std::optional<ServiceId>{renderer.id}}),
             "list_service_bindings");
  TREG_CHECK_EQ(of_renderer.total_matched, std::size_t{2});
  const Page<ServiceBinding> served_by_renderer = unwrap(
      harness.registry().list_service_bindings(BindingQuery{.tenant = std::optional<TenantId>{other.id},
                                                            .kind = std::optional<BindingKind>{
                                                                BindingKind::Serves}}),
      "list_service_bindings");
  TREG_CHECK_EQ(served_by_renderer.total_matched, std::size_t{1});
  TREG_REQUIRE(served_by_renderer.items.size() == 1u);
  TREG_CHECK_EQ(served_by_renderer.items.at(0).service, renderer.id);
  TREG_CHECK_EQ(served_by_renderer.items.at(0).tenant, other.id);
  const Page<ServiceBinding> in_force =
      unwrap(harness.registry().list_service_bindings(BindingQuery{.state = std::optional<LifecycleState>{
          LifecycleState::Active}}),
             "list_service_bindings");
  TREG_CHECK_EQ(in_force.total_matched, std::size_t{2});

  // The service query answers the same question from the binding side.
  const Page<ServiceSummary> bound_to_acme = unwrap(
      harness.registry().list_services(ServiceQuery{.bound_to_tenant = std::optional<TenantId>{acme.id}}),
      "list_services");
  TREG_CHECK_EQ(bound_to_acme.total_matched, std::size_t{2});
  const Page<ServiceSummary> operated_by =
      unwrap(harness.registry().list_services(ServiceQuery{.bound_to_tenant = std::optional<TenantId>{acme.id},
                                                          .binding_kind = std::optional<BindingKind>{
                                                              BindingKind::OperatedBy}}),
             "list_services");
  TREG_CHECK_EQ(operated_by.total_matched, std::size_t{1});
  TREG_CHECK_EQ(operated_by.items.at(0).id, renderer.id);

  // The tenant's explanation lists exactly the bindings that name it, and the
  // service's explanation lists exactly the bindings that name the service.
  const auto canonical_of = [](const std::vector<ServiceBinding>& bindings) {
    std::string text;
    for (const ServiceBinding& binding : bindings) {
      if (!text.empty()) {
        text += "\n";
      }
      text += to_canonical(binding);
    }
    return text;
  };
  std::vector<ServiceBinding> expected_for_tenant;
  std::vector<ServiceBinding> expected_for_service;
  for (const ServiceBinding& binding : harness.snapshot().service_bindings) {
    if (binding.tenant == acme.id) {
      expected_for_tenant.push_back(binding);
    }
    if (binding.service == renderer.id) {
      expected_for_service.push_back(binding);
    }
  }
  TREG_REQUIRE(expected_for_tenant.size() == 2u);
  TREG_REQUIRE(expected_for_service.size() == 2u);

  const Explanation explanation = unwrap(harness.registry().explain(TenancySubject::of_tenant(acme.id)),
                                         "explain");
  TREG_CHECK_EQ(canonical_of(explanation.bindings), canonical_of(expected_for_tenant));

  const Explanation service_explanation =
      unwrap(harness.registry().explain(TenancySubject::of_service(renderer.id)), "explain");
  TREG_CHECK_EQ(canonical_of(service_explanation.bindings), canonical_of(expected_for_service));
}

}  // namespace
}  // namespace treg_test
