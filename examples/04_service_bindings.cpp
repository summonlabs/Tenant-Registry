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

// Example 04: service bindings.
//
// A service is bound to two tenants under different kinds, bound into an
// isolation domain, and then asked for a second in-force binding of a kind it
// already has. The transcript shows the one-in-force-binding-per-kind rule,
// the refusal that enforces it, and what listing and explain answer with.

#include <cstdint>
#include <optional>
#include <string>

#include "support.hpp"

namespace tr = tenant_registry;
using namespace treg_examples;

int main() {
  StepPrinter step{"04 service bindings"};

  step("open an ephemeral registry");
  tr::TenantRegistry registry =
      required(tr::TenantRegistry::open_ephemeral(ephemeral_options()), "open an ephemeral registry");

  step("declare and admit tenant acme");
  const tr::TenantId acme = tenant("acme");
  const tr::CreateTenantOutcome acme_declared = required(
      registry.create_tenant(tr::CreateTenantRequest{context(registry.generation()), acme,
                                                     std::string{"Acme Facility"}, std::nullopt,
                                                     tr::TenancyMetadata{}}),
      "declare tenant acme");
  required_ok(registry.transition_subject(tr::TransitionSubjectRequest{context(registry.generation()),
                                                                      tr::TenancySubject::of_tenant(acme),
                                                                      acme_declared.record.revision,
                                                                      tr::LifecycleState::Active}),
              "admit tenant acme");

  step("declare and admit tenant beta");
  const tr::TenantId beta = tenant("beta");
  const tr::CreateTenantOutcome beta_declared = required(
      registry.create_tenant(tr::CreateTenantRequest{context(registry.generation()), beta,
                                                     std::string{"Beta Facility"}, std::nullopt,
                                                     tr::TenancyMetadata{}}),
      "declare tenant beta");
  required_ok(registry.transition_subject(tr::TransitionSubjectRequest{context(registry.generation()),
                                                                      tr::TenancySubject::of_tenant(beta),
                                                                      beta_declared.record.revision,
                                                                      tr::LifecycleState::Active}),
              "admit tenant beta");

  step("declare and admit service renderer");
  const tr::ServiceId renderer = service("renderer");
  const tr::CreateServiceOutcome renderer_declared = required(
      registry.create_service(tr::CreateServiceRequest{context(registry.generation()), renderer,
                                                       std::string{"Renderer"}, tr::TenancyMetadata{}}),
      "declare service renderer");
  required_ok(registry.transition_subject(tr::TransitionSubjectRequest{context(registry.generation()),
                                                                      tr::TenancySubject::of_service(renderer),
                                                                      renderer_declared.record.revision,
                                                                      tr::LifecycleState::Active}),
              "admit service renderer");

  step("declare and admit isolation domain zone-a, class fault_containment");
  const tr::IsolationDomainId zone_a = domain("zone-a");
  const tr::CreateIsolationDomainOutcome zone_a_declared = required(
      registry.create_isolation_domain(tr::CreateIsolationDomainRequest{
          context(registry.generation()), zone_a, tr::IsolationClass::FaultContainment,
          std::string{"Zone A"}, tr::TenancyMetadata{}}),
      "declare isolation domain zone-a");
  required_ok(registry.transition_subject(tr::TransitionSubjectRequest{context(registry.generation()),
                                                                      tr::TenancySubject::of_isolation_domain(zone_a),
                                                                      zone_a_declared.record.revision,
                                                                      tr::LifecycleState::Active}),
              "admit isolation domain zone-a");

  step("bind service renderer to tenant acme as operated_by");
  const tr::PutServiceBindingOutcome operated = required(
      registry.put_service_binding(tr::PutServiceBindingRequest{context(registry.generation()), renderer, acme,
                                                                tr::BindingKind::OperatedBy,
                                                                tr::LifecycleState::Active, std::nullopt}),
      "bind service renderer to tenant acme");
  step.note(field("binding", operated.binding.natural_key()) + " " +
            field("kind", tr::to_token(operated.binding.kind)) + " " +
            field("state", tr::to_token(operated.binding.state)) + " " +
            field("revision", operated.binding.revision.value()));

  step("bind service renderer to tenant beta as serves");
  const tr::PutServiceBindingOutcome serves = required(
      registry.put_service_binding(tr::PutServiceBindingRequest{context(registry.generation()), renderer, beta,
                                                                tr::BindingKind::Serves,
                                                                tr::LifecycleState::Active, std::nullopt}),
      "bind service renderer to tenant beta");
  step.note(field("binding", serves.binding.natural_key()) + " " +
            field("kind", tr::to_token(serves.binding.kind)) + " " +
            field("state", tr::to_token(serves.binding.state)) + " " +
            field("revision", serves.binding.revision.value()));

  step("try a second in-force operated_by binding, this time to tenant beta");
  const tr::Result<tr::PutServiceBindingOutcome> conflicting = registry.put_service_binding(
      tr::PutServiceBindingRequest{context(registry.generation()), renderer, beta, tr::BindingKind::OperatedBy,
                                   tr::LifecycleState::Active, std::nullopt});
  if (conflicting.has_value()) {
    fail("a second in-force operated_by binding of service renderer was accepted");
  }
  step.note("refused: " + refusal_text(conflicting.error()));

  step("bind service renderer into isolation domain zone-a");
  const tr::IsolationDomainRecord zone_a_record =
      required(registry.find_isolation_domain(zone_a), "read isolation domain zone-a");
  const tr::PutIsolationMembershipOutcome membership = required(
      registry.put_isolation_membership(tr::PutIsolationMembershipRequest{
          context(registry.generation()), tr::TenancySubject::of_service(renderer), zone_a,
          tr::MembershipRole::Secondary, tr::MembershipState::Bound,
          zone_a_record.membership_generation, std::nullopt}),
      "bind service renderer into zone-a");
  step.note(field("membership", membership.membership.natural_key()) + " " +
            field("role", tr::to_token(membership.membership.role)) + " " +
            field("state", tr::to_token(membership.membership.state)) + " " +
            field("domain_generation", membership.domain_generation.value()));

  step("ask which domains service renderer is in force in");
  const std::vector<tr::IsolationDomainId> service_domains = required(
      registry.isolation_domains_of(tr::TenancySubject::of_service(renderer)),
      "list the domains of service renderer");
  step.note(field("domains", static_cast<std::uint64_t>(service_domains.size())));
  for (const tr::IsolationDomainId& listed : service_domains) {
    step.note("domain " + listed.to_text());
  }

  step("list every binding of service renderer in canonical order");
  const tr::Page<tr::ServiceBinding> bindings = required(
      registry.list_service_bindings(tr::BindingQuery{std::nullopt, std::nullopt, std::nullopt, std::nullopt, 0,
                                                      std::nullopt}),
      "list service bindings");
  step.note(field("total_matched", static_cast<std::uint64_t>(bindings.total_matched)) + " " +
            field("truncated", yes_no(bindings.truncated)));
  for (const tr::ServiceBinding& binding : bindings.items) {
    step.note(field("binding", binding.natural_key()) + " " + field("kind", tr::to_token(binding.kind)) + " " +
              field("state", tr::to_token(binding.state)) + " " +
              field("revision", binding.revision.value()));
  }

  step("explain service renderer");
  const tr::Explanation explained = required(
      registry.explain(tr::TenancySubject::of_service(renderer)), "explain service renderer");
  step.note(field("subject", explained.subject.to_text()) + " " +
            field("state", tr::to_token(tr::subject_state(explained.record))) + " " +
            field("revision", tr::subject_revision(explained.record).value()) + " " +
            field("bindings", static_cast<std::uint64_t>(explained.bindings.size())) + " " +
            field("memberships", static_cast<std::uint64_t>(explained.memberships.size())));
  for (const tr::ServiceBinding& binding : explained.bindings) {
    step.note(field("binding", binding.natural_key()) + " " + field("kind", tr::to_token(binding.kind)) + " " +
              field("state", tr::to_token(binding.state)));
  }
  for (const std::pair<tr::IsolationDomainId, tr::DomainGeneration>& entry : explained.domain_generations) {
    step.note(field("domain", entry.first.to_text()) + " " +
              field("membership_generation", entry.second.value()));
  }
  step.note(field("unknowns", static_cast<std::uint64_t>(explained.unknowns.size())));
  for (const std::string& unknown : explained.unknowns) {
    step.note("unknown " + unknown);
  }

  return 0;
}
