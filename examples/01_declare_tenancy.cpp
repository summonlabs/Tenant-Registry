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

// Example 01: declaring tenancy.
//
// A tenant and a service are declared, admitted, and then declared again under
// the same identity bytes. The transcript shows the generation and the record
// revision moving by exactly one for every accepted mutation, and shows the
// duplicate refused with the reason that fits it.

#include <optional>
#include <string>

#include "support.hpp"

namespace tr = tenant_registry;
using namespace treg_examples;

int main() {
  StepPrinter step{"01 declaring tenancy"};

  step("open an ephemeral registry");
  tr::TenantRegistry registry =
      required(tr::TenantRegistry::open_ephemeral(ephemeral_options()), "open an ephemeral registry");
  step.note(field("generation", registry.generation().value()) + " " +
            field("control_epoch", registry.control_epoch().value()) + " " +
            field("durable", yes_no(registry.durable())));

  const tr::PrincipalId accountable_owner = principal("facility.ops");
  const tr::TenantId acme = tenant("acme");

  step("declare tenant acme, with an accountable owner");
  const tr::CreateTenantOutcome tenant_declared = required(
      registry.create_tenant(tr::CreateTenantRequest{context(registry.generation()), acme,
                                                     std::string{"Acme Facility"}, accountable_owner,
                                                     tr::TenancyMetadata{}}),
      "declare tenant acme");
  step.note(field("tenant", tenant_declared.record.id.to_text()) + " " +
            field("state", tr::to_token(tenant_declared.record.state)) + " " +
            field("revision", tenant_declared.record.revision.to_text()) + " " +
            field("owner", tenant_declared.record.owner->value()));
  step.note(field("generation", movement(0, tenant_declared.receipt.generation.value())) + " " +
            field("sequence", tenant_declared.receipt.sequence.value()));

  step("admit tenant acme: declared -> active");
  const tr::TransitionSubjectOutcome tenant_admitted = required(
      registry.transition_subject(tr::TransitionSubjectRequest{context(registry.generation()),
                                                               tr::TenancySubject::of_tenant(acme),
                                                               tenant_declared.record.revision,
                                                               tr::LifecycleState::Active}),
      "admit tenant acme");
  step.note(field("identity", tr::subject_identity_text(tenant_admitted.record)) + " " +
            field("state", tr::to_token(tr::subject_state(tenant_admitted.record))) + " " +
            field("revision", movement(tenant_declared.record.revision.value(),
                                       tr::subject_revision(tenant_admitted.record).value())) +
            " " + field("generation", tenant_admitted.receipt.generation.value()));

  const tr::ServiceId renderer = service("renderer");

  step("declare service renderer");
  const tr::CreateServiceOutcome service_declared = required(
      registry.create_service(tr::CreateServiceRequest{context(registry.generation()), renderer,
                                                       std::string{"Renderer"}, tr::TenancyMetadata{}}),
      "declare service renderer");
  step.note(field("service", service_declared.record.id.to_text()) + " " +
            field("state", tr::to_token(service_declared.record.state)) + " " +
            field("revision", service_declared.record.revision.to_text()) + " " +
            field("generation", service_declared.receipt.generation.value()));

  step("admit service renderer: declared -> active");
  const tr::TransitionSubjectOutcome service_admitted = required(
      registry.transition_subject(tr::TransitionSubjectRequest{context(registry.generation()),
                                                               tr::TenancySubject::of_service(renderer),
                                                               service_declared.record.revision,
                                                               tr::LifecycleState::Active}),
      "admit service renderer");
  step.note(field("identity", tr::subject_identity_text(service_admitted.record)) + " " +
            field("state", tr::to_token(tr::subject_state(service_admitted.record))) + " " +
            field("revision", movement(service_declared.record.revision.value(),
                                       tr::subject_revision(service_admitted.record).value())) +
            " " + field("generation", service_admitted.receipt.generation.value()));

  step("declare tenant acme a second time, with the same identity bytes");
  const tr::Result<tr::CreateTenantOutcome> duplicate = registry.create_tenant(
      tr::CreateTenantRequest{context(registry.generation()), acme, std::string{"Acme Facility, again"},
                              accountable_owner, tr::TenancyMetadata{}});
  if (duplicate.has_value()) {
    fail("the duplicate declaration of tenant:acme was accepted");
  }
  step.note("refused: " + refusal_text(duplicate.error()));
  step.note(field("code", duplicate.error().token()) + " " +
            field("class", tr::to_token(duplicate.error().error_class())));

  step("the refusal changed nothing");
  const tr::RegistryStats stats = registry.stats();
  step.note(field("generation", stats.generation.value()) + " " + field("tenants", stats.tenants) + " " +
            field("services", stats.services) + " " + field("ownership_edges", stats.ownership_edges));
  const tr::TenantRecord current = required(registry.find_tenant(acme), "read tenant acme");
  step.note(field("tenant", current.id.to_text()) + " " + field("state", tr::to_token(current.state)) + " " +
            field("revision", current.revision.to_text()) + " " +
            field("created_generation", current.created_generation.to_text()) + " " +
            field("updated_generation", current.updated_generation.to_text()));

  return 0;
}
