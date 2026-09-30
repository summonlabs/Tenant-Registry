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

// Example 05: a stale generation.
//
// Two writers inside one process. The first reads the generation and composes
// a decision against it; the second moves the registry on; the first then
// submits the decision it composed. The transcript shows the refusal naming
// both generations exactly, shows that an ordinary read is always current, and
// shows the same decision accepted once it is composed against what is there.

#include <optional>
#include <string>

#include "support.hpp"

namespace tr = tenant_registry;
using namespace treg_examples;

int main() {
  StepPrinter step{"05 a stale generation"};

  step("open an ephemeral registry");
  tr::TenantRegistry registry =
      required(tr::TenantRegistry::open_ephemeral(ephemeral_options()), "open an ephemeral registry");

  step("declare and admit tenant acme");
  const tr::TenantId acme = tenant("acme");
  const tr::CreateTenantOutcome declared = required(
      registry.create_tenant(tr::CreateTenantRequest{context(registry.generation()), acme,
                                                     std::string{"Acme Facility"}, std::nullopt,
                                                     tr::TenancyMetadata{}}),
      "declare tenant acme");
  required_ok(registry.transition_subject(tr::TransitionSubjectRequest{context(registry.generation()),
                                                                      tr::TenancySubject::of_tenant(acme),
                                                                      declared.record.revision,
                                                                      tr::LifecycleState::Active}),
              "admit tenant acme");
  step.note(field("generation", registry.generation().value()) + " " +
            field("revision", required(registry.find_tenant(acme), "read tenant acme").revision.value()));

  step("writer A reads the generation it composes its decision against");
  const tr::RegistryGeneration observed_generation = registry.generation();
  const tr::TenantRecord observed_record = required(registry.find_tenant(acme), "read tenant acme");
  const tr::MutationContext writers_context = context(observed_generation);
  step.note(field("observed_generation", observed_generation.to_text()) + " " +
            field("observed_revision", observed_record.revision.to_text()) + " " +
            field("observed_state", tr::to_token(observed_record.state)));

  step("writer B moves the registry on: suspend tenant acme");
  const tr::TransitionSubjectOutcome suspended = required(
      registry.transition_subject(tr::TransitionSubjectRequest{context(registry.generation()),
                                                               tr::TenancySubject::of_tenant(acme),
                                                               observed_record.revision,
                                                               tr::LifecycleState::Suspended}),
      "suspend tenant acme");
  step.note(field("generation", movement(observed_generation.value(), suspended.receipt.generation.value())) + " " +
            field("state", tr::to_token(tr::subject_state(suspended.record))) + " " +
            field("revision", tr::subject_revision(suspended.record).to_text()));

  step("writer A submits the decision it composed against generation:2");
  const tr::Result<tr::TransitionSubjectOutcome> stale = registry.transition_subject(
      tr::TransitionSubjectRequest{writers_context, tr::TenancySubject::of_tenant(acme),
                                   observed_record.revision, tr::LifecycleState::Retiring});
  if (stale.has_value()) {
    fail("a mutation composed against a generation that had moved on was accepted");
  }
  step.note("refused: " + refusal_text(stale.error()));
  step.note(field("code", stale.error().token()) + " " +
            field("class", tr::to_token(stale.error().error_class())) + " " +
            field("transient", yes_no(tr::is_transient(stale.error().code()))));

  step("an ordinary read is never stale: it answers from the state that is current now");
  const tr::TenantRecord current = required(registry.find_tenant(acme), "read tenant acme");
  step.note(field("generation", registry.generation().to_text()) + " " +
            field("state", tr::to_token(current.state)) + " " + field("revision", current.revision.to_text()));

  step("writer A re-reads and composes the same decision against the generation it now sees");
  const tr::TransitionSubjectOutcome retiring = required(
      registry.transition_subject(tr::TransitionSubjectRequest{context(registry.generation()),
                                                               tr::TenancySubject::of_tenant(acme),
                                                               current.revision,
                                                               tr::LifecycleState::Retiring}),
      "begin retiring tenant acme");
  step.note(field("generation", movement(current.updated_generation.value(),
                                         retiring.receipt.generation.value())) +
            " " + field("state", tr::to_token(tr::subject_state(retiring.record))) + " " +
            field("revision", tr::subject_revision(retiring.record).to_text()));

  step("the registry never applied anything to a state it did not see");
  step.note(field("generation", registry.generation().value()) + " " +
            field("state", tr::to_token(required(registry.find_tenant(acme), "read tenant acme").state)));

  return 0;
}
