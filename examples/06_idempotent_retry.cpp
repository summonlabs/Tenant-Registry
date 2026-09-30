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

// Example 06: an idempotent retry.
//
// One declaration carries an idempotency key. It is accepted once, the
// registry moves on, and the identical request is sent again: it is answered
// from the ledger with the original receipt and the original record content,
// and it commits nothing. The same key used for a different request is refused.

#include <optional>
#include <string>

#include "support.hpp"

namespace tr = tenant_registry;
using namespace treg_examples;

int main() {
  StepPrinter step{"06 an idempotent retry"};

  step("open an ephemeral registry");
  tr::TenantRegistry registry =
      required(tr::TenantRegistry::open_ephemeral(ephemeral_options()), "open an ephemeral registry");

  const tr::IdempotencyKey key = idempotency_key("declare-acme-2026-01-01");

  step("declare tenant acme under an idempotency key");
  const tr::CreateTenantRequest declaration{keyed_context(registry.generation(), key), tenant("acme"),
                                            std::string{"Acme Facility"}, principal("facility.ops"),
                                            tr::TenancyMetadata{}};
  const tr::CreateTenantOutcome accepted = required(registry.create_tenant(declaration), "declare tenant acme");
  step.note(field("replayed", yes_no(accepted.receipt.replayed)) + " " +
            field("operation", tr::to_token(accepted.receipt.operation)) + " " +
            field("generation", accepted.receipt.generation.to_text()) + " " +
            field("sequence", accepted.receipt.sequence.to_text()) + " " +
            field("revision", accepted.receipt.revision.to_text()) + " " +
            field("request_digest", accepted.receipt.request_digest.to_short_text()));

  step("let the registry move on: declare service renderer and tenant beta");
  required_ok(registry.create_service(tr::CreateServiceRequest{context(registry.generation()),
                                                               service("renderer"), std::string{"Renderer"},
                                                               tr::TenancyMetadata{}}),
              "declare service renderer");
  required_ok(registry.create_tenant(tr::CreateTenantRequest{context(registry.generation()), tenant("beta"),
                                                             std::string{"Beta Facility"}, std::nullopt,
                                                             tr::TenancyMetadata{}}),
              "declare tenant beta");
  step.note(field("generation", movement(accepted.receipt.generation.value(), registry.generation().value())) +
            " " + field("committed_sequence", registry.committed_sequence().value()));

  step("send the identical request again, without re-reading anything");
  const tr::CreateTenantOutcome replayed = required(registry.create_tenant(declaration), "replay the declaration");
  step.note(field("replayed", yes_no(replayed.receipt.replayed)) + " " +
            field("operation", tr::to_token(replayed.receipt.operation)) + " " +
            field("generation", replayed.receipt.generation.to_text()) + " " +
            field("sequence", replayed.receipt.sequence.to_text()) + " " +
            field("revision", replayed.receipt.revision.to_text()) + " " +
            field("request_digest", replayed.receipt.request_digest.to_short_text()));
  step.note(field("record_state", tr::to_token(replayed.record.state)) + " " +
            field("record_revision", replayed.record.revision.to_text()) + " " +
            field("registry_generation", registry.generation().to_text()) + " " +
            field("committed_nothing", yes_no(replayed.receipt.generation != registry.generation())));

  step("use the same key for a different request");
  const tr::Result<tr::CreateTenantOutcome> reused = registry.create_tenant(
      tr::CreateTenantRequest{keyed_context(registry.generation(), key), tenant("gamma"),
                              std::string{"Gamma Facility"}, std::nullopt, tr::TenancyMetadata{}});
  if (reused.has_value()) {
    fail("an idempotency key was accepted for a second, different request");
  }
  step.note("refused: " + refusal_text(reused.error()));
  step.note(field("code", reused.error().token()) + " " +
            field("class", tr::to_token(reused.error().error_class())) + " " +
            field("registry_generation", registry.generation().to_text()) + " " +
            field("tenants", registry.stats().tenants));

  return 0;
}
