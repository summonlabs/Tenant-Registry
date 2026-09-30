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

// Example 07: retiring and tombstoning an identity.
//
// Tenant acme is admitted, then withdrawn in two honest steps. While it is
// retired the identity may not be reused; tombstoning it with a rebind permit
// is what allows exactly one successor to take the identity over. The
// transcript shows that one reuse admitted, the permanent tombstone that
// remains afterwards with its spent permit, and a second reuse refused.

#include <optional>
#include <string>
#include <variant>

#include "support.hpp"

namespace tr = tenant_registry;
using namespace treg_examples;

namespace {

/// The consumed generation of a tombstone's permit, or "absent" when the
/// tombstone carries no permit or an unconsumed one.
[[nodiscard]] std::string consumed_text(const tr::TombstoneRecord& tombstone) {
  if (!tombstone.permit.has_value() || !tombstone.permit->consumed_generation().has_value()) {
    return "absent";
  }
  return tombstone.permit->consumed_generation()->to_text();
}

}  // namespace

int main() {
  StepPrinter step{"07 retiring and tombstoning an identity"};

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
            field("state", tr::to_token(required(registry.find_tenant(acme), "read tenant acme").state)));

  step("begin the withdrawal: active -> retiring");
  const tr::TransitionSubjectOutcome retiring = required(
      registry.transition_subject(tr::TransitionSubjectRequest{context(registry.generation()),
                                                               tr::TenancySubject::of_tenant(acme),
                                                               tr::RecordRevision::from_value(2),
                                                               tr::LifecycleState::Retiring}),
      "begin retiring tenant acme");
  step.note(field("state", tr::to_token(tr::subject_state(retiring.record))) + " " +
            field("revision", tr::subject_revision(retiring.record).to_text()) + " " +
            field("generation", retiring.receipt.generation.to_text()));

  step("complete the withdrawal: retiring -> retired");
  const tr::TransitionSubjectOutcome retired = required(
      registry.transition_subject(tr::TransitionSubjectRequest{context(registry.generation()),
                                                               tr::TenancySubject::of_tenant(acme),
                                                               tr::subject_revision(retiring.record),
                                                               tr::LifecycleState::Retired}),
      "retire tenant acme");
  const tr::TenantRecord retired_record = std::get<tr::TenantRecord>(retired.record);
  step.note(field("state", tr::to_token(retired_record.state)) + " " +
            field("revision", retired_record.revision.to_text()) + " " +
            field("retired_generation", retired_record.retired_generation->to_text()) + " " +
            field("generation", retired.receipt.generation.to_text()));

  step("declare tenant acme again while it is retired");
  const tr::Result<tr::CreateTenantOutcome> refused_reuse = registry.create_tenant(
      tr::CreateTenantRequest{context(registry.generation()), acme, std::string{"Acme Facility, again"},
                              std::nullopt, tr::TenancyMetadata{}});
  if (refused_reuse.has_value()) {
    fail("the identity of a retired tenant was reused");
  }
  step.note("refused: " + refusal_text(refused_reuse.error()));
  for (const std::string& suppressed : refused_reuse.error().suppressed()) {
    step.note("suppressed " + suppressed);
  }

  step("tombstone tenant acme, permitting exactly one rebind of tenant:acme");
  const tr::TombstoneOutcome fenced = required(
      registry.tombstone(tr::TombstoneRequest{
          context(registry.generation()), tr::TenancySubject::of_tenant(acme),
          retired_record.revision, tr::IrreversibleAcknowledgement::acknowledged(),
          tr::RebindSuccessor{tr::SubjectKind::Tenant, "acme"},
          std::string{"fenced after retirement; one successor may take the identity"}}),
      "tombstone tenant acme");
  const tr::TenantRecord fenced_record = std::get<tr::TenantRecord>(fenced.record);
  const tr::Tombstone& written_tombstone = *fenced_record.tombstone;
  const std::string permit_successor =
      std::string{tr::to_token(written_tombstone.rebind_permit()->successor_kind())} + ":" +
      written_tombstone.rebind_permit()->successor_text();
  step.note(field("state", tr::to_token(fenced_record.state)) + " " +
            field("revision", fenced_record.revision.to_text()) + " " +
            field("retired_generation", fenced_record.retired_generation->to_text()) + " " +
            field("tombstoned_generation", written_tombstone.tombstoned_generation().to_text()));
  step.note(field("permit_successor", permit_successor) + " " +
            field("permit_issued_generation", written_tombstone.rebind_permit()->issued_generation().to_text()) +
            " " + field("permit_consumed", yes_no(written_tombstone.rebind_permit()->consumed())));

  step("read the tombstone of tenant:acme before any reuse");
  const tr::TombstoneRecord pending =
      required(registry.find_tombstone(tr::SubjectKind::Tenant, "acme"), "read the tombstone of tenant:acme");
  step.note(field("identity", tr::identity_text(pending.kind, pending.identity)) + " " +
            field("state", tr::to_token(pending.state)) + " " +
            field("tombstoned_generation", pending.tombstoned_generation.to_text()) + " " +
            field("permit_consumed_at", consumed_text(pending)));

  step("declare tenant acme again, under the permit");
  const tr::CreateTenantOutcome rebound = required(
      registry.create_tenant(tr::CreateTenantRequest{context(registry.generation()), acme,
                                                     std::string{"Acme Facility, reborn"}, std::nullopt,
                                                     tr::TenancyMetadata{}}),
      "reuse the identity under the permit");
  step.note(field("state", tr::to_token(rebound.record.state)) + " " +
            field("revision", rebound.record.revision.to_text()) + " " +
            field("generation", rebound.receipt.generation.to_text()) + " " +
            field("origin_digest", rebound.record.origin_digest.to_short_text()));

  step("the permanent tombstone the reuse left behind");
  const tr::RegistrySnapshot after_reuse = registry.snapshot();
  step.note(field("tombstones", static_cast<std::uint64_t>(after_reuse.tombstones.size())));
  for (const tr::TombstoneRecord& tombstone : after_reuse.tombstones) {
    step.note(field("identity", tr::identity_text(tombstone.kind, tombstone.identity)) + " " +
              field("tombstoned_generation", tombstone.tombstoned_generation.to_text()) + " " +
              field("permit_consumed_at", consumed_text(tombstone)));
  }

  step("fence the successor in turn: declared -> retired");
  const tr::TransitionSubjectOutcome resettled = required(
      registry.transition_subject(tr::TransitionSubjectRequest{context(registry.generation()),
                                                               tr::TenancySubject::of_tenant(acme),
                                                               rebound.record.revision,
                                                               tr::LifecycleState::Retired}),
      "retire the successor");
  step.note(field("state", tr::to_token(tr::subject_state(resettled.record))) + " " +
            field("revision", tr::subject_revision(resettled.record).to_text()) + " " +
            field("generation", resettled.receipt.generation.to_text()));

  step("tombstone the successor again, which issues no second permit");
  required_ok(registry.tombstone(tr::TombstoneRequest{
                  context(registry.generation()), tr::TenancySubject::of_tenant(acme),
                  tr::subject_revision(resettled.record), tr::IrreversibleAcknowledgement::acknowledged(),
                  std::nullopt, std::string{"fenced again; the permit for this identity was spent at generation 6"}}),
              "tombstone the successor");
  step.note(field("state", tr::to_token(required(registry.find_tenant(acme), "read tenant acme").state)) + " " +
            field("generation", registry.generation().to_text()));

  step("declare tenant acme a second time");
  const tr::Result<tr::CreateTenantOutcome> refused_again = registry.create_tenant(
      tr::CreateTenantRequest{context(registry.generation()), acme, std::string{"Acme Facility, third"},
                              std::nullopt, tr::TenancyMetadata{}});
  if (refused_again.has_value()) {
    fail("the identity of a tombstoned tenant was reused a second time");
  }
  step.note("refused: " + refusal_text(refused_again.error()));
  step.note(field("code", refused_again.error().token()) + " " +
            field("class", tr::to_token(refused_again.error().error_class())));

  step("the permanent tombstone is unchanged and still queryable");
  const tr::RegistrySnapshot final_state = registry.snapshot();
  step.note(field("tombstones", static_cast<std::uint64_t>(final_state.tombstones.size())) + " " +
            field("tenants", static_cast<std::uint64_t>(final_state.tenants.size())));
  for (const tr::TombstoneRecord& tombstone : final_state.tombstones) {
    step.note(field("identity", tr::identity_text(tombstone.kind, tombstone.identity)) + " " +
              field("tombstoned_generation", tombstone.tombstoned_generation.to_text()) + " " +
              field("permit_consumed_at", consumed_text(tombstone)) + " " +
              field("note", tombstone.note));
  }

  return 0;
}
