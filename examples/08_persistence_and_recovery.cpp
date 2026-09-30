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

// Example 08: persistence and recovery.
//
// A durable registry is opened in a private temporary directory, two identities
// are committed, the session is closed, and the store is reopened. The
// transcript shows what recovery reports: the generation, the control epoch
// that taking control advanced, and the fresh writer incarnation. A read-only
// session reads the same state and may change nothing; compaction then rewrites
// the journal as a baseline and the state is read back unchanged. The directory
// is removed when the program ends, on every path.

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>

#include "support.hpp"

namespace tr = tenant_registry;
using namespace treg_examples;

int main() {
  StepPrinter step{"08 persistence and recovery"};

  step("create a private directory for the durable store");
  const TempDirectory store_root{"store"};
  step.note("the directory is removed when this program ends, on every path");

  tr::RegistryOpenRequest open_request;
  open_request.root = store_root.path();
  open_request.mode = tr::AccessMode::ReadWrite;
  open_request.clock = std::make_shared<tr::FixedClock>(kFixedClockMilliseconds);

  step("open a durable registry, read-write");
  tr::TenantRegistry writer = required(tr::TenantRegistry::open(open_request), "open a durable registry");
  const tr::StoreRecoveryReport first_report = writer.recovery_report();
  step.note(field("durable", yes_no(writer.durable())) + " " +
            field("store_created", yes_no(first_report.store_created)) + " " +
            field("manifest_present", yes_no(first_report.manifest_present)) + " " +
            field("control_epoch", writer.control_epoch().value()) + " " +
            field("generation", writer.generation().value()));

  const tr::TenantId acme = tenant("acme");
  const tr::ServiceId renderer = service("renderer");

  step("declare and admit tenant acme");
  const tr::CreateTenantOutcome tenant_declared = required(
      writer.create_tenant(tr::CreateTenantRequest{context(writer.generation()), acme,
                                                   std::string{"Acme Facility"}, std::nullopt,
                                                   tr::TenancyMetadata{}}),
      "declare tenant acme");
  required_ok(writer.transition_subject(tr::TransitionSubjectRequest{context(writer.generation()),
                                                                     tr::TenancySubject::of_tenant(acme),
                                                                     tenant_declared.record.revision,
                                                                     tr::LifecycleState::Active}),
              "admit tenant acme");

  step("declare and admit service renderer");
  const tr::CreateServiceOutcome service_declared = required(
      writer.create_service(tr::CreateServiceRequest{context(writer.generation()), renderer,
                                                     std::string{"Renderer"}, tr::TenancyMetadata{}}),
      "declare service renderer");
  required_ok(writer.transition_subject(tr::TransitionSubjectRequest{context(writer.generation()),
                                                                    tr::TenancySubject::of_service(renderer),
                                                                    service_declared.record.revision,
                                                                    tr::LifecycleState::Active}),
              "admit service renderer");
  step.note(field("generation", writer.generation().to_text()) + " " +
            field("committed_sequence", writer.committed_sequence().to_text()));

  step("close the writer session");
  required(writer.close(), "close the writer session");
  step.note(field("valid", yes_no(writer.valid())));

  step("reopen the store: recovery reports what it found");
  tr::TenantRegistry recovered =
      required(tr::TenantRegistry::open(open_request), "reopen the durable registry");
  const tr::StoreRecoveryReport second_report = recovered.recovery_report();
  step.note(field("store_created", yes_no(second_report.store_created)) + " " +
            field("manifest_present", yes_no(second_report.manifest_present)) + " " +
            field("frames_replayed", second_report.frames_replayed) + " " +
            field("baseline_frames", second_report.baseline_frames) + " " +
            field("uncommitted_tail_discarded", yes_no(second_report.uncommitted_tail_discarded)));
  step.note(field("generation", recovered.generation().to_text()) + " " +
            field("committed_generation", second_report.committed_generation.to_text()) + " " +
            field("committed_sequence", recovered.committed_sequence().to_text()));
  step.note(field("control_epoch", movement(second_report.previous_control_epoch->value(),
                                            recovered.control_epoch().value())) +
            " " + field("incarnation_advanced", yes_no(recovered.incarnation() != writer.incarnation())));

  step("the recovered state is the state that was committed");
  const tr::TenantRecord recovered_tenant = required(recovered.find_tenant(acme), "read tenant acme");
  const tr::ServiceRecord recovered_service = required(recovered.find_service(renderer), "read service renderer");
  step.note(field("tenant", recovered_tenant.id.to_text()) + " " +
            field("state", tr::to_token(recovered_tenant.state)) + " " +
            field("revision", recovered_tenant.revision.to_text()) + " " +
            field("updated_generation", recovered_tenant.updated_generation.to_text()));
  step.note(field("service", recovered_service.id.to_text()) + " " +
            field("state", tr::to_token(recovered_service.state)) + " " +
            field("revision", recovered_service.revision.to_text()) + " " +
            field("updated_generation", recovered_service.updated_generation.to_text()));

  step("open a read-only session next to the writer");
  tr::RegistryOpenRequest read_only_request = open_request;
  read_only_request.mode = tr::AccessMode::ReadOnly;
  tr::TenantRegistry reader =
      required(tr::TenantRegistry::open(read_only_request), "open a read-only session");
  const tr::StoreRecoveryReport read_only_report = reader.recovery_report();
  step.note(field("access_mode", reader.access_mode() == tr::AccessMode::ReadOnly ? "read-only" : "read-write") +
            " " + field("durable", yes_no(reader.durable())) + " " +
            field("report_read_only", yes_no(read_only_report.read_only)) + " " +
            field("generation_matches", yes_no(reader.generation() == recovered.generation())) + " " +
            field("control_epoch_matches", yes_no(reader.control_epoch() == recovered.control_epoch())) + " " +
            field("incarnation_matches", yes_no(reader.incarnation() == recovered.incarnation())));
  const tr::TenantRecord read_only_tenant = required(reader.find_tenant(acme), "read tenant acme read-only");
  step.note(field("tenant", read_only_tenant.id.to_text()) + " " +
            field("state", tr::to_token(read_only_tenant.state)) + " " +
            field("revision", read_only_tenant.revision.to_text()));

  step("a read-only session may change nothing");
  const tr::Result<tr::CreateTenantOutcome> refused_write = reader.create_tenant(
      tr::CreateTenantRequest{context(reader.generation()), tenant("beta"), std::string{"Beta Facility"},
                              std::nullopt, tr::TenancyMetadata{}});
  if (refused_write.has_value()) {
    fail("a read-only session accepted a mutation");
  }
  step.note("refused: " + refusal_text(refused_write.error()));
  const tr::Status refused_flush = reader.flush();
  if (refused_flush.ok()) {
    fail("a read-only session flushed");
  }
  step.note("refused: " + refusal_text(refused_flush.error()));
  required(reader.close(), "close the read-only session");

  step("compact the journal into a fresh baseline");
  const tr::RegistryGeneration before_compaction = recovered.generation();
  const tr::JournalSequence sequence_before_compaction = recovered.committed_sequence();
  required(recovered.compact(), "compact the store");
  step.note(field("generation", recovered.generation().to_text()) + " " +
            field("unchanged", yes_no(recovered.generation() == before_compaction)) + " " +
            field("committed_sequence", movement(sequence_before_compaction.value(),
                                                 recovered.committed_sequence().value())));
  const tr::TenantRecord after_compaction = required(recovered.find_tenant(acme), "read tenant acme");
  step.note(field("tenant", after_compaction.id.to_text()) + " " +
            field("state", tr::to_token(after_compaction.state)) + " " +
            field("revision", after_compaction.revision.to_text()) + " " +
            field("same_state", yes_no(after_compaction.state == recovered_tenant.state &&
                                       after_compaction.revision == recovered_tenant.revision)));
  step.note(field("services", recovered.stats().services) + " " +
            field("isolation_domains", recovered.stats().isolation_domains));

  step("close the writer session");
  required(recovered.close(), "close the writer session");

  step("reopen the store that compaction rewrote");
  tr::TenantRegistry compacted = required(tr::TenantRegistry::open(open_request), "reopen the compacted store");
  const tr::StoreRecoveryReport third_report = compacted.recovery_report();
  step.note(field("generation", compacted.generation().to_text()) + " " +
            field("frames_replayed", third_report.frames_replayed) + " " +
            field("baseline_frames", third_report.baseline_frames) + " " +
            field("control_epoch", movement(third_report.previous_control_epoch->value(),
                                            compacted.control_epoch().value())));
  const tr::TenantRecord read_back = required(compacted.find_tenant(acme), "read tenant acme after compaction");
  const tr::ServiceRecord service_read_back =
      required(compacted.find_service(renderer), "read service renderer after compaction");
  step.note(field("tenant", read_back.id.to_text()) + " " + field("state", tr::to_token(read_back.state)) + " " +
            field("revision", read_back.revision.to_text()) + " " +
            field("same_state", yes_no(read_back.state == recovered_tenant.state &&
                                       read_back.revision == recovered_tenant.revision)));
  step.note(field("service", service_read_back.id.to_text()) + " " +
            field("state", tr::to_token(service_read_back.state)) + " " +
            field("revision", service_read_back.revision.to_text()));
  required(compacted.close(), "close the reopened session");

  step("the temporary directory is removed when this program returns");
  return 0;
}
