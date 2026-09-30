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

// A downstream consumer of the installed Tenant Registry package.
//
// This program exists to prove that a project which has never seen this
// repository's build tree can find the package, link the namespaced imported
// target, and use the public API to do real work: declare tenancy, relate it,
// persist it, restart it, and refuse the things that must be refused. It links
// nothing from tests/ and includes nothing from src/.

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

#include <tenant_registry/tenant_registry.hpp>

namespace {

int failures = 0;

void check(bool condition, const char* what) {
  if (!condition) {
    std::fprintf(stderr, "consumer: check failed: %s\n", what);
    ++failures;
  }
}

tenant_registry::Timestamp fixed_clock_reading() { return tenant_registry::Timestamp{1'700'000'000'000}; }

/// Every mutating request states the generation it was composed against and who
/// is asking, so this is the shape a downstream caller writes once and reuses.
tenant_registry::MutationContext context_of(const tenant_registry::TenantRegistry& registry,
                                           const tenant_registry::ProvenanceRecord& actor) {
  return tenant_registry::MutationContext{registry.generation(), std::nullopt, actor};
}

}  // namespace

int main() {
  using namespace tenant_registry;

  const std::filesystem::path root = std::filesystem::temp_directory_path() / "tenant-registry-consumer";
  std::error_code error;
  std::filesystem::remove_all(root, error);

  std::string digest_before;
  std::string digest_after;
  std::uint64_t generation_after = 0;

  {
    RegistryOpenRequest open;
    open.root = root;
    open.mode = AccessMode::ReadWrite;
    open.clock = std::make_shared<FixedClock>(fixed_clock_reading().unix_milliseconds);
    auto registry = TenantRegistry::open(open);
    if (!registry) {
      std::fprintf(stderr, "consumer: could not open a store: %s\n",
                   std::string{to_token(registry.error().code())}.c_str());
      return 1;
    }

    const auto actor = ProvenanceRecord::create(ProvenanceSource::OperatorDeclaration,
                                                SourceId::create("consumer").value(),
                                                PrincipalId::create("consumer-principal").value(),
                                                std::optional<Timestamp>{fixed_clock_reading()},
                                                std::string{"declared by the downstream consumer"}, 512);
    check(static_cast<bool>(actor), "a provenance record can be built");

    const auto tenant = TenantId::create("consumer-tenant");
    const auto service = ServiceId::create("consumer-service");
    const auto domain = IsolationDomainId::create("consumer-zone");
    check(static_cast<bool>(tenant) && static_cast<bool>(service) && static_cast<bool>(domain),
          "canonical identities are accepted");

    const CreateTenantRequest create_tenant{context_of(registry.value(), actor.value()), tenant.value(), std::nullopt,
                                            std::nullopt, TenancyMetadata{}};
    auto tenant_outcome = registry.value().create_tenant(create_tenant);
    check(static_cast<bool>(tenant_outcome), "a tenant can be declared");
    if (!tenant_outcome) {
      return 1;
    }
    check(tenant_outcome.value().record.state == LifecycleState::Declared,
          "a declared tenant is not yet in force");

    auto admitted = registry.value().transition_subject(TransitionSubjectRequest{
        context_of(registry.value(), actor.value()), TenancySubject::of_tenant(tenant.value()),
        tenant_outcome.value().record.revision, LifecycleState::Active});
    check(static_cast<bool>(admitted), "a declared tenant can be admitted");

    auto service_outcome = registry.value().create_service(
        CreateServiceRequest{context_of(registry.value(), actor.value()), service.value(), std::string{"Consumer Service"},
                             TenancyMetadata{}});
    check(static_cast<bool>(service_outcome), "a service can be declared");

    auto domain_outcome = registry.value().create_isolation_domain(
        CreateIsolationDomainRequest{context_of(registry.value(), actor.value()), domain.value(),
                                     IsolationClass::FaultContainment, std::nullopt, TenancyMetadata{}});
    check(static_cast<bool>(domain_outcome), "an isolation domain can be declared");

    // A declared identity confers nothing, so relating to it must be refused.
    if (service_outcome && tenant_outcome) {
      auto premature = registry.value().put_service_binding(PutServiceBindingRequest{
          context_of(registry.value(), actor.value()), service.value(), tenant.value(), BindingKind::OperatedBy,
          LifecycleState::Active, std::nullopt});
      check(!premature, "a binding to a tenant that is not in force is refused");
    }

    // A stale request must be refused rather than applied to state it did not see.
    MutationContext stale_context = context_of(registry.value(), actor.value());
    stale_context.expected_generation = RegistryGeneration::from_value(registry.value().generation().value() + 5);
    auto stale = registry.value().create_tenant(CreateTenantRequest{stale_context, TenantId::create("stale-tenant").value(),
                                                             std::nullopt, std::nullopt, TenancyMetadata{}});
    check(!stale && stale.error().code() == ErrorCode::StaleGeneration,
          "a request composed against another generation is refused as stale");

    auto snapshot = registry.value().snapshot();
    check(snapshot.tenants.size() == 1, "the snapshot holds exactly the tenants that were admitted");
    digest_before = snapshot.digest().to_text();
    generation_after = registry.value().generation().value();

    auto explanation = registry.value().explain(TenancySubject::of_tenant(tenant.value()));
    check(static_cast<bool>(explanation), "a tenant can be explained");
    if (explanation) {
      check(!explanation.value().unknowns.empty(),
            "an explanation states what it does not know rather than staying silent");
    }

    const Status closed = registry.value().close();
    check(closed.ok(), "the session closes cleanly");
  }

  {
    // The same state, read back by a process that has just started.
    RegistryOpenRequest open;
    open.root = root;
    open.mode = AccessMode::ReadWrite;
    open.clock = std::make_shared<FixedClock>(fixed_clock_reading().unix_milliseconds);
    auto registry = TenantRegistry::open(open);
    if (!registry) {
      std::fprintf(stderr, "consumer: could not reopen the store: %s\n",
                   std::string{to_token(registry.error().code())}.c_str());
      return 1;
    }
    digest_after = registry.value().snapshot().digest().to_text();
    check(digest_after == digest_before,
          "the state digest survives a restart, because it identifies tenancy facts and not a session");
    check(registry.value().generation().value() == generation_after, "the generation survives a restart");
    check(registry.value().control_epoch() > ControlEpoch::initial(), "taking control advances the control epoch");
    (void)registry.value().close();
  }

  std::filesystem::remove_all(root, error);

  if (failures != 0) {
    std::fprintf(stderr, "consumer: %d check(s) failed\n", failures);
    return 1;
  }
  std::printf("consumer: all checks passed; state digest %s\n", digest_after.c_str());
  return 0;
}
