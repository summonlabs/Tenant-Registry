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

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "test_support.hpp"

namespace {

using tenant_registry::AccessMode;
using tenant_registry::CreateTenantRequest;
using tenant_registry::EphemeralOptions;
using tenant_registry::ErrorCode;
using tenant_registry::FixedClock;
using tenant_registry::LifecycleState;
using tenant_registry::MutationContext;
using tenant_registry::OwnershipKind;
using tenant_registry::PutOwnershipRequest;
using tenant_registry::RegistryGeneration;
using tenant_registry::RegistryOpenRequest;
using tenant_registry::RegistrySnapshot;
using tenant_registry::TenancyMetadata;
using tenant_registry::TenancySubject;
using tenant_registry::TenantQuery;
using tenant_registry::TenantRecord;
using tenant_registry::TenantRegistry;
using tenant_registry::TransitionSubjectRequest;

MutationContext context(RegistryGeneration generation) {
  return MutationContext{generation, std::nullopt,
                         treg_test::provenance("concurrency-suite", "thread-principal", 17,
                                               "declared by the concurrency suite")};
}

CreateTenantRequest tenant_request(RegistryGeneration generation, const std::string& identity) {
  return CreateTenantRequest{context(generation), treg_test::tenant_id(identity), std::nullopt, std::nullopt,
                             TenancyMetadata{}};
}

RegistryOpenRequest open_request(const std::filesystem::path& root, AccessMode mode) {
  RegistryOpenRequest request;
  request.root = root;
  request.mode = mode;
  request.clock = std::make_shared<FixedClock>(1'700'000'000'000);
  return request;
}

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

/// Re-derives every invariant a snapshot must satisfy, whatever else is
/// happening. A snapshot is taken under the registry's writer mutex, so a
/// violation here means a mutation was visible in a half-applied form -- the
/// one failure mode a concurrent caller must never be able to observe.
std::size_t snapshot_violations(const RegistrySnapshot& snapshot, std::string& first_problem) {
  std::size_t problems = 0;
  const auto note = [&problems, &first_problem](std::string text) {
    if (problems == 0) {
      first_problem = std::move(text);
    }
    ++problems;
  };

  std::vector<std::string> tenants;
  tenants.reserve(snapshot.tenants.size());
  for (const TenantRecord& tenant : snapshot.tenants) {
    tenants.push_back(tenant.id.value());
    if (tenant.revision.value() < 1) {
      note("a tenant record has revision zero");
    }
    if (tenant.state == LifecycleState::Unspecified) {
      note("a tenant record has no lifecycle state");
    }
    if (tenant.created_generation.value() < 1) {
      note("a tenant record was created at generation zero");
    }
    if (tenant.created_generation.value() > tenant.updated_generation.value()) {
      note("a tenant record was updated before it was created");
    }
    if (tenant.updated_generation.value() > snapshot.generation.value()) {
      note("a tenant record was updated after the generation it is reported at");
    }
    if (tenant.origin_digest.is_zero()) {
      note("a tenant record carries no origin digest");
    }
  }
  if (!std::is_sorted(tenants.begin(), tenants.end())) {
    note("tenant identities are not in canonical order");
  }
  if (std::adjacent_find(tenants.begin(), tenants.end()) != tenants.end()) {
    note("a tenant identity appears twice in one snapshot");
  }

  std::vector<std::string> services;
  services.reserve(snapshot.services.size());
  for (const tenant_registry::ServiceRecord& service : snapshot.services) {
    services.push_back(service.id.value());
    if (service.revision.value() < 1 || service.state == LifecycleState::Unspecified) {
      note("a service record is not well formed");
    }
  }

  std::vector<std::string> domains;
  domains.reserve(snapshot.isolation_domains.size());
  for (const tenant_registry::IsolationDomainRecord& domain : snapshot.isolation_domains) {
    domains.push_back(domain.id.value());
    if (domain.revision.value() < 1 || domain.state == LifecycleState::Unspecified) {
      note("an isolation domain record is not well formed");
    }
    const std::optional<tenant_registry::DomainGeneration> recorded = snapshot.domain_generation(domain.id);
    if (!recorded.has_value() || *recorded != domain.membership_generation) {
      note("a domain membership generation disagrees with the domain record");
    }
  }

  // A relationship whose endpoints are not in the same snapshot would be an
  // edge into nothing: exactly what a torn read would produce.
  for (const tenant_registry::OwnershipEdge& edge : snapshot.ownership_edges) {
    if (!std::binary_search(tenants.begin(), tenants.end(), edge.child.value())) {
      note("an ownership edge names a child that is not in its own snapshot");
    }
    if (!std::binary_search(tenants.begin(), tenants.end(), edge.parent.value())) {
      note("an ownership edge names a parent that is not in its own snapshot");
    }
    if (edge.child == edge.parent) {
      note("an ownership edge is its own parent");
    }
  }
  for (const tenant_registry::ServiceBinding& binding : snapshot.service_bindings) {
    if (!std::binary_search(services.begin(), services.end(), binding.service.value())) {
      note("a service binding names a service that is not in its own snapshot");
    }
    if (!std::binary_search(tenants.begin(), tenants.end(), binding.tenant.value())) {
      note("a service binding names a tenant that is not in its own snapshot");
    }
  }
  for (const tenant_registry::IsolationMembership& membership : snapshot.isolation_memberships) {
    const std::string subject = membership.subject.to_text();
    const bool subject_present =
        membership.subject.is_tenant()
            ? std::binary_search(tenants.begin(), tenants.end(), membership.subject.identity_value())
            : std::binary_search(services.begin(), services.end(), membership.subject.identity_value());
    if (!subject_present) {
      note("an isolation membership names a subject that is not in its own snapshot: " + subject);
    }
    if (!std::binary_search(domains.begin(), domains.end(), membership.domain.value())) {
      note("an isolation membership names a domain that is not in its own snapshot");
    }
  }
  return problems;
}

struct WriterOutcome {
  /// Every accepted mutation, whatever kind.
  std::uint64_t accepted = 0;
  /// The accepted mutations that created a tenant.
  std::uint64_t tenants = 0;
  std::uint64_t stale = 0;
  ErrorCode unexpected = ErrorCode::Unspecified;
};

struct ReaderOutcome {
  std::uint64_t snapshots = 0;
  std::uint64_t problems = 0;
  std::string first_problem;
};

/// Creates one identity per iteration, retrying the exact same request against
/// a freshly read generation when it is fenced. That is the whole contract a
/// concurrent caller has: state the generation you composed against, and retry
/// if the registry moved.
WriterOutcome create_concurrently(TenantRegistry& registry, std::string_view prefix, std::size_t iterations) {
  WriterOutcome outcome;
  for (std::size_t index = 0; index < iterations; ++index) {
    const std::string identity = std::string{prefix} + "-" + std::to_string(index);
    for (;;) {
      const auto created = registry.create_tenant(tenant_request(registry.generation(), identity));
      if (created) {
        ++outcome.accepted;
        break;
      }
      if (created.error().code() != ErrorCode::StaleGeneration) {
        outcome.unexpected = created.error().code();
        return outcome;
      }
      ++outcome.stale;
    }
    ++outcome.tenants;
  }
  return outcome;
}

}  // namespace

// ---------------------------------------------------------------------------
// Concurrent writers: every accepted mutation advances the generation by one,
// and nothing else does.
// ---------------------------------------------------------------------------

TREG_TEST(concurrency, concurrent_mutations_are_fenced_by_the_generation_counter) {
  EphemeralOptions options;
  options.clock = std::make_shared<FixedClock>(1'700'000'000'000);
  TenantRegistry registry = std::move(TenantRegistry::open_ephemeral(options).value());
  const RegistryGeneration start = registry.generation();

  constexpr std::size_t kThreads = 6;
  constexpr std::size_t kIterations = 6;
  std::vector<WriterOutcome> outcomes(kThreads);
  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (std::size_t index = 0; index < kThreads; ++index) {
    threads.emplace_back([&registry, &outcomes, index] {
      outcomes[index] = create_concurrently(registry, "thread-" + std::to_string(index), kIterations);
    });
  }
  for (std::thread& thread : threads) {
    thread.join();
  }

  std::uint64_t accepted = 0;
  std::uint64_t stale = 0;
  for (const WriterOutcome& outcome : outcomes) {
    TREG_CHECK_EQ(outcome.unexpected, ErrorCode::Unspecified);
    accepted += outcome.accepted;
    stale += outcome.stale;
  }
  TREG_CHECK_EQ(accepted, static_cast<std::uint64_t>(kThreads) * kIterations);

  // The generation is the count of accepted mutations: every accept advanced it
  // by exactly one, no refusal did, and no accept was lost.
  TREG_CHECK_EQ(registry.generation().value(), start.value() + accepted);
  TREG_CHECK_EQ(registry.generation().value(), static_cast<std::uint64_t>(kThreads) * kIterations);

  const RegistrySnapshot snapshot = registry.snapshot();
  TREG_CHECK_EQ(snapshot.generation.value(), registry.generation().value());
  TREG_CHECK_EQ(snapshot.tenants.size(), static_cast<std::size_t>(accepted));
  TREG_CHECK_EQ(snapshot.record_count(), snapshot.tenants.size());

  std::string first_problem;
  const std::size_t problems = snapshot_violations(snapshot, first_problem);
  if (problems != 0) {
    treg_test::report_failure(__FILE__, __LINE__,
                              "the concurrent state violates an invariant: " + first_problem);
  }

  // Every identity a thread believed it had created is present exactly once,
  // and every identity it was refused for is absent.
  for (std::size_t index = 0; index < kThreads; ++index) {
    for (std::size_t iteration = 0; iteration < kIterations; ++iteration) {
      const std::string identity = "thread-" + std::to_string(index) + "-" + std::to_string(iteration);
      const auto found = registry.find_tenant(treg_test::tenant_id(identity));
      TREG_REQUIRE_OK(found);
      TREG_CHECK_EQ(found.value().revision, tenant_registry::RecordRevision::from_value(1));
      TREG_CHECK_EQ(found.value().state, LifecycleState::Declared);
      TREG_CHECK(found.value().created_generation.value() >= 1);
    }
  }
  TREG_CHECK_EQ(registry.list_tenants(TenantQuery{}).value().total_matched,
                static_cast<std::size_t>(accepted));
}

// ---------------------------------------------------------------------------
// Concurrent readers: a snapshot is never a half-applied state.
// ---------------------------------------------------------------------------

TREG_TEST(concurrency, concurrent_readers_never_observe_a_torn_snapshot) {
  EphemeralOptions options;
  options.clock = std::make_shared<FixedClock>(1'700'000'000'000);
  TenantRegistry registry = std::move(TenantRegistry::open_ephemeral(options).value());

  // A tenant every writer attaches to, so that readers see relationships
  // appear while identities are still being created.
  const auto root = registry.create_tenant(tenant_request(registry.generation(), "root"));
  TREG_REQUIRE_OK(root);
  TREG_REQUIRE_OK(registry.transition_subject(TransitionSubjectRequest{
      context(registry.generation()), TenancySubject::of_tenant(root.value().record.id), root.value().record.revision,
      LifecycleState::Active}));

  constexpr std::size_t kWriters = 3;
  constexpr std::size_t kReaders = 3;
  constexpr std::size_t kIdentitiesPerWriter = 4;

  std::atomic<std::size_t> finished{0};
  std::vector<WriterOutcome> writers(kWriters);
  std::vector<ReaderOutcome> readers(kReaders);
  std::vector<std::thread> threads;
  threads.reserve(kWriters + kReaders);

  for (std::size_t index = 0; index < kWriters; ++index) {
    const tenant_registry::TenantId root_id = root.value().record.id;
    threads.emplace_back([&registry, &writers, &finished, root_id, index] {
      WriterOutcome outcome;
      for (std::size_t iteration = 0; iteration < kIdentitiesPerWriter; ++iteration) {
        const std::string identity = "w" + std::to_string(index) + "-" + std::to_string(iteration);
        for (;;) {
          const auto created = registry.create_tenant(tenant_request(registry.generation(), identity));
          if (created) {
            ++outcome.accepted;
            ++outcome.tenants;
            break;
          }
          if (created.error().code() != ErrorCode::StaleGeneration) {
            outcome.unexpected = created.error().code();
            break;
          }
          ++outcome.stale;
        }
        for (;;) {
          const auto record = registry.find_tenant(treg_test::tenant_id(identity));
          if (!record) {
            outcome.unexpected = record.error().code();
            break;
          }
          if (record.value().state == LifecycleState::Active) {
            break;
          }
          const auto activated = registry.transition_subject(TransitionSubjectRequest{
              context(registry.generation()), TenancySubject::of_tenant(record.value().id), record.value().revision,
              LifecycleState::Active});
          if (activated) {
            ++outcome.accepted;
            break;
          }
          if (activated.error().code() != ErrorCode::StaleGeneration &&
              activated.error().code() != ErrorCode::StaleRecordRevision) {
            outcome.unexpected = activated.error().code();
            break;
          }
          ++outcome.stale;
        }
        for (;;) {
          const auto edge = registry.put_ownership(PutOwnershipRequest{
              context(registry.generation()), treg_test::tenant_id(identity), root_id,
              OwnershipKind::Administrative, LifecycleState::Active, std::nullopt});
          if (edge) {
            ++outcome.accepted;
            break;
          }
          if (edge.error().code() != ErrorCode::StaleGeneration &&
              edge.error().code() != ErrorCode::StaleRecordRevision &&
              edge.error().code() != ErrorCode::DuplicateRelationship) {
            outcome.unexpected = edge.error().code();
            break;
          }
          ++outcome.stale;
        }
      }
      writers[index] = outcome;
      finished.fetch_add(1);
    });
  }

  for (std::size_t index = 0; index < kReaders; ++index) {
    threads.emplace_back([&registry, &readers, &finished, index] {
      ReaderOutcome outcome;
      RegistryGeneration previous_generation = RegistryGeneration::initial();
      std::string previous_digest;
      std::size_t previous_tenants = 0;
      bool first = true;
      // Readers stop when the writers are done, but never before they have
      // actually read something, and never after a hard bound, so the loop
      // cannot hold the mutex against the writers forever.
      while ((finished.load() < kWriters || outcome.snapshots < 8) && outcome.snapshots < 500) {
        const RegistrySnapshot snapshot = registry.snapshot();
        ++outcome.snapshots;
        if (!first) {
          // The registry only grows here, so a snapshot may never move
          // backwards, and two snapshots of one generation must be identical.
          if (snapshot.generation.value() < previous_generation.value()) {
            ++outcome.problems;
            if (outcome.first_problem.empty()) {
              outcome.first_problem = "a snapshot reports a generation older than an earlier one";
            }
          }
          if (snapshot.tenants.size() < previous_tenants) {
            ++outcome.problems;
            if (outcome.first_problem.empty()) {
              outcome.first_problem = "a snapshot lost tenants that an earlier one reported";
            }
          }
          if (snapshot.generation.value() == previous_generation.value() &&
              snapshot.digest().to_text() != previous_digest) {
            ++outcome.problems;
            if (outcome.first_problem.empty()) {
              outcome.first_problem = "two snapshots of one generation disagree";
            }
          }
        }
        std::string problem;
        const std::size_t violations = snapshot_violations(snapshot, problem);
        if (violations != 0) {
          outcome.problems += violations;
          if (outcome.first_problem.empty()) {
            outcome.first_problem = std::move(problem);
          }
        }
        previous_generation = snapshot.generation;
        previous_digest = snapshot.digest().to_text();
        previous_tenants = snapshot.tenants.size();
        first = false;
      }
      readers[index] = outcome;
    });
  }

  for (std::thread& thread : threads) {
    thread.join();
  }

  std::uint64_t accepted = 0;
  std::uint64_t created_tenants = 0;
  for (const WriterOutcome& outcome : writers) {
    TREG_CHECK_EQ(outcome.unexpected, ErrorCode::Unspecified);
    accepted += outcome.accepted;
    created_tenants += outcome.tenants;
  }
  TREG_CHECK_EQ(created_tenants, static_cast<std::uint64_t>(kWriters) * kIdentitiesPerWriter);
  for (const ReaderOutcome& outcome : readers) {
    TREG_CHECK(outcome.snapshots > 0);
    if (outcome.problems != 0) {
      treg_test::report_failure(__FILE__, __LINE__, "a reader saw an inconsistent state: " + outcome.first_problem);
    }
  }

  const RegistrySnapshot final_snapshot = registry.snapshot();
  // The root tenant plus every tenant a writer created; the generation is the
  // two root mutations plus every accepted write.
  TREG_CHECK_EQ(final_snapshot.tenants.size(), static_cast<std::size_t>(created_tenants) + 1);
  TREG_CHECK_EQ(final_snapshot.generation.value(), accepted + 2);
  std::string first_problem;
  const std::size_t problems = snapshot_violations(final_snapshot, first_problem);
  if (problems != 0) {
    treg_test::report_failure(__FILE__, __LINE__, "the final state violates an invariant: " + first_problem);
  }
  TREG_CHECK_EQ(registry.list_tenants(TenantQuery{}).value().total_matched,
                final_snapshot.tenants.size());
}

// ---------------------------------------------------------------------------
// A state built concurrently has to reopen: the journal is the only witness.
// ---------------------------------------------------------------------------

TREG_TEST(concurrency, a_concurrently_built_state_reopens_and_revalidates) {
  const TempTree tree{treg_test::make_temp_directory("concurrency-reopen")};
  RegistryGeneration generation_before_close = RegistryGeneration::initial();
  std::string digest_before_close;
  std::size_t tenants_before_close = 0;

  {
    auto opened = TenantRegistry::open(open_request(tree.path(), AccessMode::ReadWrite));
    TREG_REQUIRE_OK(opened);
    TenantRegistry registry = std::move(opened).value();

    const auto root = registry.create_tenant(tenant_request(registry.generation(), "root"));
    TREG_REQUIRE_OK(root);
    TREG_REQUIRE_OK(registry.transition_subject(TransitionSubjectRequest{
        context(registry.generation()), TenancySubject::of_tenant(root.value().record.id),
        root.value().record.revision, LifecycleState::Active}));

    constexpr std::size_t kWriters = 3;
    constexpr std::size_t kIdentitiesPerWriter = 3;
    std::vector<WriterOutcome> writers(kWriters);
    std::vector<std::thread> threads;
    threads.reserve(kWriters);
    for (std::size_t index = 0; index < kWriters; ++index) {
      threads.emplace_back([&registry, &writers, index] {
        WriterOutcome outcome;
        for (std::size_t iteration = 0; iteration < kIdentitiesPerWriter; ++iteration) {
          const std::string identity = "durable-" + std::to_string(index) + "-" + std::to_string(iteration);
          for (;;) {
            const auto created = registry.create_tenant(tenant_request(registry.generation(), identity));
            if (created) {
              ++outcome.accepted;
              break;
            }
            if (created.error().code() != ErrorCode::StaleGeneration) {
              outcome.unexpected = created.error().code();
              break;
            }
            ++outcome.stale;
          }
        }
        writers[index] = outcome;
      });
    }
    for (std::thread& thread : threads) {
      thread.join();
    }
    for (const WriterOutcome& outcome : writers) {
      TREG_CHECK_EQ(outcome.unexpected, ErrorCode::Unspecified);
    }

    const RegistrySnapshot snapshot = registry.snapshot();
    generation_before_close = snapshot.generation;
    digest_before_close = snapshot.digest().to_text();
    tenants_before_close = snapshot.tenants.size();
    TREG_CHECK_EQ(tenants_before_close, static_cast<std::size_t>(kWriters) * kIdentitiesPerWriter + 1);

    // Closing and reopening replays the journal through the same validator a
    // fresh process uses, so an interleaving that produced an impossible state
    // could not survive this.
    TREG_REQUIRE(registry.close().ok());
  }

  {
    auto reopened = TenantRegistry::open(open_request(tree.path(), AccessMode::ReadWrite));
    TREG_REQUIRE_OK(reopened);
    TenantRegistry registry = std::move(reopened).value();
    const RegistrySnapshot snapshot = registry.snapshot();
    TREG_CHECK_EQ(snapshot.generation, generation_before_close);
    TREG_CHECK_EQ(snapshot.tenants.size(), tenants_before_close);
    // The digest is a digest of the tenancy state, so the same records at the
    // same generation are the same state across a restart and across sessions.
    TREG_CHECK_EQ(snapshot.digest().to_text(), digest_before_close);
    std::string first_problem;
    const std::size_t problems = snapshot_violations(snapshot, first_problem);
    if (problems != 0) {
      treg_test::report_failure(__FILE__, __LINE__, "the reopened state violates an invariant: " + first_problem);
    }
    TREG_REQUIRE(registry.close().ok());
  }
}