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
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "test_support.hpp"

namespace treg_test {
namespace {

/// Re-derives every invariant a registry state must satisfy, from a snapshot
/// alone. It returns an empty string when the state is sound and a description
/// of the first violation otherwise.
///
/// This is the oracle the randomized state machine checks after every single
/// action. It is deliberately independent of the library's own validation so
/// that a defect in one of them cannot hide behind the other.
[[nodiscard]] std::string check_invariants(const RegistrySnapshot& snapshot, const RegistryLimits& limits) {
  std::set<std::string> tenants;
  std::set<std::string> services;
  std::set<std::string> domains;
  std::map<std::string, LifecycleState> tenant_state;

  for (const auto& record : snapshot.tenants) {
    if (!tenants.insert(record.id.value()).second) {
      return "duplicate tenant " + record.id.value();
    }
    if (record.revision.value() < 1) {
      return "tenant " + record.id.value() + " has revision zero";
    }
    tenant_state[record.id.value()] = record.state;
  }
  for (const auto& record : snapshot.services) {
    if (!services.insert(record.id.value()).second) {
      return "duplicate service " + record.id.value();
    }
    if (record.revision.value() < 1) {
      return "service " + record.id.value() + " has revision zero";
    }
  }
  for (const auto& record : snapshot.isolation_domains) {
    if (!domains.insert(record.id.value()).second) {
      return "duplicate isolation domain " + record.id.value();
    }
    if (record.isolation_class == IsolationClass::Unspecified) {
      return "isolation domain " + record.id.value() + " has no class";
    }
  }

  const auto is_terminal_state = [](LifecycleState state) {
    return state == LifecycleState::Retired || state == LifecycleState::Tombstoned;
  };

  std::map<std::string, std::size_t> parents_of_child;
  std::map<std::string, std::vector<std::string>> children_of;
  std::map<std::string, std::size_t> administrative_owner;
  for (const auto& edge : snapshot.ownership_edges) {
    if (tenants.find(edge.child.value()) == tenants.end()) {
      return "ownership edge names a missing child " + edge.child.value();
    }
    if (tenants.find(edge.parent.value()) == tenants.end()) {
      return "ownership edge names a missing parent " + edge.parent.value();
    }
    if (is_terminal_state(tenant_state[edge.child.value()]) ||
        is_terminal_state(tenant_state[edge.parent.value()])) {
      return "ownership edge involves a terminal tenant";
    }
    if (edge.state == LifecycleState::Unspecified || edge.state == LifecycleState::Tombstoned) {
      return "ownership edge has a state a relationship may not have";
    }
    if (edge.child == edge.parent) {
      return "ownership edge is its own parent";
    }
    children_of[edge.child.value()].push_back(edge.parent.value());
    if (is_in_force(edge.state) && edge.kind == OwnershipKind::Administrative) {
      if (++administrative_owner[edge.child.value()] > 1) {
        return "tenant " + edge.child.value() + " has more than one in-force administrative owner";
      }
    }
  }

  // Acyclicity by depth first colouring over the child -> parent adjacency.
  std::map<std::string, int> colour;
  for (const auto& entry : children_of) {
    if (colour[entry.first] == 2) {
      continue;
    }
    std::vector<std::pair<std::string, std::size_t>> stack{{entry.first, 0}};
    colour[entry.first] = 1;
    while (!stack.empty()) {
      auto& [node, index] = stack.back();
      const auto found = children_of.find(node);
      if (found == children_of.end() || index >= found->second.size()) {
        colour[node] = 2;
        stack.pop_back();
        continue;
      }
      const std::string next = found->second[index];
      ++index;
      if (colour[next] == 1) {
        return "ownership graph contains a cycle through " + next;
      }
      if (colour[next] == 2) {
        continue;
      }
      colour[next] = 1;
      stack.emplace_back(next, 0);
    }
  }

  std::set<std::string> in_force_binding;
  for (const auto& binding : snapshot.service_bindings) {
    if (services.find(binding.service.value()) == services.end()) {
      return "service binding names a missing service " + binding.service.value();
    }
    if (tenants.find(binding.tenant.value()) == tenants.end()) {
      return "service binding names a missing tenant " + binding.tenant.value();
    }
    if (binding.kind == BindingKind::Unspecified) {
      return "service binding has no kind";
    }
    if (is_in_force(binding.state)) {
      std::string marker = binding.service.value();
      marker.push_back('|');
      marker.append(std::string{to_token(binding.kind)});
      if (!in_force_binding.insert(marker).second) {
        return "service " + binding.service.value() + " has two in-force " +
               std::string{to_token(binding.kind)} + " bindings";
      }
    }
  }

  std::set<std::string> primary_membership;
  for (const auto& membership : snapshot.isolation_memberships) {
    const std::string subject_key = membership.subject.to_text();
    const bool subject_exists = membership.subject.is_tenant()
                                    ? tenants.find(std::string{membership.subject.identity_value()}) != tenants.end()
                                    : services.find(std::string{membership.subject.identity_value()}) != services.end();
    if (!subject_exists) {
      return "isolation membership names a missing subject " + subject_key;
    }
    if (domains.find(membership.domain.value()) == domains.end()) {
      return "isolation membership names a missing domain " + membership.domain.value();
    }
    if (membership.role == MembershipRole::Unspecified) {
      return "isolation membership has no role";
    }
    if (membership.state == MembershipState::Withdrawn || membership.state == MembershipState::Unspecified) {
      return "isolation membership is stored in a state that must not be stored";
    }
    if (membership.state == MembershipState::Bound && membership.role == MembershipRole::Primary) {
      if (!primary_membership.insert(subject_key).second) {
        return "subject " + subject_key + " has two in-force primary isolation domains";
      }
    }
  }

  // Canonical ordering is part of the contract, not an accident of the
  // container: it is what makes a snapshot digest comparable across runs.
  const auto ascending = [](const auto& collection, const auto& key) {
    for (std::size_t index = 1; index < collection.size(); ++index) {
      if (key(collection[index]) < key(collection[index - 1])) {
        return false;
      }
    }
    return true;
  };
  if (!ascending(snapshot.tenants, [](const TenantRecord& r) { return r.id.value(); })) {
    return "tenants are not in canonical order";
  }
  if (!ascending(snapshot.services, [](const ServiceRecord& r) { return r.id.value(); })) {
    return "services are not in canonical order";
  }
  if (!ascending(snapshot.isolation_domains, [](const IsolationDomainRecord& r) { return r.id.value(); })) {
    return "isolation domains are not in canonical order";
  }
  if (!ascending(snapshot.ownership_edges, [](const OwnershipEdge& e) { return e.natural_key(); })) {
    return "ownership edges are not in canonical order";
  }
  if (!ascending(snapshot.service_bindings, [](const ServiceBinding& b) { return b.natural_key(); })) {
    return "service bindings are not in canonical order";
  }
  if (!ascending(snapshot.isolation_memberships, [](const IsolationMembership& m) { return m.natural_key(); })) {
    return "isolation memberships are not in canonical order";
  }

  if (snapshot.tenants.size() > limits.max_tenants || snapshot.services.size() > limits.max_services ||
      snapshot.isolation_domains.size() > limits.max_isolation_domains ||
      snapshot.ownership_edges.size() > limits.max_ownership_edges ||
      snapshot.service_bindings.size() > limits.max_service_bindings ||
      snapshot.isolation_memberships.size() > limits.max_isolation_memberships) {
    return "a record count is above the configured limit";
  }
  return {};
}

[[nodiscard]] std::string identity_for(Rng& rng, const char* prefix, std::uint32_t space) {
  return std::string{prefix} + "-" + std::to_string(rng.below(space));
}

[[nodiscard]] LifecycleState state_of_any(const SubjectRecord& record) {
  return std::visit([](const auto& stored) { return stored.state; }, record);
}

/// Runs one randomized sequence against one registry and asserts the invariants
/// after every single action.
///
/// The seed is printed before anything else so that a failure is reproducible
/// from the output alone. The action space is deliberately small -- a handful of
/// identity names and a handful of relationship shapes -- because collisions,
/// re-issues and refusals are the interesting behaviour, and a large space would
/// mostly produce actions that never interact.
void run_sequence(std::uint64_t seed, std::size_t actions, std::size_t restart_every) {
  std::printf("property: %s actions=%zu restart_every=%zu\n", seed_text(seed).c_str(), actions, restart_every);

  const auto root = make_temp_directory("property-" + std::to_string(seed));
  RegistryLimits limits;
  Rng rng(seed);

  TenantRegistry registry = unwrap(TenantRegistry::open([&] {
                                     RegistryOpenRequest request;
                                     request.root = root;
                                     request.mode = tenant_registry::AccessMode::ReadWrite;
                                     request.store.limits = limits;
                                     request.clock = std::make_shared<FixedClock>(1'700'000'000'000);
                                     return request;
                                   }()),
                                   "open");

  std::size_t successes = 0;
  std::size_t refusals = 0;

  for (std::size_t step = 0; step < actions; ++step) {
    const RegistryGeneration before = registry.generation();
    const std::uint32_t choice = rng.below(20);
    const std::string tenant_name = identity_for(rng, "t", 8);
    const std::string service_name = identity_for(rng, "s", 5);
    const std::string domain_name = identity_for(rng, "d", 4);
    // One action in eight is deliberately stale: it is composed against a
    // generation that has already passed.
    const bool stale = rng.chance(1, 8);
    const RegistryGeneration expected =
        stale ? RegistryGeneration::from_value(before.value() + 1 + rng.below(3)) : before;

    bool accepted = false;
    switch (choice) {
      case 0:
      case 1: {
        const CreateTenantRequest request{context(expected), tenant_id(tenant_name),
                                          rng.chance(1, 2) ? std::optional<std::string>{"Tenant " + tenant_name}
                                                           : std::nullopt,
                                          rng.chance(1, 3) ? std::optional<PrincipalId>{principal_id("owner-a")}
                                                           : std::nullopt,
                                          tenant_registry::TenancyMetadata{}};
        accepted = registry.create_tenant(request).has_value();
        break;
      }
      case 2: {
        const CreateServiceRequest request{context(expected), service_id(service_name), std::nullopt,
                                           tenant_registry::TenancyMetadata{}};
        accepted = registry.create_service(request).has_value();
        break;
      }
      case 3: {
        const CreateIsolationDomainRequest request{context(expected), domain_id(domain_name),
                                                   IsolationClass::FaultContainment, std::nullopt,
                                                   tenant_registry::TenancyMetadata{}};
        accepted = registry.create_isolation_domain(request).has_value();
        break;
      }
      case 4:
      case 5: {
        const TenancySubject subject = rng.chance(1, 3) ? service_subject(service_name) : tenant_subject(tenant_name);
        auto found = registry.find_subject(subject);
        if (!found) {
          break;
        }
        const auto request = tenant_registry::TransitionSubjectRequest{
            context(expected), subject, revision_of(found.value()),
            rng.chance(1, 4) ? LifecycleState::Suspended : LifecycleState::Active};
        accepted = registry.transition_subject(request).has_value();
        break;
      }
      case 6:
      case 7: {
        auto found = registry.find_tenant(tenant_id(tenant_name));
        if (!found) {
          break;
        }
        const SetOwnerRequest request{context(expected), tenant_id(tenant_name), found.value().revision,
                                      std::optional<PrincipalId>{principal_id("owner-" + std::to_string(rng.below(3)))}};
        accepted = registry.set_owner(request).has_value();
        break;
      }
      case 8: {
        auto found = registry.find_tenant(tenant_id(tenant_name));
        if (!found) {
          break;
        }
        const SetMetadataRequest request{context(expected),
                                         tenant_subject(tenant_name),
                                         found.value().revision,
                                         {},
                                         {entry("zone", "z" + std::to_string(rng.below(4))),
                                          entry("tier", "t" + std::to_string(rng.below(3)))}};
        accepted = registry.set_metadata(request).has_value();
        break;
      }
      case 9:
      case 10: {
        const std::string parent_name = identity_for(rng, "t", 8);
        const PutOwnershipRequest request{
            context(expected), tenant_id(tenant_name), tenant_id(parent_name),
            rng.chance(1, 2) ? OwnershipKind::Administrative : OwnershipKind::Operational,
            rng.chance(1, 2) ? LifecycleState::Active : LifecycleState::Declared, std::nullopt};
        auto outcome = registry.put_ownership(request);
        accepted = outcome.has_value();
        if (outcome && rng.chance(1, 4)) {
          const RemoveOwnershipRequest removal{context(registry.generation()), tenant_id(tenant_name),
                                               tenant_id(parent_name), outcome.value().edge.revision};
          accepted = registry.remove_ownership(removal).has_value();
        }
        break;
      }
      case 11:
      case 12: {
        const PutServiceBindingRequest request{context(expected), service_id(service_name), tenant_id(tenant_name),
                                               BindingKind::OperatedBy,
                                               rng.chance(1, 2) ? LifecycleState::Active
                                                                : LifecycleState::Declared,
                                               std::nullopt};
        auto outcome = registry.put_service_binding(request);
        accepted = outcome.has_value();
        if (outcome && rng.chance(1, 4)) {
          const RemoveServiceBindingRequest removal{context(registry.generation()), service_id(service_name),
                                                    tenant_id(tenant_name), BindingKind::OperatedBy,
                                                    outcome.value().binding.revision};
          accepted = registry.remove_service_binding(removal).has_value();
        }
        break;
      }
      case 13:
      case 14:
      case 15: {
        auto domain = registry.find_isolation_domain(domain_id(domain_name));
        if (!domain) {
          break;
        }
        const TenancySubject subject = rng.chance(1, 3) ? service_subject(service_name) : tenant_subject(tenant_name);
        const PutIsolationMembershipRequest request{
            context(expected), subject, domain_id(domain_name),
            rng.chance(1, 4) ? MembershipRole::Secondary : MembershipRole::Primary,
            MembershipState::Bound, domain.value().membership_generation, std::nullopt};
        auto outcome = registry.put_isolation_membership(request);
        accepted = outcome.has_value();
        if (outcome && rng.chance(1, 3)) {
          const RemoveIsolationMembershipRequest removal{context(registry.generation()), subject, domain_id(domain_name),
                                                         outcome.value().membership.revision,
                                                         outcome.value().domain_generation};
          accepted = registry.remove_isolation_membership(removal).has_value();
        }
        break;
      }
      case 16: {
        auto found = registry.find_tenant(tenant_id(tenant_name));
        if (!found) {
          break;
        }
        const auto request = tenant_registry::TransitionSubjectRequest{context(expected), tenant_subject(tenant_name),
                                                                      found.value().revision,
                                                                      LifecycleState::Retiring};
        accepted = registry.transition_subject(request).has_value();
        break;
      }
      case 17: {
        auto found = registry.find_tenant(tenant_id(tenant_name));
        if (!found || found.value().state != LifecycleState::Retired) {
          break;
        }
        const TombstoneRequest request{context(expected),
                                       tenant_subject(tenant_name),
                                       found.value().revision,
                                       tenant_registry::IrreversibleAcknowledgement::acknowledged(),
                                       std::nullopt,
                                       std::string{"fenced by a property run"}};
        accepted = registry.tombstone(request).has_value();
        break;
      }
      case 18: {
        // A read never changes anything, and it must always see a sound state.
        (void)registry.stats();
        (void)registry.snapshot();
        break;
      }
      default: {
        // A listing with a filter is a read too, and it must not change state.
        TenantQuery query;
        query.limit = 4;
        (void)registry.list_tenants(query);
        break;
      }
    }

    if (accepted) {
      ++successes;
      if (registry.generation().value() != before.value() + 1) {
        fail_now("an accepted action did not advance the generation by exactly one at step " +
                 std::to_string(step));
      }
    } else {
      ++refusals;
      if (registry.generation() != before) {
        fail_now("a refused action changed the generation at step " + std::to_string(step));
      }
    }

    const RegistrySnapshot snapshot = registry.snapshot();
    const std::string violation = check_invariants(snapshot, limits);
    if (!violation.empty()) {
      fail_now("invariant violated at step " + std::to_string(step) + ": " + violation);
    }

    if (restart_every != 0 && step != 0 && step % restart_every == 0) {
      const std::string digest = snapshot.digest().to_text();
      const RegistryGeneration generation = registry.generation();
      require_ok(registry.close(), "close");
      registry = unwrap(TenantRegistry::open([&] {
                          RegistryOpenRequest request;
                          request.root = root;
                          request.mode = tenant_registry::AccessMode::ReadWrite;
                          request.store.limits = limits;
                          request.clock = std::make_shared<FixedClock>(1'700'000'000'000);
                          return request;
                        }()),
                        "reopen");
      if (registry.generation() != generation || registry.snapshot().digest().to_text() != digest) {
        fail_now("a restart changed the state at step " + std::to_string(step));
      }
    }
  }

  std::printf("property: %s accepted=%zu refused=%zu final_generation=%llu digest=%s\n",
              seed_text(seed).c_str(), successes, refusals,
              static_cast<unsigned long long>(registry.generation().value()),
              registry.snapshot().digest().to_text().c_str());
  require_ok(registry.close(), "close");
  remove_tree(root);
}

}  // namespace

TREG_TEST(property, randomized_sequences_hold_every_invariant) {
  // Bounded on purpose: the suite must finish quickly and every seed must be
  // printable, so a failure is reproducible from the output alone.
  for (std::uint64_t seed : {1ull, 2ull, 3ull, 4ull}) {
    run_sequence(seed, 140, 17);
  }
}

TREG_TEST(property, the_same_seed_produces_the_same_state_every_time) {
  const auto render = [](std::uint64_t seed) {
    const auto root = make_temp_directory("property-determinism-" + std::to_string(seed));
    RegistryLimits limits;
    Rng rng(seed);
    TenantRegistry registry = unwrap(TenantRegistry::open([&] {
                                       RegistryOpenRequest request;
                                       request.root = root;
                                       request.mode = tenant_registry::AccessMode::ReadWrite;
                                       request.store.limits = limits;
                                       request.clock = std::make_shared<FixedClock>(1'700'000'000'000);
                                       return request;
                                     }()),
                                     "open");
    for (std::size_t step = 0; step < 60; ++step) {
      const RegistryGeneration before = registry.generation();
      const std::string name = identity_for(rng, "t", 4);
      switch (rng.below(4)) {
        case 0: {
          const CreateTenantRequest request{context(before), tenant_id(name), std::nullopt, std::nullopt,
                                            tenant_registry::TenancyMetadata{}};
          (void)registry.create_tenant(request);
          break;
        }
        case 1: {
          auto found = registry.find_tenant(tenant_id(name));
          if (found) {
            (void)registry.transition_subject(tenant_registry::TransitionSubjectRequest{
                context(before), tenant_subject(name), found.value().revision, LifecycleState::Active});
          }
          break;
        }
        case 2: {
          const PutOwnershipRequest request{context(before), tenant_id(name), tenant_id(identity_for(rng, "t", 4)),
                                            OwnershipKind::Administrative, LifecycleState::Active, std::nullopt};
          (void)registry.put_ownership(request);
          break;
        }
        default: {
          TenantQuery query;
          query.limit = 3;
          (void)registry.list_tenants(query);
          break;
        }
      }
    }
    const std::string digest = registry.snapshot().digest().to_text();
    require_ok(registry.close(), "close");
    remove_tree(root);
    return digest;
  };

  for (std::uint64_t seed : {11ull, 12ull}) {
    const std::string first = render(seed);
    const std::string second = render(seed);
    std::printf("property: %s digest=%s\n", seed_text(seed).c_str(), first.c_str());
    TREG_CHECK_EQ(first, second);
  }
}

TREG_TEST(property, a_refusal_never_changes_the_state) {
  Harness harness = Harness::ephemeral();
  harness.active_tenant("acme");
  const std::string before = harness.snapshot().digest().to_text();
  const RegistryGeneration generation = harness.generation();

  // A batch of refusals of every shape the state machine can produce. Each one
  // must leave the state byte for byte identical.
  for (int index = 0; index < 40; ++index) {
    const RegistryGeneration stale = RegistryGeneration::from_value(generation.value() + 1);
    const CreateTenantRequest stale_create{context(stale), tenant_id("acme"), std::nullopt, std::nullopt,
                                           tenant_registry::TenancyMetadata{}};
    TREG_CHECK_CODE(harness.registry().create_tenant(stale_create), tenant_registry::ErrorCode::StaleGeneration);

    const CreateTenantRequest duplicate{context(generation), tenant_id("acme"), std::nullopt, std::nullopt,
                                        tenant_registry::TenancyMetadata{}};
    TREG_CHECK_CODE(harness.registry().create_tenant(duplicate), tenant_registry::ErrorCode::IdentityAlreadyExists);

    const PutOwnershipRequest missing{context(generation), tenant_id("acme"), tenant_id("nowhere"),
                                      OwnershipKind::Administrative, LifecycleState::Active, std::nullopt};
    TREG_CHECK_CODE(harness.registry().put_ownership(missing), tenant_registry::ErrorCode::NotFound);

    const PutServiceBindingRequest unbound{context(generation), service_id("nope"), tenant_id("acme"),
                                           BindingKind::OperatedBy, LifecycleState::Active, std::nullopt};
    TREG_CHECK_CODE(harness.registry().put_service_binding(unbound), tenant_registry::ErrorCode::NotFound);
  }

  TREG_CHECK_EQ(harness.generation(), generation);
  TREG_CHECK_EQ(harness.snapshot().digest().to_text(), before);
}

}  // namespace treg_test
