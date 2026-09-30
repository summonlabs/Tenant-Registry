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

// Example 02: the ownership tree.
//
// Four tenants are declared and admitted, ownership edges are declared between
// them, and the tree is walked in both directions. The transcript then shows
// the rule that a tenant has exactly one in-force administrative owner, and
// shows an attempt to close a cycle refused.

#include <optional>
#include <string>
#include <string_view>

#include "support.hpp"

namespace tr = tenant_registry;
using namespace treg_examples;

int main() {
  StepPrinter step{"02 the ownership tree"};

  step("open an ephemeral registry");
  tr::TenantRegistry registry =
      required(tr::TenantRegistry::open_ephemeral(ephemeral_options()), "open an ephemeral registry");

  // Declares one tenant and admits it in the same step, so the tree below is
  // built from tenants that are in force and may therefore own and be owned.
  const auto declare_and_admit = [&registry](std::string_view name) {
    const tr::TenantId id = tenant(name);
    const tr::CreateTenantOutcome created = required(
        registry.create_tenant(tr::CreateTenantRequest{context(registry.generation()), id,
                                                       std::string{name}, std::nullopt,
                                                       tr::TenancyMetadata{}}),
        "declare a tenant");
    required_ok(registry.transition_subject(tr::TransitionSubjectRequest{context(registry.generation()),
                                                                        tr::TenancySubject::of_tenant(id),
                                                                        created.record.revision,
                                                                        tr::LifecycleState::Active}),
                "admit a tenant");
    return id;
  };

  step("declare and admit four tenants");
  const tr::TenantId facility = declare_and_admit("facility");
  const tr::TenantId building_a = declare_and_admit("building-a");
  const tr::TenantId building_b = declare_and_admit("building-b");
  const tr::TenantId floor_1 = declare_and_admit("floor-1");
  step.note(field("generation", registry.generation().value()) + " " +
            field("tenants", registry.stats().tenants));

  step("declare ownership: floor-1 is operated by building-a");
  const tr::PutOwnershipOutcome operated = required(
      registry.put_ownership(tr::PutOwnershipRequest{context(registry.generation()), floor_1, building_a,
                                                     tr::OwnershipKind::Operational,
                                                     tr::LifecycleState::Active, std::nullopt}),
      "declare an operational ownership edge");
  step.note(field("edge", operated.edge.natural_key()) + " " +
            field("kind", tr::to_token(operated.edge.kind)) + " " +
            field("state", tr::to_token(operated.edge.state)) + " " +
            field("revision", operated.edge.revision.value()));

  step("declare ownership: the facility administers building-a");
  const tr::PutOwnershipOutcome administered = required(
      registry.put_ownership(tr::PutOwnershipRequest{context(registry.generation()), building_a, facility,
                                                     tr::OwnershipKind::Administrative,
                                                     tr::LifecycleState::Active, std::nullopt}),
      "declare an administrative ownership edge");
  step.note(field("edge", administered.edge.natural_key()) + " " +
            field("kind", tr::to_token(administered.edge.kind)) + " " +
            field("state", tr::to_token(administered.edge.state)) + " " +
            field("revision", administered.edge.revision.value()));

  step("declare ownership: the facility operates building-b");
  const tr::PutOwnershipOutcome operated_b = required(
      registry.put_ownership(tr::PutOwnershipRequest{context(registry.generation()), building_b, facility,
                                                     tr::OwnershipKind::Operational,
                                                     tr::LifecycleState::Active, std::nullopt}),
      "declare an operational ownership edge");
  step.note(field("edge", operated_b.edge.natural_key()) + " " +
            field("kind", tr::to_token(operated_b.edge.kind)) + " " +
            field("state", tr::to_token(operated_b.edge.state)) + " " +
            field("revision", operated_b.edge.revision.value()));
  step.note(field("generation", registry.generation().value()) + " " +
            field("ownership_edges", registry.stats().ownership_edges));

  step("walk descendants from facility, breadth first");
  const tr::OwnershipTraversal descendants = required(
      registry.traverse_ownership(tr::OwnershipTraversalRequest{facility, tr::TraversalDirection::Descendants,
                                                                std::nullopt, std::nullopt, 0, 0}),
      "traverse descendants of facility");
  step.note(field("reached", static_cast<std::uint64_t>(descendants.reached.size())) + " " +
            field("steps", static_cast<std::uint64_t>(descendants.steps.size())) + " " +
            field("max_depth_reached", static_cast<std::uint64_t>(descendants.max_depth_reached)) + " " +
            field("truncated", yes_no(descendants.truncated)));
  for (const tr::TenantId& reached : descendants.reached) {
    step.note("reached " + reached.to_text());
  }
  for (const tr::OwnershipStep& walked : descendants.steps) {
    step.note("step " + walked.from.to_text() + " -> " + walked.to.to_text() + " " +
              field("kind", tr::to_token(walked.kind)) + " " + field("state", tr::to_token(walked.state)) + " " +
              field("depth", static_cast<std::uint64_t>(walked.depth)));
  }

  step("walk ancestors from floor-1, breadth first");
  const tr::OwnershipTraversal ancestors = required(
      registry.traverse_ownership(tr::OwnershipTraversalRequest{floor_1, tr::TraversalDirection::Ancestors,
                                                                std::nullopt, std::nullopt, 0, 0}),
      "traverse ancestors of floor-1");
  step.note(field("reached", static_cast<std::uint64_t>(ancestors.reached.size())) + " " +
            field("steps", static_cast<std::uint64_t>(ancestors.steps.size())) + " " +
            field("truncated", yes_no(ancestors.truncated)));
  for (const tr::TenantId& reached : ancestors.reached) {
    step.note("reached " + reached.to_text());
  }

  step("try to make building-b the in-force administrative owner of building-a");
  const tr::Result<tr::PutOwnershipOutcome> second_owner = registry.put_ownership(
      tr::PutOwnershipRequest{context(registry.generation()), building_a, building_b,
                              tr::OwnershipKind::Administrative, tr::LifecycleState::Active, std::nullopt});
  if (second_owner.has_value()) {
    fail("a second in-force administrative owner of building-a was accepted");
  }
  step.note("refused: " + refusal_text(second_owner.error()));
  const tr::Explanation explained = required(
      registry.explain(tr::TenancySubject::of_tenant(building_a)), "explain tenant building-a");
  step.note(field("lineage", static_cast<std::uint64_t>(explained.ownership_lineage.size())) + " " +
            field("owns", static_cast<std::uint64_t>(explained.owns.size())) + " " +
            field("owned_by", static_cast<std::uint64_t>(explained.owned_by.size())));
  for (const tr::TenantId& ancestor : explained.ownership_lineage) {
    step.note("lineage " + ancestor.to_text());
  }

  step("try to make facility a child of floor-1, which would close a cycle");
  const tr::Result<tr::PutOwnershipOutcome> cycle = registry.put_ownership(
      tr::PutOwnershipRequest{context(registry.generation()), facility, floor_1,
                              tr::OwnershipKind::Operational, tr::LifecycleState::Active, std::nullopt});
  if (cycle.has_value()) {
    fail("an ownership edge that closes a cycle was accepted");
  }
  step.note("refused: " + refusal_text(cycle.error()));

  step("list every ownership edge in canonical order");
  const tr::Page<tr::OwnershipEdge> edges =
      required(registry.list_ownership(tr::OwnershipQuery{}), "list ownership edges");
  step.note(field("total_matched", static_cast<std::uint64_t>(edges.total_matched)) + " " +
            field("truncated", yes_no(edges.truncated)));
  for (const tr::OwnershipEdge& edge : edges.items) {
    step.note(field("edge", edge.natural_key()) + " " + field("kind", tr::to_token(edge.kind)) + " " +
              field("state", tr::to_token(edge.state)) + " " + field("revision", edge.revision.value()));
  }

  return 0;
}
