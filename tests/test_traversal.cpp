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

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "test_support.hpp"

namespace treg_test {
namespace {

using tenant_registry::ErrorCode;
using tenant_registry::OwnershipStep;
using tenant_registry::OwnershipTraversal;
using tenant_registry::OwnershipTraversalRequest;

std::string reached_text(const OwnershipTraversal& traversal) {
  std::string out;
  for (const TenantId& id : traversal.reached) {
    if (!out.empty()) {
      out += ",";
    }
    out += id.value();
  }
  return out;
}

std::string steps_text(const OwnershipTraversal& traversal) {
  std::string out;
  for (const OwnershipStep& step : traversal.steps) {
    if (!out.empty()) {
      out += ",";
    }
    out += step.from.value();
    out += ">";
    out += step.to.value();
    out += "@";
    out += std::to_string(step.depth);
  }
  return out;
}

bool reached_contains(const OwnershipTraversal& traversal, std::string_view id) {
  for (const TenantId& reached : traversal.reached) {
    if (reached.value() == id) {
      return true;
    }
  }
  return false;
}

std::size_t reached_count(const OwnershipTraversal& traversal, std::string_view id) {
  std::size_t count = 0;
  for (const TenantId& reached : traversal.reached) {
    if (reached.value() == id) {
      ++count;
    }
  }
  return count;
}

/// root owns a and b; a owns x; b owns y. Every edge is Operational and Active.
void build_tree(Harness& harness) {
  harness.active_tenant("lonely");
  harness.active_tenant("y");
  harness.active_tenant("root");
  harness.active_tenant("x");
  harness.active_tenant("b");
  harness.active_tenant("a");
  harness.own("b", "root", OwnershipKind::Operational, LifecycleState::Active);
  harness.own("a", "root", OwnershipKind::Operational, LifecycleState::Active);
  harness.own("y", "b", OwnershipKind::Operational, LifecycleState::Active);
  harness.own("x", "a", OwnershipKind::Operational, LifecycleState::Active);
}

TREG_TEST(traversal, descendants_and_ancestors_walk_breadth_first) {
  Harness harness = Harness::ephemeral();
  build_tree(harness);

  const OwnershipTraversal descendants = unwrap(
      harness.registry().traverse_ownership(OwnershipTraversalRequest{tenant_id("root"),
                                                                     TraversalDirection::Descendants,
                                                                     std::nullopt, std::nullopt, 0, 0}),
      "traverse_ownership");
  TREG_CHECK_EQ(reached_text(descendants), std::string{"a,b,x,y"});
  TREG_CHECK_EQ(steps_text(descendants), std::string{"root>a@1,root>b@1,a>x@2,b>y@2"});
  TREG_CHECK_EQ(descendants.max_depth_reached, std::size_t{3});
  TREG_CHECK(!descendants.truncated);
  TREG_CHECK(!descendants.depth_limited);
  TREG_CHECK_EQ(descendants.start, tenant_id("root"));
  TREG_CHECK_EQ(descendants.direction, TraversalDirection::Descendants);

  const OwnershipTraversal ancestors = unwrap(
      harness.registry().traverse_ownership(OwnershipTraversalRequest{tenant_id("x"),
                                                                     TraversalDirection::Ancestors,
                                                                     std::nullopt, std::nullopt, 0, 0}),
      "traverse_ownership");
  TREG_CHECK_EQ(reached_text(ancestors), std::string{"a,root"});
  TREG_CHECK_EQ(steps_text(ancestors), std::string{"x>a@1,a>root@2"});
  TREG_CHECK_EQ(ancestors.max_depth_reached, std::size_t{3});

  // The walk starts where it was told to and does not claim the start as
  // something it reached.
  TREG_CHECK(!reached_contains(descendants, "root"));
  TREG_CHECK(!reached_contains(ancestors, "x"));

  // An isolated tenant is reached by nothing and reaches nothing, without
  // pretending the answer was cut short.
  const OwnershipTraversal alone = unwrap(
      harness.registry().traverse_ownership(OwnershipTraversalRequest{tenant_id("lonely"),
                                                                     TraversalDirection::Descendants,
                                                                     std::nullopt, std::nullopt, 0, 0}),
      "traverse_ownership");
  TREG_CHECK(alone.reached.empty());
  TREG_CHECK(alone.steps.empty());
  TREG_CHECK(!alone.truncated);
  TREG_CHECK(!alone.depth_limited);
}

TREG_TEST(traversal, a_diamond_is_reached_once) {
  Harness harness = Harness::ephemeral();
  harness.active_tenant("root");
  harness.active_tenant("left");
  harness.active_tenant("right");
  harness.active_tenant("shared");
  harness.own("left", "root", OwnershipKind::Operational, LifecycleState::Active);
  harness.own("right", "root", OwnershipKind::Operational, LifecycleState::Active);
  harness.own("shared", "left", OwnershipKind::Operational, LifecycleState::Active);
  harness.own("shared", "right", OwnershipKind::Operational, LifecycleState::Active);

  const OwnershipTraversal traversal = unwrap(
      harness.registry().traverse_ownership(OwnershipTraversalRequest{tenant_id("root"),
                                                                     TraversalDirection::Descendants,
                                                                     std::nullopt, std::nullopt, 0, 0}),
      "traverse_ownership");
  TREG_CHECK_EQ(reached_text(traversal), std::string{"left,right,shared"});
  TREG_CHECK_EQ(reached_count(traversal, "shared"), std::size_t{1});
  // Both paths are reported as steps even though the tenant is reached once.
  TREG_CHECK_EQ(steps_text(traversal), std::string{"root>left@1,root>right@1,left>shared@2,right>shared@2"});

  // Every reached tenant is the target of at least one step.
  for (const TenantId& id : traversal.reached) {
    bool found = false;
    for (const OwnershipStep& step : traversal.steps) {
      found = found || step.to == id;
    }
    TREG_CHECK(found);
  }
}

TREG_TEST(traversal, a_bound_stops_the_walk_and_says_so) {
  Harness harness = Harness::ephemeral();
  build_tree(harness);

  const OwnershipTraversal shallow = unwrap(
      harness.registry().traverse_ownership(OwnershipTraversalRequest{tenant_id("root"),
                                                                     TraversalDirection::Descendants,
                                                                     std::nullopt, std::nullopt, 1, 0}),
      "traverse_ownership");
  TREG_CHECK_EQ(reached_text(shallow), std::string{"a,b"});
  TREG_CHECK_EQ(steps_text(shallow), std::string{"root>a@1,root>b@1"});
  TREG_CHECK(shallow.truncated);
  TREG_CHECK(shallow.depth_limited);

  const OwnershipTraversal narrow = unwrap(
      harness.registry().traverse_ownership(OwnershipTraversalRequest{tenant_id("root"),
                                                                     TraversalDirection::Descendants,
                                                                     std::nullopt, std::nullopt, 0, 1}),
      "traverse_ownership");
  TREG_CHECK_EQ(steps_text(narrow), std::string{"root>a@1"});
  TREG_CHECK_EQ(reached_text(narrow), std::string{"a"});
  TREG_CHECK(narrow.truncated);
  TREG_CHECK(narrow.depth_limited);

  // A bound that does not bite never claims to have bitten.
  const OwnershipTraversal roomy = unwrap(
      harness.registry().traverse_ownership(OwnershipTraversalRequest{tenant_id("root"),
                                                                     TraversalDirection::Descendants,
                                                                     std::nullopt, std::nullopt, 8, 64}),
      "traverse_ownership");
  TREG_CHECK_EQ(reached_text(roomy), std::string{"a,b,x,y"});
  TREG_CHECK(!roomy.truncated);
  TREG_CHECK(!roomy.depth_limited);
}

TREG_TEST(traversal, only_in_force_edges_are_followed) {
  Harness harness = Harness::ephemeral();
  harness.active_tenant("root");
  harness.active_tenant("quiet");
  harness.active_tenant("loud");
  harness.active_tenant("regulatory");
  harness.own("quiet", "root", OwnershipKind::Operational, LifecycleState::Declared);
  harness.own("loud", "root", OwnershipKind::Operational, LifecycleState::Active);
  harness.own("regulatory", "root", OwnershipKind::Regulatory, LifecycleState::Active);

  const OwnershipTraversal everything = unwrap(
      harness.registry().traverse_ownership(OwnershipTraversalRequest{tenant_id("root"),
                                                                     TraversalDirection::Descendants,
                                                                     std::nullopt, std::nullopt, 0, 0}),
      "traverse_ownership");
  TREG_CHECK_EQ(reached_text(everything), std::string{"loud,regulatory"});

  const OwnershipTraversal operational = unwrap(
      harness.registry().traverse_ownership(OwnershipTraversalRequest{tenant_id("root"),
                                                                     TraversalDirection::Descendants,
                                                                     std::optional<OwnershipKind>{
                                                                         OwnershipKind::Operational},
                                                                     std::nullopt, 0, 0}),
      "traverse_ownership");
  TREG_CHECK_EQ(reached_text(operational), std::string{"loud"});

  const OwnershipTraversal only_declared = unwrap(
      harness.registry().traverse_ownership(OwnershipTraversalRequest{tenant_id("root"),
                                                                     TraversalDirection::Descendants,
                                                                     std::nullopt,
                                                                     std::optional<LifecycleState>{
                                                                         LifecycleState::Declared},
                                                                     0, 0}),
      "traverse_ownership");
  TREG_CHECK(only_declared.reached.empty());

  // A declared edge that is made in force becomes walkable.
  const auto promoted = harness.registry().transition_ownership(
      TransitionOwnershipRequest{context(harness.generation()), tenant_id("quiet"), tenant_id("root"),
                                 RecordRevision::from_value(1), LifecycleState::Active});
  TREG_REQUIRE_OK(promoted);
  const OwnershipTraversal after = unwrap(
      harness.registry().traverse_ownership(OwnershipTraversalRequest{tenant_id("root"),
                                                                     TraversalDirection::Descendants,
                                                                     std::optional<OwnershipKind>{
                                                                         OwnershipKind::Operational},
                                                                     std::nullopt, 0, 0}),
      "traverse_ownership");
  TREG_CHECK_EQ(reached_text(after), std::string{"loud,quiet"});
}

TREG_TEST(traversal, a_missing_start_and_an_unspecified_direction_are_refused) {
  Harness harness = Harness::ephemeral();
  build_tree(harness);

  TREG_CHECK_CODE(harness.registry().traverse_ownership(OwnershipTraversalRequest{
                      tenant_id("root"), TraversalDirection::Unspecified, std::nullopt, std::nullopt, 0, 0}),
                  ErrorCode::InvalidEnumValue);
  TREG_CHECK_CODE(harness.registry().traverse_ownership(OwnershipTraversalRequest{
                      tenant_id("ghost"), TraversalDirection::Descendants, std::nullopt, std::nullopt, 0, 0}),
                  ErrorCode::NotFound);
}

TREG_TEST(traversal, a_bound_above_the_configured_maximum_is_refused) {
  Harness harness = Harness::ephemeral();
  build_tree(harness);

  TREG_CHECK_CODE(harness.registry().traverse_ownership(OwnershipTraversalRequest{
                      tenant_id("root"), TraversalDirection::Descendants, std::nullopt, std::nullopt, 33, 0}),
                  ErrorCode::TraversalLimitExceeded);
  TREG_CHECK_CODE(harness.registry().traverse_ownership(OwnershipTraversalRequest{
                      tenant_id("root"), TraversalDirection::Descendants, std::nullopt, std::nullopt, 0, 4097}),
                  ErrorCode::TraversalLimitExceeded);

  // Exactly the configured maximum is allowed, and zero means the maximum.
  const OwnershipTraversal at_the_bound = unwrap(
      harness.registry().traverse_ownership(OwnershipTraversalRequest{tenant_id("root"),
                                                                     TraversalDirection::Descendants,
                                                                     std::nullopt, std::nullopt, 32, 4096}),
      "traverse_ownership");
  TREG_CHECK_EQ(reached_text(at_the_bound), std::string{"a,b,x,y"});
  TREG_CHECK(!at_the_bound.truncated);
}

}  // namespace
}  // namespace treg_test
