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

#include "tenant_registry/lifecycle.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

#include "tenant_registry/errors.hpp"

namespace tenant_registry {

namespace {

struct LifecycleToken {
  LifecycleState state;
  std::string_view token;
};

constexpr std::array<LifecycleToken, 7> kLifecycleTokens = {{
    {LifecycleState::Unspecified, "unspecified"},
    {LifecycleState::Declared, "declared"},
    {LifecycleState::Active, "active"},
    {LifecycleState::Suspended, "suspended"},
    {LifecycleState::Retiring, "retiring"},
    {LifecycleState::Retired, "retired"},
    {LifecycleState::Tombstoned, "tombstoned"},
}};

struct MembershipToken {
  MembershipState state;
  std::string_view token;
};

constexpr std::array<MembershipToken, 5> kMembershipTokens = {{
    {MembershipState::Unspecified, "unspecified"},
    {MembershipState::Proposed, "proposed"},
    {MembershipState::Bound, "bound"},
    {MembershipState::Suspended, "suspended"},
    {MembershipState::Withdrawn, "withdrawn"},
}};

struct EndpointRoleToken {
  EndpointRole role;
  std::string_view token;
};

constexpr std::array<EndpointRoleToken, 3> kEndpointRoleTokens = {{
    {EndpointRole::Unspecified, "unspecified"},
    {EndpointRole::Source, "source"},
    {EndpointRole::Target, "target"},
}};

/// The states in canonical ascending order, which is the order
/// legal_targets_text reports them in.
constexpr std::array<LifecycleState, 6> kOrderedStates = {LifecycleState::Declared, LifecycleState::Active,
                                                          LifecycleState::Suspended, LifecycleState::Retiring,
                                                          LifecycleState::Retired, LifecycleState::Tombstoned};

}  // namespace

std::string_view to_token(LifecycleState state) noexcept {
  for (const LifecycleToken& entry : kLifecycleTokens) {
    if (entry.state == state) {
      return entry.token;
    }
  }
  return std::string_view{};
}

std::string_view to_token(MembershipState state) noexcept {
  for (const MembershipToken& entry : kMembershipTokens) {
    if (entry.state == state) {
      return entry.token;
    }
  }
  return std::string_view{};
}

std::string_view to_token(EndpointRole role) noexcept {
  for (const EndpointRoleToken& entry : kEndpointRoleTokens) {
    if (entry.role == role) {
      return entry.token;
    }
  }
  return std::string_view{};
}

bool parse_lifecycle_state(std::string_view token, LifecycleState& out) noexcept {
  for (const LifecycleToken& entry : kLifecycleTokens) {
    if (entry.token == token) {
      out = entry.state;
      return true;
    }
  }
  return false;
}

bool parse_membership_state(std::string_view token, MembershipState& out) noexcept {
  for (const MembershipToken& entry : kMembershipTokens) {
    if (entry.token == token) {
      out = entry.state;
      return true;
    }
  }
  return false;
}

bool is_terminal(LifecycleState state) noexcept { return state == LifecycleState::Tombstoned; }

bool is_terminal(MembershipState state) noexcept { return state == MembershipState::Withdrawn; }

bool is_in_force(LifecycleState state) noexcept { return state == LifecycleState::Active; }

bool is_in_force(MembershipState state) noexcept { return state == MembershipState::Bound; }

bool admits_new_relationships(LifecycleState state) noexcept {
  // A reservation (Declared) confers nothing, a withdrawal (Retiring) confers
  // nothing, and a suspension keeps what it has without gaining more.
  return state == LifecycleState::Active;
}

bool admits_relationship_target(LifecycleState state) noexcept {
  // Active may be named as a target, and a Suspended identity may still be
  // named as one because suspension is recoverable. Nothing that was never in
  // force, and nothing that is being or has been withdrawn, may be.
  return state == LifecycleState::Active || state == LifecycleState::Suspended;
}

bool is_legal_transition(LifecycleState from, LifecycleState to) noexcept {
  // Declared -> Active, Retired; Active -> Suspended, Retiring;
  // Suspended -> Active, Retiring; Retiring -> Active, Retired;
  // Retired -> Tombstoned; Tombstoned -> none. Unspecified is never a target.
  switch (from) {
    case LifecycleState::Declared:
      return to == LifecycleState::Active || to == LifecycleState::Retired;
    case LifecycleState::Active:
      return to == LifecycleState::Suspended || to == LifecycleState::Retiring;
    case LifecycleState::Suspended:
      return to == LifecycleState::Active || to == LifecycleState::Retiring;
    case LifecycleState::Retiring:
      return to == LifecycleState::Active || to == LifecycleState::Retired;
    case LifecycleState::Retired:
      return to == LifecycleState::Tombstoned;
    case LifecycleState::Tombstoned:
      return false;
    case LifecycleState::Unspecified:
      return false;
  }
  return false;
}

bool is_legal_membership_transition(MembershipState from, MembershipState to) noexcept {
  // Proposed -> Bound, Withdrawn; Bound -> Suspended, Withdrawn;
  // Suspended -> Bound, Withdrawn; Withdrawn -> none.
  switch (from) {
    case MembershipState::Proposed:
      return to == MembershipState::Bound || to == MembershipState::Withdrawn;
    case MembershipState::Bound:
      return to == MembershipState::Suspended || to == MembershipState::Withdrawn;
    case MembershipState::Suspended:
      return to == MembershipState::Bound || to == MembershipState::Withdrawn;
    case MembershipState::Withdrawn:
      return false;
    case MembershipState::Unspecified:
      return false;
  }
  return false;
}

std::string legal_targets_text(LifecycleState from) {
  std::string out;
  for (const LifecycleState target : kOrderedStates) {
    if (!is_legal_transition(from, target)) {
      continue;
    }
    if (!out.empty()) {
      out += ", ";
    }
    out += to_token(target);
  }
  return out;
}

}  // namespace tenant_registry
