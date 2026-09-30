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

#ifndef TENANT_REGISTRY_LIFECYCLE_HPP
#define TENANT_REGISTRY_LIFECYCLE_HPP

#include <cstdint>
#include <string>
#include <string_view>

#include "tenant_registry/errors.hpp"

namespace tenant_registry {

/// The lifecycle of a registered facility identity.
///
/// One enum is used for tenants, services and isolation domains on purpose.
/// Their lifecycles are *the same lifecycle*: an identity is declared, it is
/// admitted, it can be taken out of force, it is withdrawn, and it is finally
/// fenced forever. Three copies of that enum would drift, and a drift between
/// two lifecycles that are supposed to agree is exactly the kind of silent
/// disagreement this registry exists to prevent. The kinds are kept apart where
/// the confusion would actually be dangerous: in the identity types, which are
/// distinct classes and cannot be interchanged.
///
/// Unspecified exists so that a zero-initialized byte, a truncated field or a
/// missing value can never decode as a legal state. It is never a legal target
/// of a transition and never a legal state of a live record.
enum class LifecycleState : std::uint8_t {
  Unspecified = 0,

  /// Registered and reserved. The identity exists, is unique, and confers
  /// nothing: it may not own, may not be bound, and may not be a member of an
  /// isolation domain.
  Declared = 1,

  /// Admitted and in force. Only an Active identity may own, be owned, be
  /// bound, or hold isolation domain membership.
  Active = 2,

  /// In force previously, deliberately not in force now, recoverable. A
  /// Suspended identity keeps its relationships but may not gain new ones.
  Suspended = 3,

  /// Being withdrawn. No new relationships may be formed, and existing
  /// relationships must be removed before the identity can be retired. A
  /// Retiring identity is not a usable authority for anything.
  Retiring = 4,

  /// Withdrawn. The record remains, permanently readable, and the identity may
  /// never be reused. It is not yet a tombstone: a tombstone is the stronger,
  /// explicit, irreversible statement that also decides whether any successor
  /// may ever take the identity's place.
  Retired = 5,

  /// Fenced forever. The strongest statement this registry can make about an
  /// identity. Only reachable from Retired with an explicit acknowledgement.
  Tombstoned = 6,
};

/// The membership lifecycle of one subject in one isolation domain. It is a
/// different lifecycle from the subject's own: a subject can be Active while a
/// particular membership is only Proposed, and a membership can be Withdrawn
/// while the subject remains Active.
enum class MembershipState : std::uint8_t {
  Unspecified = 0,

  /// Declared, not yet in force. A proposed membership is visible and is
  /// queryable, but it asserts no isolation. Observation of a proposal is not
  /// evidence of isolation.
  Proposed = 1,

  /// In force. The subject is a member of the domain as of the domain's
  /// generation.
  Bound = 2,

  /// In force previously, not in force now, recoverable.
  Suspended = 3,

  /// Terminal. The membership no longer exists for any purpose; the record is
  /// removed from state when it is withdrawn.
  Withdrawn = 4,
};

/// Which of a relationship's endpoints is being described. Used by diagnostics
/// so a refusal can name the exact end that failed validation.
enum class EndpointRole : std::uint8_t {
  Unspecified = 0,
  Source = 1,
  Target = 2,
};

[[nodiscard]] std::string_view to_token(LifecycleState state) noexcept;
[[nodiscard]] std::string_view to_token(MembershipState state) noexcept;
[[nodiscard]] std::string_view to_token(EndpointRole role) noexcept;

/// Parses a token exactly. False when the token is unknown; unknown enum values
/// are never mapped onto a default, because a default would turn an
/// unrecognized durable value into a recognized one.
[[nodiscard]] bool parse_lifecycle_state(std::string_view token, LifecycleState& out) noexcept;
[[nodiscard]] bool parse_membership_state(std::string_view token, MembershipState& out) noexcept;

/// True when the state admits no further transition at all.
[[nodiscard]] bool is_terminal(LifecycleState state) noexcept;
[[nodiscard]] bool is_terminal(MembershipState state) noexcept;

/// True when the state means "in force right now". Only Active is in force:
/// Declared, Suspended, Retiring, Retired and Tombstoned are all not, and none
/// of them may be treated as if they were.
[[nodiscard]] bool is_in_force(LifecycleState state) noexcept;
[[nodiscard]] bool is_in_force(MembershipState state) noexcept;

/// True when the state may be the source of a relationship. Declared and
/// Retiring may not: a reservation confers nothing and a withdrawal confers
/// nothing.
[[nodiscard]] bool admits_new_relationships(LifecycleState state) noexcept;

/// True when the identity may still be the target of a relationship. A
/// Suspended tenant may still be named as an owner target, because suspension
/// is recoverable; a Retiring or Retired one may not.
[[nodiscard]] bool admits_relationship_target(LifecycleState state) noexcept;

/// The legal lifecycle transitions, defined in exactly one place.
///
/// Legal transitions:
///   Declared   -> Active, Retired
///   Active     -> Suspended, Retiring
///   Suspended  -> Active, Retiring
///   Retiring   -> Active, Retired
///   Retired    -> Tombstoned
///   Tombstoned -> (none)
///
/// Retiring -> Active is legal and deliberate: an operator who starts a
/// withdrawal may stop it before it completes, and the registry must be able to
/// record that honestly rather than forcing the identity into retirement.
[[nodiscard]] bool is_legal_transition(LifecycleState from, LifecycleState to) noexcept;

/// The legal membership transitions, defined in exactly one place.
///
/// Legal transitions:
///   Proposed  -> Bound, Withdrawn
///   Bound     -> Suspended, Withdrawn
///   Suspended -> Bound, Withdrawn
///   Withdrawn -> (none)
[[nodiscard]] bool is_legal_membership_transition(MembershipState from, MembershipState to) noexcept;

/// Every state a subject may still legally reach from the given state, in
/// canonical order. Used by diagnostics so a refusal can say what would have
/// been legal.
[[nodiscard]] std::string legal_targets_text(LifecycleState from);

}  // namespace tenant_registry

#endif  // TENANT_REGISTRY_LIFECYCLE_HPP
