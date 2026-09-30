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
#include <cstdint>
#include <string>
#include <string_view>

#include "test_support.hpp"

namespace treg_test {
namespace {

using tenant_registry::admits_new_relationships;
using tenant_registry::admits_relationship_target;
using tenant_registry::EndpointRole;
using tenant_registry::ErrorCode;
using tenant_registry::is_in_force;
using tenant_registry::is_legal_membership_transition;
using tenant_registry::is_legal_transition;
using tenant_registry::is_terminal;
using tenant_registry::legal_targets_text;
using tenant_registry::parse_lifecycle_state;
using tenant_registry::parse_membership_state;
using tenant_registry::to_token;

constexpr LifecycleState kAllStates[] = {
    LifecycleState::Unspecified, LifecycleState::Declared,   LifecycleState::Active,
    LifecycleState::Suspended,   LifecycleState::Retiring,   LifecycleState::Retired,
    LifecycleState::Tombstoned,
};

constexpr std::size_t kStateCount = sizeof(kAllStates) / sizeof(kAllStates[0]);

constexpr MembershipState kAllMembershipStates[] = {
    MembershipState::Unspecified, MembershipState::Proposed, MembershipState::Bound,
    MembershipState::Suspended,   MembershipState::Withdrawn,
};

constexpr std::size_t kMembershipStateCount =
    sizeof(kAllMembershipStates) / sizeof(kAllMembershipStates[0]);

struct LifecyclePair {
  LifecycleState from;
  LifecycleState to;
};

/// The complete table from lifecycle.hpp, spelled once. Every other pair in the
/// 7 by 7 matrix is illegal and must be refused.
constexpr LifecyclePair kLegalLifecycleTransitions[] = {
    {LifecycleState::Declared, LifecycleState::Active},
    {LifecycleState::Declared, LifecycleState::Retired},
    {LifecycleState::Active, LifecycleState::Suspended},
    {LifecycleState::Active, LifecycleState::Retiring},
    {LifecycleState::Suspended, LifecycleState::Active},
    {LifecycleState::Suspended, LifecycleState::Retiring},
    {LifecycleState::Retiring, LifecycleState::Active},
    {LifecycleState::Retiring, LifecycleState::Retired},
    {LifecycleState::Retired, LifecycleState::Tombstoned},
};

struct MembershipPair {
  MembershipState from;
  MembershipState to;
};

constexpr MembershipPair kLegalMembershipTransitions[] = {
    {MembershipState::Proposed, MembershipState::Bound},
    {MembershipState::Proposed, MembershipState::Withdrawn},
    {MembershipState::Bound, MembershipState::Suspended},
    {MembershipState::Bound, MembershipState::Withdrawn},
    {MembershipState::Suspended, MembershipState::Bound},
    {MembershipState::Suspended, MembershipState::Withdrawn},
};

bool is_listed_lifecycle_pair(LifecycleState from, LifecycleState to) {
  for (const LifecyclePair& pair : kLegalLifecycleTransitions) {
    if (pair.from == from && pair.to == to) {
      return true;
    }
  }
  return false;
}

bool is_listed_membership_pair(MembershipState from, MembershipState to) {
  for (const MembershipPair& pair : kLegalMembershipTransitions) {
    if (pair.from == from && pair.to == to) {
      return true;
    }
  }
  return false;
}

}  // namespace

TREG_TEST(lifecycle, every_legal_transition_is_accepted_and_every_illegal_one_refused) {
  for (std::size_t left = 0; left < kStateCount; ++left) {
    for (std::size_t right = 0; right < kStateCount; ++right) {
      const LifecycleState from = kAllStates[left];
      const LifecycleState to = kAllStates[right];
      TREG_CHECK_EQ(is_legal_transition(from, to), is_listed_lifecycle_pair(from, to));
    }
  }
  for (const LifecyclePair& pair : kLegalLifecycleTransitions) {
    TREG_CHECK(is_legal_transition(pair.from, pair.to));
    // A legal transition never lands on Unspecified and never stays put.
    TREG_CHECK(pair.to != LifecycleState::Unspecified);
    TREG_CHECK(pair.from != pair.to);
  }
  // Nothing is reachable from Tombstoned, and Unspecified is never a source.
  for (const LifecycleState target : kAllStates) {
    TREG_CHECK(!is_legal_transition(LifecycleState::Tombstoned, target));
    TREG_CHECK(!is_legal_transition(LifecycleState::Unspecified, target));
  }
  // Declared, Retired and Tombstoned can never be reached from Active directly.
  TREG_CHECK(!is_legal_transition(LifecycleState::Active, LifecycleState::Declared));
  TREG_CHECK(!is_legal_transition(LifecycleState::Active, LifecycleState::Retired));
  TREG_CHECK(!is_legal_transition(LifecycleState::Active, LifecycleState::Tombstoned));
  TREG_CHECK(!is_legal_transition(LifecycleState::Active, LifecycleState::Active));
}

TREG_TEST(lifecycle, terminal_and_in_force_predicates) {
  for (const LifecycleState state : kAllStates) {
    TREG_CHECK_EQ(is_terminal(state), state == LifecycleState::Tombstoned);
    TREG_CHECK_EQ(is_in_force(state), state == LifecycleState::Active);
    TREG_CHECK_EQ(admits_new_relationships(state), state == LifecycleState::Active);
    TREG_CHECK_EQ(admits_relationship_target(state),
                  state == LifecycleState::Active || state == LifecycleState::Suspended);
  }
  // Terminal implies not in force and not a source; the two predicates must
  // never disagree about a state that a caller is about to act on.
  for (const LifecycleState state : kAllStates) {
    if (is_terminal(state)) {
      TREG_CHECK(!is_in_force(state));
      TREG_CHECK(!admits_new_relationships(state));
    }
  }
  // A reservation confers nothing and a withdrawal confers nothing.
  TREG_CHECK(!admits_new_relationships(LifecycleState::Declared));
  TREG_CHECK(!admits_new_relationships(LifecycleState::Retiring));
  TREG_CHECK(!admits_relationship_target(LifecycleState::Declared));
  TREG_CHECK(!admits_relationship_target(LifecycleState::Retiring));
  TREG_CHECK(!admits_relationship_target(LifecycleState::Retired));
  TREG_CHECK(admits_relationship_target(LifecycleState::Suspended));

  for (const MembershipState state : kAllMembershipStates) {
    TREG_CHECK_EQ(is_terminal(state), state == MembershipState::Withdrawn);
    TREG_CHECK_EQ(is_in_force(state), state == MembershipState::Bound);
  }
  TREG_CHECK(is_terminal(MembershipState::Withdrawn));
  TREG_CHECK(!is_terminal(MembershipState::Suspended));
  TREG_CHECK(!is_in_force(MembershipState::Proposed));
  TREG_CHECK(!is_in_force(MembershipState::Suspended));
}

TREG_TEST(lifecycle, legal_targets_text_lists_targets_in_canonical_order) {
  TREG_CHECK_EQ(legal_targets_text(LifecycleState::Unspecified), std::string{});
  TREG_CHECK_EQ(legal_targets_text(LifecycleState::Declared), std::string{"active, retired"});
  TREG_CHECK_EQ(legal_targets_text(LifecycleState::Active), std::string{"suspended, retiring"});
  TREG_CHECK_EQ(legal_targets_text(LifecycleState::Suspended), std::string{"active, retiring"});
  TREG_CHECK_EQ(legal_targets_text(LifecycleState::Retiring), std::string{"active, retired"});
  TREG_CHECK_EQ(legal_targets_text(LifecycleState::Retired), std::string{"tombstoned"});
  TREG_CHECK_EQ(legal_targets_text(LifecycleState::Tombstoned), std::string{});

  // The rendered list names exactly the legal targets, and the order is the
  // canonical state order rather than an enumeration accident.
  for (const LifecycleState from : kAllStates) {
    const std::string text = legal_targets_text(from);
    std::size_t named = 0;
    std::size_t position = 0;
    while (position <= text.size() && !text.empty()) {
      const std::size_t comma = text.find(", ", position);
      const std::string token =
          comma == std::string::npos ? text.substr(position) : text.substr(position, comma - position);
      LifecycleState parsed = LifecycleState::Unspecified;
      TREG_CHECK(parse_lifecycle_state(token, parsed));
      TREG_CHECK(is_legal_transition(from, parsed));
      ++named;
      if (comma == std::string::npos) {
        break;
      }
      position = comma + 2;
    }
    TREG_CHECK_EQ(named, static_cast<std::size_t>(is_terminal(from) || from == LifecycleState::Unspecified
                                                       ? 0
                                                       : (from == LifecycleState::Retired ? 1 : 2)));
  }
}

TREG_TEST(lifecycle, membership_transition_table_is_exhaustive) {
  for (std::size_t left = 0; left < kMembershipStateCount; ++left) {
    for (std::size_t right = 0; right < kMembershipStateCount; ++right) {
      const MembershipState from = kAllMembershipStates[left];
      const MembershipState to = kAllMembershipStates[right];
      TREG_CHECK_EQ(is_legal_membership_transition(from, to), is_listed_membership_pair(from, to));
    }
  }
  for (const MembershipState target : kAllMembershipStates) {
    TREG_CHECK(!is_legal_membership_transition(MembershipState::Withdrawn, target));
    TREG_CHECK(!is_legal_membership_transition(MembershipState::Unspecified, target));
  }
  TREG_CHECK(!is_legal_membership_transition(MembershipState::Proposed, MembershipState::Proposed));
  TREG_CHECK(!is_legal_membership_transition(MembershipState::Bound, MembershipState::Proposed));
  // The membership lifecycle is not the subject lifecycle: a membership that
  // was never in force cannot become Suspended, and a membership that was
  // withdrawn can never come back.
  TREG_CHECK(!is_legal_membership_transition(MembershipState::Proposed, MembershipState::Suspended));
  TREG_CHECK(!is_legal_membership_transition(MembershipState::Withdrawn, MembershipState::Bound));
  TREG_CHECK(is_legal_membership_transition(MembershipState::Proposed, MembershipState::Bound));
}

TREG_TEST(lifecycle, token_round_trips_and_unknown_tokens_are_refused) {
  struct LifecycleTokenRow {
    LifecycleState state;
    std::string_view token;
  };
  constexpr LifecycleTokenRow kLifecycleTokens[] = {
      {LifecycleState::Unspecified, "unspecified"}, {LifecycleState::Declared, "declared"},
      {LifecycleState::Active, "active"},           {LifecycleState::Suspended, "suspended"},
      {LifecycleState::Retiring, "retiring"},       {LifecycleState::Retired, "retired"},
      {LifecycleState::Tombstoned, "tombstoned"},
  };
  for (const LifecycleTokenRow& row : kLifecycleTokens) {
    TREG_CHECK_EQ(to_token(row.state), row.token);
    LifecycleState parsed = LifecycleState::Tombstoned;
    TREG_CHECK(parse_lifecycle_state(row.token, parsed));
    TREG_CHECK_EQ(parsed, row.state);
  }
  LifecycleState ignored = LifecycleState::Active;
  TREG_CHECK(!parse_lifecycle_state("", ignored));
  TREG_CHECK(!parse_lifecycle_state("Active", ignored));
  TREG_CHECK(!parse_lifecycle_state("active ", ignored));
  TREG_CHECK(!parse_lifecycle_state("bound", ignored));
  TREG_CHECK(!parse_lifecycle_state("withdrawn", ignored));
  TREG_CHECK(!parse_lifecycle_state("tombstone", ignored));
  TREG_CHECK_EQ(ignored, LifecycleState::Active);
  TREG_CHECK_EQ(to_token(static_cast<LifecycleState>(99)), std::string_view{});

  struct MembershipTokenRow {
    MembershipState state;
    std::string_view token;
  };
  constexpr MembershipTokenRow kMembershipTokens[] = {
      {MembershipState::Unspecified, "unspecified"}, {MembershipState::Proposed, "proposed"},
      {MembershipState::Bound, "bound"},             {MembershipState::Suspended, "suspended"},
      {MembershipState::Withdrawn, "withdrawn"},
  };
  for (const MembershipTokenRow& row : kMembershipTokens) {
    TREG_CHECK_EQ(to_token(row.state), row.token);
    MembershipState parsed = MembershipState::Withdrawn;
    TREG_CHECK(parse_membership_state(row.token, parsed));
    TREG_CHECK_EQ(parsed, row.state);
  }
  MembershipState ignored_membership = MembershipState::Bound;
  TREG_CHECK(!parse_membership_state("", ignored_membership));
  TREG_CHECK(!parse_membership_state("Bound", ignored_membership));
  TREG_CHECK(!parse_membership_state("active", ignored_membership));
  TREG_CHECK(!parse_membership_state("retired", ignored_membership));
  TREG_CHECK(!parse_membership_state("bound ", ignored_membership));
  TREG_CHECK_EQ(ignored_membership, MembershipState::Bound);
  TREG_CHECK_EQ(to_token(static_cast<MembershipState>(99)), std::string_view{});

  TREG_CHECK_EQ(to_token(EndpointRole::Unspecified), std::string_view{"unspecified"});
  TREG_CHECK_EQ(to_token(EndpointRole::Source), std::string_view{"source"});
  TREG_CHECK_EQ(to_token(EndpointRole::Target), std::string_view{"target"});
  TREG_CHECK_EQ(to_token(static_cast<EndpointRole>(99)), std::string_view{});
}

TREG_TEST(lifecycle, registry_enforces_the_transition_table) {
  Harness harness = Harness::ephemeral();
  const TenantRecord created = harness.create_tenant("walker");
  TREG_CHECK_EQ(created.state, LifecycleState::Declared);
  TREG_CHECK(!is_in_force(created.state));

  const TenancySubject subject = TenancySubject::of_tenant(created.id);
  TREG_CHECK_STATUS(harness.transition(subject, created.revision, LifecycleState::Declared),
                    ErrorCode::LifecycleStateUnchanged);
  TREG_CHECK_STATUS(harness.transition(subject, created.revision, LifecycleState::Suspended),
                    ErrorCode::LifecycleTransitionIllegal);
  TREG_CHECK_STATUS(harness.transition(subject, created.revision, LifecycleState::Retiring),
                    ErrorCode::LifecycleTransitionIllegal);
  TREG_CHECK_STATUS(harness.transition(subject, created.revision, LifecycleState::Tombstoned),
                    ErrorCode::IrreversibleActionNotAcknowledged);
  TREG_CHECK_STATUS(harness.transition(subject, created.revision, LifecycleState::Unspecified),
                    ErrorCode::InvalidEnumValue);
  // A revision the record is not at is refused before the transition is even
  // considered.
  TREG_CHECK_STATUS(harness.transition(subject, RecordRevision::from_value(99), LifecycleState::Active),
                    ErrorCode::StaleRecordRevision);
  // A generation the registry has moved past is refused before that.
  const TransitionSubjectRequest stale{
      context(RegistryGeneration::initial()), subject, harness.revision_of_tenant("walker"), LifecycleState::Active};
  TREG_CHECK_CODE(harness.registry().transition_subject(stale), ErrorCode::StaleGeneration);

  require_ok(harness.transition(subject, harness.revision_of_tenant("walker"), LifecycleState::Active),
             "Declared to Active");
  TREG_CHECK_EQ(harness.tenant("walker").state, LifecycleState::Active);
  TREG_CHECK(is_in_force(harness.tenant("walker").state));
  TREG_CHECK_EQ(harness.revision_of_tenant("walker").value(),
                created.revision.value() + static_cast<std::uint64_t>(1));

  TREG_CHECK_STATUS(harness.transition(subject, harness.revision_of_tenant("walker"), LifecycleState::Declared),
                    ErrorCode::LifecycleTransitionIllegal);
  TREG_CHECK_STATUS(harness.transition(subject, harness.revision_of_tenant("walker"), LifecycleState::Retired),
                    ErrorCode::LifecycleTransitionIllegal);
  require_ok(harness.transition(subject, harness.revision_of_tenant("walker"), LifecycleState::Suspended),
             "Active to Suspended");
  TREG_CHECK_EQ(harness.tenant("walker").state, LifecycleState::Suspended);
  TREG_CHECK(!is_in_force(harness.tenant("walker").state));
  // Suspended is recoverable, so it is still a legal relationship target.
  TREG_CHECK(admits_relationship_target(harness.tenant("walker").state));
  TREG_CHECK(!admits_new_relationships(harness.tenant("walker").state));

  require_ok(harness.transition(subject, harness.revision_of_tenant("walker"), LifecycleState::Active),
             "Suspended to Active");
  require_ok(harness.transition(subject, harness.revision_of_tenant("walker"), LifecycleState::Retiring),
             "Active to Retiring");
  TREG_CHECK_EQ(harness.tenant("walker").state, LifecycleState::Retiring);
  // Withdrawing a withdrawal before it completes is legal and deliberate.
  require_ok(harness.transition(subject, harness.revision_of_tenant("walker"), LifecycleState::Active),
             "Retiring to Active");
  require_ok(harness.transition(subject, harness.revision_of_tenant("walker"), LifecycleState::Retiring),
             "Active to Retiring again");
  require_ok(harness.transition(subject, harness.revision_of_tenant("walker"), LifecycleState::Retired),
             "Retiring to Retired");
  const TenantRecord retired = harness.tenant("walker");
  TREG_CHECK_EQ(retired.state, LifecycleState::Retired);
  TREG_CHECK(retired.retired_generation.has_value());
  TREG_CHECK(!is_in_force(retired.state));
  TREG_CHECK_STATUS(harness.transition(subject, retired.revision, LifecycleState::Active),
                    ErrorCode::LifecycleTransitionIllegal);
  TREG_CHECK_STATUS(harness.transition(subject, retired.revision, LifecycleState::Retired),
                    ErrorCode::LifecycleStateUnchanged);
  TREG_CHECK_STATUS(harness.transition(subject, retired.revision, LifecycleState::Tombstoned),
                    ErrorCode::IrreversibleActionNotAcknowledged);

  // Tombstoning is reachable only through the explicit operation.
  harness.tombstone("walker", false, "fenced");
  TREG_CHECK_EQ(harness.tenant("walker").state, LifecycleState::Tombstoned);
  const TenantRecord tombstoned = harness.tenant("walker");
  TREG_CHECK(is_terminal(tombstoned.state));
  TREG_CHECK_STATUS(harness.transition(subject, tombstoned.revision, LifecycleState::Retired),
                    ErrorCode::LifecycleTransitionIllegal);

  // Declared may go straight to Retired without ever being in force.
  const TenantRecord early = harness.create_tenant("early");
  require_ok(harness.transition(TenancySubject::of_tenant(early.id), early.revision, LifecycleState::Retired),
             "Declared to Retired");
  TREG_CHECK_EQ(harness.tenant("early").state, LifecycleState::Retired);

  // A subject that was never registered is NotFound, not a silent success.
  TREG_CHECK_STATUS(harness.transition(tenant_subject("missing"), RecordRevision::from_value(1),
                                       LifecycleState::Active),
                    ErrorCode::NotFound);
}

}  // namespace treg_test
