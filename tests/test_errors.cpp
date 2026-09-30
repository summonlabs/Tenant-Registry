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
#include <utility>
#include <vector>

#include "test_support.hpp"

namespace treg_test {
namespace {

using tenant_registry::classify;
using tenant_registry::Error;
using tenant_registry::ErrorClass;
using tenant_registry::ErrorCode;
using tenant_registry::is_transient;
using tenant_registry::make_error;
using tenant_registry::parse_error_code;
using tenant_registry::Status;
using tenant_registry::to_token;

/// One code's complete documented identity: its numeric value, its stable
/// token, its class and whether a later identical attempt could plausibly
/// succeed. The table exists so that a change to any of the four is a test
/// failure rather than a silent renumbering.
struct CodeRow {
  ErrorCode code;
  std::uint16_t number;
  std::string_view token;
  ErrorClass error_class;
  bool transient;
};

constexpr CodeRow kCodes[] = {
    {ErrorCode::Unspecified, 0, "unspecified", ErrorClass::Unspecified, false},
    {ErrorCode::InvalidArgument, 100, "invalid_argument", ErrorClass::Validation, false},
    {ErrorCode::InvalidIdentity, 101, "invalid_identity", ErrorClass::Validation, false},
    {ErrorCode::InvalidIdKind, 102, "invalid_id_kind", ErrorClass::Validation, false},
    {ErrorCode::InvalidUtf8, 103, "invalid_utf8", ErrorClass::Validation, false},
    {ErrorCode::InvalidTextForm, 104, "invalid_text_form", ErrorClass::Validation, false},
    {ErrorCode::InvalidEnumValue, 105, "invalid_enum_value", ErrorClass::Validation, false},
    {ErrorCode::InvalidDigest, 106, "invalid_digest", ErrorClass::Validation, false},
    {ErrorCode::InvalidProvenance, 107, "invalid_provenance", ErrorClass::Validation, false},
    {ErrorCode::InvalidMetadata, 108, "invalid_metadata", ErrorClass::Validation, false},
    {ErrorCode::MissingRequiredField, 109, "missing_required_field", ErrorClass::Validation, false},
    {ErrorCode::ReservedFieldNotZero, 110, "reserved_field_not_zero", ErrorClass::Validation, false},
    {ErrorCode::DecodeFailed, 111, "decode_failed", ErrorClass::Validation, false},
    {ErrorCode::EncodeFailed, 112, "encode_failed", ErrorClass::Validation, false},
    {ErrorCode::DigestMismatch, 113, "digest_mismatch", ErrorClass::Validation, false},
    {ErrorCode::EncodingVersionUnsupported, 114, "encoding_version_unsupported", ErrorClass::Validation, false},
    {ErrorCode::ControlEpochSuperseded, 200, "control_epoch_superseded", ErrorClass::Authority, false},
    {ErrorCode::IncarnationSuperseded, 201, "incarnation_superseded", ErrorClass::Authority, false},
    {ErrorCode::StoreIdentityMismatch, 202, "store_identity_mismatch", ErrorClass::Authority, false},
    {ErrorCode::ExpectedGenerationMissing, 203, "expected_generation_missing", ErrorClass::Authority, false},
    {ErrorCode::StaleGeneration, 220, "stale_generation", ErrorClass::Staleness, false},
    {ErrorCode::StaleRecordRevision, 221, "stale_record_revision", ErrorClass::Staleness, false},
    {ErrorCode::StaleDomainGeneration, 222, "stale_domain_generation", ErrorClass::Staleness, false},
    {ErrorCode::RecordChangedSinceDecision, 223, "record_changed_since_decision", ErrorClass::Staleness, false},
    {ErrorCode::IdempotencyKeyReused, 240, "idempotency_key_reused", ErrorClass::Idempotency, false},
    {ErrorCode::IdempotencyLedgerFull, 241, "idempotency_ledger_full", ErrorClass::Idempotency, false},
    {ErrorCode::IdempotencyKeyMalformed, 242, "idempotency_key_malformed", ErrorClass::Idempotency, false},
    {ErrorCode::IdentityAlreadyExists, 260, "identity_already_exists", ErrorClass::Identity, false},
    {ErrorCode::IdentityRetired, 261, "identity_retired", ErrorClass::Identity, false},
    {ErrorCode::IdentityTombstoned, 262, "identity_tombstoned", ErrorClass::Identity, false},
    {ErrorCode::RebindPermitConsumed, 263, "rebind_permit_consumed", ErrorClass::Identity, false},
    {ErrorCode::RebindPermitAbsent, 264, "rebind_permit_absent", ErrorClass::Identity, false},
    {ErrorCode::IrreversibleActionNotAcknowledged, 265, "irreversible_action_not_acknowledged", ErrorClass::Identity, false},
    {ErrorCode::IdentityKindMismatch, 266, "identity_kind_mismatch", ErrorClass::Identity, false},
    {ErrorCode::ReferenceNotFound, 280, "reference_not_found", ErrorClass::Reference, false},
    {ErrorCode::ReferenceTerminal, 281, "reference_terminal", ErrorClass::Reference, false},
    {ErrorCode::ReferenceNotYetLive, 282, "reference_not_yet_live", ErrorClass::Reference, false},
    {ErrorCode::OwnershipCycle, 283, "ownership_cycle", ErrorClass::Reference, false},
    {ErrorCode::OwnershipDepthExceeded, 284, "ownership_depth_exceeded", ErrorClass::Reference, false},
    {ErrorCode::SelfReference, 285, "self_reference", ErrorClass::Reference, false},
    {ErrorCode::DuplicateRelationship, 286, "duplicate_relationship", ErrorClass::Reference, false},
    {ErrorCode::RelationshipAbsent, 287, "relationship_absent", ErrorClass::Reference, false},
    {ErrorCode::HasLiveDependents, 288, "has_live_dependents", ErrorClass::Reference, false},
    {ErrorCode::DomainMembershipDuplicate, 289, "domain_membership_duplicate", ErrorClass::Reference, false},
    {ErrorCode::DomainMembershipAbsent, 290, "domain_membership_absent", ErrorClass::Reference, false},
    {ErrorCode::BindingConflict, 291, "binding_conflict", ErrorClass::Reference, false},
    {ErrorCode::MembershipRoleConflict, 292, "membership_role_conflict", ErrorClass::Reference, false},
    {ErrorCode::LifecycleTransitionIllegal, 320, "lifecycle_transition_illegal", ErrorClass::Lifecycle, false},
    {ErrorCode::LifecycleStateUnchanged, 321, "lifecycle_state_unchanged", ErrorClass::Lifecycle, false},
    {ErrorCode::TerminalStateReached, 322, "terminal_state_reached", ErrorClass::Lifecycle, false},
    {ErrorCode::LimitExceeded, 340, "limit_exceeded", ErrorClass::Limit, false},
    {ErrorCode::TraversalLimitExceeded, 341, "traversal_limit_exceeded", ErrorClass::Limit, false},
    {ErrorCode::ListingLimitExceeded, 342, "listing_limit_exceeded", ErrorClass::Limit, false},
    {ErrorCode::PayloadTooLarge, 343, "payload_too_large", ErrorClass::Limit, false},
    {ErrorCode::CounterSaturated, 344, "counter_saturated", ErrorClass::Limit, false},
    {ErrorCode::StoreNotFound, 360, "store_not_found", ErrorClass::Store, false},
    {ErrorCode::StoreLocked, 361, "store_locked", ErrorClass::Store, true},
    {ErrorCode::StoreIoError, 362, "store_io_error", ErrorClass::Store, true},
    {ErrorCode::StoreCorrupt, 363, "store_corrupt", ErrorClass::Store, false},
    {ErrorCode::StoreFormatUnsupported, 364, "store_format_unsupported", ErrorClass::Store, false},
    {ErrorCode::StoreRolledBack, 365, "store_rolled_back", ErrorClass::Store, false},
    {ErrorCode::StoreNotWritable, 366, "store_not_writable", ErrorClass::Store, false},
    {ErrorCode::StoreClosed, 367, "store_closed", ErrorClass::Store, false},
    {ErrorCode::StoreRecoveryRefused, 368, "store_recovery_refused", ErrorClass::Store, false},
    {ErrorCode::StorePathRejected, 369, "store_path_rejected", ErrorClass::Store, false},
    {ErrorCode::NotFound, 380, "not_found", ErrorClass::Query, false},
    {ErrorCode::AmbiguousLookup, 381, "ambiguous_lookup", ErrorClass::Query, false},
    {ErrorCode::UnsupportedQuery, 382, "unsupported_query", ErrorClass::Query, false},
    {ErrorCode::InternalInvariantViolated, 400, "internal_invariant_violated", ErrorClass::Internal, false},
};

constexpr std::size_t kCodeCount = sizeof(kCodes) / sizeof(kCodes[0]);

struct ClassToken {
  ErrorClass error_class;
  std::string_view token;
};

constexpr ClassToken kClassTokens[] = {
    {ErrorClass::Unspecified, "unspecified"}, {ErrorClass::Validation, "validation"},
    {ErrorClass::Authority, "authority"},     {ErrorClass::Staleness, "staleness"},
    {ErrorClass::Idempotency, "idempotency"}, {ErrorClass::Identity, "identity"},
    {ErrorClass::Reference, "reference"},     {ErrorClass::Lifecycle, "lifecycle"},
    {ErrorClass::Limit, "limit"},             {ErrorClass::Store, "store"},
    {ErrorClass::Query, "query"},             {ErrorClass::Internal, "internal"},
};

bool token_is_lower_snake(std::string_view token) {
  for (const char character : token) {
    const bool lower = character >= 'a' && character <= 'z';
    const bool digit = character >= '0' && character <= '9';
    if (!lower && !digit && character != '_') {
      return false;
    }
  }
  return true;
}

}  // namespace

TREG_TEST(errors, every_code_has_a_stable_unique_lower_case_token) {
  TREG_CHECK_EQ(kCodeCount, static_cast<std::size_t>(69));
  for (std::size_t index = 0; index < kCodeCount; ++index) {
    const CodeRow& row = kCodes[index];
    const std::string_view token = to_token(row.code);
    TREG_CHECK(!token.empty());
    TREG_CHECK_EQ(token, row.token);
    TREG_CHECK(token_is_lower_snake(token));
    // Stability: the same code renders the same token every time.
    TREG_CHECK_EQ(to_token(row.code), token);
    TREG_CHECK_EQ(static_cast<std::uint16_t>(row.code), row.number);
  }

  // Uniqueness: no two codes may share a token, or a log line would stop
  // identifying the refusal that produced it.
  for (std::size_t left = 0; left < kCodeCount; ++left) {
    for (std::size_t right = left + 1; right < kCodeCount; ++right) {
      TREG_CHECK(kCodes[left].code != kCodes[right].code);
      TREG_CHECK(kCodes[left].token != kCodes[right].token);
      TREG_CHECK(kCodes[left].number != kCodes[right].number);
    }
  }
}

TREG_TEST(errors, parse_error_code_round_trips_every_token) {
  for (const CodeRow& row : kCodes) {
    ErrorCode parsed = ErrorCode::NotFound;
    TREG_CHECK(parse_error_code(row.token, parsed));
    TREG_CHECK_EQ(parsed, row.code);
    TREG_CHECK_EQ(parsed, row.code);
  }
  // The one code that is not a refusal still round trips: "unspecified" is the
  // token of ErrorCode::Unspecified in this build.
  ErrorCode parsed = ErrorCode::NotFound;
  TREG_CHECK(parse_error_code("unspecified", parsed));
  TREG_CHECK_EQ(parsed, ErrorCode::Unspecified);
}

TREG_TEST(errors, parse_error_code_refuses_unknown_tokens_without_defaulting) {
  const std::string_view unknown[] = {
      "",       " ",          "not_a_code",     "UNSPECIFIED",  "Unspecified",  "unspecified ",
      " unspecified",         "stale_generation ", "stale-generation", "staleGeneration", "error",
      "invalid",              "counter_saturated2", "unspecified_token", "not_found\n"};
  for (const std::string_view token : unknown) {
    // The output is seeded with a code that must survive the failed parse: a
    // parser that writes a default on failure turns an unknown refusal into a
    // known one, which is exactly what this registry must never do.
    ErrorCode parsed = ErrorCode::NotFound;
    TREG_CHECK(!parse_error_code(token, parsed));
    TREG_CHECK_EQ(parsed, ErrorCode::NotFound);
  }
}

TREG_TEST(errors, classify_gives_the_documented_class_for_every_code) {
  for (const CodeRow& row : kCodes) {
    TREG_CHECK_EQ(classify(row.code), row.error_class);
  }
  for (const ClassToken& entry : kClassTokens) {
    TREG_CHECK_EQ(to_token(entry.error_class), entry.token);
    TREG_CHECK(!to_token(entry.error_class).empty());
  }
  // An out of range code has no class and no token; it never borrows one.
  TREG_CHECK_EQ(classify(static_cast<ErrorCode>(9999)), ErrorClass::Unspecified);
  TREG_CHECK_EQ(to_token(static_cast<ErrorCode>(9999)), std::string_view{});
  TREG_CHECK_EQ(to_token(static_cast<ErrorClass>(99)), std::string_view{});
}

TREG_TEST(errors, is_transient_marks_only_a_later_identical_retry) {
  std::size_t transient_count = 0;
  for (const CodeRow& row : kCodes) {
    TREG_CHECK_EQ(is_transient(row.code), row.transient);
    if (row.transient) {
      ++transient_count;
    }
  }
  // A held lock and a transient device error are the only two refusals a later
  // identical attempt can get past without changing anything.
  TREG_CHECK_EQ(transient_count, static_cast<std::size_t>(2));
  TREG_CHECK(is_transient(ErrorCode::StoreLocked));
  TREG_CHECK(is_transient(ErrorCode::StoreIoError));
  TREG_CHECK(!is_transient(ErrorCode::StoreCorrupt));
  TREG_CHECK(!is_transient(ErrorCode::StoreClosed));
  TREG_CHECK(!is_transient(ErrorCode::Unspecified));
  TREG_CHECK(!is_transient(static_cast<ErrorCode>(9999)));
}

TREG_TEST(errors, to_text_orders_code_subject_then_detail) {
  TREG_CHECK_EQ(Error{}.to_text(), std::string{"unspecified"});
  TREG_CHECK_EQ(Error{ErrorCode::InvalidIdentity}.to_text(), std::string{"invalid_identity"});
  const Error with_detail{ErrorCode::InvalidIdentity, "not a token"};
  TREG_CHECK_EQ(with_detail.to_text(), std::string{"invalid_identity: not a token"});
  TREG_CHECK_EQ(Error::with_subject(ErrorCode::StaleGeneration, "tenant:acme", "").to_text(),
                std::string{"stale_generation: tenant:acme"});
  TREG_CHECK_EQ(Error::with_subject(ErrorCode::StaleGeneration, "tenant:acme", "generation is 4").to_text(),
                std::string{"stale_generation: tenant:acme: generation is 4"});
  TREG_CHECK_EQ(Error::with_subject(ErrorCode::NotFound, "", "tenant is not registered").to_text(),
                std::string{"not_found: tenant is not registered"});
  TREG_CHECK_EQ(make_error(ErrorCode::LimitExceeded, "too many tenants").to_text(),
                std::string{"limit_exceeded: too many tenants"});

  const Error carried = Error::with_subject(ErrorCode::HasLiveDependents, "tenant:parent", "two bindings remain");
  TREG_CHECK_EQ(carried.code(), ErrorCode::HasLiveDependents);
  TREG_CHECK_EQ(carried.token(), std::string_view{"has_live_dependents"});
  TREG_CHECK_EQ(carried.subject(), std::string{"tenant:parent"});
  TREG_CHECK_EQ(carried.detail(), std::string{"two bindings remain"});
  TREG_CHECK_EQ(carried.error_class(), ErrorClass::Reference);

  // A code this build does not know is rendered as itself rather than as a
  // known one.
  const Error unknown_code{static_cast<ErrorCode>(9999), "mystery"};
  TREG_CHECK_EQ(unknown_code.to_text(), std::string{"unknown_error_code(9999): mystery"});
}

TREG_TEST(errors, suppressed_evidence_keeps_order_and_count) {
  Error error{ErrorCode::HasLiveDependents, "tenant:parent still has dependents"};
  TREG_CHECK(error.suppressed().empty());
  error.add_suppressed("first observation");
  error.add_suppressed("second observation");
  error.add_suppressed("third observation");
  TREG_CHECK_EQ(error.suppressed().size(), static_cast<std::size_t>(3));
  TREG_CHECK_EQ(error.suppressed()[0], std::string{"first observation"});
  TREG_CHECK_EQ(error.suppressed()[1], std::string{"second observation"});
  TREG_CHECK_EQ(error.suppressed()[2], std::string{"third observation"});
  // Suppressed evidence explains what else was wrong; it is never the reason,
  // so the one line reason stays exactly code, subject, detail.
  TREG_CHECK_EQ(error.to_text(), std::string{"has_live_dependents: tenant:parent still has dependents"});
  TREG_CHECK_EQ(error.code(), ErrorCode::HasLiveDependents);

  // Evidence travels with a copy of the refusal.
  const Error copied = error;
  TREG_CHECK_EQ(copied.suppressed().size(), static_cast<std::size_t>(3));
  TREG_CHECK_EQ(copied.suppressed()[2], std::string{"third observation"});
}

TREG_TEST(errors, status_failure_carries_the_code) {
  const Status success = Status::success();
  TREG_CHECK(success.ok());
  TREG_CHECK(static_cast<bool>(success));
  TREG_CHECK_EQ(success.code(), ErrorCode::Unspecified);
  TREG_CHECK_EQ(success.error().code(), ErrorCode::Unspecified);
  TREG_CHECK_EQ(success.error().detail(), std::string{});

  const Status absent = Status::failure(Error{ErrorCode::NotFound, "tenant acme is not registered"});
  TREG_CHECK(!absent.ok());
  TREG_CHECK(!static_cast<bool>(absent));
  TREG_CHECK_EQ(absent.code(), ErrorCode::NotFound);
  TREG_CHECK_EQ(absent.error().code(), ErrorCode::NotFound);
  TREG_CHECK_EQ(absent.error().error_class(), ErrorClass::Query);
  TREG_CHECK_EQ(absent.error().detail(), std::string{"tenant acme is not registered"});

  const Status limited = Status::failure(ErrorCode::LimitExceeded, "the registry may hold at most 2 tenants");
  TREG_CHECK_EQ(limited.code(), ErrorCode::LimitExceeded);
  TREG_CHECK_EQ(limited.error().detail(), std::string{"the registry may hold at most 2 tenants"});

  const Status saturated = Status::failure(Error{ErrorCode::CounterSaturated});
  TREG_CHECK_EQ(saturated.code(), ErrorCode::CounterSaturated);
  TREG_CHECK_EQ(saturated.error().token(), std::string_view{"counter_saturated"});

  // A Result refuses the same way a Status does.
  const Result<int> refused{Error{ErrorCode::StaleGeneration, "generation moved"}};
  TREG_CHECK(!refused.has_value());
  TREG_CHECK_EQ(refused.code(), ErrorCode::StaleGeneration);
  TREG_CHECK_EQ(refused.error().detail(), std::string{"generation moved"});
}

}  // namespace treg_test
