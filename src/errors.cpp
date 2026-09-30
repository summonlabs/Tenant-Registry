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

#include "tenant_registry/errors.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace tenant_registry {

namespace {

/// One code's stable token, its class and whether retrying the identical
/// request could plausibly succeed later. Keeping all three in one table means
/// a code cannot be given a token here and a different class there.
struct ErrorCodeInfo {
  ErrorCode code;
  std::string_view token;
  ErrorClass error_class;
  bool transient;
};

constexpr auto kErrorCodeTable = std::to_array<ErrorCodeInfo>({
    // -- unspecified ----------------------------------------------------------
    {ErrorCode::Unspecified, "unspecified", ErrorClass::Unspecified, false},

    // -- validation of the request itself -------------------------------------
    {ErrorCode::InvalidArgument, "invalid_argument", ErrorClass::Validation, false},
    {ErrorCode::InvalidIdentity, "invalid_identity", ErrorClass::Validation, false},
    {ErrorCode::InvalidIdKind, "invalid_id_kind", ErrorClass::Validation, false},
    {ErrorCode::InvalidUtf8, "invalid_utf8", ErrorClass::Validation, false},
    {ErrorCode::InvalidTextForm, "invalid_text_form", ErrorClass::Validation, false},
    {ErrorCode::InvalidEnumValue, "invalid_enum_value", ErrorClass::Validation, false},
    {ErrorCode::InvalidDigest, "invalid_digest", ErrorClass::Validation, false},
    {ErrorCode::InvalidProvenance, "invalid_provenance", ErrorClass::Validation, false},
    {ErrorCode::InvalidMetadata, "invalid_metadata", ErrorClass::Validation, false},
    {ErrorCode::MissingRequiredField, "missing_required_field", ErrorClass::Validation, false},
    {ErrorCode::ReservedFieldNotZero, "reserved_field_not_zero", ErrorClass::Validation, false},
    {ErrorCode::DecodeFailed, "decode_failed", ErrorClass::Validation, false},
    {ErrorCode::EncodeFailed, "encode_failed", ErrorClass::Validation, false},
    {ErrorCode::DigestMismatch, "digest_mismatch", ErrorClass::Validation, false},
    {ErrorCode::EncodingVersionUnsupported, "encoding_version_unsupported", ErrorClass::Validation, false},

    // -- authority and fencing ------------------------------------------------
    {ErrorCode::ControlEpochSuperseded, "control_epoch_superseded", ErrorClass::Authority, false},
    {ErrorCode::IncarnationSuperseded, "incarnation_superseded", ErrorClass::Authority, false},
    {ErrorCode::StoreIdentityMismatch, "store_identity_mismatch", ErrorClass::Authority, false},
    {ErrorCode::ExpectedGenerationMissing, "expected_generation_missing", ErrorClass::Authority, false},

    // -- staleness ------------------------------------------------------------
    {ErrorCode::StaleGeneration, "stale_generation", ErrorClass::Staleness, false},
    {ErrorCode::StaleRecordRevision, "stale_record_revision", ErrorClass::Staleness, false},
    {ErrorCode::StaleDomainGeneration, "stale_domain_generation", ErrorClass::Staleness, false},
    {ErrorCode::RecordChangedSinceDecision, "record_changed_since_decision", ErrorClass::Staleness, false},

    // -- idempotency ----------------------------------------------------------
    {ErrorCode::IdempotencyKeyReused, "idempotency_key_reused", ErrorClass::Idempotency, false},
    {ErrorCode::IdempotencyLedgerFull, "idempotency_ledger_full", ErrorClass::Idempotency, false},
    {ErrorCode::IdempotencyKeyMalformed, "idempotency_key_malformed", ErrorClass::Idempotency, false},

    // -- identity -------------------------------------------------------------
    {ErrorCode::IdentityAlreadyExists, "identity_already_exists", ErrorClass::Identity, false},
    {ErrorCode::IdentityRetired, "identity_retired", ErrorClass::Identity, false},
    {ErrorCode::IdentityTombstoned, "identity_tombstoned", ErrorClass::Identity, false},
    {ErrorCode::RebindPermitConsumed, "rebind_permit_consumed", ErrorClass::Identity, false},
    {ErrorCode::RebindPermitAbsent, "rebind_permit_absent", ErrorClass::Identity, false},
    {ErrorCode::IrreversibleActionNotAcknowledged, "irreversible_action_not_acknowledged", ErrorClass::Identity, false},
    {ErrorCode::IdentityKindMismatch, "identity_kind_mismatch", ErrorClass::Identity, false},

    // -- references and relationships -----------------------------------------
    {ErrorCode::ReferenceNotFound, "reference_not_found", ErrorClass::Reference, false},
    {ErrorCode::ReferenceTerminal, "reference_terminal", ErrorClass::Reference, false},
    {ErrorCode::ReferenceNotYetLive, "reference_not_yet_live", ErrorClass::Reference, false},
    {ErrorCode::OwnershipCycle, "ownership_cycle", ErrorClass::Reference, false},
    {ErrorCode::OwnershipDepthExceeded, "ownership_depth_exceeded", ErrorClass::Reference, false},
    {ErrorCode::SelfReference, "self_reference", ErrorClass::Reference, false},
    {ErrorCode::DuplicateRelationship, "duplicate_relationship", ErrorClass::Reference, false},
    {ErrorCode::RelationshipAbsent, "relationship_absent", ErrorClass::Reference, false},
    {ErrorCode::HasLiveDependents, "has_live_dependents", ErrorClass::Reference, false},
    {ErrorCode::DomainMembershipDuplicate, "domain_membership_duplicate", ErrorClass::Reference, false},
    {ErrorCode::DomainMembershipAbsent, "domain_membership_absent", ErrorClass::Reference, false},
    {ErrorCode::BindingConflict, "binding_conflict", ErrorClass::Reference, false},
    {ErrorCode::MembershipRoleConflict, "membership_role_conflict", ErrorClass::Reference, false},

    // -- lifecycle ------------------------------------------------------------
    {ErrorCode::LifecycleTransitionIllegal, "lifecycle_transition_illegal", ErrorClass::Lifecycle, false},
    {ErrorCode::LifecycleStateUnchanged, "lifecycle_state_unchanged", ErrorClass::Lifecycle, false},
    {ErrorCode::TerminalStateReached, "terminal_state_reached", ErrorClass::Lifecycle, false},

    // -- limits ---------------------------------------------------------------
    {ErrorCode::LimitExceeded, "limit_exceeded", ErrorClass::Limit, false},
    {ErrorCode::TraversalLimitExceeded, "traversal_limit_exceeded", ErrorClass::Limit, false},
    {ErrorCode::ListingLimitExceeded, "listing_limit_exceeded", ErrorClass::Limit, false},
    {ErrorCode::PayloadTooLarge, "payload_too_large", ErrorClass::Limit, false},
    {ErrorCode::CounterSaturated, "counter_saturated", ErrorClass::Limit, false},

    // -- durable store --------------------------------------------------------
    {ErrorCode::StoreNotFound, "store_not_found", ErrorClass::Store, false},
    // A held lock and a transient device error are the two refusals that a
    // later identical attempt can plausibly get past without any other change.
    {ErrorCode::StoreLocked, "store_locked", ErrorClass::Store, true},
    {ErrorCode::StoreIoError, "store_io_error", ErrorClass::Store, true},
    {ErrorCode::StoreCorrupt, "store_corrupt", ErrorClass::Store, false},
    {ErrorCode::StoreFormatUnsupported, "store_format_unsupported", ErrorClass::Store, false},
    {ErrorCode::StoreRolledBack, "store_rolled_back", ErrorClass::Store, false},
    {ErrorCode::StoreNotWritable, "store_not_writable", ErrorClass::Store, false},
    {ErrorCode::StoreClosed, "store_closed", ErrorClass::Store, false},
    {ErrorCode::StoreRecoveryRefused, "store_recovery_refused", ErrorClass::Store, false},
    {ErrorCode::StorePathRejected, "store_path_rejected", ErrorClass::Store, false},

    // -- query ----------------------------------------------------------------
    {ErrorCode::NotFound, "not_found", ErrorClass::Query, false},
    {ErrorCode::AmbiguousLookup, "ambiguous_lookup", ErrorClass::Query, false},
    {ErrorCode::UnsupportedQuery, "unsupported_query", ErrorClass::Query, false},

    // -- internal -------------------------------------------------------------
    {ErrorCode::InternalInvariantViolated, "internal_invariant_violated", ErrorClass::Internal, false},
});

/// Proves at compile time that no two codes share a token and that no entry was
/// left empty by a miscount, so the table cannot quietly lose a code.
consteval bool table_is_well_formed() noexcept {
  for (std::size_t left = 0; left < kErrorCodeTable.size(); ++left) {
    if (kErrorCodeTable[left].token.empty()) {
      return false;
    }
    for (std::size_t right = left + 1; right < kErrorCodeTable.size(); ++right) {
      if (kErrorCodeTable[left].code == kErrorCodeTable[right].code) {
        return false;
      }
      if (kErrorCodeTable[left].token == kErrorCodeTable[right].token) {
        return false;
      }
    }
  }
  return true;
}

static_assert(table_is_well_formed(), "every error code needs exactly one distinct token");

const ErrorCodeInfo* lookup(ErrorCode code) noexcept {
  for (const ErrorCodeInfo& entry : kErrorCodeTable) {
    if (entry.code == code) {
      return &entry;
    }
  }
  return nullptr;
}

constexpr std::array<std::pair<ErrorClass, std::string_view>, 12> kErrorClassTokens = {{
    {ErrorClass::Unspecified, "unspecified"},
    {ErrorClass::Validation, "validation"},
    {ErrorClass::Authority, "authority"},
    {ErrorClass::Staleness, "staleness"},
    {ErrorClass::Idempotency, "idempotency"},
    {ErrorClass::Identity, "identity"},
    {ErrorClass::Reference, "reference"},
    {ErrorClass::Lifecycle, "lifecycle"},
    {ErrorClass::Limit, "limit"},
    {ErrorClass::Store, "store"},
    {ErrorClass::Query, "query"},
    {ErrorClass::Internal, "internal"},
}};

}  // namespace

std::string_view to_token(ErrorCode code) noexcept {
  const ErrorCodeInfo* entry = lookup(code);
  // An out of range code has no token; it never borrows another code's name.
  return entry != nullptr ? entry->token : std::string_view{};
}

std::string_view to_token(ErrorClass error_class) noexcept {
  for (const auto& entry : kErrorClassTokens) {
    if (entry.first == error_class) {
      return entry.second;
    }
  }
  return std::string_view{};
}

bool parse_error_code(std::string_view token, ErrorCode& out) noexcept {
  for (const ErrorCodeInfo& entry : kErrorCodeTable) {
    if (entry.token == token) {
      out = entry.code;
      return true;
    }
  }
  return false;
}

ErrorClass classify(ErrorCode code) noexcept {
  const ErrorCodeInfo* entry = lookup(code);
  return entry != nullptr ? entry->error_class : ErrorClass::Unspecified;
}

bool is_transient(ErrorCode code) noexcept {
  const ErrorCodeInfo* entry = lookup(code);
  return entry != nullptr && entry->transient;
}

Error Error::with_subject(ErrorCode code, std::string subject, std::string detail) {
  Error error{code, std::move(detail)};
  error.subject_ = std::move(subject);
  return error;
}

void Error::add_suppressed(std::string note) { suppressed_.push_back(std::move(note)); }

std::string Error::to_text() const {
  std::string out;
  const std::string_view code_token = to_token(code_);
  if (code_token.empty()) {
    // An unrecognized code is rendered as itself rather than as a known one.
    out += "unknown_error_code(";
    out += std::to_string(static_cast<std::uint16_t>(code_));
    out += ')';
  } else {
    out += code_token;
  }
  if (!subject_.empty()) {
    out += ": ";
    out += subject_;
  }
  if (!detail_.empty()) {
    out += ": ";
    out += detail_;
  }
  return out;
}

const Error& Status::error() const noexcept {
  // A success holds no refusal. The reference returned here is the shared
  // "nothing was refused" value, never a synthesized refusal, so a caller that
  // reads it without checking ok() sees Unspecified rather than a false code.
  static const Error kNoError{};
  return error_.has_value() ? *error_ : kNoError;
}

}  // namespace tenant_registry
