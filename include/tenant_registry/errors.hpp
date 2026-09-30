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

#ifndef TENANT_REGISTRY_ERRORS_HPP
#define TENANT_REGISTRY_ERRORS_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace tenant_registry {

/// The class of a refusal. The class is the coarse answer to "why was this
/// refused" and is stable; the code is the exact answer and is stable too.
enum class ErrorClass : std::uint8_t {
  Unspecified = 0,
  Validation = 1,
  Authority = 2,
  Staleness = 3,
  Idempotency = 4,
  Identity = 5,
  Reference = 6,
  Lifecycle = 7,
  Limit = 8,
  Store = 9,
  Query = 10,
  Internal = 11,
};

/// The exact reason an operation was refused.
///
/// New codes are appended, never inserted, and no code is ever reused for a
/// different meaning: a caller that switches on a code must keep meaning what
/// it meant.
enum class ErrorCode : std::uint16_t {
  Unspecified = 0,

  // -- validation of the request itself -------------------------------------
  InvalidArgument = 100,
  InvalidIdentity = 101,
  InvalidIdKind = 102,
  InvalidUtf8 = 103,
  InvalidTextForm = 104,
  InvalidEnumValue = 105,
  InvalidDigest = 106,
  InvalidProvenance = 107,
  InvalidMetadata = 108,
  MissingRequiredField = 109,
  ReservedFieldNotZero = 110,
  DecodeFailed = 111,
  EncodeFailed = 112,
  DigestMismatch = 113,
  EncodingVersionUnsupported = 114,

  // -- authority and fencing ------------------------------------------------
  ControlEpochSuperseded = 200,
  IncarnationSuperseded = 201,
  StoreIdentityMismatch = 202,
  ExpectedGenerationMissing = 203,

  // -- staleness ------------------------------------------------------------
  StaleGeneration = 220,
  StaleRecordRevision = 221,
  StaleDomainGeneration = 222,
  RecordChangedSinceDecision = 223,

  // -- idempotency ----------------------------------------------------------
  IdempotencyKeyReused = 240,
  IdempotencyLedgerFull = 241,
  IdempotencyKeyMalformed = 242,

  // -- identity -------------------------------------------------------------
  IdentityAlreadyExists = 260,
  IdentityRetired = 261,
  IdentityTombstoned = 262,
  RebindPermitConsumed = 263,
  RebindPermitAbsent = 264,
  IrreversibleActionNotAcknowledged = 265,
  IdentityKindMismatch = 266,

  // -- references and relationships -----------------------------------------
  ReferenceNotFound = 280,
  ReferenceTerminal = 281,
  ReferenceNotYetLive = 282,
  OwnershipCycle = 283,
  OwnershipDepthExceeded = 284,
  SelfReference = 285,
  DuplicateRelationship = 286,
  RelationshipAbsent = 287,
  HasLiveDependents = 288,
  DomainMembershipDuplicate = 289,
  DomainMembershipAbsent = 290,
  BindingConflict = 291,
  MembershipRoleConflict = 292,

  // -- lifecycle ------------------------------------------------------------
  LifecycleTransitionIllegal = 320,
  LifecycleStateUnchanged = 321,
  TerminalStateReached = 322,

  // -- limits ---------------------------------------------------------------
  LimitExceeded = 340,
  TraversalLimitExceeded = 341,
  ListingLimitExceeded = 342,
  PayloadTooLarge = 343,
  CounterSaturated = 344,

  // -- durable store --------------------------------------------------------
  StoreNotFound = 360,
  StoreLocked = 361,
  StoreIoError = 362,
  StoreCorrupt = 363,
  StoreFormatUnsupported = 364,
  StoreRolledBack = 365,
  StoreNotWritable = 366,
  StoreClosed = 367,
  StoreRecoveryRefused = 368,
  StorePathRejected = 369,

  // -- query ----------------------------------------------------------------
  NotFound = 380,
  AmbiguousLookup = 381,
  UnsupportedQuery = 382,

  // -- internal -------------------------------------------------------------
  InternalInvariantViolated = 400,
};

/// The stable lower case token of a code, for CLI output, logs and tests.
[[nodiscard]] std::string_view to_token(ErrorCode code) noexcept;
[[nodiscard]] std::string_view to_token(ErrorClass error_class) noexcept;

/// Parses a token back to a code. False when the token is not a code this build
/// knows; the caller must not fall back to a default code, because a default
/// would turn an unknown refusal into a known one.
///
/// The round trip includes the "unspecified" token, because it is the stable
/// token of ErrorCode::Unspecified. A caller must therefore decide success from
/// this function's boolean result and never from the code it produced: that code
/// is also the value an unset error carries, and the two meanings are different.
[[nodiscard]] bool parse_error_code(std::string_view token, ErrorCode& out) noexcept;

/// The class of a code. Every code maps to exactly one class.
[[nodiscard]] ErrorClass classify(ErrorCode code) noexcept;

/// True when retrying the identical request could plausibly succeed later
/// without the caller changing anything. This is a hint for operators, never an
/// authorization to retry a mutation blindly.
[[nodiscard]] bool is_transient(ErrorCode code) noexcept;

/// A refusal, with the evidence needed to explain it.
///
/// A refusal is not a string. It carries the exact code, the subject the
/// operation was about, and any secondary observations that were made before
/// the refusal was decided but that are not the reason for it. Suppressed
/// evidence is kept because "why was this refused" and "what else was wrong"
/// are different questions.
class Error {
 public:
  Error() = default;

  explicit Error(ErrorCode code) noexcept : code_(code) {}

  Error(ErrorCode code, std::string detail) noexcept : code_(code), detail_(std::move(detail)) {}

  [[nodiscard]] static Error with_subject(ErrorCode code, std::string subject, std::string detail);

  [[nodiscard]] ErrorCode code() const noexcept { return code_; }
  [[nodiscard]] ErrorClass error_class() const noexcept { return classify(code_); }
  [[nodiscard]] std::string_view token() const noexcept { return to_token(code_); }

  /// The canonical subject token the refusal is about, for example
  /// "tenant:acme" or "store:manifest". Empty when no subject applies.
  [[nodiscard]] const std::string& subject() const noexcept { return subject_; }

  /// A human readable explanation. Never parsed by a caller; always rendered.
  [[nodiscard]] const std::string& detail() const noexcept { return detail_; }

  /// Observations that were made but that are not the reason for the refusal,
  /// in the order they were made. Deterministic for equivalent inputs.
  [[nodiscard]] const std::vector<std::string>& suppressed() const noexcept { return suppressed_; }

  void add_suppressed(std::string note);

  /// One line, stable ordering: "code: subject: detail".
  [[nodiscard]] std::string to_text() const;

 private:
  ErrorCode code_ = ErrorCode::Unspecified;
  std::string subject_;
  std::string detail_;
  std::vector<std::string> suppressed_;
};

/// The result of an operation that produces no value.
class Status {
 public:
  Status() noexcept = default;

  [[nodiscard]] static Status success() noexcept { return Status{}; }
  [[nodiscard]] static Status failure(Error error) noexcept { return Status{std::move(error)}; }
  [[nodiscard]] static Status failure(ErrorCode code, std::string detail) {
    return Status{Error{code, std::move(detail)}};
  }

  [[nodiscard]] bool ok() const noexcept { return !error_.has_value(); }
  [[nodiscard]] explicit operator bool() const noexcept { return ok(); }
  [[nodiscard]] ErrorCode code() const noexcept { return error_ ? error_->code() : ErrorCode::Unspecified; }
  [[nodiscard]] const Error& error() const noexcept;

 private:
  explicit Status(Error error) noexcept : error_(std::move(error)) {}

  std::optional<Error> error_;
};

/// The result of an operation that produces a value. A Result either holds a
/// value or holds an Error; it never holds both and never holds neither.
template <class T>
class Result {
 public:
  Result(T value) noexcept : value_(std::move(value)) {}
  Result(Error error) noexcept : error_(std::move(error)) {}

  [[nodiscard]] bool has_value() const noexcept { return value_.has_value(); }
  [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }

  [[nodiscard]] T& value() & noexcept { return *value_; }
  [[nodiscard]] const T& value() const& noexcept { return *value_; }
  [[nodiscard]] T&& value() && noexcept { return std::move(*value_); }

  [[nodiscard]] const Error& error() const noexcept { return *error_; }
  [[nodiscard]] ErrorCode code() const noexcept { return error_ ? error_->code() : ErrorCode::Unspecified; }

  template <class U>
  [[nodiscard]] T value_or(U&& fallback) const& {
    return value_ ? *value_ : static_cast<T>(std::forward<U>(fallback));
  }

 private:
  std::optional<T> value_;
  std::optional<Error> error_;
};

/// Convenience for the common "return this refusal" shape.
[[nodiscard]] inline Error make_error(ErrorCode code, std::string detail) {
  return Error{code, std::move(detail)};
}

}  // namespace tenant_registry

#endif  // TENANT_REGISTRY_ERRORS_HPP
