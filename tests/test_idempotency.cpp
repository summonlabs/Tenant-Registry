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

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include "test_support.hpp"

namespace {

using tenant_registry::AccessMode;
using tenant_registry::ContentDigest;
using tenant_registry::CreateTenantRequest;
using tenant_registry::EphemeralOptions;
using tenant_registry::ErrorCode;
using tenant_registry::FixedClock;
using tenant_registry::IdempotencyKey;
using tenant_registry::JournalSequence;
using tenant_registry::LifecycleState;
using tenant_registry::MutationContext;
using tenant_registry::MutationReceipt;
using tenant_registry::OperationKind;
using tenant_registry::RecordRevision;
using tenant_registry::RegistryGeneration;
using tenant_registry::RegistryOpenRequest;
using tenant_registry::TenancyMetadata;
using tenant_registry::TenancySubject;
using tenant_registry::TenantRecord;
using tenant_registry::TenantRegistry;
using tenant_registry::TransitionSubjectRequest;

/// The actor every request in this suite states explicitly. The shared default
/// actor carries an empty provenance note, and a record whose note is empty
/// cannot be decoded back, so it could never be replayed or re-read from a
/// journal; stating the actor here keeps a failure about the ledger from being
/// a failure about the fixture.
MutationContext context(RegistryGeneration generation, std::optional<IdempotencyKey> key = std::nullopt) {
  return MutationContext{generation, std::move(key),
                         treg_test::provenance("idempotency-suite", "ledger-principal", 17,
                                               "declared by the idempotency suite")};
}

CreateTenantRequest tenant_request(RegistryGeneration generation, std::string_view text,
                                   std::optional<IdempotencyKey> key = std::nullopt) {
  return CreateTenantRequest{context(generation, std::move(key)), treg_test::tenant_id(text), std::nullopt,
                             std::nullopt, TenancyMetadata{}};
}

TenantRegistry ephemeral(RegistryGeneration* generation_out = nullptr) {
  EphemeralOptions options;
  options.clock = std::make_shared<FixedClock>(1'700'000'000'000);
  TenantRegistry registry = std::move(TenantRegistry::open_ephemeral(options).value());
  if (generation_out != nullptr) {
    *generation_out = registry.generation();
  }
  return registry;
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

RegistryOpenRequest open_request(const std::filesystem::path& root, AccessMode mode) {
  RegistryOpenRequest request;
  request.root = root;
  request.mode = mode;
  request.clock = std::make_shared<FixedClock>(1'700'000'000'000);
  return request;
}

}  // namespace

// ---------------------------------------------------------------------------
// A replay is the original answer, not a second execution.
// ---------------------------------------------------------------------------

TREG_TEST(idempotency, a_replay_returns_the_original_receipt_and_does_not_advance) {
  TenantRegistry registry = ephemeral();
  const RegistryGeneration start = registry.generation();
  const IdempotencyKey key = treg_test::idempotency_key("ledger-key-0001");
  const CreateTenantRequest request = tenant_request(start, "alpha", key);

  const auto first = registry.create_tenant(request);
  TREG_REQUIRE_OK(first);
  TREG_CHECK(!first.value().receipt.replayed);
  TREG_CHECK_EQ(first.value().receipt.operation, OperationKind::CreateTenant);
  TREG_CHECK_EQ(first.value().receipt.generation, RegistryGeneration::from_value(start.value() + 1));
  TREG_CHECK_EQ(first.value().receipt.sequence, JournalSequence::from_value(1));
  TREG_CHECK_EQ(first.value().receipt.revision, RecordRevision::from_value(1));
  const MutationReceipt original = first.value().receipt;
  const TenantRecord original_record = first.value().record;
  const RegistryGeneration after_first = registry.generation();
  TREG_CHECK_EQ(after_first, original.generation);

  // The registry moves on, which is exactly the situation in which a caller
  // whose response was lost comes back.
  TREG_REQUIRE_OK(registry.create_tenant(tenant_request(registry.generation(), "beta")));
  const RegistryGeneration after_second = registry.generation();
  TREG_CHECK(after_second.value() > after_first.value());

  const auto replay = registry.create_tenant(request);
  TREG_REQUIRE_OK(replay);
  TREG_CHECK(replay.value().receipt.replayed);
  TREG_CHECK_EQ(replay.value().receipt.generation, original.generation);
  TREG_CHECK_EQ(replay.value().receipt.sequence, original.sequence);
  TREG_CHECK_EQ(replay.value().receipt.revision, original.revision);
  TREG_CHECK_EQ(replay.value().receipt.operation, original.operation);
  TREG_CHECK_EQ(replay.value().receipt.request_digest, original.request_digest);
  TREG_CHECK_EQ(to_canonical(replay.value().record), to_canonical(original_record));

  // A replay is not progress: it must not move the registry, and it must not
  // rewrite the record it answers with.
  TREG_CHECK_EQ(registry.generation(), after_second);
  TREG_CHECK_EQ(registry.committed_sequence(), JournalSequence::from_value(2));
  TREG_CHECK_EQ(registry.find_tenant(treg_test::tenant_id("alpha")).value().revision,
                RecordRevision::from_value(1));
}

TREG_TEST(idempotency, a_replay_answers_with_the_record_as_it_was) {
  TenantRegistry registry = ephemeral();
  const IdempotencyKey key = treg_test::idempotency_key("ledger-key-0002");
  const CreateTenantRequest create = tenant_request(registry.generation(), "alpha", key);

  const auto created = registry.create_tenant(create);
  TREG_REQUIRE_OK(created);
  TREG_CHECK_EQ(created.value().record.state, LifecycleState::Declared);

  const TenantRecord before = registry.find_tenant(treg_test::tenant_id("alpha")).value();
  TREG_REQUIRE_OK(registry.transition_subject(TransitionSubjectRequest{
      context(registry.generation()), TenancySubject::of_tenant(before.id), before.revision,
      LifecycleState::Active}));
  const TenantRecord live = registry.find_tenant(treg_test::tenant_id("alpha")).value();
  TREG_CHECK_EQ(live.state, LifecycleState::Active);
  TREG_CHECK_EQ(live.revision, RecordRevision::from_value(2));

  // The ledger keeps the outcome as it was committed, so the lost answer comes
  // back exactly as it was produced and not as the record looks now.
  const auto replay = registry.create_tenant(create);
  TREG_REQUIRE_OK(replay);
  TREG_CHECK(replay.value().receipt.replayed);
  TREG_CHECK_EQ(replay.value().record.state, LifecycleState::Declared);
  TREG_CHECK_EQ(replay.value().record.revision, RecordRevision::from_value(1));
  TREG_CHECK_EQ(to_canonical(replay.value().record), to_canonical(created.value().record));

  // And the live state is untouched by having been replayed.
  TREG_CHECK_EQ(registry.find_tenant(treg_test::tenant_id("alpha")).value().state, LifecycleState::Active);
  TREG_CHECK_EQ(registry.find_tenant(treg_test::tenant_id("alpha")).value().revision,
                RecordRevision::from_value(2));
}

// ---------------------------------------------------------------------------
// One key identifies one request and nothing else.
// ---------------------------------------------------------------------------

TREG_TEST(idempotency, the_same_key_with_a_different_request_is_refused) {
  TenantRegistry registry = ephemeral();
  const IdempotencyKey key = treg_test::idempotency_key("ledger-key-0003");
  TREG_REQUIRE_OK(registry.create_tenant(tenant_request(registry.generation(), "alpha", key)));
  const RegistryGeneration committed = registry.generation();
  const std::string before = registry.snapshot().digest().to_text();

  // A different identity under the same key is a different question.
  const auto other_identity =
      registry.create_tenant(tenant_request(registry.generation(), "beta", key));
  TREG_CHECK_CODE(other_identity, ErrorCode::IdempotencyKeyReused);

  // The same identity, the same key, but composed against a different
  // generation, is also a different request: the digest binds the whole
  // request, including the state the caller says it saw.
  const auto other_generation =
      registry.create_tenant(tenant_request(registry.generation(), "alpha", key));
  TREG_CHECK_CODE(other_generation, ErrorCode::IdempotencyKeyReused);

  TREG_CHECK_EQ(registry.generation(), committed);
  TREG_CHECK_EQ(registry.snapshot().digest().to_text(), before);
  TREG_CHECK(!registry.find_tenant(treg_test::tenant_id("beta")).has_value());
}

TREG_TEST(idempotency, a_refused_request_does_not_consume_its_key) {
  TenantRegistry registry = ephemeral();
  TREG_REQUIRE_OK(registry.create_tenant(tenant_request(registry.generation(), "alpha")));

  const IdempotencyKey key = treg_test::idempotency_key("ledger-key-0004");
  const auto refused = registry.create_tenant(tenant_request(registry.generation(), "alpha", key));
  TREG_CHECK_CODE(refused, ErrorCode::IdentityAlreadyExists);

  // Nothing was committed, so nothing was promised: the key is still free, and
  // a caller that retries with a corrected request must not be told that its
  // key was already used.
  const CreateTenantRequest corrected = tenant_request(registry.generation(), "beta", key);
  const auto accepted = registry.create_tenant(corrected);
  TREG_REQUIRE_OK(accepted);
  TREG_CHECK(!accepted.value().receipt.replayed);

  const auto replay = registry.create_tenant(corrected);
  TREG_REQUIRE_OK(replay);
  TREG_CHECK(replay.value().receipt.replayed);
  TREG_CHECK_EQ(replay.value().receipt.generation, accepted.value().receipt.generation);
  TREG_CHECK_EQ(to_canonical(replay.value().record), to_canonical(accepted.value().record));
}

// ---------------------------------------------------------------------------
// A request without a key is never a replay.
// ---------------------------------------------------------------------------

TREG_TEST(idempotency, a_request_without_a_key_is_never_a_replay) {
  TenantRegistry registry = ephemeral();
  const CreateTenantRequest create = tenant_request(RegistryGeneration::initial(), "alpha");

  const auto first = registry.create_tenant(create);
  TREG_REQUIRE_OK(first);
  TREG_CHECK(!first.value().receipt.replayed);
  const RegistryGeneration committed = registry.generation();
  const std::string before = registry.snapshot().digest().to_text();

  // Byte for byte the same request, no key: it is a new question, and the
  // answer is that the registry has moved on and the identity now exists.
  const auto repeated = registry.create_tenant(create);
  TREG_CHECK_CODE(repeated, ErrorCode::StaleGeneration);
  TREG_CHECK_EQ(registry.generation(), committed);
  TREG_CHECK_EQ(registry.snapshot().digest().to_text(), before);
  TREG_CHECK_EQ(registry.find_tenant(treg_test::tenant_id("alpha")).value().revision,
                RecordRevision::from_value(1));

  // With the current generation the same unkeyed request is re-executed rather
  // than answered from a ledger, and re-execution collides with the live record.
  const auto reexecuted = registry.create_tenant(tenant_request(registry.generation(), "alpha"));
  TREG_CHECK_CODE(reexecuted, ErrorCode::IdentityAlreadyExists);
  TREG_CHECK_EQ(registry.generation(), committed);

  const auto transition = registry.transition_subject(TransitionSubjectRequest{
      context(registry.generation()), TenancySubject::of_tenant(treg_test::tenant_id("alpha")),
      RecordRevision::from_value(1), LifecycleState::Active});
  TREG_REQUIRE_OK(transition);
  TREG_CHECK(!transition.value().receipt.replayed);

  const auto transition_again = registry.transition_subject(TransitionSubjectRequest{
      context(RegistryGeneration::from_value(registry.generation().value() - 1)),
      TenancySubject::of_tenant(treg_test::tenant_id("alpha")), RecordRevision::from_value(1),
      LifecycleState::Active});
  TREG_CHECK_CODE(transition_again, ErrorCode::StaleGeneration);
}

// ---------------------------------------------------------------------------
// The ledger is bounded, and refuses rather than losing the ability to replay.
// ---------------------------------------------------------------------------

TREG_TEST(idempotency, the_ledger_is_bounded_and_refuses_rather_than_double_applying) {
  EphemeralOptions options;
  options.clock = std::make_shared<FixedClock>(1'700'000'000'000);
  options.limits.max_idempotency_entries = 2;
  TenantRegistry registry = std::move(TenantRegistry::open_ephemeral(options).value());

  const CreateTenantRequest first = tenant_request(registry.generation(), "alpha",
                                                   treg_test::idempotency_key("ledger-key-0005"));
  const auto first_outcome = registry.create_tenant(first);
  TREG_REQUIRE_OK(first_outcome);
  const CreateTenantRequest second = tenant_request(registry.generation(), "beta",
                                                    treg_test::idempotency_key("ledger-key-0006"));
  const auto second_outcome = registry.create_tenant(second);
  TREG_REQUIRE_OK(second_outcome);
  TREG_CHECK_EQ(registry.generation(), RegistryGeneration::from_value(2));

  const std::string before = registry.snapshot().digest().to_text();
  const auto overflow = registry.create_tenant(tenant_request(registry.generation(), "gamma",
                                                              treg_test::idempotency_key("ledger-key-0007")));
  TREG_CHECK_CODE(overflow, ErrorCode::IdempotencyLedgerFull);

  // Refusing to accept a new key must not apply anything: a ledger entry that
  // cannot be written is not a mutation that happened.
  TREG_CHECK_EQ(registry.generation(), RegistryGeneration::from_value(2));
  TREG_CHECK_EQ(registry.snapshot().digest().to_text(), before);
  TREG_CHECK(!registry.find_tenant(treg_test::tenant_id("gamma")).has_value());

  // The keys already held still answer, and replaying them costs no space.
  const auto first_replay = registry.create_tenant(first);
  TREG_REQUIRE_OK(first_replay);
  TREG_CHECK(first_replay.value().receipt.replayed);
  TREG_CHECK_EQ(first_replay.value().receipt.generation, first_outcome.value().receipt.generation);
  const auto second_replay = registry.create_tenant(second);
  TREG_REQUIRE_OK(second_replay);
  TREG_CHECK(second_replay.value().receipt.replayed);
  TREG_CHECK_EQ(registry.generation(), RegistryGeneration::from_value(2));

  // An unkeyed mutation is still allowed: the bound is on retained keys, not on
  // the ability of a caller that does not want replay protection to proceed.
  const auto unkeyed = registry.create_tenant(tenant_request(registry.generation(), "delta"));
  TREG_REQUIRE_OK(unkeyed);
  TREG_CHECK_EQ(registry.generation(), RegistryGeneration::from_value(3));

  // And the ledger is still full, so the next new key is refused too.
  const auto still_full = registry.create_tenant(tenant_request(registry.generation(), "epsilon",
                                                               treg_test::idempotency_key("ledger-key-0008")));
  TREG_CHECK_CODE(still_full, ErrorCode::IdempotencyLedgerFull);
  TREG_CHECK(!registry.find_tenant(treg_test::tenant_id("epsilon")).has_value());
}

// ---------------------------------------------------------------------------
// The ledger is rebuilt from the log, so a replay survives a restart.
// ---------------------------------------------------------------------------

TREG_TEST(idempotency, a_replay_survives_a_durable_close_and_reopen) {
  const TempTree tree{treg_test::make_temp_directory("idempotency-reopen")};
  const IdempotencyKey key = treg_test::idempotency_key("ledger-key-0009");

  ContentDigest request_digest;
  RegistryGeneration original_generation = RegistryGeneration::initial();
  JournalSequence original_sequence = JournalSequence::initial();
  std::string original_record;

  {
    auto opened = TenantRegistry::open(open_request(tree.path(), AccessMode::ReadWrite));
    TREG_REQUIRE_OK(opened);
    TenantRegistry registry = std::move(opened).value();
    const CreateTenantRequest request = tenant_request(registry.generation(), "alpha", key);
    const auto created = registry.create_tenant(request);
    TREG_REQUIRE_OK(created);
    request_digest = created.value().receipt.request_digest;
    original_generation = created.value().receipt.generation;
    original_sequence = created.value().receipt.sequence;
    original_record = to_canonical(created.value().record);

    TREG_REQUIRE_OK(registry.create_tenant(tenant_request(registry.generation(), "beta")));
    TREG_CHECK_EQ(registry.generation(), RegistryGeneration::from_value(2));
    TREG_REQUIRE(registry.close().ok());
  }

  {
    auto reopened = TenantRegistry::open(open_request(tree.path(), AccessMode::ReadWrite));
    TREG_REQUIRE_OK(reopened);
    TenantRegistry registry = std::move(reopened).value();
    TREG_CHECK_EQ(registry.generation(), RegistryGeneration::from_value(2));
    TREG_CHECK_EQ(registry.committed_sequence(), JournalSequence::from_value(2));

    // The ledger is not a side file that could be lost: it is derived from the
    // same frames that carry the state, so a restart cannot lose it.
    const auto replay = registry.create_tenant(tenant_request(RegistryGeneration::initial(), "alpha", key));
    TREG_REQUIRE_OK(replay);
    TREG_CHECK(replay.value().receipt.replayed);
    TREG_CHECK_EQ(replay.value().receipt.generation, original_generation);
    TREG_CHECK_EQ(replay.value().receipt.sequence, original_sequence);
    TREG_CHECK_EQ(replay.value().receipt.request_digest, request_digest);
    TREG_CHECK_EQ(to_canonical(replay.value().record), original_record);
    TREG_CHECK_EQ(registry.generation(), RegistryGeneration::from_value(2));

    // A fresh key still works after the restart, so the rebuilt ledger is live
    // and not a read-only relic.
    const auto keyed = registry.create_tenant(tenant_request(registry.generation(), "gamma",
                                                            treg_test::idempotency_key("ledger-key-0010")));
    TREG_REQUIRE_OK(keyed);
    TREG_CHECK(!keyed.value().receipt.replayed);
    TREG_REQUIRE(registry.close().ok());
  }
}