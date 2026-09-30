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
#include <fstream>
#include <string>
#include <vector>

#include "test_support.hpp"

namespace treg_test {
namespace {

namespace layout = tenant_registry::store_layout;

[[nodiscard]] std::filesystem::path manifest_path(const std::filesystem::path& root) {
  return root / std::string{layout::kManifestFileName};
}

[[nodiscard]] std::filesystem::path lock_path(const std::filesystem::path& root) {
  return root / std::string{layout::kLockFileName};
}

[[nodiscard]] bool file_exists(const std::filesystem::path& path) {
  std::error_code error;
  return std::filesystem::exists(path, error);
}

[[nodiscard]] std::vector<std::filesystem::path> journals(const std::filesystem::path& root) {
  std::vector<std::filesystem::path> found;
  std::error_code error;
  for (const auto& entry : std::filesystem::directory_iterator{root, error}) {
    std::uint64_t ordinal = 0;
    if (layout::parse_journal_file_name(entry.path().filename().string(), ordinal)) {
      found.push_back(entry.path());
    }
  }
  return found;
}

[[nodiscard]] Result<TenantRegistry> open_durable(const std::filesystem::path& root, bool read_only,
                                                  tenant_registry::StoreOptions store = {}) {
  RegistryOpenRequest request;
  request.root = root;
  request.mode = read_only ? tenant_registry::AccessMode::ReadOnly : tenant_registry::AccessMode::ReadWrite;
  request.store = std::move(store);
  request.clock = std::make_shared<FixedClock>(1'700'000'000'000);
  return TenantRegistry::open(request);
}

}  // namespace

TREG_TEST(persistence, a_new_store_creates_exactly_its_three_files) {
  const auto root = make_temp_directory("persist-create");
  {
    Harness harness = Harness::durable(root);
    TREG_CHECK_EQ(harness.registry().durable(), true);
    TREG_CHECK(harness.registry().store_identity().has_value());
    TREG_CHECK_EQ(harness.registry().committed_sequence().value(), std::uint64_t{0});
    TREG_CHECK(file_exists(manifest_path(root)));
    TREG_CHECK(file_exists(lock_path(root)));
    TREG_CHECK_EQ(journals(root).size(), std::size_t{1});
    TREG_CHECK(harness.registry().recovery_report().store_created);
  }
  remove_tree(root);
}

TREG_TEST(persistence, state_and_authority_survive_a_close_and_reopen) {
  const auto root = make_temp_directory("persist-reopen");
  std::string before;
  RegistryGeneration generation_before;
  ControlEpoch epoch_before;
  ContentDigest store_id;
  {
    Harness harness = Harness::durable(root);
    harness.active_tenant("acme");
    harness.active_service("renderer");
    harness.active_domain("zone-a", IsolationClass::FaultContainment);
    harness.bind("renderer", "acme");
    harness.join(tenant_subject("acme"), "zone-a");
    before = harness.snapshot().digest().to_text();
    generation_before = harness.generation();
    epoch_before = harness.registry().control_epoch();
    store_id = harness.registry().store_identity()->id;
    require_ok(harness.registry().close(), "close");
  }
  {
    Harness harness = Harness::durable(root);
    TREG_CHECK_EQ(harness.snapshot().digest().to_text(), before);
    TREG_CHECK_EQ(harness.generation(), generation_before);
    TREG_CHECK_EQ(harness.registry().store_identity()->id, store_id);
    // Taking control is what fences the previous writer, so the epoch must move
    // forward on every read-write open.
    TREG_CHECK(harness.registry().control_epoch() > epoch_before);
    TREG_CHECK(harness.registry().recovery_report().manifest_present);
    TREG_CHECK_EQ(harness.registry().recovery_report().uncommitted_tail_discarded, false);
    TREG_CHECK(harness.registry().recovery_report().previous_control_epoch.has_value());
    TREG_CHECK_EQ(*harness.registry().recovery_report().previous_control_epoch, epoch_before);
  }
  remove_tree(root);
}

TREG_TEST(persistence, the_incarnation_is_never_reused) {
  const auto root = make_temp_directory("persist-incarnation");
  Incarnation first;
  Incarnation second;
  {
    Harness harness = Harness::durable(root);
    first = harness.registry().incarnation();
  }
  {
    Harness harness = Harness::durable(root);
    second = harness.registry().incarnation();
  }
  TREG_CHECK(first != second);
  remove_tree(root);
}

TREG_TEST(persistence, a_read_only_session_sees_the_state_and_changes_nothing) {
  const auto root = make_temp_directory("persist-readonly");
  std::string expected;
  {
    Harness harness = Harness::durable(root);
    harness.active_tenant("acme");
    expected = harness.snapshot().digest().to_text();
  }
  {
    Harness harness = Harness::durable(root, RegistryLimits{}, {}, true);
    TREG_CHECK_EQ(harness.registry().access_mode(), tenant_registry::AccessMode::ReadOnly);
    TREG_CHECK_EQ(harness.snapshot().digest().to_text(), expected);
    TREG_CHECK_EQ(harness.registry().recovery_report().read_only, true);

    const CreateTenantRequest request{context(harness.generation()), tenant_id("other"), std::nullopt, std::nullopt,
                                      tenant_registry::TenancyMetadata{}};
    TREG_CHECK_CODE(harness.registry().create_tenant(request), tenant_registry::ErrorCode::StoreNotWritable);

    const tenant_registry::TombstoneRequest fence{
        context(harness.generation()), tenant_subject("acme"), harness.tenant("acme").revision,
        tenant_registry::IrreversibleAcknowledgement::acknowledged(), std::nullopt, std::string{"fenced"}};
    TREG_CHECK_CODE(harness.registry().tombstone(fence), tenant_registry::ErrorCode::StoreNotWritable);

    TREG_CHECK_STATUS(harness.registry().flush(), tenant_registry::ErrorCode::StoreNotWritable);
    TREG_CHECK_STATUS(harness.registry().compact(), tenant_registry::ErrorCode::StoreNotWritable);
    TREG_CHECK_EQ(harness.snapshot().digest().to_text(), expected);
  }
  remove_tree(root);
}

TREG_TEST(persistence, a_read_only_open_never_creates_a_store) {
  const auto root = make_temp_directory("persist-readonly-missing");
  auto opened = open_durable(root, true);
  TREG_CHECK_CODE(opened, tenant_registry::ErrorCode::StoreNotFound);
  TREG_CHECK_EQ(file_exists(manifest_path(root)), false);
  TREG_CHECK_EQ(journals(root).size(), std::size_t{0});
  remove_tree(root);
}

TREG_TEST(persistence, the_store_identity_can_be_pinned) {
  const auto root = make_temp_directory("persist-pin");
  ContentDigest identity;
  {
    Harness harness = Harness::durable(root);
    identity = harness.registry().store_identity()->id;
  }
  tenant_registry::StoreOptions pinned;
  pinned.expected_store_id = identity;
  {
    Harness harness = Harness::durable(root, RegistryLimits{}, pinned);
    TREG_CHECK_EQ(harness.registry().store_identity()->id, identity);
  }
  tenant_registry::StoreOptions wrong;
  wrong.expected_store_id = ContentDigest::zero();
  auto refused = open_durable(root, false, wrong);
  TREG_CHECK_CODE(refused, tenant_registry::ErrorCode::StoreIdentityMismatch);
  remove_tree(root);
}

TREG_TEST(persistence, rollback_protection_refuses_a_store_below_the_floor) {
  const auto root = make_temp_directory("persist-rollback");
  RegistryGeneration reached;
  {
    Harness harness = Harness::durable(root);
    harness.create_tenant("acme");
    harness.create_tenant("other");
    reached = harness.generation();
  }
  tenant_registry::StoreOptions floor;
  floor.min_committed_generation = RegistryGeneration::from_value(reached.value() + 1);
  auto refused = open_durable(root, false, floor);
  TREG_CHECK_CODE(refused, tenant_registry::ErrorCode::StoreRolledBack);

  tenant_registry::StoreOptions satisfied;
  satisfied.min_committed_generation = reached;
  {
    Harness harness = Harness::durable(root, RegistryLimits{}, satisfied);
    TREG_CHECK_EQ(harness.generation(), reached);
  }
  remove_tree(root);
}

TREG_TEST(persistence, compaction_preserves_the_state_exactly) {
  const auto root = make_temp_directory("persist-compact");
  std::string expected;
  RegistryGeneration generation;
  {
    Harness harness = Harness::durable(root);
    harness.active_tenant("acme");
    harness.active_tenant("beta");
    harness.active_service("renderer");
    harness.own("beta", "acme");
    expected = harness.snapshot().digest().to_text();
    generation = harness.generation();
    require_ok(harness.registry().compact(), "compact");
    TREG_CHECK_EQ(harness.snapshot().digest().to_text(), expected);
  }
  {
    Harness harness = Harness::durable(root);
    TREG_CHECK_EQ(harness.snapshot().digest().to_text(), expected);
    TREG_CHECK_EQ(harness.generation(), generation);
    TREG_CHECK_EQ(harness.tenant("beta").state, LifecycleState::Active);
    TREG_CHECK_EQ(harness.registry().recovery_report().baseline_frames, std::uint64_t{1});
  }
  // A mutation after compaction must still be appended and replayed on top of
  // the baseline.
  {
    Harness harness = Harness::durable(root);
    harness.create_tenant("gamma");
  }
  {
    Harness harness = Harness::durable(root);
    TREG_CHECK_EQ(harness.tenant("gamma").state, LifecycleState::Declared);
    TREG_CHECK_EQ(harness.snapshot().tenants.size(), std::size_t{3});
  }
  remove_tree(root);
}

TREG_TEST(persistence, compaction_replaces_the_journal_rather_than_appending_to_it) {
  const auto root = make_temp_directory("persist-compact-journal");
  std::uintmax_t before = 0;
  {
    Harness harness = Harness::durable(root);
    for (int index = 0; index < 20; ++index) {
      harness.create_tenant("tenant-" + std::to_string(index));
    }
    const auto found = journals(root);
    TREG_REQUIRE(found.size() == 1);
    before = std::filesystem::file_size(found.front());
    require_ok(harness.registry().compact(), "compact");
    const auto after = journals(root);
    TREG_REQUIRE(after.size() == 1);
    TREG_CHECK(std::filesystem::file_size(after.front()) < before);
  }
  {
    Harness harness = Harness::durable(root);
    TREG_CHECK_EQ(harness.snapshot().tenants.size(), std::size_t{20});
  }
  remove_tree(root);
}

TREG_TEST(persistence, flush_succeeds_on_a_writable_session_and_close_is_idempotent) {
  const auto root = make_temp_directory("persist-close");
  {
    Harness harness = Harness::durable(root);
    harness.create_tenant("acme");
    require_ok(harness.registry().flush(), "flush");
    require_ok(harness.registry().close(), "close");
    require_ok(harness.registry().close(), "second close");
    TREG_CHECK_EQ(harness.registry().valid(), false);

    const CreateTenantRequest request{context(harness.generation()), tenant_id("after-close"), std::nullopt,
                                      std::nullopt, tenant_registry::TenancyMetadata{}};
    TREG_CHECK_CODE(harness.registry().create_tenant(request), tenant_registry::ErrorCode::StoreClosed);
    // A closed session answers nothing at all: presenting state whose owner
    // has released the store would suggest an authority that is no longer held.
    TREG_CHECK_CODE(harness.registry().find_tenant(tenant_id("acme")), tenant_registry::ErrorCode::StoreClosed);
  }
  // The lock must have been released, so a fresh session can take control.
  {
    Harness harness = Harness::durable(root);
    TREG_CHECK_EQ(harness.tenant("acme").state, LifecycleState::Declared);
  }
  remove_tree(root);
}

TREG_TEST(persistence, the_holder_note_is_written_to_the_lock_but_is_never_an_authority) {
  const auto root = make_temp_directory("persist-holder");
  tenant_registry::StoreOptions options;
  options.holder_note = "operator-session-7";
  {
    Harness harness = Harness::durable(root, RegistryLimits{}, options);
    harness.create_tenant("acme");
    // The note exists so an operator can see who holds a store. It is evidence
    // for a human and it authorizes nothing: the state it produced is the same
    // state any other holder note would have produced.
    std::ifstream reader{lock_path(root), std::ios::binary};
    TREG_REQUIRE(reader.good());
    const std::string contents{std::istreambuf_iterator<char>{reader}, std::istreambuf_iterator<char>{}};
    TREG_CHECK(contents.find("operator-session-7") != std::string::npos);
  }
  {
    Harness harness = Harness::durable(root);
    TREG_CHECK_EQ(harness.tenant("acme").state, LifecycleState::Declared);
  }
  remove_tree(root);
}

}  // namespace treg_test
