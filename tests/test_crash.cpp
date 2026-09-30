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
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "test_process.hpp"
#include "test_support.hpp"

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace treg_test {
namespace {

/// Ends this process immediately, with no cleanup of any kind: no destructors,
/// no flushing of buffered streams, no releasing of handles by this code. The
/// operating system releases everything the process held, which is exactly the
/// situation a crash produces and exactly the situation the durability claim
/// has to survive.
[[noreturn]] void abrupt_exit() noexcept {
#if defined(_WIN32)
  TerminateProcess(GetCurrentProcess(), static_cast<UINT>(0x0DEAD));
  std::abort();
#else
  // _exit skips atexit handlers and stream flushing just as TerminateProcess
  // does; the kernel still closes every descriptor.
  ::_exit(3);
#endif
}

struct StageToken {
  tenant_registry::PublishStage stage;
  std::string_view token;
};

constexpr StageToken kStages[] = {
    {tenant_registry::PublishStage::BeforeJournalAppend, "before_journal_append"},
    {tenant_registry::PublishStage::AfterJournalAppendBeforeFlush, "after_journal_append_before_flush"},
    {tenant_registry::PublishStage::AfterJournalFlush, "after_journal_flush"},
    {tenant_registry::PublishStage::AfterReadBackVerify, "after_read_back_verify"},
    {tenant_registry::PublishStage::BeforeManifestPublish, "before_manifest_publish"},
    {tenant_registry::PublishStage::AfterManifestPublish, "after_manifest_publish"},
};

[[nodiscard]] bool parse_stage(std::string_view token, tenant_registry::PublishStage& out) {
  for (const auto& entry : kStages) {
    if (entry.token == token) {
      out = entry.stage;
      return true;
    }
  }
  return false;
}

/// The child performs exactly one mutation and dies at one named stage of the
/// commit protocol. Arguments: <root> <stage> <tenant-id>.
int crash_child(const std::vector<std::string>& arguments) {
  if (arguments.size() != 3) {
    std::fprintf(stderr, "crash-at needs <root> <stage> <tenant>\n");
    return 64;
  }
  tenant_registry::PublishStage stage = tenant_registry::PublishStage::Unspecified;
  if (!parse_stage(arguments[1], stage)) {
    std::fprintf(stderr, "unknown publish stage '%s'\n", arguments[1].c_str());
    return 64;
  }
  if (!TenantId::create(arguments[2])) {
    std::fprintf(stderr, "crash-at was given an identity that is not a valid tenant identity\n");
    return 64;
  }

  RegistryOpenRequest request;
  request.root = std::filesystem::path{arguments[0]};
  request.mode = tenant_registry::AccessMode::ReadWrite;
  request.clock = std::make_shared<FixedClock>(1'700'000'000'000);
  request.store.faults.at_stage = [stage](tenant_registry::PublishStage reached) {
    if (reached == stage) {
      abrupt_exit();
    }
  };

  auto registry = TenantRegistry::open(request);
  if (!registry) {
    std::fprintf(stderr, "child could not open the store: %s\n",
                 std::string{tenant_registry::to_token(registry.error().code())}.c_str());
    return 2;
  }

  const CreateTenantRequest create{context(registry.value().generation()), tenant_id(arguments[2]), std::nullopt,
                                   std::nullopt, tenant_registry::TenancyMetadata{}};
  auto outcome = registry.value().create_tenant(create);
  if (!outcome) {
    std::fprintf(stderr, "child mutation was refused: %s\n",
                 std::string{tenant_registry::to_token(outcome.error().code())}.c_str());
    return 3;
  }
  return 0;
}

struct CrashModeRegistrar {
  CrashModeRegistrar() { register_child_mode("crash-at", crash_child); }
};

const CrashModeRegistrar kCrashModeRegistrar{};

[[nodiscard]] Result<TenantRegistry> open_store(const std::filesystem::path& root) {
  RegistryOpenRequest request;
  request.root = root;
  request.mode = tenant_registry::AccessMode::ReadWrite;
  request.clock = std::make_shared<FixedClock>(1'700'000'000'000);
  return TenantRegistry::open(request);
}

}  // namespace

TREG_TEST(crash, every_commit_stage_leaves_a_store_that_reopens_to_exactly_one_of_two_states) {
  for (const auto& entry : kStages) {
    const std::filesystem::path root = make_temp_directory(std::string{"crash-"} + std::string{entry.token});
    RegistryGeneration seeded;
    {
      Harness harness = Harness::durable(root);
      harness.create_tenant("seed");
      seeded = harness.generation();
      require_ok(harness.registry().close(), "close");
    }

    const int code = run_child({"--child", "crash-at", root.string(), std::string{entry.token}, "crash-tenant"});
    TREG_CHECK(code != 0);

    auto reopened = open_store(root);
    if (!reopened) {
      // A refusal here means the crash produced a store the reader will not
      // accept, which is a failure of the durability claim and not of the test.
      fail_now("stage " + std::string{entry.token} + " left a store that could not be reopened: " +
               std::string{tenant_registry::to_token(reopened.error().code())} + ": " + reopened.error().detail());
    }
    TenantRegistry& registry = reopened.value();
    const bool present = registry.find_tenant(tenant_id("crash-tenant")).has_value();

    if (entry.stage == tenant_registry::PublishStage::AfterManifestPublish) {
      // The manifest named the frame, so the commit happened even though the
      // caller never received an answer. The state after the commit is the only
      // honest answer, and it is one of the two allowed outcomes.
      TREG_CHECK_EQ(present, true);
      TREG_CHECK_EQ(registry.generation().value(), seeded.value() + 1);
    } else {
      // The manifest never named the frame, so the commit did not happen and
      // the mutation must be absent. A partial state is not among the outcomes.
      TREG_CHECK_EQ(present, false);
      TREG_CHECK_EQ(registry.generation(), seeded);
    }
    TREG_CHECK_EQ(registry.snapshot().tenants.size(), present ? std::size_t{2} : std::size_t{1});

    // The store must be usable afterwards, which is what proves the crash left
    // no fence, no half written frame and no held lock behind it.
    const CreateTenantRequest after{context(registry.generation()), tenant_id("after-crash"), std::nullopt,
                                    std::nullopt, tenant_registry::TenancyMetadata{}};
    TREG_REQUIRE_OK(registry.create_tenant(after));
    require_ok(registry.close(), "close");

    remove_tree(root);
  }
}

TREG_TEST(crash, a_crash_before_any_commit_leaves_the_seeded_state_untouched) {
  const auto root = make_temp_directory("crash-seed-only");
  std::string expected;
  {
    Harness harness = Harness::durable(root);
    harness.active_tenant("acme");
    harness.active_service("renderer");
    expected = harness.snapshot().digest().to_text();
    require_ok(harness.registry().close(), "close");
  }

  const int code = run_child({"--child", "crash-at", root.string(), "before_journal_append", "never"});
  TREG_CHECK(code != 0);

  {
    Harness harness = Harness::durable(root);
    TREG_CHECK_EQ(harness.snapshot().digest().to_text(), expected);
    TREG_CHECK_EQ(harness.registry().recovery_report().uncommitted_tail_discarded, false);
  }
  remove_tree(root);
}

TREG_TEST(crash, a_crash_after_the_manifest_publish_is_observable_and_then_reconciled) {
  const auto root = make_temp_directory("crash-published");
  {
    Harness harness = Harness::durable(root);
    harness.create_tenant("seed");
    require_ok(harness.registry().close(), "close");
  }

  const int code = run_child({"--child", "crash-at", root.string(), "after_manifest_publish", "committed"});
  TREG_CHECK(code != 0);

  {
    // The caller never saw an answer, so the only safe reading is the state the
    // durable store actually reaches. The registry does not guess and does not
    // invent a rollback for a commit that was published.
    Harness harness = Harness::durable(root);
    TREG_CHECK(harness.registry().find_tenant(tenant_id("committed")).has_value());
    TREG_CHECK_EQ(harness.registry().recovery_report().uncommitted_tail_discarded, false);
    TREG_CHECK_EQ(harness.snapshot().tenants.size(), std::size_t{2});
  }
  remove_tree(root);
}

}  // namespace treg_test
