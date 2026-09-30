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

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "test_process.hpp"
#include "test_support.hpp"

namespace treg_test {
namespace {

/// Exit codes the child modes use. The parent asserts on them, so they are
/// distinct and stable.
constexpr int kChildRefusedByLock = 7;
constexpr int kChildBadArguments = 64;

[[nodiscard]] Result<TenantRegistry> open_store(const std::filesystem::path& root,
                                                tenant_registry::AccessMode mode) {
  RegistryOpenRequest request;
  request.root = root;
  request.mode = mode;
  request.clock = std::make_shared<FixedClock>(1'700'000'000'000);
  return TenantRegistry::open(request);
}

void write_marker(const std::string& path, const std::string& text) {
  std::ofstream writer{path, std::ios::binary | std::ios::trunc};
  writer << text;
  writer.flush();
}

/// Opens the store read-write, announces that it holds the writer lock, and
/// then does nothing at all until it is killed. It exists so that a real second
/// process can be shown to be refused, and so that the kernel released lock can
/// be shown after that process is killed without any cleanup.
int hold_lock_child(const std::vector<std::string>& arguments) {
  if (arguments.size() != 2) {
    return kChildBadArguments;
  }
  auto registry = open_store(std::filesystem::path{arguments[0]}, tenant_registry::AccessMode::ReadWrite);
  if (!registry) {
    return tenant_registry::to_token(registry.error().code()) == std::string_view{"store_locked"}
               ? kChildRefusedByLock
               : 5;
  }
  write_marker(arguments[1], "holding");
  for (;;) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
}

/// Attempts one write. Refusal by the writer lock is reported with its own exit
/// code so the parent can tell "someone else holds it" apart from a real
/// failure.
int try_write_child(const std::vector<std::string>& arguments) {
  if (arguments.size() != 2) {
    return kChildBadArguments;
  }
  auto registry = open_store(std::filesystem::path{arguments[0]}, tenant_registry::AccessMode::ReadWrite);
  if (!registry) {
    return registry.error().code() == tenant_registry::ErrorCode::StoreLocked ? kChildRefusedByLock : 5;
  }
  const CreateTenantRequest request{context(registry.value().generation()), tenant_id(arguments[1]), std::nullopt,
                                    std::nullopt, tenant_registry::TenancyMetadata{}};
  auto outcome = registry.value().create_tenant(request);
  if (!outcome) {
    return 6;
  }
  return 0;
}

/// Reads the committed generation and state digest from a read-only session and
/// writes them to a file, so the parent can compare them without a pipe.
int report_child(const std::vector<std::string>& arguments) {
  if (arguments.size() != 2) {
    return kChildBadArguments;
  }
  auto registry = open_store(std::filesystem::path{arguments[0]}, tenant_registry::AccessMode::ReadOnly);
  if (!registry) {
    return 5;
  }
  std::string text;
  text.append("generation=").append(std::to_string(registry.value().generation().value()));
  text.append(" digest=").append(registry.value().snapshot().digest().to_text());
  text.append(" read_only=").append(registry.value().recovery_report().read_only ? "true" : "false");
  write_marker(arguments[1], text);
  return 0;
}

struct MultiprocessModeRegistrar {
  MultiprocessModeRegistrar() {
    register_child_mode("hold-lock", hold_lock_child);
    register_child_mode("try-write", try_write_child);
    register_child_mode("report", report_child);
  }
};

const MultiprocessModeRegistrar kMultiprocessModeRegistrar{};

}  // namespace

TREG_TEST(multiprocess, a_second_writer_is_refused_while_the_first_holds_the_lock) {
  const auto root = make_temp_directory("mp-exclusion");
  const auto marker = (root / "ready.txt").string();
  {
    Harness harness = Harness::durable(root);
    harness.create_tenant("seed");
    require_ok(harness.registry().close(), "close");
  }

  std::string start_error;
  ChildProcess holder = ChildProcess::start({"--child", "hold-lock", root.string(), marker}, start_error);
  TREG_REQUIRE(holder.started());
  TREG_REQUIRE(wait_for_file(marker, 30'000));

  // The holder is a real, independent process. The refusal below is the
  // operating system refusing a second writer, not this process refusing
  // itself.
  auto refused = open_store(root, tenant_registry::AccessMode::ReadWrite);
  TREG_REQUIRE(!refused);
  TREG_CHECK_EQ(refused.error().code(), tenant_registry::ErrorCode::StoreLocked);

  const int child_code = run_child({"--child", "try-write", root.string(), "from-child"});
  TREG_CHECK_EQ(child_code, kChildRefusedByLock);

  holder.terminate();
  holder.wait();
  remove_tree(root);
}

TREG_TEST(multiprocess, the_kernel_releases_the_lock_when_the_holder_dies_without_cleanup) {
  const auto root = make_temp_directory("mp-kernel-release");
  const auto marker = (root / "ready.txt").string();
  RegistryGeneration seeded;
  {
    Harness harness = Harness::durable(root);
    harness.create_tenant("seed");
    seeded = harness.generation();
    require_ok(harness.registry().close(), "close");
  }

  std::string start_error;
  ChildProcess holder = ChildProcess::start({"--child", "hold-lock", root.string(), marker}, start_error);
  TREG_REQUIRE(holder.started());
  TREG_REQUIRE(wait_for_file(marker, 30'000));
  TREG_REQUIRE(!open_store(root, tenant_registry::AccessMode::ReadWrite));

  // Killed with no chance to run a destructor, close a handle or release
  // anything. The lock must still be gone, because the kernel owns it.
  holder.terminate();
  holder.wait();

  auto reopened = open_store(root, tenant_registry::AccessMode::ReadWrite);
  TREG_REQUIRE(reopened.has_value());
  TREG_CHECK_EQ(reopened.value().generation(), seeded);
  TREG_CHECK(reopened.value().find_tenant(tenant_id("seed")).has_value());
  require_ok(reopened.value().close(), "close");
  remove_tree(root);
}

TREG_TEST(multiprocess, a_read_only_session_inspects_while_a_writer_holds_the_lock) {
  const auto root = make_temp_directory("mp-readonly");
  const auto holder_marker = (root / "holder.txt").string();
  const auto report_path = (root / "report.txt").string();
  std::string expected_digest;
  {
    Harness harness = Harness::durable(root);
    harness.active_tenant("acme");
    expected_digest = harness.snapshot().digest().to_text();
    require_ok(harness.registry().close(), "close");
  }

  std::string start_error;
  ChildProcess holder = ChildProcess::start({"--child", "hold-lock", root.string(), holder_marker}, start_error);
  TREG_REQUIRE(holder.started());
  TREG_REQUIRE(wait_for_file(holder_marker, 30'000));

  // Reading does not need the writer lock, and it must not be blocked by it:
  // an operator has to be able to see a store while it is being written.
  const int child_code = run_child({"--child", "report", root.string(), report_path});
  TREG_CHECK_EQ(child_code, 0);

  std::ifstream reader{report_path, std::ios::binary};
  TREG_REQUIRE(reader.good());
  const std::string report{std::istreambuf_iterator<char>{reader}, std::istreambuf_iterator<char>{}};
  TREG_CHECK(report.find("read_only=true") != std::string::npos);
  TREG_CHECK(report.find("digest=" + expected_digest) != std::string::npos);

  holder.terminate();
  holder.wait();
  remove_tree(root);
}

TREG_TEST(multiprocess, competing_writers_are_serialised_and_never_lose_an_update) {
  const auto root = make_temp_directory("mp-split-brain");
  {
    Harness harness = Harness::durable(root);
    for (int index = 0; index < 5; ++index) {
      harness.create_tenant("seed-" + std::to_string(index));
    }
    require_ok(harness.registry().close(), "close");
  }

  TREG_CHECK_EQ(run_child({"--child", "try-write", root.string(), "from-first-child"}), 0);
  RegistryGeneration after_first;
  {
    auto registry = open_store(root, tenant_registry::AccessMode::ReadWrite);
    TREG_REQUIRE(registry.has_value());
    TREG_CHECK_EQ(registry.value().snapshot().tenants.size(), std::size_t{6});
    TREG_CHECK(registry.value().find_tenant(tenant_id("from-first-child")).has_value());
    after_first = registry.value().generation();
    for (int index = 0; index < 3; ++index) {
      const CreateTenantRequest request{context(registry.value().generation()),
                                        tenant_id("parent-" + std::to_string(index)), std::nullopt, std::nullopt,
                                        tenant_registry::TenancyMetadata{}};
      TREG_REQUIRE_OK(registry.value().create_tenant(request));
    }
    require_ok(registry.value().close(), "close");
  }

  TREG_CHECK_EQ(run_child({"--child", "try-write", root.string(), "from-second-child"}), 0);

  {
    // Every write from both processes is present exactly once. A lost update or
    // a divergent branch would show up here as a missing or duplicated record.
    Harness harness = Harness::durable(root);
    TREG_CHECK_EQ(harness.snapshot().tenants.size(), std::size_t{10});
    TREG_CHECK(harness.registry().find_tenant(tenant_id("from-first-child")).has_value());
    TREG_CHECK(harness.registry().find_tenant(tenant_id("from-second-child")).has_value());
    TREG_CHECK_EQ(harness.generation().value(), after_first.value() + 4);
    TREG_CHECK(harness.registry().control_epoch() > ControlEpoch::initial());
  }
  remove_tree(root);
}

TREG_TEST(multiprocess, a_writer_that_refuses_never_leaves_a_lock_behind) {
  const auto root = make_temp_directory("mp-refused-writer");
  const auto marker = (root / "ready.txt").string();
  {
    Harness harness = Harness::durable(root);
    harness.create_tenant("seed");
    require_ok(harness.registry().close(), "close");
  }

  // A refused child exits without ever taking the lock, so the very next writer
  // must still succeed. This is the case where a naive implementation leaves a
  // lock file behind and deadlocks the facility.
  TREG_CHECK_EQ(run_child({"--child", "try-write", root.string(), "first"}), 0);

  std::string start_error;
  ChildProcess holder = ChildProcess::start({"--child", "hold-lock", root.string(), marker}, start_error);
  TREG_REQUIRE(holder.started());
  TREG_REQUIRE(wait_for_file(marker, 30'000));
  TREG_CHECK_EQ(run_child({"--child", "try-write", root.string(), "refused"}), kChildRefusedByLock);
  holder.terminate();
  holder.wait();

  TREG_CHECK_EQ(run_child({"--child", "try-write", root.string(), "second"}), 0);
  {
    Harness harness = Harness::durable(root);
    TREG_CHECK(harness.registry().find_tenant(tenant_id("first")).has_value());
    TREG_CHECK(harness.registry().find_tenant(tenant_id("second")).has_value());
    TREG_CHECK(!harness.registry().find_tenant(tenant_id("refused")).has_value());
  }
  remove_tree(root);
}

}  // namespace treg_test
