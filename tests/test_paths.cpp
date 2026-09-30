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

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "test_support.hpp"

namespace {

using tenant_registry::AccessMode;
using tenant_registry::ContentDigest;
using tenant_registry::CreateTenantRequest;
using tenant_registry::ErrorClass;
using tenant_registry::ErrorCode;
using tenant_registry::FixedClock;
using tenant_registry::MutationContext;
using tenant_registry::RegistryOpenRequest;
using tenant_registry::TenancyMetadata;
using tenant_registry::TenantRegistry;

MutationContext context(tenant_registry::RegistryGeneration generation) {
  return MutationContext{generation, std::nullopt,
                         treg_test::provenance("paths-suite", "path-principal", 17, "declared by the paths suite")};
}

RegistryOpenRequest open_request(const std::filesystem::path& root, AccessMode mode) {
  RegistryOpenRequest request;
  request.root = root;
  request.mode = mode;
  request.clock = std::make_shared<FixedClock>(1'700'000'000'000);
  return request;
}

/// Removes a tree, falling back to the Windows long path prefix. A path that
/// the ordinary MAX_PATH limit hides is still a path this test created, so it
/// is still a path this test has to remove.
void remove_tree(const std::filesystem::path& root) noexcept {
  std::error_code error;
  std::filesystem::remove_all(root, error);
  if (!std::filesystem::exists(root, error)) {
    return;
  }
#if defined(_WIN32)
  std::error_code absolute_error;
  const std::filesystem::path absolute = std::filesystem::absolute(root, absolute_error);
  if (!absolute_error) {
    std::filesystem::remove_all(std::filesystem::path{L"\\\\?\\" + absolute.wstring()}, error);
  }
#else
  std::filesystem::remove_all(root, error);
#endif
}

class TempTree {
 public:
  explicit TempTree(std::filesystem::path root) : root_(std::move(root)) {}
  ~TempTree() { remove_tree(root_); }

  TempTree(const TempTree&) = delete;
  TempTree& operator=(const TempTree&) = delete;

  [[nodiscard]] const std::filesystem::path& path() const noexcept { return root_; }

 private:
  std::filesystem::path root_;
};

/// The names directly under a directory, sorted. A refused open must leave this
/// exactly as it was, which is how "nothing was created" is checked without
/// trusting the refusal's own claim.
std::vector<std::string> directory_names(const std::filesystem::path& root) {
  std::vector<std::string> names;
  std::error_code error;
  for (const std::filesystem::directory_entry& entry : std::filesystem::directory_iterator(root, error)) {
    names.push_back(entry.path().filename().string());
  }
  std::sort(names.begin(), names.end());
  return names;
}

std::string store_fingerprint(const std::filesystem::path& root) {
  std::vector<std::string> names;
  std::error_code error;
  for (const std::filesystem::directory_entry& entry : std::filesystem::directory_iterator(root, error)) {
    if (entry.is_regular_file(error)) {
      names.push_back(entry.path().filename().string());
    }
  }
  std::sort(names.begin(), names.end());
  std::string out;
  for (const std::string& name : names) {
    std::ifstream input{root / name, std::ios::binary};
    const std::string bytes{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    out += name;
    out += '=';
    out += ContentDigest::of(bytes).to_text();
    out += ';';
  }
  return out;
}

/// A path this suite must not touch is a path that must be refused, and the
/// refusal has to be the documented one for the reason it was refused.
void expect_refused(const std::filesystem::path& root, AccessMode mode, ErrorCode expected) {
  auto opened = TenantRegistry::open(open_request(root, mode));
  TREG_CHECK_CODE(opened, expected);
  if (!opened) {
    TREG_CHECK_EQ(classify(opened.error().code()), ErrorClass::Store);
  }
}

}  // namespace

// ---------------------------------------------------------------------------
// Structural refusals: the root cannot be a store at all.
// ---------------------------------------------------------------------------

TREG_TEST(paths, an_empty_root_or_one_with_a_traversal_component_is_refused) {
  const TempTree tree{treg_test::make_temp_directory("paths-structure")};
  const std::filesystem::path base = tree.path() / "roots";
  std::error_code error;
  std::filesystem::create_directories(base, error);
  const std::vector<std::string> before = directory_names(base);

  expect_refused(std::filesystem::path{}, AccessMode::ReadWrite, ErrorCode::StorePathRejected);
  expect_refused(base / ".", AccessMode::ReadWrite, ErrorCode::StorePathRejected);
  expect_refused(base / ".", AccessMode::ReadOnly, ErrorCode::StorePathRejected);
  expect_refused(base / "..", AccessMode::ReadWrite, ErrorCode::StorePathRejected);
  expect_refused(base / ".." / "escaped-store", AccessMode::ReadWrite, ErrorCode::StorePathRejected);
  expect_refused(base / "inner" / ".." / "still-traversal", AccessMode::ReadWrite,
                 ErrorCode::StorePathRejected);

  // Nothing was created, anywhere: a traversal component would have put a store
  // beside the intended one.
  TREG_CHECK(directory_names(base) == before);
  TREG_CHECK(!std::filesystem::exists(tree.path() / "escaped-store", error));
  TREG_CHECK(!std::filesystem::exists(tree.path().parent_path() / "escaped-store", error));
}

TREG_TEST(paths, a_root_that_is_an_existing_file_is_refused) {
  const TempTree tree{treg_test::make_temp_directory("paths-file")};
  const std::filesystem::path base = tree.path() / "roots";
  std::error_code error;
  std::filesystem::create_directories(base, error);
  const std::filesystem::path file = base / "not-a-store";
  {
    std::ofstream out{file, std::ios::binary};
    out << "this is a file, and a store root has to be a directory";
  }
  const std::vector<std::string> before = directory_names(base);

  expect_refused(file, AccessMode::ReadWrite, ErrorCode::StorePathRejected);
  expect_refused(file, AccessMode::ReadOnly, ErrorCode::StorePathRejected);

  // The file is untouched: a refused open must not truncate, rewrite or remove
  // whatever the caller pointed it at.
  TREG_CHECK(std::filesystem::exists(file, error));
  std::ifstream input{file, std::ios::binary};
  const std::string content{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
  TREG_CHECK_EQ(content, std::string{"this is a file, and a store root has to be a directory"});
  TREG_CHECK(directory_names(base) == before);
}

TREG_TEST(paths, windows_reserved_device_names_are_refused) {
  const TempTree tree{treg_test::make_temp_directory("paths-reserved")};
  const std::filesystem::path base = tree.path() / "roots";
  std::error_code error;
  std::filesystem::create_directories(base, error);
  const std::vector<std::string> before = directory_names(base);

  // A component that resolves to a device is not a directory to put a store in,
  // on any platform: the same root has to be accepted or refused everywhere.
  const std::vector<std::string> reserved = {"CON",  "con",     "PRN",  "AUX",   "NUL",     "COM1",
                                             "LPT1", "con.txt", "NUL.journal", "lpt1.txt", "COM9"};
  for (const std::string& name : reserved) {
    expect_refused(base / name, AccessMode::ReadWrite, ErrorCode::StorePathRejected);
  }
  expect_refused(base / "NUL", AccessMode::ReadOnly, ErrorCode::StorePathRejected);

  TREG_CHECK(directory_names(base) == before);
}

TREG_TEST(paths, a_root_with_more_components_than_the_build_accepts_is_refused) {
  const TempTree tree{treg_test::make_temp_directory("paths-deep")};
  const std::filesystem::path base = tree.path() / "roots";
  std::error_code error;
  std::filesystem::create_directories(base, error);
  const std::vector<std::string> before = directory_names(base);

  std::filesystem::path deep = base;
  for (int index = 0; index < 300; ++index) {
    deep /= "d" + std::to_string(index);
  }
  expect_refused(deep, AccessMode::ReadWrite, ErrorCode::StorePathRejected);

  // The bound is a bound, not a truncation: no prefix of the path was created.
  TREG_CHECK(directory_names(base) == before);
  TREG_CHECK(!std::filesystem::exists(base / "d0", error));
}

// ---------------------------------------------------------------------------
// A root the operating system cannot create is refused, and nothing escapes.
// ---------------------------------------------------------------------------

TREG_TEST(paths, a_root_whose_path_cannot_be_created_is_refused_without_escaping) {
  const TempTree tree{treg_test::make_temp_directory("paths-long")};
  const std::filesystem::path base = tree.path() / "roots";
  std::error_code error;
  std::filesystem::create_directories(base, error);
  const std::vector<std::string> before = directory_names(base);

  // A single component far beyond what a directory entry can hold. Where the
  // operating system refuses the creation determines the code -- StoreNotFound
  // when the path itself cannot be resolved, StoreIoError when the path
  // resolves but a file inside it cannot be opened -- and both are the
  // documented refusals for a root that cannot be used.
  const std::filesystem::path long_component = base / std::string(240, 'L');
  auto long_open = TenantRegistry::open(open_request(long_component, AccessMode::ReadWrite));
  TREG_CHECK_CODE(long_open, ErrorCode::StoreNotFound);
  if (!long_open) {
    TREG_CHECK_EQ(classify(long_open.error().code()), ErrorClass::Store);
  }

  std::filesystem::path deep = base;
  for (int index = 0; index < 12; ++index) {
    deep /= std::string(30, 'x');
  }
  auto deep_open = TenantRegistry::open(open_request(deep, AccessMode::ReadWrite));
  TREG_CHECK(!deep_open.has_value());
  if (!deep_open) {
    const ErrorCode code = deep_open.error().code();
    TREG_CHECK(code == ErrorCode::StoreNotFound || code == ErrorCode::StoreIoError);
    TREG_CHECK_EQ(classify(code), ErrorClass::Store);
  }

  // Clean up whatever partial path the operating system did create, through the
  // long path prefix if an ordinary removal cannot reach it, then prove the
  // base is exactly as it was.
  remove_tree(base / std::string(240, 'L'));
  remove_tree(base / std::string(30, 'x'));
  TREG_CHECK(!std::filesystem::exists(base / std::string(240, 'L'), error));
  TREG_CHECK(!std::filesystem::exists(base / std::string(30, 'x'), error));
  TREG_CHECK(directory_names(base) == before);
}

// ---------------------------------------------------------------------------
// A store is owned by one writer; a read-only session owns nothing.
// ---------------------------------------------------------------------------

TREG_TEST(paths, a_second_writer_on_a_live_store_is_refused_with_store_locked) {
  const TempTree tree{treg_test::make_temp_directory("paths-lock")};
  const std::filesystem::path root = tree.path() / "live-store";

  auto writer = TenantRegistry::open(open_request(root, AccessMode::ReadWrite));
  TREG_REQUIRE_OK(writer);
  TenantRegistry writing = std::move(writer).value();
  TREG_REQUIRE_OK(writing.create_tenant(CreateTenantRequest{context(writing.generation()),
                                                           treg_test::tenant_id("acme"), std::nullopt, std::nullopt,
                                                           TenancyMetadata{}}));
  const ContentDigest identity = writing.store_identity()->id;
  const std::string fingerprint = store_fingerprint(root);

  // A second writer cannot share authority over one store, and taking the lock
  // is what stops it -- not a convention.
  expect_refused(root, AccessMode::ReadWrite, ErrorCode::StoreLocked);

  // A read-only session takes no lock, so it coexists with the writer, sees the
  // committed state, and still cannot change anything.
  auto reader = TenantRegistry::open(open_request(root, AccessMode::ReadOnly));
  TREG_REQUIRE_OK(reader);
  TenantRegistry reading = std::move(reader).value();
  TREG_CHECK_EQ(reading.store_identity()->id, identity);
  TREG_CHECK(reading.find_tenant(treg_test::tenant_id("acme")).has_value());
  const auto refused = reading.create_tenant(CreateTenantRequest{context(reading.generation()),
                                                                 treg_test::tenant_id("beta"), std::nullopt,
                                                                 std::nullopt, TenancyMetadata{}});
  TREG_CHECK_CODE(refused, ErrorCode::StoreNotWritable);

  // The one thing that changes in a read-only session is nothing.
  TREG_CHECK_EQ(store_fingerprint(root), fingerprint);
  TREG_REQUIRE(writing.close().ok());
  TREG_CHECK(!reading.find_tenant(treg_test::tenant_id("beta")).has_value());

  // The reverse direction holds as well: a read-only session holds no lock, so
  // it never blocks a writer. If it did, "read-only" would quietly mean
  // "exclusive".
  auto second_writer = TenantRegistry::open(open_request(root, AccessMode::ReadWrite));
  TREG_REQUIRE_OK(second_writer);
  TenantRegistry writing_again = std::move(second_writer).value();
  TREG_CHECK_EQ(writing_again.store_identity()->id, identity);
  TREG_REQUIRE_OK(writing_again.create_tenant(CreateTenantRequest{context(writing_again.generation()),
                                                                 treg_test::tenant_id("gamma"), std::nullopt,
                                                                 std::nullopt, TenancyMetadata{}}));
  // The read-only session still answers from the state it opened, and still
  // cannot write.
  TREG_CHECK(reading.find_tenant(treg_test::tenant_id("acme")).has_value());
  TREG_CHECK_CODE(reading.create_tenant(CreateTenantRequest{context(reading.generation()),
                                                           treg_test::tenant_id("delta"), std::nullopt, std::nullopt,
                                                           TenancyMetadata{}}),
                  ErrorCode::StoreNotWritable);
  TREG_REQUIRE(writing_again.close().ok());
}

TREG_TEST(paths, a_read_only_open_of_a_missing_store_is_refused_and_creates_nothing) {
  const TempTree tree{treg_test::make_temp_directory("paths-missing")};
  const std::filesystem::path base = tree.path() / "roots";
  std::error_code error;
  std::filesystem::create_directories(base, error);
  const std::vector<std::string> before = directory_names(base);

  // A read-only session may not bring a store into existence: it would be
  // creating the state it claims only to be reading.
  expect_refused(base / "absent-store", AccessMode::ReadOnly, ErrorCode::StoreNotFound);
  TREG_CHECK(!std::filesystem::exists(base / "absent-store", error));
  TREG_CHECK(directory_names(base) == before);
}

// ---------------------------------------------------------------------------
// Names that are legal are accepted, and stay inside themselves.
// ---------------------------------------------------------------------------

TREG_TEST(paths, a_legal_but_unusual_root_is_accepted_and_stays_inside_itself) {
  const TempTree tree{treg_test::make_temp_directory("paths-unusual")};
  const std::filesystem::path root = tree.path() / "st ore + (1) #&,;='@!~";
  std::error_code error;

  auto opened = TenantRegistry::open(open_request(root, AccessMode::ReadWrite));
  TREG_REQUIRE_OK(opened);
  TenantRegistry registry = std::move(opened).value();
  TREG_REQUIRE_OK(registry.create_tenant(CreateTenantRequest{context(registry.generation()),
                                                            treg_test::tenant_id("acme"), std::nullopt, std::nullopt,
                                                            TenancyMetadata{}}));
  const ContentDigest identity = registry.store_identity()->id;
  TREG_CHECK(std::filesystem::is_directory(root, error));

  // Everything the store wrote is inside the root the caller named.
  for (const std::string& name : directory_names(root)) {
    TREG_CHECK(std::filesystem::exists(root / name, error));
  }
  TREG_REQUIRE(registry.close().ok());

  // Windows resolves a trailing dot to the same directory. What matters is that
  // the alias names the same store rather than silently creating a second one.
  auto aliased = TenantRegistry::open(open_request(tree.path() / "st ore + (1) #&,;='@!~.", AccessMode::ReadWrite));
  TREG_REQUIRE_OK(aliased);
  TenantRegistry alias_registry = std::move(aliased).value();
  TREG_CHECK_EQ(alias_registry.store_identity()->id, identity);
  TREG_CHECK(alias_registry.find_tenant(treg_test::tenant_id("acme")).has_value());
  TREG_REQUIRE(alias_registry.close().ok());
}