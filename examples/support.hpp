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

#ifndef TENANT_REGISTRY_EXAMPLES_SUPPORT_HPP
#define TENANT_REGISTRY_EXAMPLES_SUPPORT_HPP

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "tenant_registry/tenant_registry.hpp"

#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#endif

/// The helpers every example shares: the transcript, the checked unwrap, the
/// builders that keep a request readable, and the temporary directory the
/// persistence example owns. Nothing here is part of the library.

namespace treg_examples {

/// One fixed clock reading, 2026-01-01T00:00:00Z. Every example hands the
/// registry this clock, so no transcript can depend on when the example ran.
inline constexpr std::int64_t kFixedClockMilliseconds = 1767225600000;

// ---------------------------------------------------------------------------
// The transcript
// ---------------------------------------------------------------------------

/// Puts stdout into binary mode, so a line ends with LF and is never written
/// as CRLF.
inline void use_lf_only_stdout() {
#if defined(_WIN32)
  static const bool configured = [] {
    (void)std::fflush(stdout);
    (void)_setmode(_fileno(stdout), _O_BINARY);
    return true;
  }();
  (void)configured;
#endif
}

/// Writes one LF terminated line to stdout.
inline void print_line(std::string_view text) {
  use_lf_only_stdout();
  if (!text.empty()) {
    (void)std::fwrite(text.data(), 1, text.size(), stdout);
  }
  (void)std::fputc('\n', stdout);
}

/// Renders one "key=value" pair, so every transcript spells a field the same
/// way.
[[nodiscard]] inline std::string field(std::string_view key, std::string_view value) {
  std::string text{key};
  text.push_back('=');
  text.append(value);
  return text;
}

[[nodiscard]] inline std::string field(std::string_view key, std::uint64_t value) {
  return field(key, std::to_string(value));
}

/// "before -> after", for showing that a counter moved by exactly one.
[[nodiscard]] inline std::string movement(std::uint64_t before, std::uint64_t after) {
  return std::to_string(before) + " -> " + std::to_string(after);
}

/// "true" or "false", so a boolean is never rendered as 1 or 0.
[[nodiscard]] inline std::string_view yes_no(bool value) noexcept {
  return value ? std::string_view{"true"} : std::string_view{"false"};
}

/// Writes the "== example ... ==" header and then numbers the steps from one.
class StepPrinter {
 public:
  explicit StepPrinter(std::string_view title) {
    std::string header{"== example "};
    header.append(title);
    header.append(" ==");
    print_line(header);
  }

  void operator()(std::string_view text) {
    std::string line{"step "};
    line.append(std::to_string(next_));
    line.append(": ");
    line.append(text);
    print_line(line);
    ++next_;
  }

  /// An indented observation of the step above it.
  void note(std::string_view text) const {
    std::string line{"  "};
    line.append(text);
    print_line(line);
  }

 private:
  int next_ = 1;
};

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// "token: detail" for one refusal: the exact form a transcript shows.
[[nodiscard]] inline std::string refusal_text(const tenant_registry::Error& error) {
  std::string text{error.token()};
  text.append(": ");
  text.append(error.detail());
  return text;
}

/// Writes a diagnostic to stderr and ends the process with status 1.
[[noreturn]] inline void fail(std::string_view message) {
  (void)std::fflush(stdout);
  std::string line{"example failure: "};
  line.append(message);
  line.push_back('\n');
  (void)std::fwrite(line.data(), 1, line.size(), stderr);
  std::exit(1);
}

/// Writes the refusal of a failed check to stderr and ends the process with
/// status 1.
[[noreturn]] inline void fail(std::string_view what, const tenant_registry::Error& error) {
  std::string message{what};
  message.append(": ");
  message.append(error.to_text());
  fail(message);
}

/// The value of a Result, or the refusal printed to stderr and std::exit(1).
template <class T>
[[nodiscard]] T required(tenant_registry::Result<T> result, std::string_view what) {
  if (!result.has_value()) {
    fail(what, result.error());
  }
  return std::move(result).value();
}

/// The same check where the produced value is deliberately not used.
template <class T>
inline void required_ok(tenant_registry::Result<T> result, std::string_view what) {
  if (!result.has_value()) {
    fail(what, result.error());
  }
}

/// The same check for an operation that produces no value.
inline void required(tenant_registry::Status status, std::string_view what) {
  if (!status.ok()) {
    fail(what, status.error());
  }
}

// ---------------------------------------------------------------------------
// The temporary directory the persistence example owns
// ---------------------------------------------------------------------------

namespace detail {

/// Every temporary directory that is still alive, so that one is removed even
/// when the process ends through std::exit from a failed check.
[[nodiscard]] inline std::vector<std::filesystem::path>& live_temp_directories() {
  static std::vector<std::filesystem::path> paths;
  return paths;
}

inline void remove_live_temp_directories() {
  std::vector<std::filesystem::path>& paths = live_temp_directories();
  for (const std::filesystem::path& path : paths) {
    std::error_code ignored;
    std::filesystem::remove_all(path, ignored);
  }
  paths.clear();
}

}  // namespace detail

/// A directory under the system temporary directory that removes itself when it
/// goes out of scope and when the process ends, including on the failure path
/// where a checked unwrap calls std::exit.
class TempDirectory {
 public:
  explicit TempDirectory(std::string_view label) {
    // The registry is constructed before the handler is registered, so that the
    // handler is called before the registry is destroyed: exit handlers run in
    // reverse order of registration, and a block-scope static is destroyed as if
    // it had been registered at the moment its construction completed.
    static const bool cleanup_registered = [] {
      (void)detail::live_temp_directories();
      std::atexit(&detail::remove_live_temp_directories);
      return true;
    }();
    (void)cleanup_registered;

    std::error_code error;
    const std::filesystem::path root = std::filesystem::temp_directory_path(error);
    if (error) {
      fail("the system temporary directory could not be located");
    }
    std::string stem{"treg-example-"};
    stem.append(label);
    for (int attempt = 0; attempt < kMaxAttempts; ++attempt) {
      const std::filesystem::path candidate = root / (stem + "-" + std::to_string(attempt));
      std::error_code create_error;
      if (std::filesystem::create_directory(candidate, create_error)) {
        path_ = candidate;
        detail::live_temp_directories().push_back(candidate);
        return;
      }
    }
    fail("a temporary directory for this example could not be created");
  }

  ~TempDirectory() {
    if (path_.empty()) {
      return;
    }
    std::vector<std::filesystem::path>& paths = detail::live_temp_directories();
    paths.erase(std::remove(paths.begin(), paths.end(), path_), paths.end());
    std::error_code ignored;
    std::filesystem::remove_all(path_, ignored);
  }

  TempDirectory(const TempDirectory&) = delete;
  TempDirectory& operator=(const TempDirectory&) = delete;
  TempDirectory(TempDirectory&&) = delete;
  TempDirectory& operator=(TempDirectory&&) = delete;

  [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

 private:
  static constexpr int kMaxAttempts = 64;

  std::filesystem::path path_;
};

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

[[nodiscard]] inline tenant_registry::TenantId tenant(std::string_view value) {
  return required(tenant_registry::TenantId::create(value), "tenant identity");
}

[[nodiscard]] inline tenant_registry::ServiceId service(std::string_view value) {
  return required(tenant_registry::ServiceId::create(value), "service identity");
}

[[nodiscard]] inline tenant_registry::IsolationDomainId domain(std::string_view value) {
  return required(tenant_registry::IsolationDomainId::create(value), "isolation domain identity");
}

[[nodiscard]] inline tenant_registry::PrincipalId principal(std::string_view value) {
  return required(tenant_registry::PrincipalId::create(value), "principal identity");
}

[[nodiscard]] inline tenant_registry::IdempotencyKey idempotency_key(std::string_view value) {
  return required(tenant_registry::IdempotencyKey::create(value), "idempotency key");
}

/// A subject from its canonical token form: "tenant:acme",
/// "service:renderer" or "isolation_domain:zone-a".
[[nodiscard]] inline tenant_registry::TenancySubject subject(std::string_view token) {
  const std::size_t separator = token.find(':');
  if (separator == std::string_view::npos) {
    fail("a subject token must be written as \"kind:identity\"");
  }
  tenant_registry::SubjectKind kind = tenant_registry::SubjectKind::Unspecified;
  if (!tenant_registry::parse_subject_kind(token.substr(0, separator), kind)) {
    fail("a subject token must name a kind this build knows");
  }
  const std::string_view identity = token.substr(separator + 1);
  switch (kind) {
    case tenant_registry::SubjectKind::Tenant:
      return tenant_registry::TenancySubject::of_tenant(tenant(identity));
    case tenant_registry::SubjectKind::Service:
      return tenant_registry::TenancySubject::of_service(service(identity));
    case tenant_registry::SubjectKind::IsolationDomain:
      return tenant_registry::TenancySubject::of_isolation_domain(domain(identity));
    case tenant_registry::SubjectKind::Unspecified:
      break;
  }
  fail("a subject token must name a kind this build knows");
}

/// The actor every example declares under: test fixture provenance, so no
/// example can be mistaken for production data, and no declared time, so no
/// transcript ever carries a clock reading.
[[nodiscard]] inline tenant_registry::ProvenanceRecord provenance(std::string_view note) {
  const tenant_registry::RegistryLimits limits{};
  return required(tenant_registry::ProvenanceRecord::create(
                      tenant_registry::ProvenanceSource::TestFixture,
                      required(tenant_registry::SourceId::create("examples"), "source identity"),
                      required(tenant_registry::PrincipalId::create("example.operator"), "principal identity"),
                      std::nullopt, std::string{note}, limits.max_provenance_note_bytes),
                  "provenance record");
}

/// The note every example declares under. It is never empty: a provenance
/// record with an empty note is accepted by the request validation but cannot
/// be decoded again, which would make a durable store and an idempotency ledger
/// entry unreadable.
inline constexpr std::string_view kExampleNote = "declared by an example program";

/// A mutation context bound to exactly the generation it names, with no
/// idempotency key.
[[nodiscard]] inline tenant_registry::MutationContext context(
    tenant_registry::RegistryGeneration expected_generation) {
  return tenant_registry::MutationContext{expected_generation, std::nullopt, provenance(kExampleNote)};
}

/// The same, carrying the key that makes the request replay safe.
[[nodiscard]] inline tenant_registry::MutationContext keyed_context(
    tenant_registry::RegistryGeneration expected_generation, tenant_registry::IdempotencyKey key) {
  return tenant_registry::MutationContext{expected_generation,
                                          std::optional<tenant_registry::IdempotencyKey>{std::move(key)},
                                          provenance(kExampleNote)};
}

/// Options for an ephemeral registry whose clock is fixed.
[[nodiscard]] inline tenant_registry::EphemeralOptions ephemeral_options() {
  tenant_registry::EphemeralOptions options;
  options.clock = std::make_shared<tenant_registry::FixedClock>(kFixedClockMilliseconds);
  return options;
}

}  // namespace treg_examples

#endif  // TENANT_REGISTRY_EXAMPLES_SUPPORT_HPP
