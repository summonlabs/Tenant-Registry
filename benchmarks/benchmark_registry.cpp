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

// treg_benchmark: completed-operation measurements for the Tenant Registry.
//
//   treg_benchmark            full run
//   treg_benchmark --quick    short run; the ctest smoke test
//
// What is measured, and what is deliberately not:
//
//   * only completed operations. Every operation in this library is synchronous,
//     so a completed operation is one that returned a value, and where the
//     operation has an observable answer it is the answer the constructed state
//     requires. There is no queue and no submission, so no figure can contain
//     enqueue or submission latency: the timed region is the construction of the
//     request aggregate plus the whole API call.
//   * a SYNTHETIC figure was measured against data generated in this process and
//     never touched a durable store. A REAL figure went through the whole
//     durable commit path: the journal append, the flush, the read-back
//     verification and the atomic manifest replacement.
//   * every figure is a single-host wall clock measurement taken in this process
//     with std::chrono::steady_clock. Nothing here is a claim about hardware.
//   * a phase that did not complete its required iterations prints no rate and
//     no latency distribution; its refusals are counted and reported separately.
//
// Exit status is 0 when every measured phase completed its required iterations
// and 1 otherwise. Any temporary directory this program creates is removed on
// every exit path, including the failure paths.

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <initializer_list>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "tenant_registry/tenant_registry.hpp"

namespace tr = tenant_registry;

namespace {

using Clock = std::chrono::steady_clock;

/// One fixed clock reading, 2026-01-01T00:00:00Z. Every registry this program
/// opens is handed the same clock, so no recorded provenance depends on when the
/// benchmark ran.
constexpr std::int64_t kFixedClockMilliseconds = 1767225600000;

/// The bound that keeps the pagination loop of section 4 from spinning if a page
/// ever claimed to be truncated while carrying no cursor.
constexpr std::uint64_t kMaximumPagesPerPass = 1024;

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

void print_line(std::string_view text) {
  if (!text.empty()) {
    (void)std::fwrite(text.data(), 1, text.size(), stdout);
  }
  (void)std::fputc('\n', stdout);
}

[[nodiscard]] std::string field(std::string_view key, std::string_view value) {
  std::string text{key};
  text.push_back('=');
  text.append(value);
  return text;
}

[[nodiscard]] std::string field(std::string_view key, std::uint64_t value) {
  return field(key, std::to_string(value));
}

[[nodiscard]] std::string_view yes_no(bool value) noexcept {
  return value ? std::string_view{"true"} : std::string_view{"false"};
}

/// Writes one line of "key=value" fields, separated by single spaces.
void print_fields(std::initializer_list<std::string> fields) {
  std::string line;
  for (const std::string& entry : fields) {
    if (!line.empty()) {
      line.push_back(' ');
    }
    line.append(entry);
  }
  print_line(line);
}

/// Writes one prose observation: "key: text". Prose carries the shape of the
/// generated data and the scope of a section; it never carries a figure, so a
/// reader cannot mistake it for a measurement.
void print_prose(std::string_view key, std::string_view text) {
  std::string line{key};
  line.append(": ");
  line.append(text);
  print_line(line);
}

/// A fixed precision decimal, for rates and for scaled durations.
[[nodiscard]] std::string decimal(double value, int precision) {
  char buffer[64];
  const int written = std::snprintf(buffer, sizeof(buffer), "%.*f", precision, value);
  if (written <= 0) {
    return std::string{"0"};
  }
  const std::size_t length =
      static_cast<std::size_t>(written) < sizeof(buffer) ? static_cast<std::size_t>(written) : sizeof(buffer) - 1;
  return std::string(buffer, length);
}

[[nodiscard]] std::string microseconds(std::uint64_t nanoseconds) {
  return decimal(static_cast<double>(nanoseconds) / 1000.0, 3);
}

[[nodiscard]] std::string milliseconds(std::uint64_t nanoseconds) {
  return decimal(static_cast<double>(nanoseconds) / 1000000.0, 3);
}

[[nodiscard]] std::string rate_per_second(std::uint64_t completed, std::uint64_t nanoseconds) {
  if (nanoseconds == 0) {
    return std::string{"0.000"};
  }
  return decimal(static_cast<double>(completed) * 1000000000.0 / static_cast<double>(nanoseconds), 3);
}

/// Writes a diagnostic to stderr and ends the process with status 1. It is used
/// only for a broken environment or a misused command line, never for a measured
/// phase: a measured phase reports itself in the report and leaves the exit
/// status to main.
[[noreturn]] void fatal(std::string_view message) {
  (void)std::fflush(stdout);
  std::string line{"treg_benchmark: "};
  line.append(message);
  line.push_back('\n');
  (void)std::fwrite(line.data(), 1, line.size(), stderr);
  std::exit(1);
}

// ---------------------------------------------------------------------------
// A temporary directory that removes itself on every exit path
// ---------------------------------------------------------------------------

namespace temp_detail {

[[nodiscard]] std::vector<std::filesystem::path>& live_directories() {
  static std::vector<std::filesystem::path> paths;
  return paths;
}

void remove_live_directories() {
  std::vector<std::filesystem::path>& paths = live_directories();
  for (const std::filesystem::path& path : paths) {
    std::error_code ignored;
    std::filesystem::remove_all(path, ignored);
  }
  paths.clear();
}

}  // namespace temp_detail

/// A directory under the system temporary directory. It is removed when it goes
/// out of scope and, through an atexit handler, when the process ends any other
/// way. Nothing this benchmark writes lands anywhere else.
class TempDirectory {
 public:
  TempDirectory() {
    static const bool registered = [] {
      std::atexit(&temp_detail::remove_live_directories);
      return true;
    }();
    (void)registered;

    std::error_code error;
    const std::filesystem::path parent = std::filesystem::temp_directory_path(error);
    if (error) {
      fatal("the system temporary directory could not be located");
    }
    for (int attempt = 0; attempt < kMaximumAttempts; ++attempt) {
      const std::filesystem::path candidate = parent / ("treg-benchmark-" + std::to_string(attempt));
      std::error_code create_error;
      if (std::filesystem::create_directory(candidate, create_error)) {
        path_ = candidate;
        temp_detail::live_directories().push_back(candidate);
        return;
      }
    }
    fatal("a temporary directory for the durable store could not be created");
  }

  ~TempDirectory() {
    if (path_.empty()) {
      return;
    }
    std::vector<std::filesystem::path>& paths = temp_detail::live_directories();
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
  static constexpr int kMaximumAttempts = 64;

  std::filesystem::path path_;
};

// ---------------------------------------------------------------------------
// Latency samples
// ---------------------------------------------------------------------------

/// The samples of one latency phase, in nanoseconds, plus the percentile rule.
///
/// The percentile is the nearest rank over the sorted samples: for N samples and
/// a percentage p, the reported value is the sample at one-based index
/// ceil(p / 100 * N), clamped into [1, N]. No interpolation is performed, so
/// every reported figure is a measurement that was actually taken.
class Samples {
 public:
  void add(std::uint64_t nanoseconds) { values_.push_back(nanoseconds); }

  void sort() { std::sort(values_.begin(), values_.end()); }

  [[nodiscard]] std::size_t size() const noexcept { return values_.size(); }

  /// Requires sort(). The caller guarantees a non-empty sample set.
  [[nodiscard]] std::uint64_t percentile(double percent) const {
    if (values_.empty()) {
      return 0;
    }
    const double rank = (percent / 100.0) * static_cast<double>(values_.size());
    const double ceiling = std::ceil(rank);
    std::size_t index = ceiling <= 1.0 ? 0 : static_cast<std::size_t>(ceiling) - 1;
    if (index >= values_.size()) {
      index = values_.size() - 1;
    }
    return values_[index];
  }

  [[nodiscard]] std::uint64_t minimum() const { return values_.front(); }
  [[nodiscard]] std::uint64_t maximum() const { return values_.back(); }

 private:
  std::vector<std::uint64_t> values_;
};

[[nodiscard]] std::uint64_t elapsed_nanoseconds(Clock::time_point start, Clock::time_point end) {
  return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());
}

// ---------------------------------------------------------------------------
// Phase bookkeeping
// ---------------------------------------------------------------------------

/// What one phase did: how many operations it was required to complete, how many
/// it did complete, how many were refused, and the first refusal or verification
/// failure, so a failure of the run can be explained without guessing.
struct PhaseCounts {
  std::uint64_t required = 0;
  std::uint64_t completed = 0;
  std::uint64_t refused = 0;
  std::uint64_t elapsed_ns = 0;
  std::string first_failure;

  [[nodiscard]] bool complete() const noexcept { return completed == required; }

  void record(std::string failure) {
    if (failure.empty()) {
      ++completed;
      return;
    }
    ++refused;
    if (first_failure.empty()) {
      first_failure = std::move(failure);
    }
  }
};

/// The outcome of the whole run. Every phase that could not be measured is
/// counted here, and main turns that count into the exit status.
class RunOutcome {
 public:
  void failed(std::string_view what, std::string_view reason) {
    print_line("FAILED " + field("what", what) + " reason: " + std::string{reason});
    ++failures_;
  }

  [[nodiscard]] std::uint64_t failures() const noexcept { return failures_; }

 private:
  std::uint64_t failures_ = 0;
};

/// Unwraps a Result, or reports the refusal and produces nothing.
template <class T>
[[nodiscard]] std::optional<T> checked(tr::Result<T> result, std::string_view what, RunOutcome& outcome) {
  if (!result.has_value()) {
    outcome.failed(what, result.error().to_text());
    return std::nullopt;
  }
  return std::optional<T>{std::move(result).value()};
}

/// The same for an operation that produces no value.
[[nodiscard]] bool checked(tr::Status status, std::string_view what, RunOutcome& outcome) {
  if (!status.ok()) {
    outcome.failed(what, status.error().to_text());
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

/// Times the timed loop as a whole. No clock is read around an individual
/// operation, so a throughput figure carries the operations and nothing else.
template <class Operation>
[[nodiscard]] PhaseCounts measure_throughput(std::uint64_t warmup, std::uint64_t iterations, Operation operation) {
  PhaseCounts counts;
  counts.required = iterations;
  for (std::uint64_t index = 0; index < warmup; ++index) {
    (void)operation(index);
  }
  const Clock::time_point start = Clock::now();
  for (std::uint64_t step = 0; step < iterations; ++step) {
    counts.record(operation(warmup + step));
  }
  const Clock::time_point end = Clock::now();
  counts.elapsed_ns = elapsed_nanoseconds(start, end);
  return counts;
}

/// Times every operation individually, so each completed operation contributes
/// exactly one latency sample.
template <class Operation>
[[nodiscard]] PhaseCounts measure_latency(std::uint64_t warmup, std::uint64_t iterations, Operation operation,
                                          Samples& samples) {
  PhaseCounts counts;
  counts.required = iterations;
  for (std::uint64_t index = 0; index < warmup; ++index) {
    (void)operation(index);
  }
  const Clock::time_point start = Clock::now();
  for (std::uint64_t step = 0; step < iterations; ++step) {
    const Clock::time_point before = Clock::now();
    std::string failure = operation(warmup + step);
    const Clock::time_point after = Clock::now();
    const bool completed = failure.empty();
    if (completed) {
      samples.add(elapsed_nanoseconds(before, after));
    }
    counts.record(std::move(failure));
  }
  const Clock::time_point end = Clock::now();
  counts.elapsed_ns = elapsed_nanoseconds(start, end);
  return counts;
}

/// Prints one throughput phase. A phase that did not complete its required
/// iterations prints no rate: a rate over a partial set would be a rate for a
/// phase that did not happen.
void report_throughput(const PhaseCounts& counts, std::string_view phase, RunOutcome& outcome) {
  print_fields({field("phase", phase), field("required", counts.required), field("completed", counts.completed),
                field("refused", counts.refused), field("elapsed_ms", milliseconds(counts.elapsed_ns))});
  if (!counts.complete()) {
    print_line("rate=WITHHELD reason=the phase did not complete its required iterations");
    outcome.failed(phase, counts.first_failure);
    return;
  }
  print_fields({field("rate_ops_per_second", rate_per_second(counts.completed, counts.elapsed_ns))});
}

/// Prints one latency phase, with the distribution over the completed
/// operations.
void report_latency(const PhaseCounts& counts, Samples& samples, std::string_view phase, RunOutcome& outcome) {
  print_fields({field("phase", phase), field("required", counts.required), field("completed", counts.completed),
                field("refused", counts.refused)});
  if (!counts.complete()) {
    print_line("latency=WITHHELD reason=the phase did not complete its required iterations");
    outcome.failed(phase, counts.first_failure);
    return;
  }
  samples.sort();
  print_fields({field("samples", static_cast<std::uint64_t>(samples.size())),
                field("elapsed_ms", milliseconds(counts.elapsed_ns))});
  print_fields({field("median_us", microseconds(samples.percentile(50.0))),
                field("p95_us", microseconds(samples.percentile(95.0))),
                field("p99_us", microseconds(samples.percentile(99.0))),
                field("min_us", microseconds(samples.minimum())),
                field("max_us", microseconds(samples.maximum()))});
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// The warm-up count and the required iteration count of one phase. The warm-up
/// operations are never part of any reported figure.
struct PhaseSizes {
  std::uint64_t warmup = 0;
  std::uint64_t iterations = 0;

  [[nodiscard]] std::uint64_t total() const noexcept { return warmup + iterations; }
};

struct Config {
  bool quick = false;
  PhaseSizes ephemeral_create;
  PhaseSizes ephemeral_transition;
  PhaseSizes ephemeral_ownership;
  PhaseSizes ephemeral_membership;
  PhaseSizes durable_commit;
  PhaseSizes query_reads;
  PhaseSizes snapshot_create;
  PhaseSizes snapshot_digest;
  std::uint64_t tree_depth = 5;
  std::uint64_t tree_fanout = 4;
  std::uint64_t tree_memberships = 5;
};

[[nodiscard]] Config make_config(bool quick) {
  Config config;
  config.quick = quick;
  if (quick) {
    config.ephemeral_create = PhaseSizes{200, 2000};
    config.ephemeral_transition = PhaseSizes{200, 2000};
    config.ephemeral_ownership = PhaseSizes{200, 2000};
    config.ephemeral_membership = PhaseSizes{100, 500};
    config.durable_commit = PhaseSizes{5, 25};
    config.query_reads = PhaseSizes{3, 25};
    config.snapshot_create = PhaseSizes{1, 5};
    config.snapshot_digest = PhaseSizes{1, 10};
  } else {
    config.ephemeral_create = PhaseSizes{2000, 50000};
    config.ephemeral_transition = PhaseSizes{2000, 50000};
    config.ephemeral_ownership = PhaseSizes{2000, 50000};
    config.ephemeral_membership = PhaseSizes{1000, 10000};
    config.durable_commit = PhaseSizes{25, 500};
    config.query_reads = PhaseSizes{20, 200};
    config.snapshot_create = PhaseSizes{2, 30};
    config.snapshot_digest = PhaseSizes{2, 100};
  }
  return config;
}

[[nodiscard]] std::string padded(std::uint64_t value, std::size_t width) {
  std::string text = std::to_string(value);
  if (text.size() < width) {
    text.insert(0, width - text.size(), '0');
  }
  return text;
}

// ---------------------------------------------------------------------------
// The provenance every request carries
// ---------------------------------------------------------------------------

[[nodiscard]] std::optional<tr::TenantId> make_tenant_id(std::string_view text, RunOutcome& outcome) {
  tr::Result<tr::TenantId> created = tr::TenantId::create(text);
  if (!created.has_value()) {
    outcome.failed("tenant_identity", created.error().to_text());
    return std::nullopt;
  }
  return std::optional<tr::TenantId>{std::move(created).value()};
}

[[nodiscard]] std::optional<tr::ServiceId> make_service_id(std::string_view text, RunOutcome& outcome) {
  tr::Result<tr::ServiceId> created = tr::ServiceId::create(text);
  if (!created.has_value()) {
    outcome.failed("service_identity", created.error().to_text());
    return std::nullopt;
  }
  return std::optional<tr::ServiceId>{std::move(created).value()};
}

[[nodiscard]] std::optional<tr::IsolationDomainId> make_domain_id(std::string_view text, RunOutcome& outcome) {
  tr::Result<tr::IsolationDomainId> created = tr::IsolationDomainId::create(text);
  if (!created.has_value()) {
    outcome.failed("isolation_domain_identity", created.error().to_text());
    return std::nullopt;
  }
  return std::optional<tr::IsolationDomainId>{std::move(created).value()};
}

[[nodiscard]] std::optional<tr::PrincipalId> make_principal_id(std::string_view text, RunOutcome& outcome) {
  tr::Result<tr::PrincipalId> created = tr::PrincipalId::create(text);
  if (!created.has_value()) {
    outcome.failed("principal_identity", created.error().to_text());
    return std::nullopt;
  }
  return std::optional<tr::PrincipalId>{std::move(created).value()};
}

/// One provenance record for the whole run: test fixture provenance, so no
/// figure produced here can be mistaken for production data, and no declared
/// time, so nothing depends on when the run happened. It is built once and
/// copied into every request, so its construction is in no timed region.
[[nodiscard]] std::optional<tr::ProvenanceRecord> benchmark_provenance(RunOutcome& outcome) {
  const tr::RegistryLimits limits;
  const tr::Result<tr::SourceId> source = tr::SourceId::create("treg_benchmark");
  if (!source.has_value()) {
    outcome.failed("benchmark_source_identity", source.error().to_text());
    return std::nullopt;
  }
  const std::optional<tr::PrincipalId> principal = make_principal_id("benchmark.operator", outcome);
  if (!principal.has_value()) {
    return std::nullopt;
  }
  tr::Result<tr::ProvenanceRecord> record = tr::ProvenanceRecord::create(
      tr::ProvenanceSource::TestFixture, source.value(), *principal, std::nullopt,
      std::string{"declared by the tenant registry benchmark"}, limits.max_provenance_note_bytes);
  if (!record.has_value()) {
    outcome.failed("benchmark_provenance", record.error().to_text());
    return std::nullopt;
  }
  return std::optional<tr::ProvenanceRecord>{std::move(record).value()};
}

/// The binding every mutating request carries: the generation the caller read,
/// no idempotency key and the run's provenance record.
[[nodiscard]] tr::MutationContext context_for(const tr::TenantRegistry& registry, const tr::ProvenanceRecord& actor) {
  return tr::MutationContext{registry.generation(), std::nullopt, actor};
}

[[nodiscard]] tr::EphemeralOptions ephemeral_options() {
  tr::EphemeralOptions options;
  options.clock = std::make_shared<tr::FixedClock>(kFixedClockMilliseconds);
  return options;
}

/// The size of one file, or nothing when it cannot be read. Only the journal
/// file names of a store this run created are ever printed, never a path.
[[nodiscard]] std::optional<std::uint64_t> file_size_of(const std::filesystem::path& path) {
  std::error_code error;
  const std::uintmax_t size = std::filesystem::file_size(path, error);
  if (error) {
    return std::nullopt;
  }
  return std::optional<std::uint64_t>{static_cast<std::uint64_t>(size)};
}

// ---------------------------------------------------------------------------
// Section 1: ephemeral mutation throughput
// ---------------------------------------------------------------------------

void ephemeral_create(const Config& config, const tr::ProvenanceRecord& actor, RunOutcome& outcome) {
  const PhaseSizes sizes = config.ephemeral_create;
  std::optional<tr::TenantRegistry> registry =
      checked(tr::TenantRegistry::open_ephemeral(ephemeral_options()), "open_ephemeral(create_tenant)", outcome);
  if (!registry.has_value()) {
    return;
  }
  const std::optional<tr::PrincipalId> owner = make_principal_id("facility.ops", outcome);
  if (!owner.has_value()) {
    return;
  }

  std::vector<tr::TenantId> ids;
  std::vector<std::string> display_names;
  ids.reserve(static_cast<std::size_t>(sizes.total()));
  display_names.reserve(static_cast<std::size_t>(sizes.total()));
  for (std::uint64_t index = 0; index < sizes.total(); ++index) {
    std::optional<tr::TenantId> id = make_tenant_id("bulk-" + padded(index, 6), outcome);
    if (!id.has_value()) {
      return;
    }
    ids.push_back(std::move(*id));
    display_names.push_back("bulk tenant " + padded(index, 6));
  }

  const auto operation = [&](std::uint64_t index) -> std::string {
    const std::size_t position = static_cast<std::size_t>(index);
    const tr::Result<tr::CreateTenantOutcome> created = registry->create_tenant(tr::CreateTenantRequest{
        context_for(*registry, actor), ids[position], std::optional<std::string>{display_names[position]},
        std::optional<tr::PrincipalId>{*owner}, tr::TenancyMetadata{}});
    if (!created.has_value()) {
      return created.error().to_text();
    }
    return std::string{};
  };

  print_prose("shape", "each operation declares one new tenant with a display name and an accountable owner "
                       "principal, and no metadata; this phase has no setup records");
  print_fields({field("generated_records", sizes.total()), field("warmup_records", sizes.warmup)});
  const PhaseCounts counts = measure_throughput(sizes.warmup, sizes.iterations, operation);
  report_throughput(counts, "create_tenant", outcome);
}

void ephemeral_transition(const Config& config, const tr::ProvenanceRecord& actor, RunOutcome& outcome) {
  const PhaseSizes sizes = config.ephemeral_transition;
  std::optional<tr::TenantRegistry> registry =
      checked(tr::TenantRegistry::open_ephemeral(ephemeral_options()), "open_ephemeral(transition_subject)", outcome);
  if (!registry.has_value()) {
    return;
  }

  std::vector<tr::TenantId> ids;
  std::vector<tr::RecordRevision> revisions;
  ids.reserve(static_cast<std::size_t>(sizes.total()));
  revisions.reserve(static_cast<std::size_t>(sizes.total()));
  for (std::uint64_t index = 0; index < sizes.total(); ++index) {
    std::optional<tr::TenantId> id = make_tenant_id("transition-" + padded(index, 6), outcome);
    if (!id.has_value()) {
      return;
    }
    std::optional<tr::CreateTenantOutcome> created = checked(
        registry->create_tenant(tr::CreateTenantRequest{context_for(*registry, actor), *id,
                                                        std::optional<std::string>{"transition tenant " +
                                                                                   padded(index, 6)},
                                                        std::nullopt, tr::TenancyMetadata{}}),
        "setup_create_tenant(transition_subject)", outcome);
    if (!created.has_value()) {
      return;
    }
    ids.push_back(std::move(*id));
    revisions.push_back(created->record.revision);
  }

  const auto operation = [&](std::uint64_t index) -> std::string {
    const std::size_t position = static_cast<std::size_t>(index);
    const tr::Result<tr::TransitionSubjectOutcome> transitioned =
        registry->transition_subject(tr::TransitionSubjectRequest{context_for(*registry, actor),
                                                                  tr::TenancySubject::of_tenant(ids[position]),
                                                                  revisions[position], tr::LifecycleState::Active});
    if (!transitioned.has_value()) {
      return transitioned.error().to_text();
    }
    if (tr::subject_state(transitioned.value().record) != tr::LifecycleState::Active) {
      return std::string{"verification: the transition did not reach Active"};
    }
    return std::string{};
  };

  print_prose("shape", "each operation is the first lifecycle transition Declared -> Active of a distinct "
                       "tenant prepared during setup");
  print_fields({field("prepared_records", sizes.total()), field("setup_creates", sizes.total())});
  const PhaseCounts counts = measure_throughput(sizes.warmup, sizes.iterations, operation);
  report_throughput(counts, "transition_subject", outcome);
}

void ephemeral_ownership(const Config& config, const tr::ProvenanceRecord& actor, RunOutcome& outcome) {
  const PhaseSizes sizes = config.ephemeral_ownership;
  constexpr std::uint64_t kParentCount = 16;
  const std::uint64_t child_count = (sizes.total() + kParentCount - 1) / kParentCount;
  std::optional<tr::TenantRegistry> registry =
      checked(tr::TenantRegistry::open_ephemeral(ephemeral_options()), "open_ephemeral(put_ownership)", outcome);
  if (!registry.has_value()) {
    return;
  }

  const auto declare_and_admit = [&](const std::string& text) -> std::optional<tr::TenantId> {
    std::optional<tr::TenantId> id = make_tenant_id(text, outcome);
    if (!id.has_value()) {
      return std::nullopt;
    }
    std::optional<tr::CreateTenantOutcome> created =
        checked(registry->create_tenant(tr::CreateTenantRequest{context_for(*registry, actor), *id, std::nullopt,
                                                                std::nullopt, tr::TenancyMetadata{}}),
                "setup_create_tenant(put_ownership)", outcome);
    if (!created.has_value()) {
      return std::nullopt;
    }
    std::optional<tr::TransitionSubjectOutcome> admitted = checked(
        registry->transition_subject(tr::TransitionSubjectRequest{context_for(*registry, actor),
                                                                  tr::TenancySubject::of_tenant(*id),
                                                                  created->record.revision,
                                                                  tr::LifecycleState::Active}),
        "setup_transition_subject(put_ownership)", outcome);
    if (!admitted.has_value()) {
      return std::nullopt;
    }
    return id;
  };

  std::vector<tr::TenantId> parent_ids;
  std::vector<tr::TenantId> child_ids;
  parent_ids.reserve(static_cast<std::size_t>(kParentCount));
  child_ids.reserve(static_cast<std::size_t>(child_count));
  for (std::uint64_t index = 0; index < kParentCount; ++index) {
    std::optional<tr::TenantId> id = declare_and_admit("own-parent-" + padded(index, 2));
    if (!id.has_value()) {
      return;
    }
    parent_ids.push_back(std::move(*id));
  }
  for (std::uint64_t index = 0; index < child_count; ++index) {
    std::optional<tr::TenantId> id = declare_and_admit("own-child-" + padded(index, 6));
    if (!id.has_value()) {
      return;
    }
    child_ids.push_back(std::move(*id));
  }

  const auto operation = [&](std::uint64_t index) -> std::string {
    const std::uint64_t child = index / kParentCount;
    const std::uint64_t parent = index % kParentCount;
    const tr::Result<tr::PutOwnershipOutcome> placed = registry->put_ownership(tr::PutOwnershipRequest{
        context_for(*registry, actor), child_ids[static_cast<std::size_t>(child)],
        parent_ids[static_cast<std::size_t>(parent)], tr::OwnershipKind::Operational, tr::LifecycleState::Active,
        std::nullopt});
    if (!placed.has_value()) {
      return placed.error().to_text();
    }
    return std::string{};
  };

  print_prose("shape", "each operation declares one in-force Operational ownership edge child -> parent; every "
                       "child and every parent was declared and admitted during setup");
  print_fields({field("setup_parents", kParentCount), field("setup_children", child_count),
                field("setup_records", kParentCount + 2 * child_count)});
  const PhaseCounts counts = measure_throughput(sizes.warmup, sizes.iterations, operation);
  report_throughput(counts, "put_ownership", outcome);
}

void ephemeral_membership(const Config& config, const tr::ProvenanceRecord& actor, RunOutcome& outcome) {
  const PhaseSizes sizes = config.ephemeral_membership;
  constexpr std::uint64_t kMembershipsPerSubject = 16;
  const std::uint64_t subject_count = (sizes.total() + kMembershipsPerSubject - 1) / kMembershipsPerSubject;
  const std::uint64_t domain_count = (sizes.total() + subject_count - 1) / subject_count;
  std::optional<tr::TenantRegistry> registry = checked(
      tr::TenantRegistry::open_ephemeral(ephemeral_options()), "open_ephemeral(put_isolation_membership)", outcome);
  if (!registry.has_value()) {
    return;
  }

  const auto declare_and_admit = [&](const std::string& text) -> std::optional<tr::TenantId> {
    std::optional<tr::TenantId> id = make_tenant_id(text, outcome);
    if (!id.has_value()) {
      return std::nullopt;
    }
    std::optional<tr::CreateTenantOutcome> created =
        checked(registry->create_tenant(tr::CreateTenantRequest{context_for(*registry, actor), *id, std::nullopt,
                                                                std::nullopt, tr::TenancyMetadata{}}),
                "setup_create_tenant(put_isolation_membership)", outcome);
    if (!created.has_value()) {
      return std::nullopt;
    }
    std::optional<tr::TransitionSubjectOutcome> admitted = checked(
        registry->transition_subject(tr::TransitionSubjectRequest{context_for(*registry, actor),
                                                                  tr::TenancySubject::of_tenant(*id),
                                                                  created->record.revision,
                                                                  tr::LifecycleState::Active}),
        "setup_transition_subject(put_isolation_membership)", outcome);
    if (!admitted.has_value()) {
      return std::nullopt;
    }
    return id;
  };

  std::vector<tr::TenantId> subject_ids;
  std::vector<tr::IsolationDomainId> domain_ids;
  std::vector<tr::DomainGeneration> generations;
  subject_ids.reserve(static_cast<std::size_t>(subject_count));
  domain_ids.reserve(static_cast<std::size_t>(domain_count));
  generations.reserve(static_cast<std::size_t>(domain_count));
  for (std::uint64_t index = 0; index < subject_count; ++index) {
    std::optional<tr::TenantId> id = declare_and_admit("member-" + padded(index, 6));
    if (!id.has_value()) {
      return;
    }
    subject_ids.push_back(std::move(*id));
  }
  for (std::uint64_t index = 0; index < domain_count; ++index) {
    std::optional<tr::IsolationDomainId> id = make_domain_id("member-domain-" + padded(index, 3), outcome);
    if (!id.has_value()) {
      return;
    }
    std::optional<tr::CreateIsolationDomainOutcome> created = checked(
        registry->create_isolation_domain(tr::CreateIsolationDomainRequest{
            context_for(*registry, actor), *id, tr::IsolationClass::FaultContainment, std::nullopt,
            tr::TenancyMetadata{}}),
        "setup_create_isolation_domain(put_isolation_membership)", outcome);
    if (!created.has_value()) {
      return;
    }
    std::optional<tr::TransitionSubjectOutcome> admitted = checked(
        registry->transition_subject(
            tr::TransitionSubjectRequest{context_for(*registry, actor),
                                         tr::TenancySubject::of_isolation_domain(*id),
                                         created->record.revision, tr::LifecycleState::Active}),
        "setup_transition_subject(isolation_domain)", outcome);
    if (!admitted.has_value()) {
      return;
    }
    const std::optional<tr::IsolationDomainRecord> current =
        checked(registry->find_isolation_domain(*id), "setup_find_isolation_domain", outcome);
    if (!current.has_value()) {
      return;
    }
    domain_ids.push_back(std::move(*id));
    generations.push_back(current->membership_generation);
  }

  const auto operation = [&](std::uint64_t index) -> std::string {
    const std::uint64_t subject = index % subject_count;
    const std::uint64_t domain = index / subject_count;
    const std::size_t domain_position = static_cast<std::size_t>(domain);
    const tr::Result<tr::PutIsolationMembershipOutcome> joined = registry->put_isolation_membership(
        tr::PutIsolationMembershipRequest{context_for(*registry, actor),
                                          tr::TenancySubject::of_tenant(subject_ids[static_cast<std::size_t>(subject)]),
                                          domain_ids[domain_position], tr::MembershipRole::Secondary,
                                          tr::MembershipState::Bound, generations[domain_position], std::nullopt});
    if (!joined.has_value()) {
      return joined.error().to_text();
    }
    generations[domain_position] = joined.value().domain_generation;
    return std::string{};
  };

  print_prose("shape", "each operation declares one in-force Secondary Bound isolation membership of a distinct "
                       "subject in a distinct domain; every subject and domain was declared and admitted during "
                       "setup");
  print_prose("note", "the operation's own per-domain bound check scans the membership set, so this rate carries "
                      "that scan");
  print_fields({field("setup_subjects", subject_count), field("setup_domains", domain_count),
                field("setup_records", subject_count + domain_count)});
  const PhaseCounts counts = measure_throughput(sizes.warmup, sizes.iterations, operation);
  report_throughput(counts, "put_isolation_membership", outcome);
}

void ephemeral_sections(const Config& config, const tr::ProvenanceRecord& actor, RunOutcome& outcome) {
  print_line("");
  print_line("== section 1: ephemeral mutation throughput ==");
  print_line("label=SYNTHETIC");
  print_prose("scope", "TenantRegistry::open_ephemeral; an in-memory registry with no durable state and no "
                       "store I/O");
  print_prose("measure", "completed operations per second over the timed loop as a whole; the warm-up loop is "
                         "excluded");
  ephemeral_create(config, actor, outcome);
  ephemeral_transition(config, actor, outcome);
  ephemeral_ownership(config, actor, outcome);
  ephemeral_membership(config, actor, outcome);
}

// ---------------------------------------------------------------------------
// Sections 2 and 3: the durable commit path and durable compaction
// ---------------------------------------------------------------------------

void durable_sections(const Config& config, const std::filesystem::path& root, const tr::ProvenanceRecord& actor,
                      RunOutcome& outcome) {
  const PhaseSizes sizes = config.durable_commit;
  print_line("");
  print_line("== section 2: durable commit latency ==");
  print_line("label=REAL");
  print_prose("scope", "the whole of create_tenant on a durable store: the journal append, the flush, the "
                       "read-back verification and the atomic manifest replacement");

  tr::RegistryOpenRequest request;
  request.root = root;
  request.mode = tr::AccessMode::ReadWrite;
  request.store.holder_note = "treg benchmark";
  request.clock = std::make_shared<tr::FixedClock>(kFixedClockMilliseconds);

  std::optional<tr::TenantRegistry> opened =
      checked(tr::TenantRegistry::open(request), "open_durable", outcome);
  if (!opened.has_value()) {
    print_prose("SKIPPED", "the durable store could not be opened");
    return;
  }
  tr::TenantRegistry& registry = *opened;
  const tr::StoreRecoveryReport recovery = registry.recovery_report();
  print_fields({field("store_created", yes_no(recovery.store_created)),
                field("store_identity", yes_no(registry.store_identity().has_value())),
                field("control_epoch", registry.control_epoch().value()),
                field("incarnation", registry.incarnation().value()),
                field("committed_sequence_at_open", registry.committed_sequence().value())});

  const std::optional<tr::PrincipalId> owner = make_principal_id("facility.ops", outcome);
  if (!owner.has_value()) {
    return;
  }
  std::vector<tr::TenantId> ids;
  std::vector<std::string> display_names;
  ids.reserve(static_cast<std::size_t>(sizes.total()));
  display_names.reserve(static_cast<std::size_t>(sizes.total()));
  for (std::uint64_t index = 0; index < sizes.total(); ++index) {
    std::optional<tr::TenantId> id = make_tenant_id("durable-" + padded(index, 6), outcome);
    if (!id.has_value()) {
      return;
    }
    ids.push_back(std::move(*id));
    display_names.push_back("durable tenant " + padded(index, 6));
  }

  tr::JournalSequence last_sequence = registry.committed_sequence();
  const auto operation = [&](std::uint64_t index) -> std::string {
    const std::size_t position = static_cast<std::size_t>(index);
    const tr::Result<tr::CreateTenantOutcome> committed = registry.create_tenant(tr::CreateTenantRequest{
        context_for(registry, actor), ids[position], std::optional<std::string>{display_names[position]},
        std::optional<tr::PrincipalId>{*owner}, tr::TenancyMetadata{}});
    if (!committed.has_value()) {
      return committed.error().to_text();
    }
    const tr::MutationReceipt& receipt = committed.value().receipt;
    if (receipt.replayed) {
      return std::string{"verification: the commit was answered from the idempotency ledger"};
    }
    if (!(last_sequence < receipt.sequence)) {
      return std::string{"verification: the journal sequence did not advance"};
    }
    last_sequence = receipt.sequence;
    return std::string{};
  };

  print_prose("shape", "each operation commits one new tenant with a display name and an accountable owner "
                       "principal, and no metadata; this phase has no setup records");
  print_fields({field("generated_records", sizes.total()), field("warmup_records", sizes.warmup)});
  Samples samples;
  const PhaseCounts counts = measure_latency(sizes.warmup, sizes.iterations, operation, samples);
  report_latency(counts, samples, "create_tenant_durable_commit", outcome);

  const tr::RegistryStats committed_stats = registry.stats();
  print_fields({field("records_in_store", committed_stats.tenants),
                field("committed_sequence", registry.committed_sequence().value())});

  // -- section 3 ------------------------------------------------------------
  print_line("");
  print_line("== section 3: durable compaction ==");
  print_line("label=REAL");
  print_prose("scope", "one compact() over the store this session just committed to; the journal file is "
                       "rewritten as a fresh baseline plus the frames committed since");

  const std::optional<tr::StoreIdentity> identity_before = registry.store_identity();
  if (!identity_before.has_value()) {
    outcome.failed("compact", "the session reports no store identity");
    return;
  }
  const std::optional<std::uint64_t> bytes_before = file_size_of(root / identity_before->journal_name);
  if (!bytes_before.has_value()) {
    outcome.failed("compact", "the active journal could not be sized before compaction");
    return;
  }
  const std::uint64_t records_before = registry.stats().tenants;
  const Clock::time_point compact_start = Clock::now();
  const tr::Status compacted = registry.compact();
  const Clock::time_point compact_end = Clock::now();
  if (!compacted.ok()) {
    outcome.failed("compact", compacted.error().to_text());
    return;
  }
  const std::optional<tr::StoreIdentity> identity_after = registry.store_identity();
  if (!identity_after.has_value()) {
    outcome.failed("compact", "the session reports no store identity after compaction");
    return;
  }
  const std::optional<std::uint64_t> bytes_after = file_size_of(root / identity_after->journal_name);
  if (!bytes_after.has_value()) {
    outcome.failed("compact", "the active journal could not be sized after compaction");
    return;
  }
  const std::uint64_t records_after = registry.stats().tenants;
  print_fields({field("records_at_compaction", records_before),
                field("compact_ms", milliseconds(elapsed_nanoseconds(compact_start, compact_end))),
                field("journal_before_file", identity_before->journal_name),
                field("journal_before_bytes", *bytes_before),
                field("journal_after_file", identity_after->journal_name),
                field("journal_after_bytes", *bytes_after),
                field("records_after_compaction", records_after),
                field("committed_sequence_after_compaction", registry.committed_sequence().value())});
  if (records_after != records_before) {
    outcome.failed("compact", "the record count changed across compaction");
  }

  if (checked(registry.close(), "close_durable", outcome)) {
    print_line("durable_session=closed");
  }
}

// ---------------------------------------------------------------------------
// Sections 4 and 5: reads, queries and snapshots
// ---------------------------------------------------------------------------

/// The registry the read and snapshot sections measure, with the shape facts
/// that make its figures interpretable: a tree of a known depth and fan-out,
/// one service bound to the root, and one isolation domain holding a known
/// number of memberships.
struct QueryRegistry {
  tr::TenantRegistry registry;
  std::vector<tr::TenantId> tenants;
  std::uint64_t depth = 0;
  std::uint64_t fanout = 0;
  std::uint64_t memberships = 0;
};

[[nodiscard]] std::optional<QueryRegistry> build_query_registry(const Config& config, const tr::ProvenanceRecord& actor,
                                                               RunOutcome& outcome) {
  std::optional<tr::TenantRegistry> registry =
      checked(tr::TenantRegistry::open_ephemeral(ephemeral_options()), "open_ephemeral(query_registry)", outcome);
  if (!registry.has_value()) {
    return std::nullopt;
  }

  std::uint64_t tenant_count = 1;
  std::uint64_t level = 1;
  for (std::uint64_t depth = 0; depth < config.tree_depth; ++depth) {
    level *= config.tree_fanout;
    tenant_count += level;
  }

  std::vector<tr::TenantId> tenants;
  tenants.reserve(static_cast<std::size_t>(tenant_count));
  for (std::uint64_t index = 0; index < tenant_count; ++index) {
    std::optional<tr::TenantId> id = make_tenant_id("node-" + padded(index, 5), outcome);
    if (!id.has_value()) {
      return std::nullopt;
    }
    std::optional<tr::CreateTenantOutcome> created = checked(
        registry->create_tenant(tr::CreateTenantRequest{context_for(*registry, actor), *id,
                                                        std::optional<std::string>{"node " + padded(index, 5)},
                                                        std::nullopt, tr::TenancyMetadata{}}),
        "setup_create_tenant(query_registry)", outcome);
    if (!created.has_value()) {
      return std::nullopt;
    }
    std::optional<tr::TransitionSubjectOutcome> admitted = checked(
        registry->transition_subject(tr::TransitionSubjectRequest{context_for(*registry, actor),
                                                                  tr::TenancySubject::of_tenant(*id),
                                                                  created->record.revision,
                                                                  tr::LifecycleState::Active}),
        "setup_transition_subject(query_registry)", outcome);
    if (!admitted.has_value()) {
      return std::nullopt;
    }
    if (index > 0) {
      const std::uint64_t parent_index = (index - 1) / config.tree_fanout;
      std::optional<tr::PutOwnershipOutcome> edge = checked(
          registry->put_ownership(tr::PutOwnershipRequest{context_for(*registry, actor), *id,
                                                          tenants[static_cast<std::size_t>(parent_index)],
                                                          tr::OwnershipKind::Administrative,
                                                          tr::LifecycleState::Active, std::nullopt}),
          "setup_put_ownership(query_registry)", outcome);
      if (!edge.has_value()) {
        return std::nullopt;
      }
    }
    tenants.push_back(std::move(*id));
  }

  std::optional<tr::ServiceId> service = make_service_id("svc-renderer", outcome);
  if (!service.has_value()) {
    return std::nullopt;
  }
  std::optional<tr::CreateServiceOutcome> service_created = checked(
      registry->create_service(tr::CreateServiceRequest{context_for(*registry, actor), *service,
                                                        std::optional<std::string>{"Renderer"},
                                                        tr::TenancyMetadata{}}),
      "setup_create_service", outcome);
  if (!service_created.has_value()) {
    return std::nullopt;
  }
  std::optional<tr::TransitionSubjectOutcome> service_admitted = checked(
      registry->transition_subject(tr::TransitionSubjectRequest{context_for(*registry, actor),
                                                                tr::TenancySubject::of_service(*service),
                                                                service_created->record.revision,
                                                                tr::LifecycleState::Active}),
      "setup_transition_service", outcome);
  if (!service_admitted.has_value()) {
    return std::nullopt;
  }
  std::optional<tr::PutServiceBindingOutcome> binding = checked(
      registry->put_service_binding(tr::PutServiceBindingRequest{context_for(*registry, actor), *service,
                                                                 tenants.front(), tr::BindingKind::OperatedBy,
                                                                 tr::LifecycleState::Active, std::nullopt}),
      "setup_put_service_binding", outcome);
  if (!binding.has_value()) {
    return std::nullopt;
  }

  std::optional<tr::IsolationDomainId> domain = make_domain_id("zone-a", outcome);
  if (!domain.has_value()) {
    return std::nullopt;
  }
  std::optional<tr::CreateIsolationDomainOutcome> domain_created = checked(
      registry->create_isolation_domain(tr::CreateIsolationDomainRequest{
          context_for(*registry, actor), *domain, tr::IsolationClass::FaultContainment,
          std::optional<std::string>{"Zone A"}, tr::TenancyMetadata{}}),
      "setup_create_isolation_domain", outcome);
  if (!domain_created.has_value()) {
    return std::nullopt;
  }
  std::optional<tr::TransitionSubjectOutcome> domain_admitted = checked(
      registry->transition_subject(
          tr::TransitionSubjectRequest{context_for(*registry, actor),
                                       tr::TenancySubject::of_isolation_domain(*domain),
                                       domain_created->record.revision, tr::LifecycleState::Active}),
      "setup_transition_domain", outcome);
  if (!domain_admitted.has_value()) {
    return std::nullopt;
  }

  std::optional<tr::IsolationDomainRecord> current =
      checked(registry->find_isolation_domain(*domain), "setup_find_isolation_domain", outcome);
  if (!current.has_value()) {
    return std::nullopt;
  }
  tr::DomainGeneration generation = current->membership_generation;
  const std::uint64_t membership_count = std::min<std::uint64_t>(config.tree_memberships, tenant_count);
  for (std::uint64_t index = 0; index < membership_count; ++index) {
    std::optional<tr::PutIsolationMembershipOutcome> joined = checked(
        registry->put_isolation_membership(tr::PutIsolationMembershipRequest{
            context_for(*registry, actor), tr::TenancySubject::of_tenant(tenants[static_cast<std::size_t>(index)]),
            *domain, tr::MembershipRole::Primary, tr::MembershipState::Bound, generation, std::nullopt}),
        "setup_put_isolation_membership", outcome);
    if (!joined.has_value()) {
      return std::nullopt;
    }
    generation = joined->domain_generation;
  }

  return std::optional<QueryRegistry>{QueryRegistry{std::move(*registry), std::move(tenants), config.tree_depth,
                                                    config.tree_fanout, membership_count}};
}

void reads_and_snapshot(const Config& config, const tr::ProvenanceRecord& actor, RunOutcome& outcome) {
  const std::optional<QueryRegistry> shape = build_query_registry(config, actor, outcome);
  if (!shape.has_value()) {
    print_prose("SKIPPED", "the query registry could not be built");
    return;
  }
  const tr::TenantRegistry& registry = shape->registry;
  const PhaseSizes sizes = config.query_reads;
  const tr::TenantId& root = shape->tenants.front();
  const tr::TenancySubject explained_subject = tr::TenancySubject::of_tenant(shape->tenants[1]);
  const std::uint64_t expected_tenants = static_cast<std::uint64_t>(shape->tenants.size());
  const std::uint64_t expected_edges = expected_tenants - 1;
  const tr::RegistryStats stats = registry.stats();

  print_line("");
  print_line("== section 4: read and query latency ==");
  print_line("label=SYNTHETIC");
  print_prose("scope", "one in-memory ephemeral registry; every read holds the registry mutex and touches no "
                       "store");
  print_prose("measure", "median and p95 over the completed operations, using the nearest rank rule stated above");
  print_fields({field("registry_tenants", stats.tenants),
                field("registry_ownership_edges", stats.ownership_edges),
                field("registry_services", stats.services),
                field("registry_service_bindings", stats.service_bindings),
                field("registry_isolation_domains", stats.isolation_domains),
                field("registry_isolation_memberships", stats.isolation_memberships)});
  print_fields({field("tree_depth", shape->depth), field("tree_fanout", shape->fanout),
                field("tree_tenants", expected_tenants), field("tree_edges", expected_edges),
                field("tree_memberships", shape->memberships), field("tree_root", root.to_text())});
  print_fields({field("read_iterations_each", sizes.iterations), field("read_warmup_each", sizes.warmup)});
  print_prose("traverse_bound", "the walk is given a depth bound one level deeper than the tree, so it terminates by "
                                "exhausting the frontier instead of by the bound, which is what makes it a complete "
                                "answer");

  Samples find_samples;
  const PhaseCounts find_counts = measure_latency(
      sizes.warmup, sizes.iterations,
      [&](std::uint64_t) -> std::string {
        const tr::Result<tr::TenantRecord> found = registry.find_tenant(root);
        if (!found.has_value()) {
          return found.error().to_text();
        }
        if (!(found.value().id == root)) {
          return std::string{"verification: find_tenant returned a different identity"};
        }
        return std::string{};
      },
      find_samples);
  report_latency(find_counts, find_samples, "find_tenant", outcome);

  const std::size_t page_limit = registry.limits().max_listing_limit;
  std::uint64_t pages_observed = 0;
  Samples list_samples;
  const PhaseCounts list_counts = measure_latency(
      sizes.warmup, sizes.iterations,
      [&](std::uint64_t) -> std::string {
        tr::TenantQuery query;
        query.limit = page_limit;
        std::uint64_t items = 0;
        std::uint64_t pages = 0;
        while (true) {
          const tr::Result<tr::Page<tr::TenantSummary>> page = registry.list_tenants(query);
          if (!page.has_value()) {
            return page.error().to_text();
          }
          ++pages;
          items += static_cast<std::uint64_t>(page.value().items.size());
          if (!page.value().truncated) {
            break;
          }
          if (!page.value().next_cursor.has_value()) {
            return std::string{"verification: a truncated page carried no cursor"};
          }
          query.cursor = page.value().next_cursor;
          if (pages > kMaximumPagesPerPass) {
            return std::string{"verification: pagination did not terminate"};
          }
        }
        if (items != expected_tenants) {
          return std::string{"verification: the listing did not cover the whole registry"};
        }
        pages_observed = pages;
        return std::string{};
      },
      list_samples);
  report_latency(list_counts, list_samples, "list_tenants_whole_registry", outcome);
  print_fields({field("list_page_limit", static_cast<std::uint64_t>(page_limit)),
                field("list_pages_per_pass", pages_observed), field("list_items_per_pass", expected_tenants)});

  std::uint64_t reached_observed = 0;
  std::uint64_t steps_observed = 0;
  std::uint64_t depth_observed = 0;
  Samples traverse_samples;
  const PhaseCounts traverse_counts = measure_latency(
      sizes.warmup, sizes.iterations,
      [&](std::uint64_t) -> std::string {
        const tr::Result<tr::OwnershipTraversal> walked = registry.traverse_ownership(tr::OwnershipTraversalRequest{
            root, tr::TraversalDirection::Descendants, std::nullopt, std::nullopt,
            static_cast<std::size_t>(shape->depth + 1), 0});
        if (!walked.has_value()) {
          return walked.error().to_text();
        }
        if (walked.value().truncated) {
          return std::string{"verification: the traversal was truncated"};
        }
        if (static_cast<std::uint64_t>(walked.value().reached.size()) != expected_edges) {
          return std::string{"verification: the traversal did not reach every other tenant"};
        }
        if (static_cast<std::uint64_t>(walked.value().steps.size()) != expected_edges) {
          return std::string{"verification: the traversal did not walk every edge"};
        }
        reached_observed = static_cast<std::uint64_t>(walked.value().reached.size());
        steps_observed = static_cast<std::uint64_t>(walked.value().steps.size());
        depth_observed = static_cast<std::uint64_t>(walked.value().max_depth_reached);
        return std::string{};
      },
      traverse_samples);
  report_latency(traverse_counts, traverse_samples, "traverse_ownership_descendants", outcome);
  print_fields({field("traverse_reached", reached_observed), field("traverse_steps", steps_observed),
                field("traverse_depth_bound", shape->depth + 1),
                field("traverse_max_depth_reached", depth_observed), field("traverse_truncated", yes_no(false))});

  std::uint64_t owns_observed = 0;
  std::uint64_t owned_by_observed = 0;
  std::uint64_t lineage_observed = 0;
  std::uint64_t bindings_observed = 0;
  std::uint64_t memberships_observed = 0;
  std::uint64_t unknowns_observed = 0;
  Samples explain_samples;
  const PhaseCounts explain_counts = measure_latency(
      sizes.warmup, sizes.iterations,
      [&](std::uint64_t) -> std::string {
        const tr::Result<tr::Explanation> answer = registry.explain(explained_subject);
        if (!answer.has_value()) {
          return answer.error().to_text();
        }
        if (!(answer.value().subject == explained_subject)) {
          return std::string{"verification: the explanation is about a different subject"};
        }
        if (static_cast<std::uint64_t>(answer.value().owns.size()) != shape->fanout) {
          return std::string{"verification: the explanation does not hold every owned edge"};
        }
        if (answer.value().ownership_lineage.size() != 1) {
          return std::string{"verification: the explanation lineage is not the expected depth"};
        }
        if (answer.value().memberships.size() != 1) {
          return std::string{"verification: the explanation does not hold the expected membership"};
        }
        owns_observed = static_cast<std::uint64_t>(answer.value().owns.size());
        owned_by_observed = static_cast<std::uint64_t>(answer.value().owned_by.size());
        lineage_observed = static_cast<std::uint64_t>(answer.value().ownership_lineage.size());
        bindings_observed = static_cast<std::uint64_t>(answer.value().bindings.size());
        memberships_observed = static_cast<std::uint64_t>(answer.value().memberships.size());
        unknowns_observed = static_cast<std::uint64_t>(answer.value().unknowns.size());
        return std::string{};
      },
      explain_samples);
  report_latency(explain_counts, explain_samples, "explain_tenant", outcome);
  print_fields({field("explain_subject", explained_subject.to_text()), field("explain_owns", owns_observed),
                field("explain_owned_by", owned_by_observed), field("explain_lineage", lineage_observed),
                field("explain_bindings", bindings_observed), field("explain_memberships", memberships_observed),
                field("explain_unknowns", unknowns_observed)});

  print_line("");
  print_line("== section 5: snapshot cost ==");
  print_line("label=SYNTHETIC");
  print_prose("scope", "snapshot() of the whole registry and digest() of one retained snapshot; no store I/O");
  const tr::RegistrySnapshot retained = registry.snapshot();
  const std::uint64_t records = static_cast<std::uint64_t>(retained.record_count());
  const std::uint64_t canonical_bytes = static_cast<std::uint64_t>(retained.to_canonical_bytes().size());
  print_fields({field("records_in_snapshot", records), field("canonical_bytes", canonical_bytes),
                field("snapshot_iterations", config.snapshot_create.iterations),
                field("snapshot_warmup", config.snapshot_create.warmup),
                field("digest_iterations", config.snapshot_digest.iterations),
                field("digest_warmup", config.snapshot_digest.warmup)});

  Samples snapshot_samples;
  const PhaseCounts snapshot_counts = measure_latency(
      config.snapshot_create.warmup, config.snapshot_create.iterations,
      [&](std::uint64_t) -> std::string {
        const tr::RegistrySnapshot taken = registry.snapshot();
        if (static_cast<std::uint64_t>(taken.record_count()) != records) {
          return std::string{"verification: the snapshot holds a different record count"};
        }
        return std::string{};
      },
      snapshot_samples);
  report_latency(snapshot_counts, snapshot_samples, "snapshot", outcome);

  Samples digest_samples;
  const PhaseCounts digest_counts = measure_latency(
      config.snapshot_digest.warmup, config.snapshot_digest.iterations,
      [&](std::uint64_t) -> std::string {
        if (retained.digest().is_zero()) {
          return std::string{"verification: the snapshot digest is the zero digest"};
        }
        return std::string{};
      },
      digest_samples);
  report_latency(digest_counts, digest_samples, "snapshot_digest", outcome);
}

// ---------------------------------------------------------------------------
// The report header and the summary
// ---------------------------------------------------------------------------

void print_counts(std::string_view phase, const PhaseSizes& sizes) {
  print_fields({field("configured", phase), field("warmup", sizes.warmup), field("iterations", sizes.iterations)});
}

void print_methodology(const Config& config) {
  print_line("treg_benchmark: Tenant Registry benchmark; completed operations only");
  print_fields({field("mode", config.quick ? "quick" : "full"),
                field("library_version", tr::version_string()),
                field("store_format_version", std::to_string(tr::kStoreFormatVersion)),
                field("canonical_encoding_version", std::to_string(tr::kCanonicalEncodingVersion)),
                field("export_format_version", std::to_string(tr::kExportFormatVersion))});
  print_prose("clock", "std::chrono::steady_clock; every figure is a single-host wall clock measurement taken "
                       "in this process");
  print_prose("labels", "SYNTHETIC = generated data in this process with no durable path; REAL = the whole durable "
                        "commit path");
  print_prose("percentile_method", "nearest rank over sorted samples: index = ceil(p/100 * N), clamped to [1, N]");
  print_prose("rate_policy", "completed operations only; refusals are counted separately and never enter a rate");
  print_prose("warmup_policy", "every warm-up operation is excluded from every reported figure");
  print_prose("timed_region", "the construction of the request aggregate plus the complete synchronous API call; "
                              "there is no enqueue and no submission to measure");
  print_prose("provenance", "one ProvenanceRecord (source=test_fixture, no declared time) is built once and copied "
                            "into every request; its construction is not timed");
  print_prose("temporary_directory", "a directory under the system temporary directory is created and removed on "
                                     "every exit path; no file outside it is written and no path inside it is "
                                     "printed");

  print_line("registry_limits (the RegistryLimits in force for every registry in this run):");
  const tr::RegistryLimits limits;
  const std::string rendered = limits.to_text();
  std::size_t begin = 0;
  while (begin <= rendered.size()) {
    const std::size_t end = rendered.find('\n', begin);
    const std::size_t stop = end == std::string::npos ? rendered.size() : end;
    const std::string_view line{rendered.data() + begin, stop - begin};
    if (!line.empty()) {
      print_line("  " + std::string{line});
    }
    if (end == std::string::npos) {
      break;
    }
    begin = end + 1;
  }

  print_line("configured_counts (warm-up operations are excluded; iterations are the required completed count):");
  print_counts("ephemeral_create", config.ephemeral_create);
  print_counts("ephemeral_transition", config.ephemeral_transition);
  print_counts("ephemeral_ownership", config.ephemeral_ownership);
  print_counts("ephemeral_membership", config.ephemeral_membership);
  print_counts("durable_commit", config.durable_commit);
  print_counts("query_reads_each", config.query_reads);
  print_counts("snapshot_create", config.snapshot_create);
  print_counts("snapshot_digest", config.snapshot_digest);
  print_fields({field("query_tree_depth", config.tree_depth), field("query_tree_fanout", config.tree_fanout),
                field("query_tree_memberships", config.tree_memberships)});
}

void print_summary(const RunOutcome& outcome) {
  print_line("");
  print_line("== summary ==");
  print_fields({field("phases_failed", outcome.failures()), field("result", outcome.failures() == 0 ? "PASS" : "FAIL"),
                field("exit_code", outcome.failures() == 0 ? 0 : 1)});
}

}  // namespace

int main(int argc, char** argv) {
  bool quick = false;
  for (int index = 1; index < argc; ++index) {
    const std::string_view argument{argv[index]};
    if (argument == "--quick") {
      quick = true;
      continue;
    }
    fatal("usage: treg_benchmark [--quick]");
  }

  const Config config = make_config(quick);
  print_methodology(config);

  RunOutcome outcome;
  {
    TempDirectory directory;
    const std::optional<tr::ProvenanceRecord> actor = benchmark_provenance(outcome);
    if (!actor.has_value()) {
      print_prose("SKIPPED", "the benchmark provenance record could not be created");
    } else {
      ephemeral_sections(config, *actor, outcome);
      durable_sections(config, directory.path(), *actor, outcome);
      reads_and_snapshot(config, *actor, outcome);
    }
  }

  print_summary(outcome);
  return outcome.failures() == 0 ? 0 : 1;
}
