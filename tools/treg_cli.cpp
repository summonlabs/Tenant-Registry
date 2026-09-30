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

// treg -- the Tenant Registry command line tool.
//
// The tool is a thin, strict operator surface over the whole public API: it
// parses, it validates, it calls exactly one library operation, and it renders
// the answer. It never invents a token, a state, a kind or a counter: every
// token that names a library value is parsed by the library's own parse
// function, and every counter is printed as a plain decimal number.
//
// Three properties are load bearing here:
//
//   * Argument parsing is strict. An unknown flag, a missing value, a repeated
//     single valued flag, a positional argument in the wrong place and an
//     unparsable or out of range number are usage errors (exit 2), and the
//     message names the offending token.
//   * A refusal is not an error message. The library's Error carries an exact
//     code, a subject and suppressed notes; the tool prints the code and the
//     detail on stderr, one indented note line per suppressed note, and maps
//     the refusal class onto the exit code.
//   * --self-check and --scenario are the two modes ctest runs. Both are byte
//     for byte deterministic, both build every registry they touch inside a
//     scratch directory that is removed through RAII on every path including
//     the failure paths, and neither ever prints a path, a clock reading or a
//     randomly minted store identity.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <limits>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "tenant_registry/tenant_registry.hpp"

namespace {

using namespace tenant_registry;

// ---------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------

constexpr int kExitSuccess = 0;
constexpr int kExitRefusal = 1;
constexpr int kExitUsage = 2;
constexpr int kExitStore = 3;

/// The limits this tool configures. It configures none: the registry's own
/// defaults are the bounds the tool validates against, so a bound the tool
/// accepts is exactly a bound the library accepts.
constexpr RegistryLimits kLimits{};

constexpr std::string_view kUsageText =
    "usage: treg [--root <dir>] [--read-only] [--json] [--quiet] [--principal <id>] [--source <id>]\n"
    "            [--provenance <source>] [--accepted-generation <n>] [--idempotency-key <key>]\n"
    "            <command> [arguments]\n"
    "\n"
    "  With no --root the registry is ephemeral and the output header says so.\n"
    "  With --root the registry is durable at that directory.\n"
    "\n"
    "special modes (no other arguments):\n"
    "  --self-check                     internal battery against an ephemeral and a temporary durable registry\n"
    "  --scenario                       deterministic end to end scenario transcript\n"
    "\n"
    "tenant:\n"
    "  tenant create <id> [--display-name <text>] [--owner <principal>] [--metadata k=v]...\n"
    "  tenant show <id>\n"
    "  tenant list [--state <s>] [--member-of <domain>] [--limit <n>] [--cursor <c>]\n"
    "  tenant transition <id> --to <state> --revision <n>\n"
    "  tenant set-owner <id> --revision <n> (--owner <principal> | --clear-owner)\n"
    "  tenant metadata <id> --revision <n> [--put k=v]... [--remove k]...\n"
    "  tenant tombstone <id> --revision <n> --acknowledge [--rebind-to <id>] [--note <text>]\n"
    "  tenant tombstone-show <id>\n"
    "\n"
    "service:\n"
    "  service create <id> [--display-name <text>] [--metadata k=v]...\n"
    "  service show <id>\n"
    "  service list [--state <s>] [--limit <n>] [--cursor <c>]\n"
    "  service transition <id> --to <state> --revision <n>\n"
    "\n"
    "domain:\n"
    "  domain create <id> --class <fault_containment|administrative|regulatory|tenant_private>\n"
    "                    [--display-name <text>] [--metadata k=v]...\n"
    "  domain transition <id> --to <state> --revision <n>\n"
    "  domain show <id> [--membership-generation <n>]\n"
    "  domain list [--state <s>] [--class <c>] [--limit <n>] [--cursor <c>]\n"
    "  domain members <id> [--limit <n>]\n"
    "\n"
    "ownership:\n"
    "  ownership put <child> <parent> --kind <administrative|operational|regulatory|data_residency>\n"
    "                [--state <declared|active>] [--revision <n>]\n"
    "  ownership remove <child> <parent> --revision <n>\n"
    "  ownership transition <child> <parent> --to <state> --revision <n>\n"
    "  ownership list [--child <id>] [--parent <id>] [--kind <k>] [--state <s>] [--limit <n>] [--cursor <c>]\n"
    "\n"
    "binding:\n"
    "  binding put <service> <tenant> --kind <operated_by|serves|consumed_by>\n"
    "              [--state <declared|active>] [--revision <n>]\n"
    "  binding remove <service> <tenant> --kind <k> --revision <n>\n"
    "  binding transition <service> <tenant> --kind <k> --to <state> --revision <n>\n"
    "  binding list [--service <id>] [--tenant <id>] [--kind <k>] [--state <s>] [--limit <n>] [--cursor <c>]\n"
    "\n"
    "membership:\n"
    "  membership put <tenant|service>:<id> --domain <domain> --role <primary|secondary|fallback>\n"
    "                 [--membership-state <proposed|bound>] --domain-generation <n> [--revision <n>]\n"
    "  membership transition <tenant|service>:<id> --domain <domain> --to <state>\n"
    "                        --revision <n> --domain-generation <n>\n"
    "  membership remove <tenant|service>:<id> --domain <domain> --revision <n> --domain-generation <n>\n"
    "  membership list [--domain <id>] [--subject <token>] [--state <s>] [--limit <n>] [--cursor <c>]\n"
    "\n"
    "other:\n"
    "  isolate <tenant|service>:<id>            every in-force isolation domain the subject is in\n"
    "  traverse <tenant> --direction <ancestors|descendants> [--kind <k>] [--max-depth <n>]\n"
    "           [--max-results <n>]\n"
    "  explain <tenant|service|isolation_domain>:<id> [--lineage-depth <n>]\n"
    "  stats\n"
    "  snapshot [--json]\n"
    "  export                                   canonical JSON of the whole state\n"
    "  compact\n"
    "  verify                                   re-opens the same root read-only and reports what it recovered\n";

// ---------------------------------------------------------------------------
// Usage errors
// ---------------------------------------------------------------------------

/// A malformed command line. It is not a refusal: nothing was asked of the
/// registry, so nothing can refuse it.
class UsageError {
 public:
  explicit UsageError(std::string message) : message_(std::move(message)) {}

  [[nodiscard]] const std::string& message() const noexcept { return message_; }

 private:
  std::string message_;
};

[[noreturn]] void usage_error(std::string message) { throw UsageError{std::move(message)}; }

[[nodiscard]] bool is_flag_token(std::string_view token) noexcept {
  return !token.empty() && token.front() == '-';
}

// ---------------------------------------------------------------------------
// JSON rendering
// ---------------------------------------------------------------------------

void append_json_escaped(std::string& out, std::string_view text) {
  constexpr char kHexDigits[] = "0123456789abcdef";
  for (const char character : text) {
    const unsigned char byte = static_cast<unsigned char>(character);
    switch (byte) {
      case '"':
        out.append("\\\"");
        break;
      case '\\':
        out.append("\\\\");
        break;
      case '\b':
        out.append("\\b");
        break;
      case '\f':
        out.append("\\f");
        break;
      case '\n':
        out.append("\\n");
        break;
      case '\r':
        out.append("\\r");
        break;
      case '\t':
        out.append("\\t");
        break;
      default:
        if (byte < 0x20U) {
          out.append("\\u00");
          out.push_back(kHexDigits[byte >> 4]);
          out.push_back(kHexDigits[byte & 0x0FU]);
        } else {
          out.push_back(character);
        }
        break;
    }
  }
}

/// Builds one compact JSON value. Members are written in the order the caller
/// emits them, so the rendering of a value is a property of the value and of
/// nothing else.
class JsonWriter {
 public:
  JsonWriter& begin_object() {
    prefix();
    out_.push_back('{');
    first_.push_back(true);
    kinds_.push_back('{');
    return *this;
  }

  JsonWriter& end_object() {
    out_.push_back('}');
    first_.pop_back();
    kinds_.pop_back();
    return *this;
  }

  JsonWriter& begin_array() {
    prefix();
    out_.push_back('[');
    first_.push_back(true);
    kinds_.push_back('[');
    return *this;
  }

  JsonWriter& end_array() {
    out_.push_back(']');
    first_.pop_back();
    kinds_.pop_back();
    return *this;
  }

  JsonWriter& key(std::string_view name) {
    if (!first_.back()) {
      out_.push_back(',');
    }
    first_.back() = false;
    out_.push_back('"');
    append_json_escaped(out_, name);
    out_.append("\":");
    after_key_ = true;
    return *this;
  }

  JsonWriter& string(std::string_view value) {
    prefix();
    out_.push_back('"');
    append_json_escaped(out_, value);
    out_.push_back('"');
    return *this;
  }

  JsonWriter& text_or_null(const std::optional<std::string>& value) {
    if (value.has_value()) {
      return string(*value);
    }
    return null_value();
  }

  JsonWriter& number(std::uint64_t value) {
    prefix();
    out_.append(std::to_string(value));
    return *this;
  }

  JsonWriter& signed_number(std::int64_t value) {
    prefix();
    out_.append(std::to_string(value));
    return *this;
  }

  JsonWriter& boolean(bool value) {
    prefix();
    out_.append(value ? "true" : "false");
    return *this;
  }

  JsonWriter& null_value() {
    prefix();
    out_.append("null");
    return *this;
  }

  /// A value that the library already rendered as compact JSON.
  JsonWriter& raw(std::string_view json_text) {
    prefix();
    out_.append(json_text);
    return *this;
  }

  /// Closes every container that is still open, innermost first, and returns
  /// the value. A rendering path opens one root object and hands it back here,
  /// so there is no way to emit an unbalanced document by forgetting a close.
  [[nodiscard]] std::string finish() {
    while (!kinds_.empty()) {
      out_.push_back(kinds_.back() == '{' ? '}' : ']');
      kinds_.pop_back();
      first_.pop_back();
    }
    return std::move(out_);
  }

 private:
  void prefix() {
    if (after_key_) {
      after_key_ = false;
      return;
    }
    if (first_.empty()) {
      return;
    }
    if (!first_.back()) {
      out_.push_back(',');
    }
    first_.back() = false;
  }

  std::string out_;
  std::vector<bool> first_;
  std::vector<char> kinds_;
  bool after_key_ = false;
};

[[nodiscard]] std::string json_receipt(const MutationReceipt& receipt) {
  JsonWriter writer;
  writer.begin_object();
  writer.key("operation").string(to_token(receipt.operation));
  writer.key("generation").number(receipt.generation.value());
  writer.key("sequence").number(receipt.sequence.value());
  writer.key("revision").number(receipt.revision.value());
  writer.key("request_digest").string(receipt.request_digest.to_text());
  writer.key("replayed").boolean(receipt.replayed);
  return writer.finish();
}

template <class Record>
[[nodiscard]] std::string json_receipt_and_record(const MutationReceipt& receipt, const Record& record) {
  JsonWriter writer;
  writer.begin_object();
  writer.key("receipt").raw(json_receipt(receipt));
  writer.key("record").raw(to_json(record));
  return writer.finish();
}

[[nodiscard]] std::string json_session(const TenantRegistry& registry) {
  const std::optional<StoreIdentity> identity = registry.store_identity();
  JsonWriter writer;
  writer.begin_object();
  writer.key("registry").string(registry.durable() ? "durable" : "ephemeral");
  writer.key("access").string(registry.access_mode() == AccessMode::ReadOnly ? "read-only" : "read-write");
  writer.key("generation").number(registry.generation().value());
  writer.key("control_epoch").number(registry.control_epoch().value());
  writer.key("incarnation").number(registry.incarnation().value());
  writer.key("sequence").number(registry.committed_sequence().value());
  writer.key("store_id");
  if (identity.has_value()) {
    writer.string(identity->id.to_text());
  } else {
    writer.null_value();
  }
  return writer.finish();
}

// ---------------------------------------------------------------------------
// Aligned text rendering
// ---------------------------------------------------------------------------

/// A block of "key : value" lines. Keys are padded to the widest key of their
/// own run, so a block reads as a table without any caller having to know the
/// widths in advance.
class TextBlock {
 public:
  void row(std::string_view key, std::string_view value) {
    rows_.push_back(Row{0, false, std::string{key}, std::string{value}});
  }

  void sub_row(std::string_view key, std::string_view value) {
    rows_.push_back(Row{2, false, std::string{key}, std::string{value}});
  }

  /// A line that is not a key/value pair. It also ends the current alignment
  /// run, which is why it doubles as a blank line.
  void line(std::string_view text) { rows_.push_back(Row{0, true, std::string{text}, std::string{}}); }

  void blank() { line(std::string_view{}); }

  /// Appends another block, keeping its own relative alignment.
  void append(const TextBlock& other) {
    for (const Row& row : other.rows_) {
      rows_.push_back(row);
    }
  }

  void append_indented(const TextBlock& other, std::size_t extra) {
    for (const Row& row : other.rows_) {
      Row shifted = row;
      shifted.indent += extra;
      rows_.push_back(std::move(shifted));
    }
  }

  /// Appends pre-rendered text, one raw line per line of the input.
  void append_text(std::string_view text) {
    std::size_t start = 0;
    while (start < text.size()) {
      const std::size_t end = text.find('\n', start);
      if (end == std::string_view::npos) {
        line(text.substr(start));
        return;
      }
      line(text.substr(start, end - start));
      start = end + 1;
    }
  }

  [[nodiscard]] std::string render() const {
    std::string out;
    std::size_t index = 0;
    while (index < rows_.size()) {
      if (rows_[index].raw) {
        out.append(rows_[index].indent, ' ');
        out.append(rows_[index].text);
        out.push_back('\n');
        ++index;
        continue;
      }
      std::size_t end = index;
      std::size_t width = 0;
      while (end < rows_.size() && !rows_[end].raw && rows_[end].indent == rows_[index].indent) {
        width = std::max(width, rows_[end].text.size());
        ++end;
      }
      for (std::size_t position = index; position < end; ++position) {
        const Row& row = rows_[position];
        out.append(row.indent, ' ');
        out.append(row.text);
        out.append(width - row.text.size(), ' ');
        out.append(" : ");
        out.append(row.value);
        out.push_back('\n');
      }
      index = end;
    }
    return out;
  }

 private:
  struct Row {
    std::size_t indent = 0;
    bool raw = false;
    std::string text;
    std::string value;
  };

  std::vector<Row> rows_;
};

[[nodiscard]] std::string unset_or(const std::optional<std::string>& value) {
  return value.has_value() ? *value : std::string{"unset"};
}

[[nodiscard]] std::string describe(const Error& error) {
  std::string out{error.token()};
  if (!error.detail().empty()) {
    out.append(": ");
    out.append(error.detail());
  }
  return out;
}

// ---------------------------------------------------------------------------
// Global options
// ---------------------------------------------------------------------------

enum class SpecialMode {
  None,
  SelfCheck,
  Scenario,
};

/// The command line as it was read, before the identities and the numbers in it
/// have been validated.
struct MutableGlobals {
  std::optional<std::string> root_text;
  bool read_only = false;
  bool json = false;
  bool quiet = false;
  bool help = false;
  bool version = false;
  std::string principal_text = "operator";
  bool principal_set = false;
  std::string source_text = "cli";
  bool source_set = false;
  std::string provenance_text = "operator_declaration";
  bool provenance_set = false;
  std::optional<RegistryGeneration> accepted_generation;
  bool accepted_generation_set = false;
  std::optional<std::string> idempotency_key;
};

/// The validated global options.
struct Globals {
  bool json = false;
  bool quiet = false;
  bool read_only = false;
  std::optional<std::filesystem::path> root;
  PrincipalId principal;
  SourceId source;
  ProvenanceSource provenance;
  std::optional<RegistryGeneration> accepted_generation;
  std::optional<IdempotencyKey> idempotency_key;
};

void reject_duplicate(bool& seen, const std::string& flag) {
  if (seen) {
    usage_error("the flag '" + flag + "' was given more than once");
  }
  seen = true;
}

void reject_duplicate(const std::optional<std::string>& present, const std::string& flag) {
  if (present.has_value()) {
    usage_error("the flag '" + flag + "' was given more than once");
  }
}

/// Reads a token cursor over the arguments of one command.
class ArgReader {
 public:
  ArgReader(std::vector<std::string> tokens, MutableGlobals& globals)
      : tokens_(std::move(tokens)), globals_(&globals) {}

  [[nodiscard]] bool done() const noexcept { return index_ >= tokens_.size(); }

  [[nodiscard]] const std::string& peek() const { return tokens_[index_]; }

  std::string take() { return tokens_[index_++]; }

  /// Consumes the value that follows a flag. A flag with nothing after it is a
  /// usage error, never an empty value.
  std::string value_of(const std::string& flag) {
    if (index_ + 1 >= tokens_.size()) {
      usage_error("the flag '" + flag + "' needs a value");
    }
    ++index_;
    return tokens_[index_++];
  }

  /// Consumes one positional argument.
  std::string take_positional(const std::string& what) {
    if (done()) {
      usage_error("missing " + what);
    }
    const std::string token = tokens_[index_++];
    if (is_flag_token(token)) {
      usage_error("missing " + what + " before the flag '" + token + "'");
    }
    return token;
  }

  /// Consumes the next token as a command word and records it in the command
  /// path, so output can name the command the caller actually ran.
  std::string take_command_word() {
    std::string word = tokens_[index_++];
    words_.push_back(word);
    return word;
  }

  [[nodiscard]] const std::vector<std::string>& command_words() const noexcept { return words_; }

  /// Consumes one global flag when the next token is one, wherever it appears.
  bool consume_global();

  [[nodiscard]] MutableGlobals& globals() noexcept { return *globals_; }

 private:
  std::vector<std::string> tokens_;
  std::vector<std::string> words_;
  std::size_t index_ = 0;
  MutableGlobals* globals_;
};

/// Consumes the subcommand word of a command group, skipping any global flag
/// that was written between the group and the subcommand.
[[nodiscard]] std::string take_subcommand(ArgReader& reader, const char* command, const char* options) {
  while (!reader.done() && reader.consume_global()) {
  }
  if (reader.done()) {
    usage_error(std::string{"'"} + command + "' needs a subcommand: " + options);
  }
  const std::string word = reader.take_command_word();
  if (is_flag_token(word)) {
    usage_error("unknown flag '" + word + "' for '" + command + "'");
  }
  return word;
}

[[nodiscard]] std::uint64_t parse_number(const std::string& flag, const std::string& text,
                                         std::uint64_t maximum);
[[nodiscard]] RegistryGeneration parse_generation(const std::string& flag, const std::string& text);

bool ArgReader::consume_global() {
  if (done()) {
    return false;
  }
  const std::string& token = tokens_[index_];
  if (token == "--root") {
    reject_duplicate(globals_->root_text, token);
    globals_->root_text = value_of(token);
    return true;
  }
  if (token == "--read-only") {
    globals_->read_only = true;
    ++index_;
    return true;
  }
  if (token == "--json") {
    globals_->json = true;
    ++index_;
    return true;
  }
  if (token == "--quiet") {
    globals_->quiet = true;
    ++index_;
    return true;
  }
  if (token == "--principal") {
    reject_duplicate(globals_->principal_set, token);
    globals_->principal_text = value_of(token);
    return true;
  }
  if (token == "--source") {
    reject_duplicate(globals_->source_set, token);
    globals_->source_text = value_of(token);
    return true;
  }
  if (token == "--provenance") {
    reject_duplicate(globals_->provenance_set, token);
    globals_->provenance_text = value_of(token);
    return true;
  }
  if (token == "--accepted-generation") {
    reject_duplicate(globals_->accepted_generation_set, token);
    globals_->accepted_generation = parse_generation(token, value_of(token));
    return true;
  }
  if (token == "--idempotency-key") {
    reject_duplicate(globals_->idempotency_key, token);
    globals_->idempotency_key = value_of(token);
    return true;
  }
  if (token == "--help") {
    globals_->help = true;
    ++index_;
    return true;
  }
  if (token == "--version") {
    globals_->version = true;
    ++index_;
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Value parsing. Every one of these is a usage error when the text is not
// exactly what the flag accepts.
// ---------------------------------------------------------------------------

[[nodiscard]] std::uint64_t parse_number(const std::string& flag, const std::string& text,
                                         std::uint64_t maximum) {
  if (text.empty()) {
    usage_error("the flag '" + flag + "' needs a decimal integer value");
  }
  std::uint64_t value = 0;
  for (const char character : text) {
    if (character < '0' || character > '9') {
      usage_error("the flag '" + flag + "' expects a decimal integer but was given '" + text + "'");
    }
    const std::uint64_t digit = static_cast<std::uint64_t>(character - '0');
    if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10U) {
      usage_error("the value '" + text + "' given to '" + flag + "' is too large for a counter");
    }
    value = value * 10U + digit;
  }
  if (value > maximum) {
    usage_error("the value '" + text + "' given to '" + flag + "' is above the maximum of " +
                std::to_string(maximum));
  }
  return value;
}

[[nodiscard]] std::size_t parse_limit(const std::string& flag, const std::string& text) {
  const std::uint64_t parse_ceiling = static_cast<std::uint64_t>(kLimits.max_listing_limit);
  const std::uint64_t value = parse_number(flag, text, parse_ceiling);
  if (value == 0) {
    usage_error("the flag '" + flag + "' must be at least 1");
  }
  return static_cast<std::size_t>(value);
}

[[nodiscard]] RecordRevision parse_revision(const std::string& flag, const std::string& text) {
  return RecordRevision::from_value(parse_number(flag, text, std::numeric_limits<std::uint64_t>::max()));
}

[[nodiscard]] RegistryGeneration parse_generation(const std::string& flag, const std::string& text) {
  return RegistryGeneration::from_value(parse_number(flag, text, std::numeric_limits<std::uint64_t>::max()));
}

[[nodiscard]] DomainGeneration parse_domain_generation(const std::string& flag, const std::string& text) {
  return DomainGeneration::from_value(parse_number(flag, text, std::numeric_limits<std::uint64_t>::max()));
}

[[nodiscard]] LifecycleState parse_state_value(const std::string& flag, const std::string& text) {
  LifecycleState state = LifecycleState::Unspecified;
  if (!parse_lifecycle_state(text, state)) {
    usage_error("the flag '" + flag + "' expects a lifecycle state but was given '" + text + "'");
  }
  return state;
}

[[nodiscard]] MembershipState parse_membership_value(const std::string& flag, const std::string& text) {
  MembershipState state = MembershipState::Unspecified;
  if (!parse_membership_state(text, state)) {
    usage_error("the flag '" + flag + "' expects a membership state but was given '" + text + "'");
  }
  return state;
}

[[nodiscard]] OwnershipKind parse_ownership_value(const std::string& flag, const std::string& text) {
  OwnershipKind kind = OwnershipKind::Unspecified;
  if (!parse_ownership_kind(text, kind)) {
    usage_error("the flag '" + flag + "' expects an ownership kind but was given '" + text + "'");
  }
  return kind;
}

[[nodiscard]] BindingKind parse_binding_value(const std::string& flag, const std::string& text) {
  BindingKind kind = BindingKind::Unspecified;
  if (!parse_binding_kind(text, kind)) {
    usage_error("the flag '" + flag + "' expects a binding kind but was given '" + text + "'");
  }
  return kind;
}

[[nodiscard]] MembershipRole parse_role_value(const std::string& flag, const std::string& text) {
  MembershipRole role = MembershipRole::Unspecified;
  if (!parse_membership_role(text, role)) {
    usage_error("the flag '" + flag + "' expects a membership role but was given '" + text + "'");
  }
  return role;
}

[[nodiscard]] IsolationClass parse_class_value(const std::string& flag, const std::string& text) {
  IsolationClass isolation_class = IsolationClass::Unspecified;
  if (!parse_isolation_class(text, isolation_class)) {
    usage_error("the flag '" + flag + "' expects an isolation class but was given '" + text + "'");
  }
  return isolation_class;
}

[[nodiscard]] TraversalDirection parse_direction_value(const std::string& flag, const std::string& text) {
  TraversalDirection direction = TraversalDirection::Unspecified;
  if (!parse_traversal_direction(text, direction)) {
    usage_error("the flag '" + flag + "' expects a traversal direction but was given '" + text + "'");
  }
  return direction;
}

[[nodiscard]] TenantId require_tenant_id(const std::string& text) {
  auto created = TenantId::create(text);
  if (!created) {
    usage_error("the tenant identity '" + text + "' is not usable: " + describe(created.error()));
  }
  return std::move(created).value();
}

[[nodiscard]] ServiceId require_service_id(const std::string& text) {
  auto created = ServiceId::create(text);
  if (!created) {
    usage_error("the service identity '" + text + "' is not usable: " + describe(created.error()));
  }
  return std::move(created).value();
}

[[nodiscard]] IsolationDomainId require_domain_id(const std::string& text) {
  auto created = IsolationDomainId::create(text);
  if (!created) {
    usage_error("the isolation domain identity '" + text + "' is not usable: " + describe(created.error()));
  }
  return std::move(created).value();
}

[[nodiscard]] PrincipalId require_principal(const std::string& text) {
  auto created = PrincipalId::create(text);
  if (!created) {
    usage_error("the principal identity '" + text + "' is not usable: " + describe(created.error()));
  }
  return std::move(created).value();
}

[[nodiscard]] SourceId require_source(const std::string& text) {
  auto created = SourceId::create(text);
  if (!created) {
    usage_error("the source identity '" + text + "' is not usable: " + describe(created.error()));
  }
  return std::move(created).value();
}

[[nodiscard]] MetadataKey require_metadata_key(const std::string& text) {
  auto created = MetadataKey::create(text);
  if (!created) {
    usage_error("the metadata key '" + text + "' is not usable: " + describe(created.error()));
  }
  return std::move(created).value();
}

[[nodiscard]] std::string require_text(const std::string& text, std::size_t max_bytes, const char* what) {
  auto validated = validate_text_field(text, max_bytes, what);
  if (!validated) {
    usage_error(std::string{what} + " '" + text + "' is not usable: " + describe(validated.error()));
  }
  return std::move(validated).value();
}

/// Splits one "key=value" pair. The value is recorded as text: the tool never
/// guesses a type for what an operator typed.
[[nodiscard]] MetadataEntry require_metadata_entry(const std::string& text) {
  const std::size_t separator = text.find('=');
  if (separator == std::string::npos) {
    usage_error("the metadata entry '" + text + "' must have the form key=value");
  }
  const std::string key_text = text.substr(0, separator);
  const std::string value_text = text.substr(separator + 1);
  if (key_text.empty()) {
    usage_error("the metadata entry '" + text + "' has an empty key");
  }
  auto value = MetadataValue::text(value_text, kLimits.max_metadata_value_bytes);
  if (!value) {
    usage_error("the value of the metadata entry '" + text + "' is not usable: " + describe(value.error()));
  }
  return MetadataEntry{require_metadata_key(key_text), std::move(value).value()};
}

[[nodiscard]] TenancyMetadata require_metadata(std::vector<MetadataEntry> entries) {
  auto created = TenancyMetadata::create(std::move(entries), kLimits.max_metadata_entries_per_record,
                                         kLimits.max_metadata_value_bytes);
  if (!created) {
    usage_error("the metadata given on the command line is not usable: " + describe(created.error()));
  }
  return std::move(created).value();
}

/// A strictly parsed subject token: "tenant:<id>", "service:<id>" or
/// "isolation_domain:<id>". An unknown prefix is a usage error, never a guess.
struct SubjectToken {
  SubjectKind kind = SubjectKind::Unspecified;
  std::string text;
};

[[nodiscard]] SubjectToken parse_subject_token(const std::string& token, bool allow_domain) {
  const std::size_t separator = token.find(':');
  if (separator == std::string::npos || separator == 0 || separator + 1 >= token.size()) {
    usage_error("the subject token '" + token +
                "' must have the form tenant:<id>, service:<id> or isolation_domain:<id>");
  }
  const std::string prefix = token.substr(0, separator);
  SubjectKind kind = SubjectKind::Unspecified;
  if (!parse_subject_kind(prefix, kind) || kind == SubjectKind::Unspecified) {
    usage_error("the subject token '" + token + "' has the unknown kind prefix '" + prefix + "'");
  }
  if (!allow_domain && kind == SubjectKind::IsolationDomain) {
    usage_error("the subject token '" + token +
                "' names an isolation domain, which is not a member of an isolation domain");
  }
  return SubjectToken{kind, token.substr(separator + 1)};
}

[[nodiscard]] TenancySubject make_subject(const SubjectToken& token) {
  switch (token.kind) {
    case SubjectKind::Tenant:
      return TenancySubject::of_tenant(require_tenant_id(token.text));
    case SubjectKind::Service:
      return TenancySubject::of_service(require_service_id(token.text));
    case SubjectKind::IsolationDomain:
      return TenancySubject::of_isolation_domain(require_domain_id(token.text));
    case SubjectKind::Unspecified:
      break;
  }
  usage_error("the subject token '" + token.text + "' has no kind");
}

/// The successor text of a rebind permit is validated against the identity
/// rules of the kind it names.
[[nodiscard]] std::string require_successor_text(SubjectKind kind, const std::string& text) {
  switch (kind) {
    case SubjectKind::Tenant:
      return require_tenant_id(text).value();
    case SubjectKind::Service:
      return require_service_id(text).value();
    case SubjectKind::IsolationDomain:
      return require_domain_id(text).value();
    case SubjectKind::Unspecified:
      break;
  }
  usage_error("a rebind successor must name the kind of the identity it takes over");
}

// ---------------------------------------------------------------------------
// Session and context
// ---------------------------------------------------------------------------

[[nodiscard]] Globals finalize_globals(const MutableGlobals& raw) {
  const PrincipalId principal = require_principal(raw.principal_text);
  const SourceId source = require_source(raw.source_text);
  ProvenanceSource provenance = ProvenanceSource::Unspecified;
  if (!parse_provenance_source(raw.provenance_text, provenance) ||
      provenance == ProvenanceSource::Unspecified) {
    usage_error("the provenance source '" + raw.provenance_text + "' is not a source this build knows");
  }
  std::optional<std::filesystem::path> root;
  if (raw.root_text.has_value()) {
    if (raw.root_text->empty()) {
      usage_error("the flag '--root' needs a directory name that is not empty");
    }
    root = std::filesystem::path{*raw.root_text};
  }
  std::optional<IdempotencyKey> key;
  if (raw.idempotency_key.has_value()) {
    auto created = IdempotencyKey::create(*raw.idempotency_key);
    if (!created) {
      usage_error("the idempotency key '" + *raw.idempotency_key + "' is not usable: " +
                  describe(created.error()));
    }
    key = std::move(created).value();
  }
  const std::optional<RegistryGeneration> accepted = raw.accepted_generation;
  return Globals{raw.json,
                 raw.quiet,
                 raw.read_only,
                 root,
                 principal,
                 source,
                 provenance,
                 accepted,
                 key};
}

/// Composes the actor every mutation is recorded as having come from. The tool
/// records no time: a declaration with no time stays a declaration with no
/// time, so two runs of the same command produce the same request digest.
[[nodiscard]] ProvenanceRecord make_actor(const Globals& globals) {
  auto created = ProvenanceRecord::create(globals.provenance, globals.source, globals.principal, std::nullopt,
                                          std::string{}, kLimits.max_provenance_note_bytes);
  if (!created) {
    usage_error("the session actor could not be composed: " + describe(created.error()));
  }
  return std::move(created).value();
}

/// The binding every mutation carries. Without --accepted-generation the
/// generation the session reads is used: this tool is the only writer in its
/// own process, and the registry still refuses a request composed against a
/// generation it has moved past.
[[nodiscard]] MutationContext make_context(const TenantRegistry& registry, const Globals& globals,
                                           const ProvenanceRecord& actor) {
  const RegistryGeneration expected =
      globals.accepted_generation.has_value() ? *globals.accepted_generation : registry.generation();
  return MutationContext{expected, globals.idempotency_key, actor};
}

[[nodiscard]] Result<TenantRegistry> open_session(const Globals& globals) {
  if (!globals.root.has_value()) {
    EphemeralOptions options;
    options.limits = kLimits;
    return TenantRegistry::open_ephemeral(options);
  }
  RegistryOpenRequest request;
  request.root = *globals.root;
  request.mode = globals.read_only ? AccessMode::ReadOnly : AccessMode::ReadWrite;
  request.store.limits = kLimits;
  request.store.holder_note = "treg cli; principal=" + globals.principal.value();
  return TenantRegistry::open(request);
}

// ---------------------------------------------------------------------------
// Command results
// ---------------------------------------------------------------------------

struct CommandResult {
  int exit_code = kExitSuccess;
  std::string stdout_text;
  std::string stderr_text;
};

/// Turns a refusal into the exit code and the stderr report it deserves. A
/// store class refusal is a store error; everything else is a refusal.
[[nodiscard]] CommandResult refusal(const Error& error) {
  CommandResult result;
  result.exit_code = error.error_class() == ErrorClass::Store ? kExitStore : kExitRefusal;
  std::string text{"error: "};
  text.append(error.token().empty() ? std::string_view{"unspecified"} : error.token());
  const std::string& detail = error.detail().empty() ? error.subject() : error.detail();
  if (!detail.empty()) {
    text.append(": ");
    text.append(detail);
  }
  text.push_back('\n');
  for (const std::string& note : error.suppressed()) {
    text.append("  note: ");
    text.append(note);
    text.push_back('\n');
  }
  result.stderr_text = std::move(text);
  return result;
}

[[nodiscard]] CommandResult success_text(std::string text) {
  CommandResult result;
  result.stdout_text = std::move(text);
  return result;
}

void append_session_rows(TextBlock& block, const TenantRegistry& registry) {
  const std::optional<StoreIdentity> identity = registry.store_identity();
  block.row("registry", registry.durable() ? "durable" : "ephemeral");
  block.row("access", registry.access_mode() == AccessMode::ReadOnly ? "read-only" : "read-write");
  block.row("generation", std::to_string(registry.generation().value()));
  block.row("control_epoch", std::to_string(registry.control_epoch().value()));
  block.row("incarnation", std::to_string(registry.incarnation().value()));
  block.row("sequence", std::to_string(registry.committed_sequence().value()));
  block.row("store_id", identity.has_value() ? identity->id.to_text() : std::string{"unset"});
}

[[nodiscard]] CommandResult emit_human(const TenantRegistry& registry, const Globals& globals, TextBlock body) {
  TextBlock page;
  if (!globals.quiet) {
    append_session_rows(page, registry);
    page.blank();
  }
  page.append(body);
  return success_text(page.render());
}

[[nodiscard]] CommandResult emit_json_with_session(const std::string& session_json, bool quiet,
                                                   std::string_view command, std::string_view result_json) {
  JsonWriter writer;
  writer.begin_object();
  if (!quiet) {
    writer.key("session").raw(session_json);
  }
  writer.key("command").string(command);
  writer.key("result").raw(result_json);
  std::string text = writer.finish();
  text.push_back('\n');
  return success_text(std::move(text));
}

[[nodiscard]] CommandResult emit_json(const TenantRegistry& registry, const Globals& globals,
                                      std::string_view command, std::string_view result_json) {
  return emit_json_with_session(json_session(registry), globals.quiet, command, result_json);
}

// ---------------------------------------------------------------------------
// Human record rendering
// ---------------------------------------------------------------------------

void render_metadata(TextBlock& block, const TenancyMetadata& metadata) {
  if (metadata.empty()) {
    block.row("metadata", "unset");
    return;
  }
  std::string key;
  for (const MetadataEntry& entry : metadata.entries()) {
    key.assign("metadata.");
    key.append(entry.key.value());
    block.row(key, entry.value.to_canonical());
  }
}

void render_tenant_record(TextBlock& block, const TenantRecord& record) {
  block.row("identity", identity_text(SubjectKind::Tenant, record.id.value()));
  block.row("display_name", unset_or(record.display_name));
  block.row("state", to_token(record.state));
  block.row("revision", std::to_string(record.revision.value()));
  block.row("created_generation", std::to_string(record.created_generation.value()));
  block.row("updated_generation", std::to_string(record.updated_generation.value()));
  block.row("retired_generation",
            record.retired_generation.has_value() ? std::to_string(record.retired_generation->value())
                                                  : std::string{"unset"});
  block.row("tombstone", record.tombstone.has_value() ? record.tombstone->to_text() : std::string{"unset"});
  block.row("owner", record.owner.has_value() ? record.owner->value() : std::string{"unset"});
  render_metadata(block, record.metadata);
  block.row("provenance", record.provenance.to_text());
  block.row("origin_digest", record.origin_digest.to_text());
}

void render_service_record(TextBlock& block, const ServiceRecord& record) {
  block.row("identity", identity_text(SubjectKind::Service, record.id.value()));
  block.row("display_name", unset_or(record.display_name));
  block.row("state", to_token(record.state));
  block.row("revision", std::to_string(record.revision.value()));
  block.row("created_generation", std::to_string(record.created_generation.value()));
  block.row("updated_generation", std::to_string(record.updated_generation.value()));
  block.row("retired_generation",
            record.retired_generation.has_value() ? std::to_string(record.retired_generation->value())
                                                  : std::string{"unset"});
  block.row("tombstone", record.tombstone.has_value() ? record.tombstone->to_text() : std::string{"unset"});
  render_metadata(block, record.metadata);
  block.row("provenance", record.provenance.to_text());
  block.row("origin_digest", record.origin_digest.to_text());
}

void render_domain_record(TextBlock& block, const IsolationDomainRecord& record) {
  block.row("identity", identity_text(SubjectKind::IsolationDomain, record.id.value()));
  block.row("display_name", unset_or(record.display_name));
  block.row("isolation_class", to_token(record.isolation_class));
  block.row("state", to_token(record.state));
  block.row("revision", std::to_string(record.revision.value()));
  block.row("membership_generation", std::to_string(record.membership_generation.value()));
  block.row("created_generation", std::to_string(record.created_generation.value()));
  block.row("updated_generation", std::to_string(record.updated_generation.value()));
  block.row("retired_generation",
            record.retired_generation.has_value() ? std::to_string(record.retired_generation->value())
                                                  : std::string{"unset"});
  block.row("tombstone", record.tombstone.has_value() ? record.tombstone->to_text() : std::string{"unset"});
  render_metadata(block, record.metadata);
  block.row("provenance", record.provenance.to_text());
  block.row("origin_digest", record.origin_digest.to_text());
}

void render_subject_record(TextBlock& block, const SubjectRecord& record) {
  std::visit(
      [&block](const auto& stored) {
        using Stored = std::decay_t<decltype(stored)>;
        if constexpr (std::is_same_v<Stored, TenantRecord>) {
          render_tenant_record(block, stored);
        } else if constexpr (std::is_same_v<Stored, ServiceRecord>) {
          render_service_record(block, stored);
        } else {
          render_domain_record(block, stored);
        }
      },
      record);
}

void render_relationship_tail(TextBlock& block, RegistryGeneration created_generation,
                              RegistryGeneration updated_generation, const ProvenanceRecord& provenance,
                              const ContentDigest& origin_digest) {
  block.row("created_generation", std::to_string(created_generation.value()));
  block.row("updated_generation", std::to_string(updated_generation.value()));
  block.row("provenance", provenance.to_text());
  block.row("origin_digest", origin_digest.to_text());
}

void render_ownership_edge(TextBlock& block, const OwnershipEdge& edge) {
  block.row("child", identity_text(SubjectKind::Tenant, edge.child.value()));
  block.row("parent", identity_text(SubjectKind::Tenant, edge.parent.value()));
  block.row("kind", to_token(edge.kind));
  block.row("state", to_token(edge.state));
  block.row("revision", std::to_string(edge.revision.value()));
  render_relationship_tail(block, edge.created_generation, edge.updated_generation, edge.provenance,
                           edge.origin_digest);
}

void render_service_binding(TextBlock& block, const ServiceBinding& binding) {
  block.row("service", identity_text(SubjectKind::Service, binding.service.value()));
  block.row("tenant", identity_text(SubjectKind::Tenant, binding.tenant.value()));
  block.row("kind", to_token(binding.kind));
  block.row("state", to_token(binding.state));
  block.row("revision", std::to_string(binding.revision.value()));
  render_relationship_tail(block, binding.created_generation, binding.updated_generation, binding.provenance,
                           binding.origin_digest);
}

void render_isolation_membership(TextBlock& block, const IsolationMembership& membership) {
  block.row("subject", membership.subject.to_text());
  block.row("domain", identity_text(SubjectKind::IsolationDomain, membership.domain.value()));
  block.row("role", to_token(membership.role));
  block.row("state", to_token(membership.state));
  block.row("revision", std::to_string(membership.revision.value()));
  render_relationship_tail(block, membership.created_generation, membership.updated_generation,
                           membership.provenance, membership.origin_digest);
}

void render_tombstone_record(TextBlock& block, const TombstoneRecord& record) {
  block.row("kind", to_token(record.kind));
  block.row("identity", identity_text(record.kind, record.identity));
  block.row("state", to_token(record.state));
  block.row("revision", std::to_string(record.revision.value()));
  block.row("retired_generation", std::to_string(record.retired_generation.value()));
  block.row("tombstoned_generation", std::to_string(record.tombstoned_generation.value()));
  block.row("permit", record.permit.has_value() ? record.permit->to_text() : std::string{"unset"});
  block.row("note", record.note.empty() ? std::string{"unset"} : record.note);
  block.row("provenance", record.provenance.to_text());
  block.row("origin_digest", record.origin_digest.to_text());
}

void append_receipt_row(TextBlock& block, const MutationReceipt& receipt) {
  block.row("receipt", receipt.to_text());
}

void append_page_rows(TextBlock& block, std::size_t items, std::size_t total_matched, bool truncated,
                      const std::optional<std::string>& next_cursor) {
  block.row("items", std::to_string(items));
  block.row("total_matched", std::to_string(total_matched));
  block.row("truncated", truncated ? "true" : "false");
  block.row("next_cursor", unset_or(next_cursor));
}

[[nodiscard]] std::string json_tenant_summary(const TenantSummary& summary) {
  JsonWriter writer;
  writer.begin_object();
  writer.key("identity").string(identity_text(SubjectKind::Tenant, summary.id.value()));
  writer.key("display_name").text_or_null(summary.display_name);
  writer.key("state").string(to_token(summary.state));
  writer.key("revision").number(summary.revision.value());
  return writer.finish();
}

[[nodiscard]] std::string json_service_summary(const ServiceSummary& summary) {
  JsonWriter writer;
  writer.begin_object();
  writer.key("identity").string(identity_text(SubjectKind::Service, summary.id.value()));
  writer.key("display_name").text_or_null(summary.display_name);
  writer.key("state").string(to_token(summary.state));
  writer.key("revision").number(summary.revision.value());
  return writer.finish();
}

[[nodiscard]] std::string json_domain_summary(const DomainSummary& summary) {
  JsonWriter writer;
  writer.begin_object();
  writer.key("identity").string(identity_text(SubjectKind::IsolationDomain, summary.id.value()));
  writer.key("display_name").text_or_null(summary.display_name);
  writer.key("isolation_class").string(to_token(summary.isolation_class));
  writer.key("state").string(to_token(summary.state));
  writer.key("revision").number(summary.revision.value());
  writer.key("membership_generation").number(summary.membership_generation.value());
  return writer.finish();
}

[[nodiscard]] std::string json_membership_summary(const MembershipSummary& summary) {
  JsonWriter writer;
  writer.begin_object();
  writer.key("subject").string(summary.subject.to_text());
  writer.key("domain").string(identity_text(SubjectKind::IsolationDomain, summary.domain.value()));
  writer.key("role").string(to_token(summary.role));
  writer.key("state").string(to_token(summary.state));
  writer.key("revision").number(summary.revision.value());
  return writer.finish();
}

template <class Item, class Render>
[[nodiscard]] std::string json_page(const Page<Item>& page, Render render_item) {
  JsonWriter writer;
  writer.begin_object();
  writer.key("items").begin_array();
  for (const Item& item : page.items) {
    writer.raw(render_item(item));
  }
  writer.end_array();
  writer.key("total_matched").number(static_cast<std::uint64_t>(page.total_matched));
  writer.key("truncated").boolean(page.truncated);
  writer.key("next_cursor").text_or_null(page.next_cursor);
  return writer.finish();
}

void append_item_block(TextBlock& block, std::size_t index, const TextBlock& item) {
  block.row("item", std::to_string(index));
  block.append_indented(item, 2);
  block.blank();
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

using Runner = std::function<CommandResult(TenantRegistry&, const Globals&, std::string_view)>;

// -- tenant ------------------------------------------------------------------

[[nodiscard]] Runner parse_tenant_create(ArgReader& reader) {
  const TenantId id = require_tenant_id(reader.take_positional("a tenant identity"));
  std::optional<std::string> display_name;
  bool display_name_seen = false;
  std::optional<PrincipalId> owner;
  bool owner_seen = false;
  std::vector<MetadataEntry> metadata_entries;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--display-name") {
      reject_duplicate(display_name_seen, token);
      display_name = require_text(reader.value_of(token), kLimits.max_display_name_bytes, "the display name");
    } else if (token == "--owner") {
      reject_duplicate(owner_seen, token);
      owner = require_principal(reader.value_of(token));
    } else if (token == "--metadata") {
      metadata_entries.push_back(require_metadata_entry(reader.value_of(token)));
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'tenant create'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'tenant create'");
    }
  }
  const TenancyMetadata metadata = require_metadata(std::move(metadata_entries));
  return [id, display_name, owner, metadata](TenantRegistry& registry, const Globals& globals,
                                             std::string_view command) -> CommandResult {
    const ProvenanceRecord actor = make_actor(globals);
    const CreateTenantRequest request{make_context(registry, globals, actor), id, display_name, owner, metadata};
    const auto outcome = registry.create_tenant(request);
    if (!outcome) {
      return refusal(outcome.error());
    }
    if (globals.json) {
      return emit_json(registry, globals, command,
                       json_receipt_and_record(outcome.value().receipt, outcome.value().record));
    }
    TextBlock body;
    append_receipt_row(body, outcome.value().receipt);
    body.blank();
    render_tenant_record(body, outcome.value().record);
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_tenant_show(ArgReader& reader) {
  const TenantId id = require_tenant_id(reader.take_positional("a tenant identity"));
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (reader.consume_global()) {
      continue;
    }
    if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'tenant show'");
    }
    usage_error("unexpected argument '" + token + "' for 'tenant show'");
  }
  return [id](TenantRegistry& registry, const Globals& globals, std::string_view) -> CommandResult {
    const auto found = registry.find_tenant(id);
    if (!found) {
      return refusal(found.error());
    }
    if (globals.json) {
      JsonWriter writer;
      writer.begin_object();
      writer.key("record").raw(to_json(found.value()));
      return emit_json(registry, globals, "tenant show", writer.finish());
    }
    TextBlock body;
    render_tenant_record(body, found.value());
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_tenant_list(ArgReader& reader) {
  TenantQuery query;
  bool state_seen = false;
  bool member_of_seen = false;
  bool limit_seen = false;
  bool cursor_seen = false;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--state") {
      reject_duplicate(state_seen, token);
      query.state = parse_state_value(token, reader.value_of(token));
    } else if (token == "--member-of") {
      reject_duplicate(member_of_seen, token);
      query.member_of_domain = require_domain_id(reader.value_of(token));
    } else if (token == "--limit") {
      reject_duplicate(limit_seen, token);
      query.limit = parse_limit(token, reader.value_of(token));
    } else if (token == "--cursor") {
      reject_duplicate(cursor_seen, token);
      query.cursor = reader.value_of(token);
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'tenant list'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'tenant list'");
    }
  }
  return [query](TenantRegistry& registry, const Globals& globals, std::string_view command) -> CommandResult {
    const auto page = registry.list_tenants(query);
    if (!page) {
      return refusal(page.error());
    }
    if (globals.json) {
      return emit_json(registry, globals, command,
                       json_page(page.value(), [](const TenantSummary& summary) {
                         return json_tenant_summary(summary);
                       }));
    }
    TextBlock body;
    append_page_rows(body, page.value().items.size(), page.value().total_matched, page.value().truncated,
                     page.value().next_cursor);
    body.blank();
    std::size_t index = 0;
    for (const TenantSummary& summary : page.value().items) {
      TextBlock item;
      item.row("identity", identity_text(SubjectKind::Tenant, summary.id.value()));
      item.row("display_name", unset_or(summary.display_name));
      item.row("state", to_token(summary.state));
      item.row("revision", std::to_string(summary.revision.value()));
      append_item_block(body, index, item);
      ++index;
    }
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_tenant_transition(ArgReader& reader) {
  const TenantId id = require_tenant_id(reader.take_positional("a tenant identity"));
  std::optional<LifecycleState> target;
  bool target_seen = false;
  std::optional<RecordRevision> revision;
  bool revision_seen = false;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--to") {
      reject_duplicate(target_seen, token);
      target = parse_state_value(token, reader.value_of(token));
    } else if (token == "--revision") {
      reject_duplicate(revision_seen, token);
      revision = parse_revision(token, reader.value_of(token));
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'tenant transition'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'tenant transition'");
    }
  }
  if (!target.has_value()) {
    usage_error("'tenant transition' needs --to <state>");
  }
  if (!revision.has_value()) {
    usage_error("'tenant transition' needs --revision <n>");
  }
  return [id, target, revision](TenantRegistry& registry, const Globals& globals,
                                std::string_view command) -> CommandResult {
    const ProvenanceRecord actor = make_actor(globals);
    const TransitionSubjectRequest request{make_context(registry, globals, actor),
                                           TenancySubject::of_tenant(id), *revision, *target};
    const auto outcome = registry.transition_subject(request);
    if (!outcome) {
      return refusal(outcome.error());
    }
    if (globals.json) {
      return emit_json(registry, globals, command,
                       json_receipt_and_record(outcome.value().receipt, outcome.value().record));
    }
    TextBlock body;
    append_receipt_row(body, outcome.value().receipt);
    body.blank();
    render_subject_record(body, outcome.value().record);
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_tenant_set_owner(ArgReader& reader) {
  const TenantId id = require_tenant_id(reader.take_positional("a tenant identity"));
  std::optional<PrincipalId> owner;
  bool owner_seen = false;
  bool clear_seen = false;
  std::optional<RecordRevision> revision;
  bool revision_seen = false;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--owner") {
      reject_duplicate(owner_seen, token);
      owner = require_principal(reader.value_of(token));
    } else if (token == "--clear-owner") {
      clear_seen = true;
      reader.take();
    } else if (token == "--revision") {
      reject_duplicate(revision_seen, token);
      revision = parse_revision(token, reader.value_of(token));
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'tenant set-owner'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'tenant set-owner'");
    }
  }
  if (owner_seen && clear_seen) {
    usage_error("'tenant set-owner' accepts --owner or --clear-owner, not both");
  }
  if (!owner_seen && !clear_seen) {
    usage_error("'tenant set-owner' needs --owner <principal> or --clear-owner");
  }
  if (!revision.has_value()) {
    usage_error("'tenant set-owner' needs --revision <n>");
  }
  return [id, owner, revision](TenantRegistry& registry, const Globals& globals,
                               std::string_view command) -> CommandResult {
    const ProvenanceRecord actor = make_actor(globals);
    const SetOwnerRequest request{make_context(registry, globals, actor), id, *revision, owner};
    const auto outcome = registry.set_owner(request);
    if (!outcome) {
      return refusal(outcome.error());
    }
    if (globals.json) {
      JsonWriter writer;
      writer.begin_object();
      writer.key("receipt").raw(json_receipt(outcome.value()));
      return emit_json(registry, globals, command, writer.finish());
    }
    TextBlock body;
    append_receipt_row(body, outcome.value());
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_tenant_metadata(ArgReader& reader) {
  const TenantId id = require_tenant_id(reader.take_positional("a tenant identity"));
  std::optional<RecordRevision> revision;
  bool revision_seen = false;
  std::vector<MetadataKey> remove_keys;
  std::vector<MetadataEntry> put_entries;
  std::vector<std::string> remove_texts;
  std::vector<std::string> put_texts;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--revision") {
      reject_duplicate(revision_seen, token);
      revision = parse_revision(token, reader.value_of(token));
    } else if (token == "--put") {
      const std::string text = reader.value_of(token);
      MetadataEntry entry = require_metadata_entry(text);
      for (const std::string& seen : put_texts) {
        if (seen == entry.key.value()) {
          usage_error("the metadata key '" + entry.key.value() + "' was given more than once");
        }
      }
      put_texts.push_back(entry.key.value());
      put_entries.push_back(std::move(entry));
    } else if (token == "--remove") {
      const std::string text = reader.value_of(token);
      MetadataKey key = require_metadata_key(text);
      for (const std::string& seen : remove_texts) {
        if (seen == key.value()) {
          usage_error("the metadata key '" + key.value() + "' was given more than once");
        }
      }
      remove_texts.push_back(key.value());
      remove_keys.push_back(std::move(key));
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'tenant metadata'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'tenant metadata'");
    }
  }
  for (const std::string& put : put_texts) {
    for (const std::string& removed : remove_texts) {
      if (put == removed) {
        usage_error("the metadata key '" + put + "' was given to both --put and --remove");
      }
    }
  }
  if (!revision.has_value()) {
    usage_error("'tenant metadata' needs --revision <n>");
  }
  if (put_entries.empty() && remove_keys.empty()) {
    usage_error("'tenant metadata' needs at least one --put k=v or --remove k");
  }
  return [id, revision, remove_keys, put_entries](TenantRegistry& registry, const Globals& globals,
                                                  std::string_view command) -> CommandResult {
    const ProvenanceRecord actor = make_actor(globals);
    const SetMetadataRequest request{make_context(registry, globals, actor), TenancySubject::of_tenant(id),
                                     *revision, remove_keys, put_entries};
    const auto outcome = registry.set_metadata(request);
    if (!outcome) {
      return refusal(outcome.error());
    }
    if (globals.json) {
      return emit_json(registry, globals, command,
                       json_receipt_and_record(outcome.value().receipt, outcome.value().record));
    }
    TextBlock body;
    append_receipt_row(body, outcome.value().receipt);
    body.blank();
    render_subject_record(body, outcome.value().record);
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_tenant_tombstone(ArgReader& reader) {
  const TenantId id = require_tenant_id(reader.take_positional("a tenant identity"));
  std::optional<RecordRevision> revision;
  bool revision_seen = false;
  bool acknowledged = false;
  std::optional<std::string> rebind_text;
  bool rebind_seen = false;
  std::string note;
  bool note_seen = false;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--revision") {
      reject_duplicate(revision_seen, token);
      revision = parse_revision(token, reader.value_of(token));
    } else if (token == "--acknowledge") {
      acknowledged = true;
      reader.take();
    } else if (token == "--rebind-to") {
      reject_duplicate(rebind_seen, token);
      rebind_text = reader.value_of(token);
    } else if (token == "--note") {
      reject_duplicate(note_seen, token);
      note = reader.value_of(token);
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'tenant tombstone'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'tenant tombstone'");
    }
  }
  if (!revision.has_value()) {
    usage_error("'tenant tombstone' needs --revision <n>");
  }
  if (!acknowledged) {
    usage_error("'tenant tombstone' needs --acknowledge: fencing an identity forever cannot be undone");
  }
  if (!note.empty()) {
    note = require_text(note, kLimits.max_provenance_note_bytes, "the tombstone note");
  }
  std::optional<RebindSuccessor> successor;
  if (rebind_text.has_value()) {
    successor = RebindSuccessor{SubjectKind::Tenant,
                                require_successor_text(SubjectKind::Tenant, *rebind_text)};
  }
  return [id, revision, successor, note](TenantRegistry& registry, const Globals& globals,
                                         std::string_view command) -> CommandResult {
    const ProvenanceRecord actor = make_actor(globals);
    const TombstoneRequest request{make_context(registry, globals, actor), TenancySubject::of_tenant(id),
                                   *revision, IrreversibleAcknowledgement::acknowledged(), successor, note};
    const auto outcome = registry.tombstone(request);
    if (!outcome) {
      return refusal(outcome.error());
    }
    if (globals.json) {
      return emit_json(registry, globals, command,
                       json_receipt_and_record(outcome.value().receipt, outcome.value().record));
    }
    TextBlock body;
    append_receipt_row(body, outcome.value().receipt);
    body.blank();
    render_subject_record(body, outcome.value().record);
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_tenant_tombstone_show(ArgReader& reader) {
  const TenantId id = require_tenant_id(reader.take_positional("a tenant identity"));
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (reader.consume_global()) {
      continue;
    }
    if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'tenant tombstone-show'");
    }
    usage_error("unexpected argument '" + token + "' for 'tenant tombstone-show'");
  }
  return [id](TenantRegistry& registry, const Globals& globals, std::string_view command) -> CommandResult {
    const auto found = registry.find_tombstone(SubjectKind::Tenant, id.value());
    if (!found) {
      return refusal(found.error());
    }
    if (globals.json) {
      JsonWriter writer;
      writer.begin_object();
      writer.key("tombstone").raw(to_json(found.value()));
      return emit_json(registry, globals, command, writer.finish());
    }
    TextBlock body;
    render_tombstone_record(body, found.value());
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_tenant_command(ArgReader& reader) {
  const std::string subcommand =
      take_subcommand(reader, "tenant", "create, show, list, transition, set-owner, metadata, tombstone or "
                                        "tombstone-show");
  if (subcommand == "create") {
    return parse_tenant_create(reader);
  }
  if (subcommand == "show") {
    return parse_tenant_show(reader);
  }
  if (subcommand == "list") {
    return parse_tenant_list(reader);
  }
  if (subcommand == "transition") {
    return parse_tenant_transition(reader);
  }
  if (subcommand == "set-owner") {
    return parse_tenant_set_owner(reader);
  }
  if (subcommand == "metadata") {
    return parse_tenant_metadata(reader);
  }
  if (subcommand == "tombstone") {
    return parse_tenant_tombstone(reader);
  }
  if (subcommand == "tombstone-show") {
    return parse_tenant_tombstone_show(reader);
  }
  usage_error("unknown tenant subcommand '" + subcommand + "'");
}

// -- service -----------------------------------------------------------------

[[nodiscard]] Runner parse_service_create(ArgReader& reader) {
  const ServiceId id = require_service_id(reader.take_positional("a service identity"));
  std::optional<std::string> display_name;
  bool display_name_seen = false;
  std::vector<MetadataEntry> metadata_entries;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--display-name") {
      reject_duplicate(display_name_seen, token);
      display_name = require_text(reader.value_of(token), kLimits.max_display_name_bytes, "the display name");
    } else if (token == "--metadata") {
      metadata_entries.push_back(require_metadata_entry(reader.value_of(token)));
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'service create'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'service create'");
    }
  }
  const TenancyMetadata metadata = require_metadata(std::move(metadata_entries));
  return [id, display_name, metadata](TenantRegistry& registry, const Globals& globals,
                                      std::string_view command) -> CommandResult {
    const ProvenanceRecord actor = make_actor(globals);
    const CreateServiceRequest request{make_context(registry, globals, actor), id, display_name, metadata};
    const auto outcome = registry.create_service(request);
    if (!outcome) {
      return refusal(outcome.error());
    }
    if (globals.json) {
      return emit_json(registry, globals, command,
                       json_receipt_and_record(outcome.value().receipt, outcome.value().record));
    }
    TextBlock body;
    append_receipt_row(body, outcome.value().receipt);
    body.blank();
    render_service_record(body, outcome.value().record);
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_service_show(ArgReader& reader) {
  const ServiceId id = require_service_id(reader.take_positional("a service identity"));
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (reader.consume_global()) {
      continue;
    }
    if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'service show'");
    }
    usage_error("unexpected argument '" + token + "' for 'service show'");
  }
  return [id](TenantRegistry& registry, const Globals& globals, std::string_view command) -> CommandResult {
    const auto found = registry.find_service(id);
    if (!found) {
      return refusal(found.error());
    }
    if (globals.json) {
      JsonWriter writer;
      writer.begin_object();
      writer.key("record").raw(to_json(found.value()));
      return emit_json(registry, globals, command, writer.finish());
    }
    TextBlock body;
    render_service_record(body, found.value());
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_service_list(ArgReader& reader) {
  ServiceQuery query;
  bool state_seen = false;
  bool limit_seen = false;
  bool cursor_seen = false;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--state") {
      reject_duplicate(state_seen, token);
      query.state = parse_state_value(token, reader.value_of(token));
    } else if (token == "--limit") {
      reject_duplicate(limit_seen, token);
      query.limit = parse_limit(token, reader.value_of(token));
    } else if (token == "--cursor") {
      reject_duplicate(cursor_seen, token);
      query.cursor = reader.value_of(token);
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'service list'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'service list'");
    }
  }
  return [query](TenantRegistry& registry, const Globals& globals, std::string_view command) -> CommandResult {
    const auto page = registry.list_services(query);
    if (!page) {
      return refusal(page.error());
    }
    if (globals.json) {
      return emit_json(registry, globals, command,
                       json_page(page.value(), [](const ServiceSummary& summary) {
                         return json_service_summary(summary);
                       }));
    }
    TextBlock body;
    append_page_rows(body, page.value().items.size(), page.value().total_matched, page.value().truncated,
                     page.value().next_cursor);
    body.blank();
    std::size_t index = 0;
    for (const ServiceSummary& summary : page.value().items) {
      TextBlock item;
      item.row("identity", identity_text(SubjectKind::Service, summary.id.value()));
      item.row("display_name", unset_or(summary.display_name));
      item.row("state", to_token(summary.state));
      item.row("revision", std::to_string(summary.revision.value()));
      append_item_block(body, index, item);
      ++index;
    }
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_service_transition(ArgReader& reader) {
  const ServiceId id = require_service_id(reader.take_positional("a service identity"));
  std::optional<LifecycleState> target;
  bool target_seen = false;
  std::optional<RecordRevision> revision;
  bool revision_seen = false;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--to") {
      reject_duplicate(target_seen, token);
      target = parse_state_value(token, reader.value_of(token));
    } else if (token == "--revision") {
      reject_duplicate(revision_seen, token);
      revision = parse_revision(token, reader.value_of(token));
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'service transition'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'service transition'");
    }
  }
  if (!target.has_value()) {
    usage_error("'service transition' needs --to <state>");
  }
  if (!revision.has_value()) {
    usage_error("'service transition' needs --revision <n>");
  }
  return [id, target, revision](TenantRegistry& registry, const Globals& globals,
                                std::string_view command) -> CommandResult {
    const ProvenanceRecord actor = make_actor(globals);
    const TransitionSubjectRequest request{make_context(registry, globals, actor),
                                           TenancySubject::of_service(id), *revision, *target};
    const auto outcome = registry.transition_subject(request);
    if (!outcome) {
      return refusal(outcome.error());
    }
    if (globals.json) {
      return emit_json(registry, globals, command,
                       json_receipt_and_record(outcome.value().receipt, outcome.value().record));
    }
    TextBlock body;
    append_receipt_row(body, outcome.value().receipt);
    body.blank();
    render_subject_record(body, outcome.value().record);
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_service_command(ArgReader& reader) {
  const std::string subcommand = take_subcommand(reader, "service", "create, show, list or transition");
  if (subcommand == "create") {
    return parse_service_create(reader);
  }
  if (subcommand == "show") {
    return parse_service_show(reader);
  }
  if (subcommand == "list") {
    return parse_service_list(reader);
  }
  if (subcommand == "transition") {
    return parse_service_transition(reader);
  }
  usage_error("unknown service subcommand '" + subcommand + "'");
}

// -- domain ------------------------------------------------------------------

[[nodiscard]] Runner parse_domain_create(ArgReader& reader) {
  const IsolationDomainId id = require_domain_id(reader.take_positional("an isolation domain identity"));
  std::optional<IsolationClass> isolation_class;
  bool class_seen = false;
  std::optional<std::string> display_name;
  bool display_name_seen = false;
  std::vector<MetadataEntry> metadata_entries;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--class") {
      reject_duplicate(class_seen, token);
      isolation_class = parse_class_value(token, reader.value_of(token));
    } else if (token == "--display-name") {
      reject_duplicate(display_name_seen, token);
      display_name = require_text(reader.value_of(token), kLimits.max_display_name_bytes, "the display name");
    } else if (token == "--metadata") {
      metadata_entries.push_back(require_metadata_entry(reader.value_of(token)));
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'domain create'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'domain create'");
    }
  }
  if (!isolation_class.has_value()) {
    usage_error("'domain create' needs --class <fault_containment|administrative|regulatory|tenant_private>");
  }
  const TenancyMetadata metadata = require_metadata(std::move(metadata_entries));
  return [id, isolation_class, display_name, metadata](TenantRegistry& registry, const Globals& globals,
                                                       std::string_view command) -> CommandResult {
    const ProvenanceRecord actor = make_actor(globals);
    const CreateIsolationDomainRequest request{make_context(registry, globals, actor), id, *isolation_class,
                                               display_name, metadata};
    const auto outcome = registry.create_isolation_domain(request);
    if (!outcome) {
      return refusal(outcome.error());
    }
    if (globals.json) {
      return emit_json(registry, globals, command,
                       json_receipt_and_record(outcome.value().receipt, outcome.value().record));
    }
    TextBlock body;
    append_receipt_row(body, outcome.value().receipt);
    body.blank();
    render_domain_record(body, outcome.value().record);
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_domain_transition(ArgReader& reader) {
  const IsolationDomainId id = require_domain_id(reader.take_positional("an isolation domain identity"));
  std::optional<LifecycleState> target;
  bool target_seen = false;
  std::optional<RecordRevision> revision;
  bool revision_seen = false;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--to") {
      reject_duplicate(target_seen, token);
      target = parse_state_value(token, reader.value_of(token));
    } else if (token == "--revision") {
      reject_duplicate(revision_seen, token);
      revision = parse_revision(token, reader.value_of(token));
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'domain transition'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'domain transition'");
    }
  }
  if (!target.has_value()) {
    usage_error("'domain transition' needs --to <state>");
  }
  if (!revision.has_value()) {
    usage_error("'domain transition' needs --revision <n>");
  }
  return [id, target, revision](TenantRegistry& registry, const Globals& globals,
                                std::string_view command) -> CommandResult {
    const ProvenanceRecord actor = make_actor(globals);
    const TransitionSubjectRequest request{make_context(registry, globals, actor),
                                           TenancySubject::of_isolation_domain(id), *revision, *target};
    const auto outcome = registry.transition_subject(request);
    if (!outcome) {
      return refusal(outcome.error());
    }
    if (globals.json) {
      return emit_json(registry, globals, command,
                       json_receipt_and_record(outcome.value().receipt, outcome.value().record));
    }
    TextBlock body;
    append_receipt_row(body, outcome.value().receipt);
    body.blank();
    render_subject_record(body, outcome.value().record);
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_domain_show(ArgReader& reader) {
  const IsolationDomainId id = require_domain_id(reader.take_positional("an isolation domain identity"));
  std::optional<DomainGeneration> membership_generation;
  bool generation_seen = false;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--membership-generation") {
      reject_duplicate(generation_seen, token);
      membership_generation = parse_domain_generation(token, reader.value_of(token));
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'domain show'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'domain show'");
    }
  }
  return [id, membership_generation](TenantRegistry& registry, const Globals& globals,
                                     std::string_view command) -> CommandResult {
    const auto found = membership_generation.has_value() ? registry.find_isolation_domain(id, *membership_generation)
                                                         : registry.find_isolation_domain(id);
    if (!found) {
      return refusal(found.error());
    }
    if (globals.json) {
      JsonWriter writer;
      writer.begin_object();
      writer.key("record").raw(to_json(found.value()));
      return emit_json(registry, globals, command, writer.finish());
    }
    TextBlock body;
    render_domain_record(body, found.value());
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_domain_list(ArgReader& reader) {
  DomainQuery query;
  bool state_seen = false;
  bool class_seen = false;
  bool limit_seen = false;
  bool cursor_seen = false;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--state") {
      reject_duplicate(state_seen, token);
      query.state = parse_state_value(token, reader.value_of(token));
    } else if (token == "--class") {
      reject_duplicate(class_seen, token);
      query.isolation_class = parse_class_value(token, reader.value_of(token));
    } else if (token == "--limit") {
      reject_duplicate(limit_seen, token);
      query.limit = parse_limit(token, reader.value_of(token));
    } else if (token == "--cursor") {
      reject_duplicate(cursor_seen, token);
      query.cursor = reader.value_of(token);
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'domain list'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'domain list'");
    }
  }
  return [query](TenantRegistry& registry, const Globals& globals, std::string_view command) -> CommandResult {
    const auto page = registry.list_isolation_domains(query);
    if (!page) {
      return refusal(page.error());
    }
    if (globals.json) {
      return emit_json(registry, globals, command,
                       json_page(page.value(), [](const DomainSummary& summary) {
                         return json_domain_summary(summary);
                       }));
    }
    TextBlock body;
    append_page_rows(body, page.value().items.size(), page.value().total_matched, page.value().truncated,
                     page.value().next_cursor);
    body.blank();
    std::size_t index = 0;
    for (const DomainSummary& summary : page.value().items) {
      TextBlock item;
      item.row("identity", identity_text(SubjectKind::IsolationDomain, summary.id.value()));
      item.row("display_name", unset_or(summary.display_name));
      item.row("isolation_class", to_token(summary.isolation_class));
      item.row("state", to_token(summary.state));
      item.row("revision", std::to_string(summary.revision.value()));
      item.row("membership_generation", std::to_string(summary.membership_generation.value()));
      append_item_block(body, index, item);
      ++index;
    }
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_domain_members(ArgReader& reader) {
  const IsolationDomainId id = require_domain_id(reader.take_positional("an isolation domain identity"));
  std::optional<std::size_t> limit;
  bool limit_seen = false;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--limit") {
      reject_duplicate(limit_seen, token);
      limit = parse_limit(token, reader.value_of(token));
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'domain members'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'domain members'");
    }
  }
  return [id, limit](TenantRegistry& registry, const Globals& globals, std::string_view command) -> CommandResult {
    const auto members = registry.members_of(id, limit.value_or(0));
    if (!members) {
      return refusal(members.error());
    }
    if (globals.json) {
      JsonWriter writer;
      writer.begin_object();
      writer.key("domain").string(identity_text(SubjectKind::IsolationDomain, id.value()));
      writer.key("limit").number(limit.has_value() ? static_cast<std::uint64_t>(*limit)
                                                   : static_cast<std::uint64_t>(kLimits.default_listing_limit));
      writer.key("members").begin_array();
      for (const TenancySubject& subject : members.value()) {
        writer.string(subject.to_text());
      }
      writer.end_array();
      return emit_json(registry, globals, command, writer.finish());
    }
    TextBlock body;
    body.row("domain", identity_text(SubjectKind::IsolationDomain, id.value()));
    body.row("limit", std::to_string(limit.value_or(kLimits.default_listing_limit)));
    body.row("members", std::to_string(members.value().size()));
    body.blank();
    for (const TenancySubject& subject : members.value()) {
      body.row("member", subject.to_text());
    }
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_domain_command(ArgReader& reader) {
  const std::string subcommand = take_subcommand(reader, "domain", "create, transition, show, list or members");
  if (subcommand == "create") {
    return parse_domain_create(reader);
  }
  if (subcommand == "transition") {
    return parse_domain_transition(reader);
  }
  if (subcommand == "show") {
    return parse_domain_show(reader);
  }
  if (subcommand == "list") {
    return parse_domain_list(reader);
  }
  if (subcommand == "members") {
    return parse_domain_members(reader);
  }
  usage_error("unknown domain subcommand '" + subcommand + "'");
}

// -- ownership ---------------------------------------------------------------

[[nodiscard]] Runner parse_ownership_put(ArgReader& reader) {
  const TenantId child = require_tenant_id(reader.take_positional("a child tenant identity"));
  const TenantId parent = require_tenant_id(reader.take_positional("a parent tenant identity"));
  std::optional<OwnershipKind> kind;
  bool kind_seen = false;
  LifecycleState initial = LifecycleState::Declared;
  bool state_seen = false;
  std::optional<RecordRevision> revision;
  bool revision_seen = false;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--kind") {
      reject_duplicate(kind_seen, token);
      kind = parse_ownership_value(token, reader.value_of(token));
    } else if (token == "--state") {
      reject_duplicate(state_seen, token);
      initial = parse_state_value(token, reader.value_of(token));
      if (initial != LifecycleState::Declared && initial != LifecycleState::Active) {
        usage_error("the flag '--state' accepts declared or active for an ownership edge");
      }
    } else if (token == "--revision") {
      reject_duplicate(revision_seen, token);
      revision = parse_revision(token, reader.value_of(token));
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'ownership put'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'ownership put'");
    }
  }
  if (!kind.has_value()) {
    usage_error("'ownership put' needs --kind <administrative|operational|regulatory|data_residency>");
  }
  return [child, parent, kind, initial, revision](TenantRegistry& registry, const Globals& globals,
                                                  std::string_view command) -> CommandResult {
    const ProvenanceRecord actor = make_actor(globals);
    const PutOwnershipRequest request{make_context(registry, globals, actor), child, parent, *kind, initial,
                                      revision};
    const auto outcome = registry.put_ownership(request);
    if (!outcome) {
      return refusal(outcome.error());
    }
    if (globals.json) {
      return emit_json(registry, globals, command,
                       json_receipt_and_record(outcome.value().receipt, outcome.value().edge));
    }
    TextBlock body;
    append_receipt_row(body, outcome.value().receipt);
    body.blank();
    render_ownership_edge(body, outcome.value().edge);
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_ownership_remove(ArgReader& reader) {
  const TenantId child = require_tenant_id(reader.take_positional("a child tenant identity"));
  const TenantId parent = require_tenant_id(reader.take_positional("a parent tenant identity"));
  std::optional<RecordRevision> revision;
  bool revision_seen = false;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--revision") {
      reject_duplicate(revision_seen, token);
      revision = parse_revision(token, reader.value_of(token));
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'ownership remove'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'ownership remove'");
    }
  }
  if (!revision.has_value()) {
    usage_error("'ownership remove' needs --revision <n>");
  }
  return [child, parent, revision](TenantRegistry& registry, const Globals& globals,
                                   std::string_view command) -> CommandResult {
    const ProvenanceRecord actor = make_actor(globals);
    const RemoveOwnershipRequest request{make_context(registry, globals, actor), child, parent, *revision};
    const auto outcome = registry.remove_ownership(request);
    if (!outcome) {
      return refusal(outcome.error());
    }
    if (globals.json) {
      JsonWriter writer;
      writer.begin_object();
      writer.key("receipt").raw(json_receipt(outcome.value()));
      return emit_json(registry, globals, command, writer.finish());
    }
    TextBlock body;
    append_receipt_row(body, outcome.value());
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_ownership_transition(ArgReader& reader) {
  const TenantId child = require_tenant_id(reader.take_positional("a child tenant identity"));
  const TenantId parent = require_tenant_id(reader.take_positional("a parent tenant identity"));
  std::optional<LifecycleState> target;
  bool target_seen = false;
  std::optional<RecordRevision> revision;
  bool revision_seen = false;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--to") {
      reject_duplicate(target_seen, token);
      target = parse_state_value(token, reader.value_of(token));
    } else if (token == "--revision") {
      reject_duplicate(revision_seen, token);
      revision = parse_revision(token, reader.value_of(token));
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'ownership transition'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'ownership transition'");
    }
  }
  if (!target.has_value()) {
    usage_error("'ownership transition' needs --to <state>");
  }
  if (!revision.has_value()) {
    usage_error("'ownership transition' needs --revision <n>");
  }
  return [child, parent, target, revision](TenantRegistry& registry, const Globals& globals,
                                           std::string_view command) -> CommandResult {
    const ProvenanceRecord actor = make_actor(globals);
    const TransitionOwnershipRequest request{make_context(registry, globals, actor), child, parent, *revision,
                                             *target};
    const auto outcome = registry.transition_ownership(request);
    if (!outcome) {
      return refusal(outcome.error());
    }
    if (globals.json) {
      JsonWriter writer;
      writer.begin_object();
      writer.key("receipt").raw(json_receipt(outcome.value()));
      return emit_json(registry, globals, command, writer.finish());
    }
    TextBlock body;
    append_receipt_row(body, outcome.value());
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_ownership_list(ArgReader& reader) {
  OwnershipQuery query;
  bool child_seen = false;
  bool parent_seen = false;
  bool kind_seen = false;
  bool state_seen = false;
  bool limit_seen = false;
  bool cursor_seen = false;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--child") {
      reject_duplicate(child_seen, token);
      query.child = require_tenant_id(reader.value_of(token));
    } else if (token == "--parent") {
      reject_duplicate(parent_seen, token);
      query.parent = require_tenant_id(reader.value_of(token));
    } else if (token == "--kind") {
      reject_duplicate(kind_seen, token);
      query.kind = parse_ownership_value(token, reader.value_of(token));
    } else if (token == "--state") {
      reject_duplicate(state_seen, token);
      query.state = parse_state_value(token, reader.value_of(token));
    } else if (token == "--limit") {
      reject_duplicate(limit_seen, token);
      query.limit = parse_limit(token, reader.value_of(token));
    } else if (token == "--cursor") {
      reject_duplicate(cursor_seen, token);
      query.cursor = reader.value_of(token);
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'ownership list'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'ownership list'");
    }
  }
  return [query](TenantRegistry& registry, const Globals& globals, std::string_view command) -> CommandResult {
    const auto page = registry.list_ownership(query);
    if (!page) {
      return refusal(page.error());
    }
    if (globals.json) {
      return emit_json(registry, globals, command,
                       json_page(page.value(), [](const OwnershipEdge& edge) { return to_json(edge); }));
    }
    TextBlock body;
    append_page_rows(body, page.value().items.size(), page.value().total_matched, page.value().truncated,
                     page.value().next_cursor);
    body.blank();
    std::size_t index = 0;
    for (const OwnershipEdge& edge : page.value().items) {
      TextBlock item;
      render_ownership_edge(item, edge);
      append_item_block(body, index, item);
      ++index;
    }
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_ownership_command(ArgReader& reader) {
  const std::string subcommand = take_subcommand(reader, "ownership", "put, remove, transition or list");
  if (subcommand == "put") {
    return parse_ownership_put(reader);
  }
  if (subcommand == "remove") {
    return parse_ownership_remove(reader);
  }
  if (subcommand == "transition") {
    return parse_ownership_transition(reader);
  }
  if (subcommand == "list") {
    return parse_ownership_list(reader);
  }
  usage_error("unknown ownership subcommand '" + subcommand + "'");
}

// -- binding -----------------------------------------------------------------

[[nodiscard]] Runner parse_binding_put(ArgReader& reader) {
  const ServiceId service = require_service_id(reader.take_positional("a service identity"));
  const TenantId tenant = require_tenant_id(reader.take_positional("a tenant identity"));
  std::optional<BindingKind> kind;
  bool kind_seen = false;
  LifecycleState initial = LifecycleState::Declared;
  bool state_seen = false;
  std::optional<RecordRevision> revision;
  bool revision_seen = false;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--kind") {
      reject_duplicate(kind_seen, token);
      kind = parse_binding_value(token, reader.value_of(token));
    } else if (token == "--state") {
      reject_duplicate(state_seen, token);
      initial = parse_state_value(token, reader.value_of(token));
      if (initial != LifecycleState::Declared && initial != LifecycleState::Active) {
        usage_error("the flag '--state' accepts declared or active for a service binding");
      }
    } else if (token == "--revision") {
      reject_duplicate(revision_seen, token);
      revision = parse_revision(token, reader.value_of(token));
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'binding put'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'binding put'");
    }
  }
  if (!kind.has_value()) {
    usage_error("'binding put' needs --kind <operated_by|serves|consumed_by>");
  }
  return [service, tenant, kind, initial, revision](TenantRegistry& registry, const Globals& globals,
                                                    std::string_view command) -> CommandResult {
    const ProvenanceRecord actor = make_actor(globals);
    const PutServiceBindingRequest request{make_context(registry, globals, actor), service, tenant, *kind, initial,
                                           revision};
    const auto outcome = registry.put_service_binding(request);
    if (!outcome) {
      return refusal(outcome.error());
    }
    if (globals.json) {
      return emit_json(registry, globals, command,
                       json_receipt_and_record(outcome.value().receipt, outcome.value().binding));
    }
    TextBlock body;
    append_receipt_row(body, outcome.value().receipt);
    body.blank();
    render_service_binding(body, outcome.value().binding);
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_binding_remove(ArgReader& reader) {
  const ServiceId service = require_service_id(reader.take_positional("a service identity"));
  const TenantId tenant = require_tenant_id(reader.take_positional("a tenant identity"));
  std::optional<BindingKind> kind;
  bool kind_seen = false;
  std::optional<RecordRevision> revision;
  bool revision_seen = false;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--kind") {
      reject_duplicate(kind_seen, token);
      kind = parse_binding_value(token, reader.value_of(token));
    } else if (token == "--revision") {
      reject_duplicate(revision_seen, token);
      revision = parse_revision(token, reader.value_of(token));
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'binding remove'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'binding remove'");
    }
  }
  if (!kind.has_value()) {
    usage_error("'binding remove' needs --kind <operated_by|serves|consumed_by>");
  }
  if (!revision.has_value()) {
    usage_error("'binding remove' needs --revision <n>");
  }
  return [service, tenant, kind, revision](TenantRegistry& registry, const Globals& globals,
                                           std::string_view command) -> CommandResult {
    const ProvenanceRecord actor = make_actor(globals);
    const RemoveServiceBindingRequest request{make_context(registry, globals, actor), service, tenant, *kind,
                                              *revision};
    const auto outcome = registry.remove_service_binding(request);
    if (!outcome) {
      return refusal(outcome.error());
    }
    if (globals.json) {
      JsonWriter writer;
      writer.begin_object();
      writer.key("receipt").raw(json_receipt(outcome.value()));
      return emit_json(registry, globals, command, writer.finish());
    }
    TextBlock body;
    append_receipt_row(body, outcome.value());
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_binding_transition(ArgReader& reader) {
  const ServiceId service = require_service_id(reader.take_positional("a service identity"));
  const TenantId tenant = require_tenant_id(reader.take_positional("a tenant identity"));
  std::optional<BindingKind> kind;
  bool kind_seen = false;
  std::optional<LifecycleState> target;
  bool target_seen = false;
  std::optional<RecordRevision> revision;
  bool revision_seen = false;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--kind") {
      reject_duplicate(kind_seen, token);
      kind = parse_binding_value(token, reader.value_of(token));
    } else if (token == "--to") {
      reject_duplicate(target_seen, token);
      target = parse_state_value(token, reader.value_of(token));
    } else if (token == "--revision") {
      reject_duplicate(revision_seen, token);
      revision = parse_revision(token, reader.value_of(token));
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'binding transition'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'binding transition'");
    }
  }
  if (!kind.has_value()) {
    usage_error("'binding transition' needs --kind <operated_by|serves|consumed_by>");
  }
  if (!target.has_value()) {
    usage_error("'binding transition' needs --to <state>");
  }
  if (!revision.has_value()) {
    usage_error("'binding transition' needs --revision <n>");
  }
  return [service, tenant, kind, target, revision](TenantRegistry& registry, const Globals& globals,
                                                   std::string_view command) -> CommandResult {
    const ProvenanceRecord actor = make_actor(globals);
    const TransitionServiceBindingRequest request{make_context(registry, globals, actor), service, tenant, *kind,
                                                  *revision, *target};
    const auto outcome = registry.transition_service_binding(request);
    if (!outcome) {
      return refusal(outcome.error());
    }
    if (globals.json) {
      JsonWriter writer;
      writer.begin_object();
      writer.key("receipt").raw(json_receipt(outcome.value()));
      return emit_json(registry, globals, command, writer.finish());
    }
    TextBlock body;
    append_receipt_row(body, outcome.value());
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_binding_list(ArgReader& reader) {
  BindingQuery query;
  bool service_seen = false;
  bool tenant_seen = false;
  bool kind_seen = false;
  bool state_seen = false;
  bool limit_seen = false;
  bool cursor_seen = false;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--service") {
      reject_duplicate(service_seen, token);
      query.service = require_service_id(reader.value_of(token));
    } else if (token == "--tenant") {
      reject_duplicate(tenant_seen, token);
      query.tenant = require_tenant_id(reader.value_of(token));
    } else if (token == "--kind") {
      reject_duplicate(kind_seen, token);
      query.kind = parse_binding_value(token, reader.value_of(token));
    } else if (token == "--state") {
      reject_duplicate(state_seen, token);
      query.state = parse_state_value(token, reader.value_of(token));
    } else if (token == "--limit") {
      reject_duplicate(limit_seen, token);
      query.limit = parse_limit(token, reader.value_of(token));
    } else if (token == "--cursor") {
      reject_duplicate(cursor_seen, token);
      query.cursor = reader.value_of(token);
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'binding list'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'binding list'");
    }
  }
  return [query](TenantRegistry& registry, const Globals& globals, std::string_view command) -> CommandResult {
    const auto page = registry.list_service_bindings(query);
    if (!page) {
      return refusal(page.error());
    }
    if (globals.json) {
      return emit_json(registry, globals, command,
                       json_page(page.value(), [](const ServiceBinding& binding) { return to_json(binding); }));
    }
    TextBlock body;
    append_page_rows(body, page.value().items.size(), page.value().total_matched, page.value().truncated,
                     page.value().next_cursor);
    body.blank();
    std::size_t index = 0;
    for (const ServiceBinding& binding : page.value().items) {
      TextBlock item;
      render_service_binding(item, binding);
      append_item_block(body, index, item);
      ++index;
    }
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_binding_command(ArgReader& reader) {
  const std::string subcommand = take_subcommand(reader, "binding", "put, remove, transition or list");
  if (subcommand == "put") {
    return parse_binding_put(reader);
  }
  if (subcommand == "remove") {
    return parse_binding_remove(reader);
  }
  if (subcommand == "transition") {
    return parse_binding_transition(reader);
  }
  if (subcommand == "list") {
    return parse_binding_list(reader);
  }
  usage_error("unknown binding subcommand '" + subcommand + "'");
}

// -- membership --------------------------------------------------------------

[[nodiscard]] Runner parse_membership_put(ArgReader& reader) {
  const SubjectToken subject_token = parse_subject_token(reader.take_positional("a subject token"), false);
  const TenancySubject subject = make_subject(subject_token);
  std::optional<IsolationDomainId> domain;
  bool domain_seen = false;
  std::optional<MembershipRole> role;
  bool role_seen = false;
  MembershipState initial = MembershipState::Proposed;
  bool state_seen = false;
  std::optional<DomainGeneration> domain_generation;
  bool generation_seen = false;
  std::optional<RecordRevision> revision;
  bool revision_seen = false;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--domain") {
      reject_duplicate(domain_seen, token);
      domain = require_domain_id(reader.value_of(token));
    } else if (token == "--role") {
      reject_duplicate(role_seen, token);
      role = parse_role_value(token, reader.value_of(token));
    } else if (token == "--membership-state") {
      reject_duplicate(state_seen, token);
      initial = parse_membership_value(token, reader.value_of(token));
      if (initial != MembershipState::Proposed && initial != MembershipState::Bound) {
        usage_error("the flag '--membership-state' accepts proposed or bound for a new membership");
      }
    } else if (token == "--domain-generation") {
      reject_duplicate(generation_seen, token);
      domain_generation = parse_domain_generation(token, reader.value_of(token));
    } else if (token == "--revision") {
      reject_duplicate(revision_seen, token);
      revision = parse_revision(token, reader.value_of(token));
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'membership put'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'membership put'");
    }
  }
  if (!domain.has_value()) {
    usage_error("'membership put' needs --domain <domain>");
  }
  if (!role.has_value()) {
    usage_error("'membership put' needs --role <primary|secondary|fallback>");
  }
  if (!domain_generation.has_value()) {
    usage_error("'membership put' needs --domain-generation <n>");
  }
  return [subject, domain, role, initial, domain_generation, revision](TenantRegistry& registry,
                                                                     const Globals& globals,
                                                                     std::string_view command) -> CommandResult {
    const ProvenanceRecord actor = make_actor(globals);
    const PutIsolationMembershipRequest request{make_context(registry, globals, actor), subject, *domain, *role,
                                                initial, *domain_generation, revision};
    const auto outcome = registry.put_isolation_membership(request);
    if (!outcome) {
      return refusal(outcome.error());
    }
    if (globals.json) {
      JsonWriter writer;
      writer.begin_object();
      writer.key("receipt").raw(json_receipt(outcome.value().receipt));
      writer.key("membership").raw(to_json(outcome.value().membership));
      writer.key("domain_generation").number(outcome.value().domain_generation.value());
      return emit_json(registry, globals, command, writer.finish());
    }
    TextBlock body;
    append_receipt_row(body, outcome.value().receipt);
    body.row("domain_generation", std::to_string(outcome.value().domain_generation.value()));
    body.blank();
    render_isolation_membership(body, outcome.value().membership);
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_membership_transition(ArgReader& reader) {
  const SubjectToken subject_token = parse_subject_token(reader.take_positional("a subject token"), false);
  const TenancySubject subject = make_subject(subject_token);
  std::optional<IsolationDomainId> domain;
  bool domain_seen = false;
  std::optional<MembershipState> target;
  bool target_seen = false;
  std::optional<RecordRevision> revision;
  bool revision_seen = false;
  std::optional<DomainGeneration> domain_generation;
  bool generation_seen = false;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--domain") {
      reject_duplicate(domain_seen, token);
      domain = require_domain_id(reader.value_of(token));
    } else if (token == "--to") {
      reject_duplicate(target_seen, token);
      target = parse_membership_value(token, reader.value_of(token));
    } else if (token == "--revision") {
      reject_duplicate(revision_seen, token);
      revision = parse_revision(token, reader.value_of(token));
    } else if (token == "--domain-generation") {
      reject_duplicate(generation_seen, token);
      domain_generation = parse_domain_generation(token, reader.value_of(token));
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'membership transition'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'membership transition'");
    }
  }
  if (!domain.has_value()) {
    usage_error("'membership transition' needs --domain <domain>");
  }
  if (!target.has_value()) {
    usage_error("'membership transition' needs --to <state>");
  }
  if (!revision.has_value()) {
    usage_error("'membership transition' needs --revision <n>");
  }
  if (!domain_generation.has_value()) {
    usage_error("'membership transition' needs --domain-generation <n>");
  }
  return [subject, domain, target, revision, domain_generation](TenantRegistry& registry, const Globals& globals,
                                                               std::string_view command) -> CommandResult {
    const ProvenanceRecord actor = make_actor(globals);
    const TransitionIsolationMembershipRequest request{make_context(registry, globals, actor), subject, *domain,
                                                       *revision, *domain_generation, *target};
    const auto outcome = registry.transition_isolation_membership(request);
    if (!outcome) {
      return refusal(outcome.error());
    }
    if (globals.json) {
      JsonWriter writer;
      writer.begin_object();
      writer.key("receipt").raw(json_receipt(outcome.value().receipt));
      writer.key("membership").raw(to_json(outcome.value().membership));
      writer.key("domain_generation").number(outcome.value().domain_generation.value());
      return emit_json(registry, globals, command, writer.finish());
    }
    TextBlock body;
    append_receipt_row(body, outcome.value().receipt);
    body.row("domain_generation", std::to_string(outcome.value().domain_generation.value()));
    body.blank();
    render_isolation_membership(body, outcome.value().membership);
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_membership_remove(ArgReader& reader) {
  const SubjectToken subject_token = parse_subject_token(reader.take_positional("a subject token"), false);
  const TenancySubject subject = make_subject(subject_token);
  std::optional<IsolationDomainId> domain;
  bool domain_seen = false;
  std::optional<RecordRevision> revision;
  bool revision_seen = false;
  std::optional<DomainGeneration> domain_generation;
  bool generation_seen = false;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--domain") {
      reject_duplicate(domain_seen, token);
      domain = require_domain_id(reader.value_of(token));
    } else if (token == "--revision") {
      reject_duplicate(revision_seen, token);
      revision = parse_revision(token, reader.value_of(token));
    } else if (token == "--domain-generation") {
      reject_duplicate(generation_seen, token);
      domain_generation = parse_domain_generation(token, reader.value_of(token));
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'membership remove'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'membership remove'");
    }
  }
  if (!domain.has_value()) {
    usage_error("'membership remove' needs --domain <domain>");
  }
  if (!revision.has_value()) {
    usage_error("'membership remove' needs --revision <n>");
  }
  if (!domain_generation.has_value()) {
    usage_error("'membership remove' needs --domain-generation <n>");
  }
  return [subject, domain, revision, domain_generation](TenantRegistry& registry, const Globals& globals,
                                                        std::string_view command) -> CommandResult {
    const ProvenanceRecord actor = make_actor(globals);
    const RemoveIsolationMembershipRequest request{make_context(registry, globals, actor), subject, *domain,
                                                   *revision, *domain_generation};
    const auto outcome = registry.remove_isolation_membership(request);
    if (!outcome) {
      return refusal(outcome.error());
    }
    if (globals.json) {
      JsonWriter writer;
      writer.begin_object();
      writer.key("receipt").raw(json_receipt(outcome.value()));
      return emit_json(registry, globals, command, writer.finish());
    }
    TextBlock body;
    append_receipt_row(body, outcome.value());
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_membership_list(ArgReader& reader) {
  MembershipQuery query;
  bool domain_seen = false;
  bool subject_seen = false;
  bool state_seen = false;
  bool limit_seen = false;
  bool cursor_seen = false;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--domain") {
      reject_duplicate(domain_seen, token);
      query.domain = require_domain_id(reader.value_of(token));
    } else if (token == "--subject") {
      reject_duplicate(subject_seen, token);
      query.subject = make_subject(parse_subject_token(reader.value_of(token), false));
    } else if (token == "--state") {
      reject_duplicate(state_seen, token);
      query.state = parse_membership_value(token, reader.value_of(token));
    } else if (token == "--limit") {
      reject_duplicate(limit_seen, token);
      query.limit = parse_limit(token, reader.value_of(token));
    } else if (token == "--cursor") {
      reject_duplicate(cursor_seen, token);
      query.cursor = reader.value_of(token);
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'membership list'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'membership list'");
    }
  }
  return [query](TenantRegistry& registry, const Globals& globals, std::string_view command) -> CommandResult {
    const auto page = registry.list_isolation_memberships(query);
    if (!page) {
      return refusal(page.error());
    }
    if (globals.json) {
      return emit_json(registry, globals, command,
                       json_page(page.value(), [](const MembershipSummary& summary) {
                         return json_membership_summary(summary);
                       }));
    }
    TextBlock body;
    append_page_rows(body, page.value().items.size(), page.value().total_matched, page.value().truncated,
                     page.value().next_cursor);
    body.blank();
    std::size_t index = 0;
    for (const MembershipSummary& summary : page.value().items) {
      TextBlock item;
      item.row("subject", summary.subject.to_text());
      item.row("domain", identity_text(SubjectKind::IsolationDomain, summary.domain.value()));
      item.row("role", to_token(summary.role));
      item.row("state", to_token(summary.state));
      item.row("revision", std::to_string(summary.revision.value()));
      append_item_block(body, index, item);
      ++index;
    }
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_membership_command(ArgReader& reader) {
  const std::string subcommand = take_subcommand(reader, "membership", "put, transition, remove or list");
  if (subcommand == "put") {
    return parse_membership_put(reader);
  }
  if (subcommand == "transition") {
    return parse_membership_transition(reader);
  }
  if (subcommand == "remove") {
    return parse_membership_remove(reader);
  }
  if (subcommand == "list") {
    return parse_membership_list(reader);
  }
  usage_error("unknown membership subcommand '" + subcommand + "'");
}

// -- isolate -----------------------------------------------------------------

[[nodiscard]] Runner parse_isolate(ArgReader& reader) {
  const TenancySubject subject = make_subject(parse_subject_token(reader.take_positional("a subject token"), false));
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (reader.consume_global()) {
      continue;
    }
    if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'isolate'");
    }
    usage_error("unexpected argument '" + token + "' for 'isolate'");
  }
  return [subject](TenantRegistry& registry, const Globals& globals, std::string_view command) -> CommandResult {
    const auto domains = registry.isolation_domains_of(subject);
    if (!domains) {
      return refusal(domains.error());
    }
    if (globals.json) {
      JsonWriter writer;
      writer.begin_object();
      writer.key("subject").string(subject.to_text());
      writer.key("domains").begin_array();
      for (const IsolationDomainId& domain : domains.value()) {
        writer.string(identity_text(SubjectKind::IsolationDomain, domain.value()));
      }
      writer.end_array();
      return emit_json(registry, globals, command, writer.finish());
    }
    TextBlock body;
    body.row("subject", subject.to_text());
    body.row("domains", std::to_string(domains.value().size()));
    body.blank();
    for (const IsolationDomainId& domain : domains.value()) {
      body.row("domain", identity_text(SubjectKind::IsolationDomain, domain.value()));
    }
    return emit_human(registry, globals, std::move(body));
  };
}

// -- traverse ----------------------------------------------------------------

[[nodiscard]] Runner parse_traverse(ArgReader& reader) {
  const TenantId start = require_tenant_id(reader.take_positional("a tenant identity"));
  std::optional<TraversalDirection> direction;
  bool direction_seen = false;
  std::optional<OwnershipKind> kind;
  bool kind_seen = false;
  std::optional<std::size_t> max_depth;
  bool depth_seen = false;
  std::optional<std::size_t> max_results;
  bool results_seen = false;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--direction") {
      reject_duplicate(direction_seen, token);
      direction = parse_direction_value(token, reader.value_of(token));
    } else if (token == "--kind") {
      reject_duplicate(kind_seen, token);
      kind = parse_ownership_value(token, reader.value_of(token));
    } else if (token == "--max-depth") {
      reject_duplicate(depth_seen, token);
      const std::uint64_t value =
          parse_number(token, reader.value_of(token), static_cast<std::uint64_t>(kLimits.max_traversal_depth));
      if (value == 0) {
        usage_error("the flag '--max-depth' must be at least 1");
      }
      max_depth = static_cast<std::size_t>(value);
    } else if (token == "--max-results") {
      reject_duplicate(results_seen, token);
      const std::uint64_t value = parse_number(token, reader.value_of(token),
                                               static_cast<std::uint64_t>(kLimits.max_traversal_results));
      if (value == 0) {
        usage_error("the flag '--max-results' must be at least 1");
      }
      max_results = static_cast<std::size_t>(value);
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'traverse'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'traverse'");
    }
  }
  if (!direction.has_value()) {
    usage_error("'traverse' needs --direction <ancestors|descendants>");
  }
  return [start, direction, kind, max_depth, max_results](TenantRegistry& registry, const Globals& globals,
                                                          std::string_view command) -> CommandResult {
    const OwnershipTraversalRequest request{start, *direction, kind, std::nullopt, max_depth.value_or(0),
                                            max_results.value_or(0)};
    const auto traversal = registry.traverse_ownership(request);
    if (!traversal) {
      return refusal(traversal.error());
    }
    const OwnershipTraversal& walked = traversal.value();
    if (globals.json) {
      JsonWriter writer;
      writer.begin_object();
      writer.key("start").string(identity_text(SubjectKind::Tenant, walked.start.value()));
      writer.key("direction").string(to_token(walked.direction));
      writer.key("kind").string(kind.has_value() ? to_token(*kind) : std::string_view{"unset"});
      writer.key("steps").begin_array();
      for (const OwnershipStep& step : walked.steps) {
        JsonWriter step_writer;
        step_writer.begin_object();
        step_writer.key("from").string(identity_text(SubjectKind::Tenant, step.from.value()));
        step_writer.key("to").string(identity_text(SubjectKind::Tenant, step.to.value()));
        step_writer.key("kind").string(to_token(step.kind));
        step_writer.key("state").string(to_token(step.state));
        step_writer.key("depth").number(static_cast<std::uint64_t>(step.depth));
        writer.raw(step_writer.finish());
      }
      writer.end_array();
      writer.key("reached").begin_array();
      for (const TenantId& tenant : walked.reached) {
        writer.string(identity_text(SubjectKind::Tenant, tenant.value()));
      }
      writer.end_array();
      writer.key("max_depth_reached").number(static_cast<std::uint64_t>(walked.max_depth_reached));
      writer.key("truncated").boolean(walked.truncated);
      writer.key("depth_limited").boolean(walked.depth_limited);
      return emit_json(registry, globals, command, writer.finish());
    }
    TextBlock body;
    body.row("start", identity_text(SubjectKind::Tenant, walked.start.value()));
    body.row("direction", to_token(walked.direction));
    body.row("kind", kind.has_value() ? to_token(*kind) : std::string_view{"unset"});
    body.row("max_depth_reached", std::to_string(walked.max_depth_reached));
    body.row("reached", std::to_string(walked.reached.size()));
    body.row("truncated", walked.truncated ? "true" : "false");
    body.row("depth_limited", walked.depth_limited ? "true" : "false");
    body.blank();
    std::size_t index = 0;
    for (const OwnershipStep& step : walked.steps) {
      TextBlock item;
      item.row("from", identity_text(SubjectKind::Tenant, step.from.value()));
      item.row("to", identity_text(SubjectKind::Tenant, step.to.value()));
      item.row("kind", to_token(step.kind));
      item.row("state", to_token(step.state));
      item.row("depth", std::to_string(step.depth));
      append_item_block(body, index, item);
      ++index;
    }
    for (const TenantId& tenant : walked.reached) {
      body.row("reached", identity_text(SubjectKind::Tenant, tenant.value()));
    }
    return emit_human(registry, globals, std::move(body));
  };
}

// -- explain -----------------------------------------------------------------

[[nodiscard]] Runner parse_explain(ArgReader& reader) {
  const TenancySubject subject =
      make_subject(parse_subject_token(reader.take_positional("a subject token"), true));
  std::optional<std::size_t> lineage_depth;
  bool depth_seen = false;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--lineage-depth") {
      reject_duplicate(depth_seen, token);
      const std::uint64_t value =
          parse_number(token, reader.value_of(token), static_cast<std::uint64_t>(kLimits.max_ownership_depth));
      if (value == 0) {
        usage_error("the flag '--lineage-depth' must be at least 1");
      }
      lineage_depth = static_cast<std::size_t>(value);
    } else if (reader.consume_global()) {
      continue;
    } else if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'explain'");
    } else {
      usage_error("unexpected argument '" + token + "' for 'explain'");
    }
  }
  return [subject, lineage_depth](TenantRegistry& registry, const Globals& globals,
                                  std::string_view command) -> CommandResult {
    ExplainOptions options;
    if (lineage_depth.has_value()) {
      options.max_lineage_depth = *lineage_depth;
    }
    const auto explanation = registry.explain(subject, options);
    if (!explanation) {
      return refusal(explanation.error());
    }
    const Explanation& value = explanation.value();
    if (globals.json) {
      JsonWriter writer;
      writer.begin_object();
      writer.key("subject").string(value.subject.to_text());
      writer.key("record").raw(to_json(value.record));
      writer.key("owner");
      if (value.owner.has_value()) {
        writer.string(value.owner->value());
      } else {
        writer.null_value();
      }
      writer.key("owned_by").begin_array();
      for (const OwnershipEdge& edge : value.owned_by) {
        writer.raw(to_json(edge));
      }
      writer.end_array();
      writer.key("ownership_lineage").begin_array();
      for (const TenantId& ancestor : value.ownership_lineage) {
        writer.string(identity_text(SubjectKind::Tenant, ancestor.value()));
      }
      writer.end_array();
      writer.key("owns").begin_array();
      for (const OwnershipEdge& edge : value.owns) {
        writer.raw(to_json(edge));
      }
      writer.end_array();
      writer.key("bindings").begin_array();
      for (const ServiceBinding& binding : value.bindings) {
        writer.raw(to_json(binding));
      }
      writer.end_array();
      writer.key("memberships").begin_array();
      for (const IsolationMembership& membership : value.memberships) {
        writer.raw(to_json(membership));
      }
      writer.end_array();
      writer.key("domain_generations").begin_array();
      for (const auto& [domain, generation] : value.domain_generations) {
        JsonWriter entry;
        entry.begin_object();
        entry.key("domain").string(identity_text(SubjectKind::IsolationDomain, domain.value()));
        entry.key("membership_generation").number(generation.value());
        writer.raw(entry.finish());
      }
      writer.end_array();
      writer.key("outstanding_rebind_permit");
      if (value.outstanding_rebind_permit.has_value()) {
        writer.string(value.outstanding_rebind_permit->to_text());
      } else {
        writer.null_value();
      }
      writer.key("generation").number(value.generation.value());
      writer.key("control_epoch").number(value.control_epoch.value());
      writer.key("incarnation").number(value.incarnation.value());
      writer.key("unknowns").begin_array();
      for (const std::string& unknown : value.unknowns) {
        writer.string(unknown);
      }
      writer.end_array();
      writer.key("digest").string(value.digest().to_text());
      return emit_json(registry, globals, command, writer.finish());
    }
    TextBlock body;
    body.row("subject", value.subject.to_text());
    body.row("owner", value.owner.has_value() ? value.owner->value() : std::string{"unset"});
    body.row("owned_by", std::to_string(value.owned_by.size()));
    body.row("owns", std::to_string(value.owns.size()));
    body.row("bindings", std::to_string(value.bindings.size()));
    body.row("memberships", std::to_string(value.memberships.size()));
    body.row("outstanding_rebind_permit",
             value.outstanding_rebind_permit.has_value() ? value.outstanding_rebind_permit->to_text()
                                                         : std::string{"unset"});
    body.row("generation", std::to_string(value.generation.value()));
    body.row("control_epoch", std::to_string(value.control_epoch.value()));
    body.row("incarnation", std::to_string(value.incarnation.value()));
    body.row("digest", value.digest().to_text());
    body.blank();
    for (const TenantId& ancestor : value.ownership_lineage) {
      body.row("lineage", identity_text(SubjectKind::Tenant, ancestor.value()));
    }
    if (value.ownership_lineage.empty()) {
      body.row("lineage", "unset");
    }
    for (const auto& [domain, generation] : value.domain_generations) {
      body.row(identity_text(SubjectKind::IsolationDomain, domain.value()),
               std::to_string(generation.value()));
    }
    if (value.unknowns.empty()) {
      body.row("unknowns", "none");
    } else {
      for (const std::string& unknown : value.unknowns) {
        body.row("unknown", unknown);
      }
    }
    body.blank();
    body.line("record");
    TextBlock record_block;
    render_subject_record(record_block, value.record);
    body.append_indented(record_block, 2);
    return emit_human(registry, globals, std::move(body));
  };
}

// -- stats, snapshot, export, compact, verify --------------------------------

[[nodiscard]] std::string json_stats(const RegistryStats& stats) {
  const auto emit_states = [](JsonWriter& writer, std::string_view name, const std::vector<StateCount>& counts) {
    writer.key(name).begin_array();
    for (const StateCount& entry : counts) {
      JsonWriter item;
      item.begin_object();
      item.key("state").string(to_token(entry.state));
      item.key("count").number(entry.count);
      writer.raw(item.finish());
    }
    writer.end_array();
  };
  JsonWriter writer;
  writer.begin_object();
  writer.key("generation").number(stats.generation.value());
  writer.key("control_epoch").number(stats.control_epoch.value());
  writer.key("incarnation").number(stats.incarnation.value());
  writer.key("committed_sequence").number(stats.committed_sequence.value());
  writer.key("store_id");
  if (stats.store_id.has_value()) {
    writer.string(stats.store_id->to_text());
  } else {
    writer.null_value();
  }
  writer.key("tenants").number(stats.tenants);
  writer.key("services").number(stats.services);
  writer.key("isolation_domains").number(stats.isolation_domains);
  writer.key("ownership_edges").number(stats.ownership_edges);
  writer.key("service_bindings").number(stats.service_bindings);
  writer.key("isolation_memberships").number(stats.isolation_memberships);
  emit_states(writer, "tenants_by_state", stats.tenants_by_state);
  emit_states(writer, "services_by_state", stats.services_by_state);
  emit_states(writer, "domains_by_state", stats.domains_by_state);
  return writer.finish();
}

[[nodiscard]] Runner parse_stats(ArgReader& reader) {
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (reader.consume_global()) {
      continue;
    }
    if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'stats'");
    }
    usage_error("unexpected argument '" + token + "' for 'stats'");
  }
  return [](TenantRegistry& registry, const Globals& globals, std::string_view command) -> CommandResult {
    const RegistryStats stats = registry.stats();
    if (globals.json) {
      return emit_json(registry, globals, command, json_stats(stats));
    }
    TextBlock body;
    body.append_text(stats.to_text());
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_snapshot(ArgReader& reader) {
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (reader.consume_global()) {
      continue;
    }
    if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'snapshot'");
    }
    usage_error("unexpected argument '" + token + "' for 'snapshot'");
  }
  return [](TenantRegistry& registry, const Globals& globals, std::string_view) -> CommandResult {
    const RegistrySnapshot snapshot = registry.snapshot();
    if (globals.json) {
      std::string text = snapshot.to_json();
      text.push_back('\n');
      return success_text(std::move(text));
    }
    TextBlock body;
    body.append_text(snapshot.to_text());
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_export(ArgReader& reader) {
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (reader.consume_global()) {
      continue;
    }
    if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'export'");
    }
    usage_error("unexpected argument '" + token + "' for 'export'");
  }
  return [](TenantRegistry& registry, const Globals&, std::string_view) -> CommandResult {
    const auto exported = registry.export_json();
    if (!exported) {
      return refusal(exported.error());
    }
    std::string text = exported.value();
    text.push_back('\n');
    return success_text(std::move(text));
  };
}

[[nodiscard]] Runner parse_compact(ArgReader& reader) {
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (reader.consume_global()) {
      continue;
    }
    if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'compact'");
    }
    usage_error("unexpected argument '" + token + "' for 'compact'");
  }
  return [](TenantRegistry& registry, const Globals& globals, std::string_view command) -> CommandResult {
    const Status compacted = registry.compact();
    if (!compacted.ok()) {
      return refusal(compacted.error());
    }
    const ContentDigest digest = registry.snapshot().digest();
    if (globals.json) {
      JsonWriter writer;
      writer.begin_object();
      writer.key("compaction").string("complete");
      writer.key("generation").number(registry.generation().value());
      writer.key("sequence").number(registry.committed_sequence().value());
      writer.key("snapshot_digest").string(digest.to_text());
      return emit_json(registry, globals, command, writer.finish());
    }
    TextBlock body;
    body.row("compaction", "complete");
    body.row("generation", std::to_string(registry.generation().value()));
    body.row("sequence", std::to_string(registry.committed_sequence().value()));
    body.row("snapshot_digest", digest.to_text());
    return emit_human(registry, globals, std::move(body));
  };
}

[[nodiscard]] Runner parse_verify(ArgReader& reader) {
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (reader.consume_global()) {
      continue;
    }
    if (is_flag_token(token)) {
      usage_error("unknown flag '" + token + "' for 'verify'");
    }
    usage_error("unexpected argument '" + token + "' for 'verify'");
  }
  return [](TenantRegistry& registry, const Globals& globals, std::string_view command) -> CommandResult {
    // The session is described before it is released: a closed session still
    // reports its counters, but the description belongs to the session that
    // wrote the store, not to the reader that replaces it.
    const std::string session_json = globals.json ? json_session(registry) : std::string{};
    // The first session is released before the second one opens, so the report
    // describes a genuinely independent read of the same durable store rather
    // than two sessions sharing one process's state.
    const ContentDigest first_digest = registry.snapshot().digest();
    const Status closed = registry.close();
    if (!closed.ok()) {
      return refusal(closed.error());
    }
    RegistryOpenRequest request;
    request.root = *globals.root;
    request.mode = AccessMode::ReadOnly;
    request.store.limits = kLimits;
    auto reopened = TenantRegistry::open(request);
    if (!reopened) {
      return refusal(reopened.error());
    }
    TenantRegistry second = std::move(reopened).value();
    const StoreRecoveryReport report = second.recovery_report();
    const ContentDigest second_digest = second.snapshot().digest();
    const bool consistent = first_digest == second_digest;
    const Status second_closed = second.close();
    if (!second_closed.ok()) {
      return refusal(second_closed.error());
    }
    if (!consistent) {
      Error mismatch{ErrorCode::InternalInvariantViolated,
                     "the reopened session digests to " + second_digest.to_text() +
                         " but the session that wrote it digested to " + first_digest.to_text()};
      return refusal(mismatch);
    }
    if (globals.json) {
      JsonWriter writer;
      writer.begin_object();
      writer.key("verified").boolean(true);
      writer.key("consistent").boolean(consistent);
      writer.key("digest").string(second_digest.to_text());
      writer.key("generation").number(report.committed_generation.value());
      writer.key("control_epoch").number(report.control_epoch.value());
      writer.key("incarnation").number(report.incarnation.value());
      writer.key("committed_sequence").number(report.committed_sequence.value());
      writer.key("store_created").boolean(report.store_created);
      writer.key("manifest_present").boolean(report.manifest_present);
      writer.key("uncommitted_tail_discarded").boolean(report.uncommitted_tail_discarded);
      writer.key("uncommitted_bytes_discarded").number(report.uncommitted_bytes_discarded);
      writer.key("frames_replayed").number(report.frames_replayed);
      writer.key("baseline_frames").number(report.baseline_frames);
      writer.key("read_only").boolean(report.read_only);
      writer.key("previous_control_epoch");
      if (report.previous_control_epoch.has_value()) {
        writer.number(report.previous_control_epoch->value());
      } else {
        writer.null_value();
      }
      writer.key("notes").begin_array();
      for (const std::string& note : report.notes) {
        writer.string(note);
      }
      writer.end_array();
      return emit_json_with_session(session_json, globals.quiet, command, writer.finish());
    }
    TextBlock body;
    body.row("registry", "durable");
    body.row("verified", "true");
    body.row("consistent", consistent ? "true" : "false");
    body.row("digest", second_digest.to_text());
    body.row("generation", std::to_string(report.committed_generation.value()));
    body.row("control_epoch", std::to_string(report.control_epoch.value()));
    body.row("incarnation", std::to_string(report.incarnation.value()));
    body.row("committed_sequence", std::to_string(report.committed_sequence.value()));
    body.row("store_created", report.store_created ? "true" : "false");
    body.row("manifest_present", report.manifest_present ? "true" : "false");
    body.row("uncommitted_tail_discarded", report.uncommitted_tail_discarded ? "true" : "false");
    body.row("uncommitted_bytes_discarded", std::to_string(report.uncommitted_bytes_discarded));
    body.row("frames_replayed", std::to_string(report.frames_replayed));
    body.row("baseline_frames", std::to_string(report.baseline_frames));
    body.row("read_only", report.read_only ? "true" : "false");
    body.row("previous_control_epoch",
             report.previous_control_epoch.has_value()
                 ? std::to_string(report.previous_control_epoch->value())
                 : std::string{"unset"});
    body.blank();
    for (const std::string& note : report.notes) {
      body.row("note", note);
    }
    return success_text(body.render());
  };
}

// ---------------------------------------------------------------------------
// Command dispatch
// ---------------------------------------------------------------------------

[[nodiscard]] Runner parse_command(const std::string& word, ArgReader& reader) {
  if (word == "tenant") {
    return parse_tenant_command(reader);
  }
  if (word == "service") {
    return parse_service_command(reader);
  }
  if (word == "domain") {
    return parse_domain_command(reader);
  }
  if (word == "ownership") {
    return parse_ownership_command(reader);
  }
  if (word == "binding") {
    return parse_binding_command(reader);
  }
  if (word == "membership") {
    return parse_membership_command(reader);
  }
  if (word == "isolate") {
    return parse_isolate(reader);
  }
  if (word == "traverse") {
    return parse_traverse(reader);
  }
  if (word == "explain") {
    return parse_explain(reader);
  }
  if (word == "stats") {
    return parse_stats(reader);
  }
  if (word == "snapshot") {
    return parse_snapshot(reader);
  }
  if (word == "export") {
    return parse_export(reader);
  }
  if (word == "compact") {
    return parse_compact(reader);
  }
  if (word == "verify") {
    return parse_verify(reader);
  }
  usage_error("unknown command '" + word + "'");
}

struct Invocation {
  MutableGlobals raw;
  SpecialMode mode = SpecialMode::None;
  std::string command_name;
  Runner runner;
  std::optional<std::filesystem::path> scratch;
};

[[nodiscard]] std::string special_mode_name(SpecialMode mode) {
  switch (mode) {
    case SpecialMode::SelfCheck:
      return "--self-check";
    case SpecialMode::Scenario:
      return "--scenario";
    case SpecialMode::None:
      break;
  }
  return "--self-check";
}

/// --self-check and --scenario take no arguments of their own. One scratch
/// directory may be named (positionally, or through --root): it is where the
/// temporary durable registry lives, and it is removed before the mode
/// returns. --quiet and --help/--version are accepted; anything else is a
/// usage error naming the offending token.
void parse_special_mode(const std::vector<std::string>& tokens, Invocation& invocation) {
  ArgReader reader{tokens, invocation.raw};
  bool scratch_seen = false;
  while (!reader.done()) {
    const std::string& token = reader.peek();
    if (token == "--self-check" || token == "--scenario") {
      reader.take();
      continue;
    }
    if (token == "--root") {
      reject_duplicate(invocation.raw.root_text, token);
      invocation.raw.root_text = reader.value_of(token);
      continue;
    }
    if (token == "--quiet") {
      invocation.raw.quiet = true;
      reader.take();
      continue;
    }
    if (token == "--help") {
      invocation.raw.help = true;
      reader.take();
      continue;
    }
    if (token == "--version") {
      invocation.raw.version = true;
      reader.take();
      continue;
    }
    if (is_flag_token(token)) {
      usage_error("the flag '" + token + "' is not accepted by " + special_mode_name(invocation.mode));
    }
    if (scratch_seen) {
      usage_error("unexpected argument '" + token + "' for " + special_mode_name(invocation.mode));
    }
    invocation.raw.root_text = token;
    scratch_seen = true;
    reader.take();
  }
  if (invocation.raw.root_text.has_value()) {
    if (invocation.raw.root_text->empty()) {
      usage_error("the scratch directory of " + special_mode_name(invocation.mode) + " must not be empty");
    }
    invocation.scratch = std::filesystem::path{*invocation.raw.root_text};
  }
}

[[nodiscard]] Invocation parse_invocation(const std::vector<std::string>& tokens) {
  Invocation invocation;
  for (const std::string& token : tokens) {
    if (token == "--self-check") {
      if (invocation.mode == SpecialMode::Scenario) {
        usage_error("--self-check and --scenario cannot be combined");
      }
      invocation.mode = SpecialMode::SelfCheck;
    } else if (token == "--scenario") {
      if (invocation.mode == SpecialMode::SelfCheck) {
        usage_error("--self-check and --scenario cannot be combined");
      }
      invocation.mode = SpecialMode::Scenario;
    }
  }
  if (invocation.mode != SpecialMode::None) {
    parse_special_mode(tokens, invocation);
    return invocation;
  }

  ArgReader reader{tokens, invocation.raw};
  while (!reader.done() && reader.consume_global()) {
  }
  if (invocation.raw.help || invocation.raw.version) {
    return invocation;
  }
  if (reader.done()) {
    usage_error("no command was given; run 'treg --help' for the command list");
  }
  const std::string word = reader.take_command_word();
  if (is_flag_token(word)) {
    usage_error("unknown flag '" + word + "'");
  }
  const Runner runner = parse_command(word, reader);
  if (!reader.done()) {
    usage_error("unexpected argument '" + reader.peek() + "'");
  }
  std::string name = word;
  for (const std::string& part : reader.command_words()) {
    name.push_back(' ');
    name.append(part);
  }
  invocation.command_name = std::move(name);
  invocation.runner = runner;
  if (word == "verify" && !invocation.raw.root_text.has_value()) {
    usage_error("'verify' needs --root: an ephemeral registry has no durable state to re-open");
  }
  return invocation;
}

// ---------------------------------------------------------------------------
// Scratch directories
// ---------------------------------------------------------------------------

[[nodiscard]] std::string random_suffix() {
  std::random_device device;
  std::mt19937_64 generator{device()};
  std::uniform_int_distribution<std::uint64_t> distribution;
  const std::uint64_t value = distribution(generator);
  constexpr char kHexDigits[] = "0123456789abcdef";
  std::string text;
  text.reserve(16);
  for (int shift = 60; shift >= 0; shift -= 4) {
    text.push_back(kHexDigits[(value >> static_cast<unsigned>(shift)) & 0x0FU]);
  }
  return text;
}

/// A uniquely named directory that removes itself. Every temporary durable
/// registry the self-check and the scenario build lives inside one, so a
/// failure at any point -- including an exception -- still leaves nothing
/// behind.
class ScratchDirectory {
 public:
  ScratchDirectory() = default;

  ScratchDirectory(const ScratchDirectory&) = delete;
  ScratchDirectory& operator=(const ScratchDirectory&) = delete;

  ScratchDirectory(ScratchDirectory&& other) noexcept
      : path_(std::move(other.path_)),
        created_parent_(std::move(other.created_parent_)),
        active_(other.active_) {
    other.active_ = false;
  }

  ScratchDirectory& operator=(ScratchDirectory&& other) noexcept {
    if (this != &other) {
      cleanup();
      path_ = std::move(other.path_);
      created_parent_ = std::move(other.created_parent_);
      active_ = other.active_;
      other.active_ = false;
    }
    return *this;
  }

  ~ScratchDirectory() { cleanup(); }

  [[nodiscard]] static std::optional<ScratchDirectory> create(
      const std::optional<std::filesystem::path>& parent, std::string& error) {
    std::error_code code;
    ScratchDirectory scratch;
    std::filesystem::path base;
    if (parent.has_value()) {
      base = *parent;
      const bool present = std::filesystem::exists(base, code);
      if (code) {
        error = "the scratch directory could not be inspected";
        return std::nullopt;
      }
      if (!present) {
        std::error_code create_code;
        const bool created = std::filesystem::create_directories(base, create_code);
        if (!created || create_code) {
          error = "the scratch directory could not be created";
          return std::nullopt;
        }
        scratch.created_parent_ = base;
      } else if (!std::filesystem::is_directory(base, code) || code) {
        error = "the scratch path exists and is not a directory";
        return std::nullopt;
      }
    } else {
      base = std::filesystem::temp_directory_path(code);
      if (code) {
        error = "the system temporary directory could not be located";
        return std::nullopt;
      }
    }
    const std::filesystem::path target = base / ("treg-cli-" + random_suffix());
    std::error_code make_code;
    const bool created = std::filesystem::create_directories(target, make_code);
    if (!created || make_code) {
      error = "a scratch directory could not be created";
      return std::nullopt;
    }
    scratch.path_ = target;
    scratch.active_ = true;
    return std::optional<ScratchDirectory>{std::move(scratch)};
  }

  [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

  void cleanup() noexcept {
    if (!active_) {
      return;
    }
    active_ = false;
    std::error_code code;
    if (!path_.empty()) {
      (void)std::filesystem::remove_all(path_, code);
    }
    if (created_parent_.has_value()) {
      std::error_code parent_code;
      (void)std::filesystem::remove(*created_parent_, parent_code);
    }
    path_.clear();
    created_parent_.reset();
  }

 private:
  std::filesystem::path path_;
  std::optional<std::filesystem::path> created_parent_;
  bool active_ = false;
};

// ---------------------------------------------------------------------------
// The self-check battery
// ---------------------------------------------------------------------------

/// Collects one line per check. A check body returns an empty string when it
/// passed and the reason it did not when it failed.
class Battery {
 public:
  explicit Battery(std::string& out) : out_(&out) {}

  void check(std::string_view name, const std::function<std::string()>& body) {
    const std::string detail = body();
    record(name, detail.empty(), detail);
  }

  void check(std::string_view name, bool passed, std::string_view detail) {
    record(name, passed, detail);
  }

  [[nodiscard]] int finish(bool quiet) {
    if (!quiet) {
      std::string line{"self-check: "};
      line.append(std::to_string(count_));
      line.append(failed_ == 0 ? " checks passed" : " checks, " + std::to_string(failed_) + " failed");
      line.push_back('\n');
      out_->append(line);
    }
    return failed_ == 0 ? kExitSuccess : kExitRefusal;
  }

 private:
  void record(std::string_view name, bool passed, std::string_view detail) {
    ++count_;
    std::string line{"check "};
    line.append(count_ < 10 ? "0" : "");
    line.append(std::to_string(count_));
    line.push_back(' ');
    line.append(name);
    line.append(passed ? ": ok" : ": failed");
    if (!passed) {
      ++failed_;
      if (!detail.empty()) {
        line.append(" (");
        line.append(detail);
        line.append(")");
      }
    }
    line.push_back('\n');
    out_->append(line);
  }

  std::string* out_;
  std::size_t count_ = 0;
  std::size_t failed_ = 0;
};

/// Checks that do not need a registry: the parser the tool is built on.
void battery_parsing(Battery& battery) {
  battery.check("parse-lifecycle-state", []() -> std::string {
    LifecycleState state = LifecycleState::Unspecified;
    if (!parse_lifecycle_state("active", state) || state != LifecycleState::Active) {
      return "the token 'active' did not parse to the active state";
    }
    if (parse_lifecycle_state("bogus", state)) {
      return "an unknown lifecycle token was accepted";
    }
    return {};
  });

  battery.check("parse-subject-token", []() -> std::string {
    const SubjectToken token = parse_subject_token("tenant:acme", true);
    if (token.kind != SubjectKind::Tenant || token.text != "acme") {
      return "a tenant subject token did not parse";
    }
    bool refused = false;
    try {
      (void)parse_subject_token("domain:acme", true);
    } catch (const UsageError&) {
      refused = true;
    }
    if (!refused) {
      return "an unknown subject prefix was accepted";
    }
    return {};
  });

  battery.check("bound-numbers", []() -> std::string {
    bool refused = false;
    try {
      (void)parse_number("--revision", "12x", 100);
    } catch (const UsageError&) {
      refused = true;
    }
    if (!refused) {
      return "a non decimal number was accepted";
    }
    refused = false;
    try {
      (void)parse_number("--revision", "101", 100);
    } catch (const UsageError&) {
      refused = true;
    }
    if (!refused) {
      return "an out of range number was accepted";
    }
    if (parse_number("--revision", "100", 100) != 100) {
      return "an in range number was not parsed";
    }
    return {};
  });

  battery.check("metadata-pairs", []() -> std::string {
    const MetadataEntry entry = require_metadata_entry("tier=gold");
    if (entry.key.value() != "tier" || entry.value.to_canonical() != "text:4:gold") {
      return "a key=value metadata pair did not parse";
    }
    bool refused = false;
    try {
      (void)require_metadata_entry("tier");
    } catch (const UsageError&) {
      refused = true;
    }
    if (!refused) {
      return "a metadata entry without '=' was accepted";
    }
    return {};
  });
}

void battery_ephemeral(Battery& battery, TenantRegistry& registry) {
  const auto principal = PrincipalId::create("self-check-principal");
  const auto source = SourceId::create("self-check");
  if (!principal || !source) {
    battery.check("battery-actor", false, "the battery actor identity could not be created");
    return;
  }
  auto created_actor = ProvenanceRecord::create(ProvenanceSource::TestFixture, source.value(), principal.value(),
                                                std::nullopt, std::string{},
                                                kLimits.max_provenance_note_bytes);
  if (!created_actor) {
    battery.check("battery-actor", false, describe(created_actor.error()));
    return;
  }
  const ProvenanceRecord actor = std::move(created_actor).value();
  const auto context = [&registry, &actor](std::optional<IdempotencyKey> key = std::nullopt) {
    return MutationContext{registry.generation(), key, actor};
  };

  const auto acme_result = TenantId::create("acme");
  const auto team_result = TenantId::create("team");
  const auto service_result = ServiceId::create("renderer");
  const auto zone_a_result = IsolationDomainId::create("zone-a");
  const auto zone_b_result = IsolationDomainId::create("zone-b");
  if (!acme_result || !team_result || !service_result || !zone_a_result || !zone_b_result) {
    battery.check("battery-identities", false, "the battery identities could not be created");
    return;
  }
  const TenantId acme = acme_result.value();
  const TenantId team = team_result.value();
  const ServiceId renderer = service_result.value();
  const IsolationDomainId zone_a = zone_a_result.value();
  const IsolationDomainId zone_b = zone_b_result.value();

  battery.check("ephemeral-state", [&]() -> std::string {
    if (registry.durable()) {
      return "an ephemeral session claims to be durable";
    }
    if (registry.access_mode() != AccessMode::ReadWrite) {
      return "an ephemeral session is not read-write";
    }
    if (registry.generation().value() != 0) {
      return "an ephemeral session does not start at generation 0";
    }
    if (registry.store_identity().has_value()) {
      return "an ephemeral session reports a store identity";
    }
    return {};
  });

  battery.check("create-tenant", [&]() -> std::string {
    const CreateTenantRequest request{context(), acme, std::optional<std::string>{"Acme Facility"},
                                      std::optional<PrincipalId>{principal.value()}, TenancyMetadata{}};
    const auto outcome = registry.create_tenant(request);
    if (!outcome) {
      return "refused: " + describe(outcome.error());
    }
    if (outcome.value().receipt.operation != OperationKind::CreateTenant) {
      return "the receipt does not name create_tenant";
    }
    if (outcome.value().receipt.generation.value() != 1 || outcome.value().receipt.revision.value() != 1) {
      return "the receipt does not report generation 1 and revision 1";
    }
    if (outcome.value().receipt.replayed) {
      return "a first commit was reported as a replay";
    }
    if (outcome.value().record.state != LifecycleState::Declared) {
      return "a new tenant is not declared";
    }
    return {};
  });

  battery.check("create-tenant-duplicate", [&]() -> std::string {
    const CreateTenantRequest request{context(), acme, std::optional<std::string>{"Acme Facility"},
                                      std::optional<PrincipalId>{principal.value()}, TenancyMetadata{}};
    const auto outcome = registry.create_tenant(request);
    if (outcome) {
      return "a duplicate tenant was accepted";
    }
    if (outcome.error().code() != ErrorCode::IdentityAlreadyExists) {
      return "the refusal was " + describe(outcome.error());
    }
    return {};
  });

  battery.check("find-tenant", [&]() -> std::string {
    const auto found = registry.find_tenant(acme);
    if (!found) {
      return "refused: " + describe(found.error());
    }
    if (!found.value().display_name.has_value() || *found.value().display_name != "Acme Facility") {
      return "the display name was not preserved";
    }
    if (!found.value().owner.has_value() || *found.value().owner != principal.value()) {
      return "the owner was not preserved";
    }
    return {};
  });

  battery.check("transition-refusals", [&]() -> std::string {
    const TransitionSubjectRequest illegal{context(), TenancySubject::of_tenant(acme), RecordRevision::from_value(1),
                                           LifecycleState::Suspended};
    const auto illegal_outcome = registry.transition_subject(illegal);
    if (illegal_outcome) {
      return "an illegal transition was accepted";
    }
    if (illegal_outcome.error().code() != ErrorCode::LifecycleTransitionIllegal) {
      return "the illegal transition refusal was " + describe(illegal_outcome.error());
    }
    const TransitionSubjectRequest stale{
        MutationContext{RegistryGeneration::from_value(registry.generation().value() - 1U), std::nullopt, actor},
        TenancySubject::of_tenant(acme), RecordRevision::from_value(1), LifecycleState::Active};
    const auto stale_outcome = registry.transition_subject(stale);
    if (stale_outcome) {
      return "a stale generation was accepted";
    }
    if (stale_outcome.error().code() != ErrorCode::StaleGeneration) {
      return "the stale generation refusal was " + describe(stale_outcome.error());
    }
    const TransitionSubjectRequest wrong_revision{context(), TenancySubject::of_tenant(acme),
                                                  RecordRevision::from_value(9), LifecycleState::Active};
    const auto revision_outcome = registry.transition_subject(wrong_revision);
    if (revision_outcome) {
      return "a stale revision was accepted";
    }
    if (revision_outcome.error().code() != ErrorCode::StaleRecordRevision) {
      return "the stale revision refusal was " + describe(revision_outcome.error());
    }
    return {};
  });

  battery.check("transition-active", [&]() -> std::string {
    const TransitionSubjectRequest request{context(), TenancySubject::of_tenant(acme), RecordRevision::from_value(1),
                                           LifecycleState::Active};
    const auto outcome = registry.transition_subject(request);
    if (!outcome) {
      return "refused: " + describe(outcome.error());
    }
    if (subject_state(outcome.value().record) != LifecycleState::Active) {
      return "the record is not active";
    }
    if (subject_revision(outcome.value().record).value() != 2) {
      return "the record revision did not advance to 2";
    }
    return {};
  });

  battery.check("set-and-clear-owner", [&]() -> std::string {
    const auto ops = PrincipalId::create("ops");
    if (!ops) {
      return "the owner principal could not be created";
    }
    const SetOwnerRequest set{context(), acme, RecordRevision::from_value(2), std::optional<PrincipalId>{ops.value()}};
    const auto set_outcome = registry.set_owner(set);
    if (!set_outcome) {
      return "the owner could not be set: " + describe(set_outcome.error());
    }
    const auto with_owner = registry.find_tenant(acme);
    if (!with_owner || !with_owner.value().owner.has_value() || *with_owner.value().owner != ops.value()) {
      return "the owner was not recorded";
    }
    const SetOwnerRequest clear{context(), acme, RecordRevision::from_value(3), std::nullopt};
    const auto clear_outcome = registry.set_owner(clear);
    if (!clear_outcome) {
      return "the owner could not be cleared: " + describe(clear_outcome.error());
    }
    const auto without_owner = registry.find_tenant(acme);
    if (!without_owner || without_owner.value().owner.has_value()) {
      return "the owner was not cleared";
    }
    return {};
  });

  battery.check("metadata-put-and-remove", [&]() -> std::string {
    const auto tier_key = MetadataKey::create("tier");
    const auto region_key = MetadataKey::create("region");
    auto tier_value = MetadataValue::text("gold", kLimits.max_metadata_value_bytes);
    auto region_value = MetadataValue::text("lab-1", kLimits.max_metadata_value_bytes);
    if (!tier_key || !region_key || !tier_value || !region_value) {
      return "the metadata pair could not be created";
    }
    std::vector<MetadataEntry> puts;
    puts.push_back(MetadataEntry{tier_key.value(), std::move(tier_value).value()});
    puts.push_back(MetadataEntry{region_key.value(), std::move(region_value).value()});
    const SetMetadataRequest request{context(), TenancySubject::of_tenant(acme), RecordRevision::from_value(4), {},
                                     puts};
    const auto outcome = registry.set_metadata(request);
    if (!outcome) {
      return "the metadata could not be set: " + describe(outcome.error());
    }
    if (subject_revision(outcome.value().record).value() != 5) {
      return "the record revision did not advance to 5";
    }
    std::vector<MetadataKey> removals;
    removals.push_back(region_key.value());
    const SetMetadataRequest removal{context(), TenancySubject::of_tenant(acme), RecordRevision::from_value(5),
                                     removals, {}};
    const auto removed = registry.set_metadata(removal);
    if (!removed) {
      return "the metadata could not be removed: " + describe(removed.error());
    }
    const auto* tenant = std::get_if<TenantRecord>(&removed.value().record);
    if (tenant == nullptr) {
      return "the outcome is not a tenant record";
    }
    if (tenant->metadata.size() != 1 || !tenant->metadata.contains(tier_key.value())) {
      return "the metadata set is not the expected one";
    }
    const MetadataValue absent = tenant->metadata.find(region_key.value());
    if (absent.kind() != MetadataKind::Unknown) {
      return "an absent metadata key does not read back as unknown";
    }
    return {};
  });

  battery.check("create-service-and-bind", [&]() -> std::string {
    const CreateServiceRequest create{context(), renderer, std::optional<std::string>{"Renderer"}, TenancyMetadata{}};
    const auto created = registry.create_service(create);
    if (!created) {
      return "the service could not be created: " + describe(created.error());
    }
    const TransitionSubjectRequest activate{context(), TenancySubject::of_service(renderer),
                                            RecordRevision::from_value(1), LifecycleState::Active};
    if (const auto activated = registry.transition_subject(activate); !activated) {
      return "the service could not be activated: " + describe(activated.error());
    }
    const PutServiceBindingRequest binding{context(), renderer, acme, BindingKind::Serves, LifecycleState::Active,
                                           std::nullopt};
    const auto bound = registry.put_service_binding(binding);
    if (!bound) {
      return "the binding could not be declared: " + describe(bound.error());
    }
    if (bound.value().binding.state != LifecycleState::Active) {
      return "the binding is not active";
    }
    const PutServiceBindingRequest duplicate{context(), renderer, acme, BindingKind::Serves,
                                             LifecycleState::Active, std::nullopt};
    const auto refused = registry.put_service_binding(duplicate);
    if (refused) {
      return "a duplicate binding was accepted";
    }
    if (refused.error().code() != ErrorCode::DuplicateRelationship) {
      return "the duplicate binding refusal was " + describe(refused.error());
    }
    return {};
  });

  battery.check("domains-and-membership", [&]() -> std::string {
    const CreateIsolationDomainRequest first{context(), zone_a, IsolationClass::FaultContainment, std::nullopt,
                                             TenancyMetadata{}};
    const auto created_a = registry.create_isolation_domain(first);
    if (!created_a) {
      return "the first domain could not be created: " + describe(created_a.error());
    }
    if (created_a.value().record.membership_generation.value() != 0) {
      return "a new domain does not start at membership generation 0";
    }
    const CreateIsolationDomainRequest second{context(), zone_b, IsolationClass::Administrative, std::nullopt,
                                              TenancyMetadata{}};
    const auto created_b = registry.create_isolation_domain(second);
    if (!created_b) {
      return "the second domain could not be created: " + describe(created_b.error());
    }
    const TransitionSubjectRequest activate_a{context(), TenancySubject::of_isolation_domain(zone_a),
                                              RecordRevision::from_value(1), LifecycleState::Active};
    if (const auto activated = registry.transition_subject(activate_a); !activated) {
      return "the first domain could not be activated: " + describe(activated.error());
    }
    const TransitionSubjectRequest activate_b{context(), TenancySubject::of_isolation_domain(zone_b),
                                              RecordRevision::from_value(1), LifecycleState::Active};
    if (const auto activated = registry.transition_subject(activate_b); !activated) {
      return "the second domain could not be activated: " + describe(activated.error());
    }
    const PutIsolationMembershipRequest membership{context(), TenancySubject::of_tenant(acme), zone_a,
                                                   MembershipRole::Primary, MembershipState::Bound,
                                                   DomainGeneration::from_value(0), std::nullopt};
    const auto bound = registry.put_isolation_membership(membership);
    if (!bound) {
      return "the membership could not be declared: " + describe(bound.error());
    }
    if (bound.value().domain_generation.value() != 1) {
      return "the domain generation did not advance to 1";
    }
    const PutIsolationMembershipRequest stale{context(), TenancySubject::of_tenant(acme), zone_a,
                                              MembershipRole::Secondary, MembershipState::Bound,
                                              DomainGeneration::from_value(0), std::nullopt};
    const auto stale_outcome = registry.put_isolation_membership(stale);
    if (stale_outcome) {
      return "a stale domain generation was accepted";
    }
    if (stale_outcome.error().code() != ErrorCode::StaleDomainGeneration) {
      return "the stale domain generation refusal was " + describe(stale_outcome.error());
    }
    const PutIsolationMembershipRequest conflict{context(), TenancySubject::of_tenant(acme), zone_b,
                                                 MembershipRole::Primary, MembershipState::Bound,
                                                 DomainGeneration::from_value(0), std::nullopt};
    const auto conflict_outcome = registry.put_isolation_membership(conflict);
    if (conflict_outcome) {
      return "a second in-force primary membership was accepted";
    }
    if (conflict_outcome.error().code() != ErrorCode::MembershipRoleConflict) {
      return "the primary role conflict refusal was " + describe(conflict_outcome.error());
    }
    const auto domains = registry.isolation_domains_of(TenancySubject::of_tenant(acme));
    if (!domains) {
      return "the isolation domains could not be read: " + describe(domains.error());
    }
    if (domains.value().size() != 1 || !(domains.value().front() == zone_a)) {
      return "the in-force isolation domain set is not the expected one";
    }
    const auto members = registry.members_of(zone_a, 8);
    if (!members) {
      return "the members could not be read: " + describe(members.error());
    }
    if (members.value().size() != 1 || !(members.value().front() == TenancySubject::of_tenant(acme))) {
      return "the in-force member set is not the expected one";
    }
    return {};
  });

  battery.check("ownership-tree", [&]() -> std::string {
    const CreateTenantRequest create{context(), team, std::optional<std::string>{"Team"}, std::nullopt,
                                     TenancyMetadata{}};
    const auto created = registry.create_tenant(create);
    if (!created) {
      return "the child tenant could not be created: " + describe(created.error());
    }
    const TransitionSubjectRequest activate{context(), TenancySubject::of_tenant(team),
                                            RecordRevision::from_value(1), LifecycleState::Active};
    if (const auto activated = registry.transition_subject(activate); !activated) {
      return "the child tenant could not be activated: " + describe(activated.error());
    }
    const PutOwnershipRequest edge{context(), team, acme, OwnershipKind::Administrative, LifecycleState::Active,
                                   std::nullopt};
    const auto put = registry.put_ownership(edge);
    if (!put) {
      return "the ownership edge could not be declared: " + describe(put.error());
    }
    const PutOwnershipRequest itself{context(), acme, acme, OwnershipKind::Administrative, LifecycleState::Active,
                                     std::nullopt};
    const auto self = registry.put_ownership(itself);
    if (self) {
      return "a self owning tenant was accepted";
    }
    if (self.error().code() != ErrorCode::SelfReference) {
      return "the self reference refusal was " + describe(self.error());
    }
    const PutOwnershipRequest cycle{context(), acme, team, OwnershipKind::Administrative, LifecycleState::Active,
                                    std::nullopt};
    const auto cyclic = registry.put_ownership(cycle);
    if (cyclic) {
      return "an ownership cycle was accepted";
    }
    if (cyclic.error().code() != ErrorCode::OwnershipCycle) {
      return "the ownership cycle refusal was " + describe(cyclic.error());
    }
    return {};
  });

  battery.check("traversal", [&]() -> std::string {
    const OwnershipTraversalRequest ancestors{team, TraversalDirection::Ancestors, std::nullopt, std::nullopt, 0, 0};
    const auto walked = registry.traverse_ownership(ancestors);
    if (!walked) {
      return "the ancestor walk was refused: " + describe(walked.error());
    }
    if (walked.value().reached.size() != 1 || !(walked.value().reached.front() == acme)) {
      return "the ancestor walk did not reach the parent";
    }
    if (walked.value().steps.size() != 1 || walked.value().steps.front().depth != 1) {
      return "the ancestor walk did not report one step at depth 1";
    }
    const OwnershipTraversalRequest descendants{acme, TraversalDirection::Descendants, std::nullopt, std::nullopt, 0,
                                                0};
    const auto down = registry.traverse_ownership(descendants);
    if (!down) {
      return "the descendant walk was refused: " + describe(down.error());
    }
    if (down.value().reached.size() != 1 || !(down.value().reached.front() == team)) {
      return "the descendant walk did not reach the child";
    }
    return {};
  });

  battery.check("explain", [&]() -> std::string {
    const auto explained = registry.explain(TenancySubject::of_tenant(team));
    if (!explained) {
      return "the explanation was refused: " + describe(explained.error());
    }
    if (explained.value().ownership_lineage.size() != 1 ||
        !(explained.value().ownership_lineage.front() == acme)) {
      return "the lineage does not name the parent";
    }
    if (explained.value().digest().is_zero()) {
      return "the explanation digest is the zero digest";
    }
    if (explained.value().unknowns.empty()) {
      return "an incomplete record reported no unknowns";
    }
    return {};
  });

  battery.check("idempotency", [&]() -> std::string {
    const auto key = IdempotencyKey::create("self-check-key-1");
    if (!key) {
      return "the idempotency key could not be created";
    }
    const auto extra = TenantId::create("extra");
    if (!extra) {
      return "the extra tenant identity could not be created";
    }
    const CreateTenantRequest request{
        MutationContext{registry.generation(), std::optional<IdempotencyKey>{key.value()}, actor}, extra.value(),
        std::optional<std::string>{"Extra"}, std::nullopt, TenancyMetadata{}};
    const auto first = registry.create_tenant(request);
    if (!first) {
      return "the keyed create was refused: " + describe(first.error());
    }
    const auto replay = registry.create_tenant(request);
    if (!replay) {
      return "the replay was refused: " + describe(replay.error());
    }
    if (!replay.value().receipt.replayed) {
      return "the replay was not reported as a replay";
    }
    if (replay.value().receipt.generation.value() != first.value().receipt.generation.value()) {
      return "the replay reported a different generation than the original";
    }
    const auto other = TenantId::create("other");
    if (!other) {
      return "the other tenant identity could not be created";
    }
    const CreateTenantRequest conflicting{
        MutationContext{registry.generation(), std::optional<IdempotencyKey>{key.value()}, actor}, other.value(),
        std::nullopt, std::nullopt, TenancyMetadata{}};
    const auto reused = registry.create_tenant(conflicting);
    if (reused) {
      return "a different request under an existing key was accepted";
    }
    if (reused.error().code() != ErrorCode::IdempotencyKeyReused) {
      return "the reused key refusal was " + describe(reused.error());
    }
    return {};
  });

  battery.check("stats-and-restatements", [&]() -> std::string {
    const RegistryStats stats = registry.stats();
    if (stats.tenants != 3 || stats.services != 1 || stats.isolation_domains != 2) {
      return "the record counts are not the expected ones";
    }
    if (stats.ownership_edges != 1 || stats.service_bindings != 1 || stats.isolation_memberships != 1) {
      return "the relationship counts are not the expected ones";
    }
    if (stats.generation.value() != registry.generation().value()) {
      return "the statistics generation is not the session generation";
    }
    const RegistrySnapshot first = registry.snapshot();
    const RegistrySnapshot second = registry.snapshot();
    if (first.to_canonical_bytes() != second.to_canonical_bytes()) {
      return "two snapshots of one state did not encode identically";
    }
    if (!(first.digest() == second.digest())) {
      return "two snapshots of one state did not digest identically";
    }
    const auto exported = registry.export_json();
    if (!exported) {
      return "the export was refused: " + describe(exported.error());
    }
    const auto exported_again = registry.export_json();
    if (!exported_again || exported.value() != exported_again.value()) {
      return "two exports of one state did not render identically";
    }
    if (exported.value().empty() || exported.value().front() != '{') {
      return "the export is not a JSON object";
    }
    return {};
  });

  battery.check("tombstone", [&]() -> std::string {
    // A tenant that still has an ownership edge may not begin retirement, so
    // the fencing walk is run against an identity that has no relationships at
    // all: the refusal for a tenant that does is checked below.
    const auto fenced_result = TenantId::create("fenced");
    if (!fenced_result) {
      return "the identity to fence could not be created";
    }
    const TenantId fenced = fenced_result.value();
    const CreateTenantRequest create{context(), fenced, std::optional<std::string>{"Fenced"}, std::nullopt,
                                     TenancyMetadata{}};
    if (const auto created = registry.create_tenant(create); !created) {
      return "the identity to fence could not be registered: " + describe(created.error());
    }
    const TombstoneRequest missing_ack{context(), TenancySubject::of_tenant(fenced), RecordRevision::from_value(1),
                                       IrreversibleAcknowledgement{}, std::nullopt, std::string{"fenced"}};
    const auto unacknowledged = registry.tombstone(missing_ack);
    if (unacknowledged) {
      return "an unacknowledged tombstone was accepted";
    }
    if (unacknowledged.error().code() != ErrorCode::IrreversibleActionNotAcknowledged) {
      return "the unacknowledged refusal was " + describe(unacknowledged.error());
    }
    const TransitionSubjectRequest blocked{context(), TenancySubject::of_tenant(team), RecordRevision::from_value(2),
                                           LifecycleState::Retiring};
    const auto declined = registry.transition_subject(blocked);
    if (declined) {
      return "a tenant that still has relationships was allowed to begin retirement";
    }
    if (declined.error().code() != ErrorCode::HasLiveDependents) {
      return "the live dependent refusal was " + describe(declined.error());
    }
    const TransitionSubjectRequest activate{context(), TenancySubject::of_tenant(fenced),
                                            RecordRevision::from_value(1), LifecycleState::Active};
    if (const auto activated = registry.transition_subject(activate); !activated) {
      return "the identity to fence could not be activated: " + describe(activated.error());
    }
    const TransitionSubjectRequest retiring{context(), TenancySubject::of_tenant(fenced), RecordRevision::from_value(2),
                                            LifecycleState::Retiring};
    if (const auto started = registry.transition_subject(retiring); !started) {
      return "the identity could not begin retirement: " + describe(started.error());
    }
    const TransitionSubjectRequest retired{context(), TenancySubject::of_tenant(fenced), RecordRevision::from_value(3),
                                           LifecycleState::Retired};
    if (const auto withdrawn = registry.transition_subject(retired); !withdrawn) {
      return "the identity could not be retired: " + describe(withdrawn.error());
    }
    const TombstoneRequest request{context(), TenancySubject::of_tenant(fenced), RecordRevision::from_value(4),
                                   IrreversibleAcknowledgement::acknowledged(), std::nullopt,
                                   std::string{"fenced forever"}};
    const auto outcome = registry.tombstone(request);
    if (!outcome) {
      return "the tombstone was refused: " + describe(outcome.error());
    }
    if (subject_state(outcome.value().record) != LifecycleState::Tombstoned) {
      return "the record is not tombstoned";
    }
    const auto found = registry.find_tombstone(SubjectKind::Tenant, fenced.value());
    if (!found) {
      return "the tombstone could not be read back: " + describe(found.error());
    }
    if (found.value().note != "fenced forever") {
      return "the tombstone note was not preserved";
    }
    if (found.value().kind != SubjectKind::Tenant || found.value().identity != fenced.value()) {
      return "the tombstone does not name the fenced identity";
    }
    const auto absent = registry.find_tombstone(SubjectKind::Tenant, acme.value());
    if (absent) {
      return "an identity that was never tombstoned reported a tombstone";
    }
    if (absent.error().code() != ErrorCode::NotFound) {
      return "the absent tombstone refusal was " + describe(absent.error());
    }
    return {};
  });

  battery.check("tombstone-rebind", [&]() -> std::string {
    // A rebind permit is the one way a fenced identity can be taken over, and
    // consuming it moves the tombstone to its permanent key. Both halves of that
    // are checked here, because a permit that survives a restart as consumed is
    // the difference between "fenced forever" and "fenced forever, once".
    const auto rebound_result = TenantId::create("rebound");
    if (!rebound_result) {
      return "the identity to rebind could not be created";
    }
    const TenantId rebound = rebound_result.value();
    const CreateTenantRequest create{context(), rebound, std::optional<std::string>{"Rebound"}, std::nullopt,
                                     TenancyMetadata{}};
    if (const auto created = registry.create_tenant(create); !created) {
      return "the identity to rebind could not be registered: " + describe(created.error());
    }
    const TransitionSubjectRequest activate{context(), TenancySubject::of_tenant(rebound),
                                            RecordRevision::from_value(1), LifecycleState::Active};
    if (const auto activated = registry.transition_subject(activate); !activated) {
      return "the identity to rebind could not be activated: " + describe(activated.error());
    }
    const TransitionSubjectRequest retiring{context(), TenancySubject::of_tenant(rebound),
                                            RecordRevision::from_value(2), LifecycleState::Retiring};
    if (const auto started = registry.transition_subject(retiring); !started) {
      return "the identity could not begin retirement: " + describe(started.error());
    }
    const TransitionSubjectRequest retired{context(), TenancySubject::of_tenant(rebound),
                                           RecordRevision::from_value(3), LifecycleState::Retired};
    if (const auto withdrawn = registry.transition_subject(retired); !withdrawn) {
      return "the identity could not be retired: " + describe(withdrawn.error());
    }
    const RebindSuccessor successor{SubjectKind::Tenant, rebound.value()};
    const TombstoneRequest fence{context(), TenancySubject::of_tenant(rebound), RecordRevision::from_value(4),
                                 IrreversibleAcknowledgement::acknowledged(),
                                 std::optional<RebindSuccessor>{successor}, std::string{"successor permitted"}};
    const auto fenced = registry.tombstone(fence);
    if (!fenced) {
      return "the tombstone with a rebind permit was refused: " + describe(fenced.error());
    }
    const CreateTenantRequest reuse{context(), rebound, std::optional<std::string>{"Rebound Two"}, std::nullopt,
                                    TenancyMetadata{}};
    const auto reused = registry.create_tenant(reuse);
    if (!reused) {
      return "the permitted successor could not take the identity: " + describe(reused.error());
    }
    if (reused.value().record.state != LifecycleState::Declared) {
      return "the successor record is not declared";
    }
    const auto permanent = registry.find_tombstone(SubjectKind::Tenant, rebound.value());
    if (!permanent) {
      return "the permanent tombstone could not be read back: " + describe(permanent.error());
    }
    if (!permanent.value().permit.has_value() || !permanent.value().permit->consumed()) {
      return "the permanent tombstone does not record a consumed permit";
    }
    const CreateTenantRequest again{context(), rebound, std::nullopt, std::nullopt, TenancyMetadata{}};
    const auto refused = registry.create_tenant(again);
    if (refused) {
      return "a second takeover of a live identity was accepted";
    }
    if (refused.error().code() != ErrorCode::IdentityAlreadyExists) {
      return "the second takeover refusal was " + describe(refused.error());
    }
    return {};
  });
}

void battery_durable(Battery& battery, const std::filesystem::path& root) {
  const std::filesystem::path store_root = root / "store";
  const auto source = SourceId::create("self-check");
  const auto principal = PrincipalId::create("self-check-principal");
  const auto tenant_result = TenantId::create("durable-acme");
  if (!source || !principal || !tenant_result) {
    battery.check("durable-identities", false, "the durable battery identities could not be created");
    return;
  }
  auto created_actor = ProvenanceRecord::create(ProvenanceSource::TestFixture, source.value(), principal.value(),
                                                std::nullopt, std::string{},
                                                kLimits.max_provenance_note_bytes);
  if (!created_actor) {
    battery.check("durable-actor", false, describe(created_actor.error()));
    return;
  }
  const ProvenanceRecord actor = std::move(created_actor).value();
  const TenantId durable_acme = tenant_result.value();

  const auto open_store = [&store_root](AccessMode mode) {
    RegistryOpenRequest request;
    request.root = store_root;
    request.mode = mode;
    request.store.limits = kLimits;
    request.store.holder_note = "treg self-check";
    return TenantRegistry::open(request);
  };

  std::optional<TenantRegistry> writer;
  std::optional<ContentDigest> written_digest;

  battery.check("durable-create", [&]() -> std::string {
    auto opened = open_store(AccessMode::ReadWrite);
    if (!opened) {
      return "the durable registry could not be created: " + describe(opened.error());
    }
    writer.emplace(std::move(opened).value());
    const StoreRecoveryReport report = writer->recovery_report();
    if (!report.store_created) {
      return "a store that did not exist was not reported as created";
    }
    if (!writer->durable() || !writer->store_identity().has_value()) {
      return "a durable session reports no store identity";
    }
    if (writer->generation().value() != 0) {
      return "a new store does not start at generation 0";
    }
    return {};
  });

  if (writer.has_value()) {
    battery.check("durable-mutate", [&]() -> std::string {
      const CreateTenantRequest request{
          MutationContext{writer->generation(), std::nullopt, actor}, durable_acme,
          std::optional<std::string>{"Durable Acme"}, std::nullopt, TenancyMetadata{}};
      const auto outcome = writer->create_tenant(request);
      if (!outcome) {
        return "the durable create was refused: " + describe(outcome.error());
      }
      if (outcome.value().receipt.generation.value() != 1) {
        return "the first durable commit is not generation 1";
      }
      return {};
    });

    battery.check("durable-writer-locked", [&]() -> std::string {
      auto second = open_store(AccessMode::ReadWrite);
      if (second) {
        return "a second writer took a store that was already held";
      }
      if (second.error().code() != ErrorCode::StoreLocked) {
        return "the second writer refusal was " + describe(second.error());
      }
      return {};
    });

    battery.check("durable-compact", [&]() -> std::string {
      const Status compacted = writer->compact();
      if (!compacted.ok()) {
        return "the compaction was refused: " + describe(compacted.error());
      }
      if (writer->generation().value() != 1) {
        return "the compaction changed the generation";
      }
      written_digest = writer->snapshot().digest();
      return {};
    });

    battery.check("durable-close", [&]() -> std::string {
      const Status closed = writer->close();
      if (!closed.ok()) {
        return "the session could not be closed: " + describe(closed.error());
      }
      return {};
    });
    writer.reset();
  }

  battery.check("durable-reopen-read-only", [&]() -> std::string {
    auto reopened = open_store(AccessMode::ReadOnly);
    if (!reopened) {
      return "the store could not be reopened read-only: " + describe(reopened.error());
    }
    TenantRegistry reader = std::move(reopened).value();
    const StoreRecoveryReport report = reader.recovery_report();
    if (!report.read_only) {
      return "the recovery report does not mark the session read-only";
    }
    if (report.uncommitted_tail_discarded || report.uncommitted_bytes_discarded != 0) {
      return "the reopened store reported a discarded tail";
    }
    if (report.committed_generation.value() != 1) {
      return "the reopened store is not at generation 1";
    }
    if (!report.manifest_present) {
      return "the reopened store reports no manifest";
    }
    if (report.frames_replayed == 0) {
      return "the reopened store replayed no frames";
    }
    const auto found = reader.find_tenant(durable_acme);
    if (!found) {
      return "the durable tenant did not survive the reopen: " + describe(found.error());
    }
    if (found.value().state != LifecycleState::Declared) {
      return "the durable tenant did not survive with its state";
    }
    if (written_digest.has_value() && !(reader.snapshot().digest() == *written_digest)) {
      return "the state changed across compaction and reopen";
    }
    const CreateTenantRequest forbidden{
        MutationContext{reader.generation(), std::nullopt, actor}, durable_acme,
        std::optional<std::string>{"Durable Acme"}, std::nullopt, TenancyMetadata{}};
    const auto refused = reader.create_tenant(forbidden);
    if (refused) {
      return "a read-only session accepted a mutation";
    }
    if (refused.error().error_class() != ErrorClass::Store) {
      return "the read-only refusal is not a store class refusal: " + describe(refused.error());
    }
    const Status closed = reader.close();
    if (!closed.ok()) {
      return "the read-only session could not be closed: " + describe(closed.error());
    }
    return {};
  });
}

[[nodiscard]] int run_self_check(const std::optional<std::filesystem::path>& scratch_parent, bool quiet,
                                 std::string& out) {
  Battery battery{out};
  battery_parsing(battery);

  {
    auto opened = TenantRegistry::open_ephemeral(EphemeralOptions{});
    if (!opened) {
      battery.check("ephemeral-open", false, describe(opened.error()));
    } else {
      battery.check("ephemeral-open", true, {});
      TenantRegistry registry = std::move(opened).value();
      battery_ephemeral(battery, registry);
      const Status closed = registry.close();
      battery.check("ephemeral-close", closed.ok(), closed.ok() ? std::string_view{} : describe(closed.error()));
    }
  }

  std::optional<std::filesystem::path> scratch_path;
  {
    std::string error;
    std::optional<ScratchDirectory> scratch = ScratchDirectory::create(scratch_parent, error);
    if (!scratch.has_value()) {
      battery.check("scratch-directory", false, error);
    } else {
      battery.check("scratch-directory", true, {});
      scratch_path = scratch->path();
      battery_durable(battery, scratch->path());
    }
  }
  std::error_code cleanup_code;
  const bool cleaned = !scratch_path.has_value() || !std::filesystem::exists(*scratch_path, cleanup_code);
  battery.check("scratch-cleaned", cleaned, "a temporary directory was left behind");

  return battery.finish(quiet);
}

// ---------------------------------------------------------------------------
// The scenario
// ---------------------------------------------------------------------------

/// Prints the transcript. Every line is a function of the steps that ran, and
/// no step ever prints a path, a clock reading or a minted identity.
class Scenario {
 public:
  Scenario(std::string& out, bool quiet) : out_(&out), quiet_(quiet) {}

  void step(std::string_view text) {
    if (quiet_) {
      return;
    }
    out_->append("scenario: ");
    out_->append(text);
    out_->push_back('\n');
  }

  void result(std::string_view text) {
    out_->append("scenario: ");
    out_->append(text);
    out_->push_back('\n');
  }

 private:
  std::string* out_;
  bool quiet_;
};

struct StepOutcome {
  bool ok = false;
  std::string text;
};

[[nodiscard]] StepOutcome step_ok(std::string text) { return StepOutcome{true, std::move(text)}; }

[[nodiscard]] StepOutcome step_failed(const Error& error) { return StepOutcome{false, describe(error)}; }

[[nodiscard]] int run_scenario(const std::optional<std::filesystem::path>& scratch_parent, bool quiet,
                               std::string& out) {
  Scenario scenario{out, quiet};
  scenario.step("begin");
  scenario.step("registry: ephemeral");

  auto opened = TenantRegistry::open_ephemeral(EphemeralOptions{});
  if (!opened) {
    scenario.result("failed: the ephemeral registry could not be opened: " + describe(opened.error()));
    return kExitRefusal;
  }
  TenantRegistry registry = std::move(opened).value();

  const auto source = SourceId::create("cli-scenario");
  const auto principal = PrincipalId::create("scenario-operator");
  if (!source || !principal) {
    scenario.result("failed: the scenario actor could not be created");
    return kExitRefusal;
  }
  auto created_actor = ProvenanceRecord::create(ProvenanceSource::TestFixture, source.value(), principal.value(),
                                                std::nullopt, std::string{},
                                                kLimits.max_provenance_note_bytes);
  if (!created_actor) {
    scenario.result("failed: the scenario actor could not be created: " + describe(created_actor.error()));
    return kExitRefusal;
  }
  const ProvenanceRecord actor = std::move(created_actor).value();
  const auto context = [&registry, &actor]() { return MutationContext{registry.generation(), std::nullopt, actor}; };

  /// Runs one step, prints its outcome and stops the scenario when it failed.
  const auto run = [&scenario](std::string_view label, const std::function<StepOutcome()>& body) {
    const StepOutcome outcome = body();
    if (outcome.ok) {
      scenario.step(std::string{label} + " -> " + outcome.text);
    } else {
      scenario.result(std::string{"failed: "} + std::string{label} + ": " + outcome.text);
    }
    return outcome.ok;
  };

  const auto create_tenant = [&](const std::string& text, const std::string& display) -> StepOutcome {
    const auto id = TenantId::create(text);
    if (!id) {
      return StepOutcome{false, describe(id.error())};
    }
    const CreateTenantRequest request{context(), id.value(), std::optional<std::string>{display},
                                      std::optional<PrincipalId>{principal.value()}, TenancyMetadata{}};
    const auto outcome = registry.create_tenant(request);
    if (!outcome) {
      return step_failed(outcome.error());
    }
    std::string text_out{"generation="};
    text_out.append(std::to_string(outcome.value().receipt.generation.value()));
    text_out.append(" revision=");
    text_out.append(std::to_string(outcome.value().receipt.revision.value()));
    text_out.append(" state=");
    text_out.append(to_token(outcome.value().record.state));
    return step_ok(std::move(text_out));
  };

  const auto activate = [&](const TenancySubject& subject) -> StepOutcome {
    const auto found = registry.find_subject(subject);
    if (!found) {
      return step_failed(found.error());
    }
    const TransitionSubjectRequest request{context(), subject, subject_revision(found.value()),
                                           LifecycleState::Active};
    const auto outcome = registry.transition_subject(request);
    if (!outcome) {
      return step_failed(outcome.error());
    }
    std::string rendered{"revision="};
    rendered.append(std::to_string(subject_revision(outcome.value().record).value()));
    rendered.append(" state=");
    rendered.append(to_token(subject_state(outcome.value().record)));
    return step_ok(std::move(rendered));
  };

  const auto activate_tenant = [&activate](const std::string& text) -> StepOutcome {
    const auto id = TenantId::create(text);
    if (!id) {
      return step_failed(id.error());
    }
    return activate(TenancySubject::of_tenant(id.value()));
  };

  const auto activate_service = [&activate](const std::string& text) -> StepOutcome {
    const auto id = ServiceId::create(text);
    if (!id) {
      return step_failed(id.error());
    }
    return activate(TenancySubject::of_service(id.value()));
  };

  const auto activate_domain = [&activate](const std::string& text) -> StepOutcome {
    const auto id = IsolationDomainId::create(text);
    if (!id) {
      return step_failed(id.error());
    }
    return activate(TenancySubject::of_isolation_domain(id.value()));
  };

  if (!run("open ephemeral registry", [&]() -> StepOutcome {
        std::string text{"generation="};
        text.append(std::to_string(registry.generation().value()));
        text.append(" durable=false");
        return step_ok(std::move(text));
      })) {
    return kExitRefusal;
  }

  const char* const tenants[4] = {"facility", "ops", "team-a", "team-b"};
  const char* const displays[4] = {"Facility", "Operations", "Team A", "Team B"};
  for (std::size_t index = 0; index < 4; ++index) {
    if (!run(std::string{"create tenant tenant:"} + tenants[index],
             [&create_tenant, &tenants, &displays, index]() { return create_tenant(tenants[index], displays[index]); })) {
      return kExitRefusal;
    }
  }
  for (const char* const tenant : tenants) {
    if (!run(std::string{"transition tenant:"} + tenant + " to active",
             [&activate_tenant, tenant]() { return activate_tenant(tenant); })) {
      return kExitRefusal;
    }
  }

  const auto facility = TenantId::create("facility").value();
  const auto team_a = TenantId::create("team-a").value();
  const auto team_b = TenantId::create("team-b").value();

  if (!run("declare tenant:team-a owned by tenant:facility", [&]() -> StepOutcome {
        const PutOwnershipRequest request{context(), team_a, facility, OwnershipKind::Administrative,
                                          LifecycleState::Active, std::nullopt};
        const auto outcome = registry.put_ownership(request);
        if (!outcome) {
          return step_failed(outcome.error());
        }
        std::string text{"revision="};
        text.append(std::to_string(outcome.value().edge.revision.value()));
        return step_ok(std::move(text));
      })) {
    return kExitRefusal;
  }
  if (!run("declare tenant:team-b owned by tenant:facility", [&]() -> StepOutcome {
        const PutOwnershipRequest request{context(), team_b, facility, OwnershipKind::Administrative,
                                          LifecycleState::Active, std::nullopt};
        const auto outcome = registry.put_ownership(request);
        if (!outcome) {
          return step_failed(outcome.error());
        }
        std::string text{"revision="};
        text.append(std::to_string(outcome.value().edge.revision.value()));
        return step_ok(std::move(text));
      })) {
    return kExitRefusal;
  }

  if (!run("annotate tenant:team-a", [&]() -> StepOutcome {
        const auto tier_key = MetadataKey::create("tier");
        const auto region_key = MetadataKey::create("region");
        auto tier_value = MetadataValue::text("gold", kLimits.max_metadata_value_bytes);
        auto region_value = MetadataValue::text("lab-1", kLimits.max_metadata_value_bytes);
        if (!tier_key || !region_key || !tier_value || !region_value) {
          return StepOutcome{false, "the metadata pair could not be created"};
        }
        std::vector<MetadataEntry> entries;
        entries.push_back(MetadataEntry{tier_key.value(), std::move(tier_value).value()});
        entries.push_back(MetadataEntry{region_key.value(), std::move(region_value).value()});
        const SetMetadataRequest request{context(), TenancySubject::of_tenant(team_a),
                                         RecordRevision::from_value(2), {}, entries};
        const auto outcome = registry.set_metadata(request);
        if (!outcome) {
          return step_failed(outcome.error());
        }
        std::string text{"revision="};
        text.append(std::to_string(subject_revision(outcome.value().record).value()));
        text.append(" entries=");
        text.append(std::to_string(std::get<TenantRecord>(outcome.value().record).metadata.size()));
        return step_ok(std::move(text));
      })) {
    return kExitRefusal;
  }

  if (!run("declare isolation_domain:zone-a", [&]() -> StepOutcome {
        const auto zone = IsolationDomainId::create("zone-a");
        if (!zone) {
          return StepOutcome{false, describe(zone.error())};
        }
        const CreateIsolationDomainRequest request{context(), zone.value(), IsolationClass::FaultContainment,
                                                   std::optional<std::string>{"Zone A"}, TenancyMetadata{}};
        const auto outcome = registry.create_isolation_domain(request);
        if (!outcome) {
          return step_failed(outcome.error());
        }
        std::string text{"class="};
        text.append(to_token(outcome.value().record.isolation_class));
        text.append(" membership_generation=");
        text.append(std::to_string(outcome.value().record.membership_generation.value()));
        return step_ok(std::move(text));
      })) {
    return kExitRefusal;
  }

  if (!run("transition isolation_domain:zone-a to active",
           [&activate_domain]() { return activate_domain("zone-a"); })) {
    return kExitRefusal;
  }

  if (!run("bind tenant:team-a into isolation_domain:zone-a", [&]() -> StepOutcome {
        const auto zone = IsolationDomainId::create("zone-a");
        if (!zone) {
          return StepOutcome{false, describe(zone.error())};
        }
        const PutIsolationMembershipRequest request{
            context(), TenancySubject::of_tenant(team_a), zone.value(), MembershipRole::Primary,
            MembershipState::Bound, DomainGeneration::from_value(0), std::nullopt};
        const auto outcome = registry.put_isolation_membership(request);
        if (!outcome) {
          return step_failed(outcome.error());
        }
        std::string text{"role="};
        text.append(to_token(outcome.value().membership.role));
        text.append(" state=");
        text.append(to_token(outcome.value().membership.state));
        text.append(" domain_generation=");
        text.append(std::to_string(outcome.value().domain_generation.value()));
        return step_ok(std::move(text));
      })) {
    return kExitRefusal;
  }

  if (!run("isolate tenant:team-a", [&]() -> StepOutcome {
        const auto domains = registry.isolation_domains_of(TenancySubject::of_tenant(team_a));
        if (!domains) {
          return step_failed(domains.error());
        }
        std::string text{"domains="};
        text.append(std::to_string(domains.value().size()));
        for (const IsolationDomainId& domain : domains.value()) {
          text.append(" ");
          text.append(identity_text(SubjectKind::IsolationDomain, domain.value()));
        }
        return step_ok(std::move(text));
      })) {
    return kExitRefusal;
  }

  if (!run("register service:renderer", [&]() -> StepOutcome {
        const auto service = ServiceId::create("renderer");
        if (!service) {
          return StepOutcome{false, describe(service.error())};
        }
        const CreateServiceRequest request{context(), service.value(), std::optional<std::string>{"Renderer"},
                                           TenancyMetadata{}};
        const auto outcome = registry.create_service(request);
        if (!outcome) {
          return step_failed(outcome.error());
        }
        std::string text{"revision="};
        text.append(std::to_string(outcome.value().record.revision.value()));
        return step_ok(std::move(text));
      })) {
    return kExitRefusal;
  }
  if (!run("transition service:renderer to active",
           [&activate_service]() { return activate_service("renderer"); })) {
    return kExitRefusal;
  }

  if (!run("bind service:renderer serves tenant:team-a", [&]() -> StepOutcome {
        const auto service = ServiceId::create("renderer");
        if (!service) {
          return StepOutcome{false, describe(service.error())};
        }
        const PutServiceBindingRequest request{context(), service.value(), team_a, BindingKind::Serves,
                                               LifecycleState::Active, std::nullopt};
        const auto outcome = registry.put_service_binding(request);
        if (!outcome) {
          return step_failed(outcome.error());
        }
        std::string text{"kind="};
        text.append(to_token(outcome.value().binding.kind));
        text.append(" state=");
        text.append(to_token(outcome.value().binding.state));
        return step_ok(std::move(text));
      })) {
    return kExitRefusal;
  }

  if (!run("traverse ancestors of tenant:team-a", [&]() -> StepOutcome {
        const OwnershipTraversalRequest request{team_a, TraversalDirection::Ancestors, std::nullopt, std::nullopt, 0,
                                                0};
        const auto walked = registry.traverse_ownership(request);
        if (!walked) {
          return step_failed(walked.error());
        }
        std::string text{"reached="};
        text.append(std::to_string(walked.value().reached.size()));
        for (const TenantId& tenant : walked.value().reached) {
          text.append(" ");
          text.append(identity_text(SubjectKind::Tenant, tenant.value()));
        }
        return step_ok(std::move(text));
      })) {
    return kExitRefusal;
  }

  if (!run("traverse descendants of tenant:facility", [&]() -> StepOutcome {
        const OwnershipTraversalRequest request{facility, TraversalDirection::Descendants, std::nullopt, std::nullopt,
                                                0, 0};
        const auto walked = registry.traverse_ownership(request);
        if (!walked) {
          return step_failed(walked.error());
        }
        std::string text{"reached="};
        text.append(std::to_string(walked.value().reached.size()));
        for (const TenantId& tenant : walked.value().reached) {
          text.append(" ");
          text.append(identity_text(SubjectKind::Tenant, tenant.value()));
        }
        return step_ok(std::move(text));
      })) {
    return kExitRefusal;
  }

  if (!run("explain tenant:team-a", [&]() -> StepOutcome {
        const auto explained = registry.explain(TenancySubject::of_tenant(team_a));
        if (!explained) {
          return step_failed(explained.error());
        }
        std::string text{"lineage="};
        text.append(std::to_string(explained.value().ownership_lineage.size()));
        text.append(" memberships=");
        text.append(std::to_string(explained.value().memberships.size()));
        text.append(" bindings=");
        text.append(std::to_string(explained.value().bindings.size()));
        text.append(" digest=");
        text.append(explained.value().digest().to_text());
        return step_ok(std::move(text));
      })) {
    return kExitRefusal;
  }

  if (!run("refuse a stale generation", [&]() -> StepOutcome {
        const auto ops = TenantId::create("ops");
        if (!ops) {
          return StepOutcome{false, describe(ops.error())};
        }
        const auto found = registry.find_tenant(ops.value());
        if (!found) {
          return step_failed(found.error());
        }
        const MutationContext stale{RegistryGeneration::from_value(registry.generation().value() - 1U),
                                    std::nullopt, actor};
        const TransitionSubjectRequest request{stale, TenancySubject::of_tenant(ops.value()),
                                               found.value().revision, LifecycleState::Active};
        const auto outcome = registry.transition_subject(request);
        if (outcome) {
          return StepOutcome{false, "a stale generation was accepted"};
        }
        if (outcome.error().code() != ErrorCode::StaleGeneration) {
          return step_failed(outcome.error());
        }
        return step_ok(std::string{"refusal="} + std::string{outcome.error().token()});
      })) {
    return kExitRefusal;
  }

  if (!run("replay a keyed create", [&]() -> StepOutcome {
        const auto key = IdempotencyKey::create("scenario-key-0001");
        const auto id = TenantId::create("team-c");
        if (!key || !id) {
          return StepOutcome{false, "the idempotency key or the tenant identity could not be created"};
        }
        const CreateTenantRequest request{
            MutationContext{registry.generation(), std::optional<IdempotencyKey>{key.value()}, actor}, id.value(),
            std::optional<std::string>{"Team C"}, std::nullopt, TenancyMetadata{}};
        const auto first = registry.create_tenant(request);
        if (!first) {
          return step_failed(first.error());
        }
        const auto replay = registry.create_tenant(request);
        if (!replay) {
          return step_failed(replay.error());
        }
        std::string text{"generation="};
        text.append(std::to_string(replay.value().receipt.generation.value()));
        text.append(" replayed=");
        text.append(replay.value().receipt.replayed ? "true" : "false");
        return step_ok(std::move(text));
      })) {
    return kExitRefusal;
  }

  if (!run("statistics", [&]() -> StepOutcome {
        const RegistryStats stats = registry.stats();
        std::string text{"tenants="};
        text.append(std::to_string(stats.tenants));
        text.append(" services=");
        text.append(std::to_string(stats.services));
        text.append(" domains=");
        text.append(std::to_string(stats.isolation_domains));
        text.append(" edges=");
        text.append(std::to_string(stats.ownership_edges));
        text.append(" bindings=");
        text.append(std::to_string(stats.service_bindings));
        text.append(" memberships=");
        text.append(std::to_string(stats.isolation_memberships));
        if (stats.tenants != 5 || stats.services != 1 || stats.isolation_domains != 1 || stats.ownership_edges != 2 ||
            stats.service_bindings != 1 || stats.isolation_memberships != 1) {
          return StepOutcome{false, "the record counts are not the expected ones: " + text};
        }
        return step_ok(std::move(text));
      })) {
    return kExitRefusal;
  }

  if (!run("snapshot", [&]() -> StepOutcome {
        const RegistrySnapshot snapshot = registry.snapshot();
        const RegistrySnapshot again = registry.snapshot();
        if (!(snapshot.digest() == again.digest()) || snapshot.to_canonical_bytes() != again.to_canonical_bytes()) {
          return StepOutcome{false, "two snapshots of one state did not agree"};
        }
        std::string text{"records="};
        text.append(std::to_string(snapshot.record_count()));
        text.append(" digest=");
        text.append(snapshot.digest().to_text());
        return step_ok(std::move(text));
      })) {
    return kExitRefusal;
  }

  if (!run("export", [&]() -> StepOutcome {
        const auto exported = registry.export_json();
        if (!exported) {
          return step_failed(exported.error());
        }
        std::string text{"bytes="};
        text.append(std::to_string(exported.value().size()));
        return step_ok(std::move(text));
      })) {
    return kExitRefusal;
  }

  if (!run("compact", [&]() -> StepOutcome {
        const Status compacted = registry.compact();
        if (!compacted.ok()) {
          return step_failed(compacted.error());
        }
        return step_ok(std::string{"generation="} + std::to_string(registry.generation().value()));
      })) {
    return kExitRefusal;
  }

  const Status ephemeral_closed = registry.close();
  if (!run("close ephemeral registry", [&ephemeral_closed]() -> StepOutcome {
        if (!ephemeral_closed.ok()) {
          return step_failed(ephemeral_closed.error());
        }
        return step_ok("closed");
      })) {
    return kExitRefusal;
  }

  std::string scratch_error;
  std::optional<ScratchDirectory> scratch = ScratchDirectory::create(scratch_parent, scratch_error);
  if (!scratch.has_value()) {
    scenario.result("failed: " + scratch_error);
    return kExitRefusal;
  }

  const std::filesystem::path store_root = scratch->path() / "store";
  const auto open_store = [&store_root](AccessMode mode) {
    RegistryOpenRequest request;
    request.root = store_root;
    request.mode = mode;
    request.store.limits = kLimits;
    request.store.holder_note = "treg scenario";
    return TenantRegistry::open(request);
  };

  std::optional<TenantRegistry> writer;
  std::optional<ContentDigest> digest_before_close;

  if (!run("create durable registry", [&]() -> StepOutcome {
        auto durable = open_store(AccessMode::ReadWrite);
        if (!durable) {
          return step_failed(durable.error());
        }
        writer.emplace(std::move(durable).value());
        const StoreRecoveryReport report = writer->recovery_report();
        std::string text{"created="};
        text.append(report.store_created ? "true" : "false");
        text.append(" generation=");
        text.append(std::to_string(writer->generation().value()));
        if (!report.store_created) {
          return StepOutcome{false, "a store that did not exist was not reported as created"};
        }
        return step_ok(std::move(text));
      })) {
    return kExitRefusal;
  }

  if (!run("write to the durable registry", [&]() -> StepOutcome {
        const auto id = TenantId::create("durable-team");
        if (!id) {
          return StepOutcome{false, describe(id.error())};
        }
        const CreateTenantRequest request{
            MutationContext{writer->generation(), std::nullopt, actor}, id.value(),
            std::optional<std::string>{"Durable Team"}, std::nullopt, TenancyMetadata{}};
        const auto outcome = writer->create_tenant(request);
        if (!outcome) {
          return step_failed(outcome.error());
        }
        std::string text{"generation="};
        text.append(std::to_string(outcome.value().receipt.generation.value()));
        text.append(" revision=");
        text.append(std::to_string(outcome.value().receipt.revision.value()));
        return step_ok(std::move(text));
      })) {
    return kExitRefusal;
  }

  digest_before_close = writer->snapshot().digest();

  const Status durable_closed = writer->close();
  if (!run("close the durable registry", [&durable_closed]() -> StepOutcome {
        if (!durable_closed.ok()) {
          return step_failed(durable_closed.error());
        }
        return step_ok("closed");
      })) {
    return kExitRefusal;
  }
  writer.reset();

  if (!run("re-open the durable registry read-only", [&]() -> StepOutcome {
        auto reopened = open_store(AccessMode::ReadOnly);
        if (!reopened) {
          return step_failed(reopened.error());
        }
        TenantRegistry reader = std::move(reopened).value();
        const StoreRecoveryReport report = reader.recovery_report();
        const ContentDigest digest = reader.snapshot().digest();
        const bool consistent = digest_before_close.has_value() && (digest == *digest_before_close);
        const Status closed = reader.close();
        std::string text{"generation="};
        text.append(std::to_string(report.committed_generation.value()));
        text.append(" consistent=");
        text.append(consistent ? "true" : "false");
        text.append(" discarded_tail=");
        text.append(report.uncommitted_tail_discarded ? "true" : "false");
        text.append(" frames_replayed=");
        text.append(std::to_string(report.frames_replayed));
        if (!closed.ok()) {
          return step_failed(closed.error());
        }
        if (!report.read_only || !consistent || report.uncommitted_tail_discarded) {
          return StepOutcome{false, "the reopened store did not verify: " + text};
        }
        return step_ok(std::move(text));
      })) {
    return kExitRefusal;
  }

  if (!run("compact the durable registry", [&]() -> StepOutcome {
        auto reopened = open_store(AccessMode::ReadWrite);
        if (!reopened) {
          return step_failed(reopened.error());
        }
        TenantRegistry compactor = std::move(reopened).value();
        const Status compacted = compactor.compact();
        if (!compacted.ok()) {
          return step_failed(compacted.error());
        }
        std::string text{"generation="};
        text.append(std::to_string(compactor.generation().value()));
        const Status closed = compactor.close();
        if (!closed.ok()) {
          return step_failed(closed.error());
        }
        return step_ok(std::move(text));
      })) {
    return kExitRefusal;
  }

  const std::filesystem::path scratch_path = scratch->path();
  scratch->cleanup();
  scratch.reset();

  if (!run("remove every temporary directory", [&scratch_path]() -> StepOutcome {
        std::error_code inspection_code;
        if (std::filesystem::exists(scratch_path, inspection_code)) {
          return StepOutcome{false, "a temporary directory was left behind"};
        }
        return step_ok("clean");
      })) {
    return kExitRefusal;
  }

  scenario.result("ok");
  return kExitSuccess;
}

}  // namespace

int main(int argc, char** argv) {
  std::vector<std::string> tokens;
  if (argc > 1) {
    tokens.reserve(static_cast<std::size_t>(argc - 1));
  }
  for (int index = 1; index < argc; ++index) {
    tokens.emplace_back(argv[index]);
  }

  const auto write_stream = [](std::FILE* stream, const std::string& text) {
    if (!text.empty()) {
      (void)std::fwrite(text.data(), 1, text.size(), stream);
    }
  };

  try {
    const Invocation invocation = parse_invocation(tokens);

    if (invocation.mode != SpecialMode::None) {
      if (invocation.raw.help) {
        write_stream(stdout, std::string{kUsageText});
        return kExitSuccess;
      }
      if (invocation.raw.version) {
        std::string text{"treg "};
        text.append(tenant_registry::version_text());
        text.push_back('\n');
        write_stream(stdout, text);
        return kExitSuccess;
      }
      std::string out;
      const int code = invocation.mode == SpecialMode::SelfCheck
                           ? run_self_check(invocation.scratch, invocation.raw.quiet, out)
                           : run_scenario(invocation.scratch, invocation.raw.quiet, out);
      write_stream(stdout, out);
      return code;
    }

    if (invocation.raw.help) {
      write_stream(stdout, std::string{kUsageText});
      return kExitSuccess;
    }
    if (invocation.raw.version) {
      TextBlock block;
      block.row("treg", "1.0.0");
      block.row("library", tenant_registry::version_text());
      block.row("store_format", std::to_string(tenant_registry::kStoreFormatVersion));
      block.row("canonical_encoding", std::to_string(tenant_registry::kCanonicalEncodingVersion));
      block.row("export_format", std::to_string(tenant_registry::kExportFormatVersion));
      write_stream(stdout, block.render());
      return kExitSuccess;
    }

    const Globals globals = finalize_globals(invocation.raw);
    auto opened = open_session(globals);
    if (!opened) {
      CommandResult failed = refusal(opened.error());
      write_stream(stdout, failed.stdout_text);
      write_stream(stderr, failed.stderr_text);
      return failed.exit_code;
    }
    tenant_registry::TenantRegistry registry = std::move(opened).value();
    CommandResult result = invocation.runner(registry, globals, invocation.command_name);
    const tenant_registry::Status closed = registry.close();
    if (!closed.ok() && result.exit_code == kExitSuccess) {
      CommandResult closing = refusal(closed.error());
      result.stderr_text.append(closing.stderr_text);
      result.exit_code = closing.exit_code;
    }
    write_stream(stdout, result.stdout_text);
    write_stream(stderr, result.stderr_text);
    return result.exit_code;
  } catch (const UsageError& error) {
    std::string text{"usage error: "};
    text.append(error.message());
    text.append("\nrun 'treg --help' for the command list\n");
    write_stream(stderr, text);
    return kExitUsage;
  }
}
