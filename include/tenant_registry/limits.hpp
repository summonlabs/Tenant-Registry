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

#ifndef TENANT_REGISTRY_LIMITS_HPP
#define TENANT_REGISTRY_LIMITS_HPP

#include <cstddef>
#include <cstdint>
#include <string>

namespace tenant_registry {

/// Every bound the registry enforces.
///
/// A limit is not a tuning knob for performance: each one is the bound that
/// makes an untrusted input unable to make this process allocate, recurse or
/// iterate without end. Lowering a limit is always safe. Raising one is a
/// deliberate decision about how much untrusted input this process is willing
/// to carry.
struct RegistryLimits {
  // -- text and identity ----------------------------------------------------
  /// Bounds an identity read from a durable container. Identities arriving on
  /// the request path are validated against each identity type's own static
  /// grammar instead, so lowering this limit fences what can be read back
  /// rather than what can be declared.
  std::size_t max_identity_bytes = 128;
  std::size_t max_display_name_bytes = 256;
  std::size_t max_metadata_key_bytes = 96;
  std::size_t max_metadata_value_bytes = 512;
  std::size_t max_provenance_note_bytes = 512;
  std::size_t max_principal_bytes = 128;
  std::size_t max_source_bytes = 128;

  // -- record counts --------------------------------------------------------
  std::uint64_t max_tenants = 100'000;
  std::uint64_t max_services = 100'000;
  std::uint64_t max_isolation_domains = 4'096;
  std::uint64_t max_ownership_edges = 200'000;
  std::uint64_t max_service_bindings = 200'000;
  std::uint64_t max_isolation_memberships = 400'000;

  // -- per record cardinality ----------------------------------------------
  std::size_t max_metadata_entries_per_record = 64;
  std::size_t max_bindings_per_service = 16;
  std::size_t max_memberships_per_subject = 16;
  std::size_t max_memberships_per_domain = 4'096;
  /// Bounds how many tenants one tenant may own, and is enforced when an
  /// ownership edge is created.
  std::size_t max_children_per_tenant = 4'096;

  // -- traversal and listing ------------------------------------------------
  std::size_t max_ownership_depth = 64;
  std::size_t max_traversal_depth = 32;
  std::size_t max_traversal_results = 4'096;
  std::size_t default_listing_limit = 128;
  std::size_t max_listing_limit = 1'024;

  // -- idempotency ----------------------------------------------------------
  /// The number of distinct idempotency keys the ledger retains. The ledger is
  /// never silently pruned: when it is full, a new keyed mutation is refused
  /// with IdempotencyLedgerFull rather than risking a double apply.
  std::size_t max_idempotency_entries = 65'536;
  /// How much canonical record content a ledger entry retains so that a replay
  /// can return the record as it was at the original commit.
  std::size_t max_idempotency_outcome_bytes = 64 * 1024;

  // -- durable container ----------------------------------------------------
  std::uint64_t max_journal_frames = 1'000'000;
  std::uint64_t max_journal_bytes = 512ull * 1024ull * 1024ull;
  std::uint32_t max_commit_payload_bytes = 256u * 1024u;
  std::uint32_t max_baseline_payload_bytes = 64u * 1024u * 1024u;
  std::uint64_t max_snapshot_bytes = 64ull * 1024ull * 1024ull;
  std::uint64_t max_manifest_bytes = 4'096;
  std::size_t max_store_roots_per_process = 16;

  /// A short description of the limits, for diagnostics and for the CLI.
  [[nodiscard]] std::string to_text() const;
};

/// Checks that a limit set is internally coherent: no limit may be zero where
/// zero would mean "refuse everything", and no maximum may be smaller than the
/// corresponding default. Returns a description of the first incoherence found.
[[nodiscard]] bool validate_limits(const RegistryLimits& limits, std::string& reason);

}  // namespace tenant_registry

#endif  // TENANT_REGISTRY_LIMITS_HPP
