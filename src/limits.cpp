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

#include "tenant_registry/limits.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace tenant_registry {

namespace {

struct LimitText {
  std::string_view name;
  std::string value;
};

struct LimitCheck {
  std::string_view name;
  bool is_zero;
};

}  // namespace

std::string RegistryLimits::to_text() const {
  // Every limit is rendered, sorted by name, so that two runs and two builds
  // produce the same text for the same limit set and no limit can be omitted
  // without the omission being visible in a diff.
  std::vector<LimitText> lines;
  lines.push_back({"default_listing_limit", std::to_string(default_listing_limit)});
  lines.push_back({"max_baseline_payload_bytes", std::to_string(max_baseline_payload_bytes)});
  lines.push_back({"max_bindings_per_service", std::to_string(max_bindings_per_service)});
  lines.push_back({"max_children_per_tenant", std::to_string(max_children_per_tenant)});
  lines.push_back({"max_commit_payload_bytes", std::to_string(max_commit_payload_bytes)});
  lines.push_back({"max_display_name_bytes", std::to_string(max_display_name_bytes)});
  lines.push_back({"max_idempotency_entries", std::to_string(max_idempotency_entries)});
  lines.push_back({"max_idempotency_outcome_bytes", std::to_string(max_idempotency_outcome_bytes)});
  lines.push_back({"max_identity_bytes", std::to_string(max_identity_bytes)});
  lines.push_back({"max_isolation_domains", std::to_string(max_isolation_domains)});
  lines.push_back({"max_isolation_memberships", std::to_string(max_isolation_memberships)});
  lines.push_back({"max_journal_bytes", std::to_string(max_journal_bytes)});
  lines.push_back({"max_journal_frames", std::to_string(max_journal_frames)});
  lines.push_back({"max_listing_limit", std::to_string(max_listing_limit)});
  lines.push_back({"max_manifest_bytes", std::to_string(max_manifest_bytes)});
  lines.push_back({"max_memberships_per_domain", std::to_string(max_memberships_per_domain)});
  lines.push_back({"max_memberships_per_subject", std::to_string(max_memberships_per_subject)});
  lines.push_back({"max_metadata_entries_per_record", std::to_string(max_metadata_entries_per_record)});
  lines.push_back({"max_metadata_key_bytes", std::to_string(max_metadata_key_bytes)});
  lines.push_back({"max_metadata_value_bytes", std::to_string(max_metadata_value_bytes)});
  lines.push_back({"max_ownership_depth", std::to_string(max_ownership_depth)});
  lines.push_back({"max_ownership_edges", std::to_string(max_ownership_edges)});
  lines.push_back({"max_principal_bytes", std::to_string(max_principal_bytes)});
  lines.push_back({"max_provenance_note_bytes", std::to_string(max_provenance_note_bytes)});
  lines.push_back({"max_service_bindings", std::to_string(max_service_bindings)});
  lines.push_back({"max_services", std::to_string(max_services)});
  lines.push_back({"max_snapshot_bytes", std::to_string(max_snapshot_bytes)});
  lines.push_back({"max_source_bytes", std::to_string(max_source_bytes)});
  lines.push_back({"max_store_roots_per_process", std::to_string(max_store_roots_per_process)});
  lines.push_back({"max_tenants", std::to_string(max_tenants)});
  lines.push_back({"max_traversal_depth", std::to_string(max_traversal_depth)});
  lines.push_back({"max_traversal_results", std::to_string(max_traversal_results)});

  std::sort(lines.begin(), lines.end(),
            [](const LimitText& left, const LimitText& right) { return left.name < right.name; });

  std::string out;
  for (const LimitText& line : lines) {
    if (!out.empty()) {
      out += '\n';
    }
    out += line.name;
    out += " = ";
    out += line.value;
  }
  return out;
}

bool validate_limits(const RegistryLimits& limits, std::string& reason) {
  reason.clear();
  // The checks run in declaration order, so "the first incoherence" is the same
  // one on every build.
  const LimitCheck checks[] = {
      {"max_identity_bytes", limits.max_identity_bytes == 0},
      {"max_display_name_bytes", limits.max_display_name_bytes == 0},
      {"max_metadata_key_bytes", limits.max_metadata_key_bytes == 0},
      {"max_metadata_value_bytes", limits.max_metadata_value_bytes == 0},
      {"max_provenance_note_bytes", limits.max_provenance_note_bytes == 0},
      {"max_principal_bytes", limits.max_principal_bytes == 0},
      {"max_source_bytes", limits.max_source_bytes == 0},
      {"max_tenants", limits.max_tenants == 0},
      {"max_services", limits.max_services == 0},
      {"max_isolation_domains", limits.max_isolation_domains == 0},
      {"max_ownership_edges", limits.max_ownership_edges == 0},
      {"max_service_bindings", limits.max_service_bindings == 0},
      {"max_isolation_memberships", limits.max_isolation_memberships == 0},
      {"max_metadata_entries_per_record", limits.max_metadata_entries_per_record == 0},
      {"max_bindings_per_service", limits.max_bindings_per_service == 0},
      {"max_memberships_per_subject", limits.max_memberships_per_subject == 0},
      {"max_memberships_per_domain", limits.max_memberships_per_domain == 0},
      {"max_children_per_tenant", limits.max_children_per_tenant == 0},
      {"max_ownership_depth", limits.max_ownership_depth == 0},
      {"max_traversal_depth", limits.max_traversal_depth == 0},
      {"max_traversal_results", limits.max_traversal_results == 0},
      {"default_listing_limit", limits.default_listing_limit == 0},
      {"max_listing_limit", limits.max_listing_limit == 0},
      {"max_idempotency_entries", limits.max_idempotency_entries == 0},
      {"max_idempotency_outcome_bytes", limits.max_idempotency_outcome_bytes == 0},
      {"max_journal_frames", limits.max_journal_frames == 0},
      {"max_journal_bytes", limits.max_journal_bytes == 0},
      {"max_commit_payload_bytes", limits.max_commit_payload_bytes == 0},
      {"max_baseline_payload_bytes", limits.max_baseline_payload_bytes == 0},
      {"max_snapshot_bytes", limits.max_snapshot_bytes == 0},
      {"max_manifest_bytes", limits.max_manifest_bytes == 0},
      {"max_store_roots_per_process", limits.max_store_roots_per_process == 0},
  };
  for (const LimitCheck& check : checks) {
    if (check.is_zero) {
      reason = std::string{check.name} + " must be greater than zero";
      return false;
    }
  }
  if (limits.default_listing_limit > limits.max_listing_limit) {
    reason = "default_listing_limit (" + std::to_string(limits.default_listing_limit) +
             ") must not exceed max_listing_limit (" + std::to_string(limits.max_listing_limit) + ")";
    return false;
  }
  return true;
}

}  // namespace tenant_registry
