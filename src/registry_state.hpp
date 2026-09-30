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

#ifndef TENANT_REGISTRY_SRC_REGISTRY_STATE_HPP
#define TENANT_REGISTRY_SRC_REGISTRY_STATE_HPP

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>

#include "canonical_codec.hpp"
#include "tenant_registry/errors.hpp"
#include "tenant_registry/ids.hpp"
#include "tenant_registry/limits.hpp"
#include "tenant_registry/query.hpp"
#include "tenant_registry/records.hpp"

namespace tenant_registry {
namespace detail {

// ---------------------------------------------------------------------------
// Canonical keys, built from raw components.
//
// canonical_key(AnyRecord) in canonical_codec.hpp builds the same strings from
// a whole record. Two builders exist because the mutation path often knows the
// components before it has a record, and because a lookup should not have to
// manufacture a record to ask a question. They are kept identical by a test
// that compares every key this file builds with the key the codec builds for
// the record it produced.
// ---------------------------------------------------------------------------

[[nodiscard]] std::string identity_key(SubjectKind kind, std::string_view value);
[[nodiscard]] std::string tenant_key(std::string_view value);
[[nodiscard]] std::string service_key(std::string_view value);
[[nodiscard]] std::string domain_key(std::string_view value);
[[nodiscard]] std::string ownership_key(std::string_view child, std::string_view parent);
[[nodiscard]] std::string binding_key(std::string_view service, std::string_view tenant, BindingKind kind);
[[nodiscard]] std::string membership_key(const TenancySubject& subject, const IsolationDomainId& domain);
[[nodiscard]] std::string tombstone_key(SubjectKind kind, std::string_view value);

/// The key prefix that selects every record of one kind.
[[nodiscard]] std::string_view key_prefix(RecordKind kind) noexcept;

/// The kind a canonical key names, read from its prefix. Unspecified when the
/// prefix is not one this build knows.
[[nodiscard]] RecordKind kind_of_key(std::string_view key) noexcept;

/// The prefix that selects every ownership edge whose child is this tenant.
[[nodiscard]] std::string ownership_child_prefix(std::string_view child);
/// The prefix that selects every binding of this service.
[[nodiscard]] std::string binding_service_prefix(std::string_view service);
/// The prefix that selects every membership of this subject.
[[nodiscard]] std::string membership_subject_prefix(const TenancySubject& subject);

// ---------------------------------------------------------------------------
// The authoritative in-memory state.
//
// Every record lives in one ordered map keyed by its canonical key. Ordering is
// therefore byte ordering of the canonical key, which is a total order that
// does not depend on any hash, any insertion order or any platform. Records of
// one kind form a contiguous range because the key is prefixed by the kind, so
// "every edge whose child is X" is a bounded range scan rather than a full one.
//
// State is only ever changed through apply() and erase(), both of which keep
// the counts consistent with the map, and neither of which validates. Every
// caller validates first; validate() then re-derives every cross record
// invariant from scratch, and is run after recovery precisely so that a
// corrupted journal cannot install a state a live mutation could not have
// produced.
// ---------------------------------------------------------------------------

class RegistryState {
 public:
  explicit RegistryState(RegistryLimits limits);

  // -- lookup ---------------------------------------------------------------

  [[nodiscard]] const AnyRecord* find(std::string_view key) const noexcept;
  [[nodiscard]] const TenantRecord* find_tenant(const TenantId& id) const noexcept;
  [[nodiscard]] const ServiceRecord* find_service(const ServiceId& id) const noexcept;
  [[nodiscard]] const IsolationDomainRecord* find_domain(const IsolationDomainId& id) const noexcept;
  [[nodiscard]] const OwnershipEdge* find_ownership(std::string_view child, std::string_view parent) const noexcept;
  [[nodiscard]] const ServiceBinding* find_binding(std::string_view service, std::string_view tenant,
                                                   BindingKind kind) const noexcept;
  [[nodiscard]] const IsolationMembership* find_membership(const TenancySubject& subject,
                                                           const IsolationDomainId& domain) const noexcept;
  /// The tombstone of an identity, projected from the identity record when the
  /// tombstone has not been reused yet, and read from the permanent tombstone
  /// record once it has. Both forms answer the same question identically.
  [[nodiscard]] std::optional<TombstoneRecord> find_tombstone(SubjectKind kind, std::string_view value) const;

  /// Calls fn for every record whose canonical key begins with prefix, in key
  /// order. The range is bounded by the map, so the walk is bounded by the
  /// number of records that actually match.
  template <class Fn>
  void for_each_prefix(std::string_view prefix, Fn&& fn) const {
    for (auto it = records.lower_bound(std::string{prefix}); it != records.end(); ++it) {
      if (!starts_with(it->first, prefix)) {
        break;
      }
      if (!fn(it->second)) {
        return;
      }
    }
  }

  /// Calls fn for every record of one kind, in key order.
  template <class Fn>
  void for_each_kind(RecordKind kind, Fn&& fn) const {
    for_each_prefix(key_prefix(kind), std::forward<Fn>(fn));
  }

  // -- mutation -------------------------------------------------------------

  /// Inserts or replaces the record under its own canonical key.
  void apply(AnyRecord record);

  /// Removes the record stored under this canonical key. Returns false when no
  /// such record existed.
  bool erase(std::string_view key);

  /// Empties the state. Used only when a baseline frame replaces everything the
  /// journal said before it.
  void reset();

  // -- accounting -----------------------------------------------------------

  [[nodiscard]] std::uint64_t count(RecordKind kind) const noexcept;

  /// How many ownership edges name this tenant as the owner.
  ///
  /// This is maintained with the record map rather than derived on demand,
  /// because the canonical key of an ownership edge begins with the child, so
  /// "the children of this tenant" is not a key range and a scan would make
  /// declaring one edge cost the whole registry.
  [[nodiscard]] std::uint64_t child_count(std::string_view parent) const noexcept;
  [[nodiscard]] std::size_t ledger_size() const noexcept { return ledger.size(); }
  [[nodiscard]] bool ledger_full() const noexcept { return ledger.size() >= limits.max_idempotency_entries; }

  // -- integrity ------------------------------------------------------------

  /// Re-derives every invariant that must hold of a state this registry could
  /// have produced. Returns a refusal whose detail names the first violated
  /// invariant, in a fixed order, so two runs on the same state refuse
  /// identically.
  [[nodiscard]] Status validate(std::string& detail) const;

  /// A short description of the state's shape, for diagnostics.
  [[nodiscard]] std::string shape_text() const;

  [[nodiscard]] static bool starts_with(std::string_view text, std::string_view prefix) noexcept;

  RegistryLimits limits;
  RegistryGeneration generation;
  std::map<std::string, AnyRecord> records;
  std::map<std::string, IdempotencyLedgerEntry> ledger;

 private:
  [[nodiscard]] static std::size_t kind_index(RecordKind kind) noexcept;

  std::array<std::uint64_t, 8> counts_{};
  std::map<std::string, std::uint64_t> children_of_;
};

}  // namespace detail
}  // namespace tenant_registry

#endif  // TENANT_REGISTRY_SRC_REGISTRY_STATE_HPP
