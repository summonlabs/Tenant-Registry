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

#ifndef TENANT_REGISTRY_SNAPSHOT_HPP
#define TENANT_REGISTRY_SNAPSHOT_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "tenant_registry/digest.hpp"
#include "tenant_registry/ids.hpp"
#include "tenant_registry/records.hpp"

namespace tenant_registry {

/// An immutable copy of the whole authoritative registry state at one
/// generation.
///
/// A snapshot is a value: it is taken under the registry's writer mutex, it
/// shares nothing with the live state afterwards, and it is self consistent by
/// construction. Because every collection inside it is held in canonical order,
/// two snapshots of the same state produce identical canonical bytes and
/// therefore the same digest, on any machine, in any process, in any order of
/// operations that led there.
///
/// Ordering, exactly:
///   tenants, services, isolation domains  ascending by identity bytes
///   ownership edges                       ascending by (child, parent)
///   service bindings                      ascending by (service, tenant, kind)
///   isolation memberships                 ascending by (subject, domain)
///   tombstones                            ascending by (kind, identity)
///   domain generations                    ascending by domain identity bytes
struct RegistrySnapshot {
  RegistryGeneration generation;
  ControlEpoch control_epoch;
  Incarnation incarnation;
  std::optional<ContentDigest> store_id;
  JournalSequence committed_sequence;

  std::vector<TenantRecord> tenants;
  std::vector<ServiceRecord> services;
  std::vector<IsolationDomainRecord> isolation_domains;
  std::vector<OwnershipEdge> ownership_edges;
  std::vector<ServiceBinding> service_bindings;
  std::vector<IsolationMembership> isolation_memberships;
  std::vector<TombstoneRecord> tombstones;
  std::vector<std::pair<IsolationDomainId, DomainGeneration>> domain_generations;

  [[nodiscard]] std::size_t record_count() const noexcept;

  /// The canonical binary encoding of the tenancy state: the generation and
  /// every record, in canonical order. Stable across platforms, compilers, map
  /// iteration orders and, deliberately, across sessions: the control epoch,
  /// the incarnation, the store identity and the journal position are session
  /// facts rather than tenancy facts, so they are reported by this snapshot but
  /// are not part of what identifies its state.
  [[nodiscard]] std::string to_canonical_bytes() const;

  /// SHA-256 over the canonical encoding of the tenancy state. Two registries
  /// that hold the same records at the same generation share a digest, whatever
  /// process wrote them and however many restarts they survived.
  [[nodiscard]] ContentDigest digest() const;

  /// The canonical JSON export. Keys are emitted in canonical order, so the
  /// export is diffable and reproducible.
  [[nodiscard]] std::string to_json() const;

  /// A short human readable rendering, for the CLI and for diagnostics.
  [[nodiscard]] std::string to_text() const;

  /// The generation of one domain's membership set as recorded in this
  /// snapshot, or nothing when the snapshot does not contain that domain.
  [[nodiscard]] std::optional<DomainGeneration> domain_generation(const IsolationDomainId& id) const;
};

}  // namespace tenant_registry

#endif  // TENANT_REGISTRY_SNAPSHOT_HPP
