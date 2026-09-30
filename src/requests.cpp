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

#include <string>
#include <string_view>

#include "tenant_registry/requests.hpp"

namespace tenant_registry {
namespace {

struct OperationToken {
  OperationKind kind;
  std::string_view token;
};

/// The one and only table that maps an operation to its token. A token is
/// stable: it appears in durable payloads, in the CLI and in diagnostics, so a
/// token is never renamed and never reused for a different operation.
constexpr OperationToken kOperationTokens[] = {
    {OperationKind::Unspecified, "unspecified"},
    {OperationKind::CreateTenant, "create_tenant"},
    {OperationKind::CreateService, "create_service"},
    {OperationKind::CreateIsolationDomain, "create_isolation_domain"},
    {OperationKind::TransitionSubject, "transition_subject"},
    {OperationKind::SetOwner, "set_owner"},
    {OperationKind::SetMetadata, "set_metadata"},
    {OperationKind::PutOwnership, "put_ownership"},
    {OperationKind::RemoveOwnership, "remove_ownership"},
    {OperationKind::TransitionOwnership, "transition_ownership"},
    {OperationKind::PutServiceBinding, "put_service_binding"},
    {OperationKind::RemoveServiceBinding, "remove_service_binding"},
    {OperationKind::TransitionServiceBinding, "transition_service_binding"},
    {OperationKind::PutIsolationMembership, "put_isolation_membership"},
    {OperationKind::TransitionIsolationMembership, "transition_isolation_membership"},
    {OperationKind::RemoveIsolationMembership, "remove_isolation_membership"},
    {OperationKind::Tombstone, "tombstone"},
};

}  // namespace

std::string_view to_token(OperationKind kind) noexcept {
  for (const auto& entry : kOperationTokens) {
    if (entry.kind == kind) {
      return entry.token;
    }
  }
  return "unspecified";
}

bool parse_operation_kind(std::string_view token, OperationKind& out) noexcept {
  for (const auto& entry : kOperationTokens) {
    if (entry.token == token && entry.kind != OperationKind::Unspecified) {
      out = entry.kind;
      return true;
    }
  }
  return false;
}

std::string MutationReceipt::to_text() const {
  std::string out;
  out.append("operation=").append(to_token(operation));
  out.append(" generation=").append(std::to_string(generation.value()));
  out.append(" sequence=").append(std::to_string(sequence.value()));
  out.append(" revision=").append(std::to_string(revision.value()));
  out.append(" request_digest=").append(request_digest.to_text());
  out.append(" replayed=").append(replayed ? "true" : "false");
  return out;
}

}  // namespace tenant_registry
