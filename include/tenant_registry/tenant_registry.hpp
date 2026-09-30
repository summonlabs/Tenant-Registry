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

#ifndef TENANT_REGISTRY_TENANT_REGISTRY_HPP
#define TENANT_REGISTRY_TENANT_REGISTRY_HPP

/// The Tenant Registry public interface.
///
/// Include this header to use the library. Everything it exposes is stable for
/// the 1.x series; everything in a detail namespace, or in src, is not.
///
/// What this repository owns, in one paragraph: the canonical identities of
/// facility tenants, services and isolation domains; their lifecycles and the
/// legal transitions between them; their ownership, service and isolation
/// relationships; the generation, revision, control epoch and incarnation that
/// make a decision bindable to the exact state it was made against; and the
/// versioned, integrity checked, atomically published durable form of all of
/// that. It owns nothing else. It does not authenticate anyone, does not bill
/// anyone, does not schedule accelerators, does not segment a network, does not
/// decide entitlement or placement, and does not treat any external directory
/// as a source of truth about its own state.

#include "tenant_registry/clock.hpp"
#include "tenant_registry/digest.hpp"
#include "tenant_registry/errors.hpp"
#include "tenant_registry/ids.hpp"
#include "tenant_registry/lifecycle.hpp"
#include "tenant_registry/limits.hpp"
#include "tenant_registry/metadata.hpp"
#include "tenant_registry/persistence.hpp"
#include "tenant_registry/provenance.hpp"
#include "tenant_registry/query.hpp"
#include "tenant_registry/records.hpp"
#include "tenant_registry/registry.hpp"
#include "tenant_registry/requests.hpp"
#include "tenant_registry/snapshot.hpp"
#include "tenant_registry/version.hpp"

#endif  // TENANT_REGISTRY_TENANT_REGISTRY_HPP
