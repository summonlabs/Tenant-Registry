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

#ifndef TENANT_REGISTRY_VERSION_HPP
#define TENANT_REGISTRY_VERSION_HPP

#include <cstdint>
#include <string>
#include <string_view>

namespace tenant_registry {

/// The library version. This is the version of the software, not of any
/// persisted structure; a persisted structure carries its own version and is
/// refused when this build cannot prove it understands it.
inline constexpr int kVersionMajor = 1;
inline constexpr int kVersionMinor = 0;
inline constexpr int kVersionPatch = 0;
inline constexpr std::string_view kVersionString = "1.0.0";

/// The version of the durable container (manifest and frame) layout.
inline constexpr std::uint16_t kStoreFormatVersion = 1;

/// The version of the canonical record encoding. Any change to a canonical
/// encoding that alters a single produced byte requires this number to change,
/// because a digest computed by an older build must never be silently accepted
/// as the digest of the new encoding.
inline constexpr std::uint16_t kCanonicalEncodingVersion = 1;

/// The version of the canonical text (JSON) export.
inline constexpr std::uint16_t kExportFormatVersion = 1;

[[nodiscard]] std::string_view version_string() noexcept;

/// Renders the version as major.minor.patch.
[[nodiscard]] std::string version_text();

/// True when the running build can read a container written in
/// container_version. Only the exact version this build was compiled against is
/// readable: forward compatibility is not claimed.
[[nodiscard]] bool can_read_store_format(std::uint16_t container_version) noexcept;

/// True when the running build can compare canonical encodings produced with
/// encoding_version.
[[nodiscard]] bool can_read_canonical_encoding(std::uint16_t encoding_version) noexcept;

}  // namespace tenant_registry

#endif  // TENANT_REGISTRY_VERSION_HPP
