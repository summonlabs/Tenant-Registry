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

#include "tenant_registry/version.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace tenant_registry {

std::string_view version_string() noexcept { return kVersionString; }

std::string version_text() {
  return std::to_string(kVersionMajor) + "." + std::to_string(kVersionMinor) + "." + std::to_string(kVersionPatch);
}

bool can_read_store_format(std::uint16_t container_version) noexcept {
  // Only the exact layout this build was compiled against is readable: a
  // container written by another layout is refused rather than guessed at.
  return container_version == kStoreFormatVersion;
}

bool can_read_canonical_encoding(std::uint16_t encoding_version) noexcept {
  return encoding_version == kCanonicalEncodingVersion;
}

}  // namespace tenant_registry
