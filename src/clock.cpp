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

#include "tenant_registry/clock.hpp"

#include <chrono>
#include <cstdint>

namespace tenant_registry {

// Timestamp::to_text() is rendered in src/export.cpp, next to the other
// canonical renderings, so that there is exactly one textual form of a time in
// this repository and exactly one place that produces it.

Timestamp SystemClock::now() const {
  const std::chrono::milliseconds reading =
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch());
  return Timestamp{static_cast<std::int64_t>(reading.count())};
}

}  // namespace tenant_registry
