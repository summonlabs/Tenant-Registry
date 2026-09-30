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

#ifndef TENANT_REGISTRY_CLOCK_HPP
#define TENANT_REGISTRY_CLOCK_HPP

#include <compare>
#include <cstdint>
#include <memory>
#include <string>

namespace tenant_registry {

/// A wall clock reading in milliseconds since the Unix epoch.
///
/// The clock is an input, not an authority. It is recorded as evidence about
/// when a declaration was made; it never decides whether a declaration is
/// current. Ordering inside the registry comes from generations and sequence
/// numbers, which are monotonic by construction and survive a clock that moves
/// backwards or jumps.
struct Timestamp {
  std::int64_t unix_milliseconds = 0;

  friend bool operator==(const Timestamp&, const Timestamp&) = default;
  friend auto operator<=>(const Timestamp&, const Timestamp&) = default;

  [[nodiscard]] std::string to_text() const;
};

/// The clock abstraction. Calls are expected to be cheap and non-throwing.
class Clock {
 public:
  virtual ~Clock() = default;
  [[nodiscard]] virtual Timestamp now() const = 0;
};

/// Reads the system clock.
class SystemClock final : public Clock {
 public:
  [[nodiscard]] Timestamp now() const override;
};

/// Returns a fixed reading. Used by tests and by callers that need byte for
/// byte reproducible output.
class FixedClock final : public Clock {
 public:
  explicit FixedClock(std::int64_t unix_milliseconds) noexcept : value_(unix_milliseconds) {}
  [[nodiscard]] Timestamp now() const override { return Timestamp{value_}; }
  void set(std::int64_t unix_milliseconds) noexcept { value_ = unix_milliseconds; }

 private:
  std::int64_t value_;
};

}  // namespace tenant_registry

#endif  // TENANT_REGISTRY_CLOCK_HPP
