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

#ifndef TENANT_REGISTRY_SRC_UTF8_HPP
#define TENANT_REGISTRY_SRC_UTF8_HPP

#include <cstddef>
#include <span>
#include <string>
#include <string_view>

namespace tenant_registry {
namespace detail {

/// True when the bytes are well formed UTF-8: no overlong form, no surrogate,
/// no code point above U+10FFFF, no truncated sequence.
[[nodiscard]] bool utf8_valid(std::string_view text) noexcept;

/// True when every byte is in the printable ASCII range 0x20..0x7E.
[[nodiscard]] bool ascii_printable(std::string_view text) noexcept;

/// True when the text contains no byte below 0x20 and no 0x7F. Control bytes
/// are refused in every text field this registry stores, because they make
/// logs, terminals and exports disagree about what was recorded.
[[nodiscard]] bool has_no_control_bytes(std::string_view text) noexcept;

/// True when the text contains no byte below 0x20 (including tab and newline).
/// Used where a multi line value would break a line oriented format.
[[nodiscard]] bool has_no_line_breaks(std::string_view text) noexcept;

/// Appends the canonical JSON escaping of text, without surrounding quotes.
/// Escapes exactly the characters RFC 8259 requires, plus the C1 range, using
/// lower case hexadecimal, so the escaping has one form.
void json_escape(std::string& out, std::string_view text);

/// Renders arbitrary bytes for a diagnostic, replacing anything that is not
/// printable ASCII or valid UTF-8, bounded to max_bytes. Diagnostics must never
/// be able to make a terminal execute something.
[[nodiscard]] std::string render_bytes_bounded(std::span<const std::byte> bytes, std::size_t max_bytes);

/// Decodes whole-string UTF-8 to a code point sequence, refusing invalid input.
/// Used only where a canonical order over text is needed; the registry orders
/// identities by their bytes, not by code points.
[[nodiscard]] bool utf8_code_points(std::string_view text, std::u32string& out);

}  // namespace detail
}  // namespace tenant_registry

#endif  // TENANT_REGISTRY_SRC_UTF8_HPP
