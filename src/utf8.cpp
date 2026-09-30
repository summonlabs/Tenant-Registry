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

#include "utf8.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace tenant_registry {
namespace detail {

namespace {

constexpr char kHexDigits[] = "0123456789abcdef";

// The UTF-8 encoding of U+FFFD, substituted for a byte sequence that is not
// well formed. A registry field never holds one, but a diagnostic or an export
// must still produce well formed output for arbitrary bytes.
constexpr std::string_view kReplacementCharacter = "\xEF\xBF\xBD";

void append_u00_escape(std::string& out, std::uint8_t value) {
  out += "\\u00";
  out += kHexDigits[(value >> 4) & 0x0Fu];
  out += kHexDigits[value & 0x0Fu];
}

// Decodes the UTF-8 sequence that starts at index. Returns the number of bytes
// it occupies, or zero when the sequence is truncated, overlong, a surrogate or
// above U+10FFFF. Every caller advances by the returned count or refuses.
std::size_t decode_sequence(std::string_view text, std::size_t index, char32_t& code_point) noexcept {
  const std::uint8_t first = static_cast<std::uint8_t>(text[index]);
  if (first < 0x80u) {
    code_point = static_cast<char32_t>(first);
    return 1;
  }
  if (first < 0xC2u) {
    // A continuation byte, or one of the two overlong two byte leads.
    return 0;
  }
  if (first < 0xE0u) {
    if (text.size() - index < 2) {
      return 0;
    }
    const std::uint8_t second = static_cast<std::uint8_t>(text[index + 1]);
    if ((second & 0xC0u) != 0x80u) {
      return 0;
    }
    code_point = static_cast<char32_t>(((first & 0x1Fu) << 6) | (second & 0x3Fu));
    return 2;
  }
  if (first < 0xF0u) {
    if (text.size() - index < 3) {
      return 0;
    }
    const std::uint8_t second = static_cast<std::uint8_t>(text[index + 1]);
    const std::uint8_t third = static_cast<std::uint8_t>(text[index + 2]);
    if ((second & 0xC0u) != 0x80u || (third & 0xC0u) != 0x80u) {
      return 0;
    }
    if (first == 0xE0u && second < 0xA0u) {
      return 0;  // overlong
    }
    if (first == 0xEDu && second > 0x9Fu) {
      return 0;  // U+D800..U+DFFF
    }
    code_point = static_cast<char32_t>(((first & 0x0Fu) << 12) | ((second & 0x3Fu) << 6) | (third & 0x3Fu));
    return 3;
  }
  if (first < 0xF5u) {
    if (text.size() - index < 4) {
      return 0;
    }
    const std::uint8_t second = static_cast<std::uint8_t>(text[index + 1]);
    const std::uint8_t third = static_cast<std::uint8_t>(text[index + 2]);
    const std::uint8_t fourth = static_cast<std::uint8_t>(text[index + 3]);
    if ((second & 0xC0u) != 0x80u || (third & 0xC0u) != 0x80u || (fourth & 0xC0u) != 0x80u) {
      return 0;
    }
    if (first == 0xF0u && second < 0x90u) {
      return 0;  // overlong
    }
    if (first == 0xF4u && second > 0x8Fu) {
      return 0;  // above U+10FFFF
    }
    code_point = static_cast<char32_t>(((first & 0x07u) << 18) | ((second & 0x3Fu) << 12) |
                                       ((third & 0x3Fu) << 6) | (fourth & 0x3Fu));
    return 4;
  }
  return 0;
}

}  // namespace

bool utf8_valid(std::string_view text) noexcept {
  std::size_t index = 0;
  while (index < text.size()) {
    char32_t code_point = 0;
    const std::size_t consumed = decode_sequence(text, index, code_point);
    if (consumed == 0) {
      return false;
    }
    index += consumed;
  }
  return true;
}

bool ascii_printable(std::string_view text) noexcept {
  for (const char character : text) {
    const std::uint8_t byte = static_cast<std::uint8_t>(character);
    if (byte < 0x20u || byte > 0x7Eu) {
      return false;
    }
  }
  return true;
}

bool has_no_control_bytes(std::string_view text) noexcept {
  for (const char character : text) {
    const std::uint8_t byte = static_cast<std::uint8_t>(character);
    if (byte < 0x20u || byte == 0x7Fu) {
      return false;
    }
  }
  return true;
}

bool has_no_line_breaks(std::string_view text) noexcept {
  for (const char character : text) {
    if (static_cast<std::uint8_t>(character) < 0x20u) {
      return false;
    }
  }
  return true;
}

void json_escape(std::string& out, std::string_view text) {
  std::size_t index = 0;
  while (index < text.size()) {
    const std::uint8_t byte = static_cast<std::uint8_t>(text[index]);
    if (byte < 0x80u) {
      switch (byte) {
        case '"':
          out += "\\\"";
          break;
        case '\\':
          out += "\\\\";
          break;
        case '\b':
          out += "\\b";
          break;
        case '\f':
          out += "\\f";
          break;
        case '\n':
          out += "\\n";
          break;
        case '\r':
          out += "\\r";
          break;
        case '\t':
          out += "\\t";
          break;
        default:
          if (byte < 0x20u) {
            append_u00_escape(out, byte);
          } else {
            out += static_cast<char>(byte);
          }
          break;
      }
      ++index;
      continue;
    }
    char32_t code_point = 0;
    const std::size_t consumed = decode_sequence(text, index, code_point);
    if (consumed == 0) {
      out += kReplacementCharacter;
      ++index;
      continue;
    }
    if (code_point <= 0x9Fu) {
      // The C1 range is escaped rather than emitted: a terminal that reads the
      // raw bytes would interpret some of them as control sequences.
      append_u00_escape(out, static_cast<std::uint8_t>(code_point));
    } else {
      out.append(text.substr(index, consumed));
    }
    index += consumed;
  }
}

std::string render_bytes_bounded(std::span<const std::byte> bytes, std::size_t max_bytes) {
  std::string out;
  if (bytes.empty() || max_bytes == 0) {
    return out;
  }
  out.reserve(std::min(max_bytes, bytes.size()));
  const std::string_view text{reinterpret_cast<const char*>(bytes.data()), bytes.size()};
  std::size_t index = 0;
  while (index < text.size() && out.size() < max_bytes) {
    const std::uint8_t byte = static_cast<std::uint8_t>(text[index]);
    if (byte >= 0x20u && byte <= 0x7Eu) {
      out += static_cast<char>(byte);
      ++index;
      continue;
    }
    char32_t code_point = 0;
    const std::size_t consumed = byte < 0x80u ? 0 : decode_sequence(text, index, code_point);
    if (consumed != 0 && code_point > 0x9Fu) {
      if (out.size() + consumed > max_bytes) {
        break;
      }
      out.append(text.substr(index, consumed));
      index += consumed;
      continue;
    }
    // A control byte, a malformed sequence or a C1 control: one replacement
    // character, so the rendering can never carry an instruction to a terminal.
    if (out.size() + 1 > max_bytes) {
      break;
    }
    out += '?';
    ++index;
  }
  return out;
}

bool utf8_code_points(std::string_view text, std::u32string& out) {
  out.clear();
  std::size_t index = 0;
  while (index < text.size()) {
    char32_t code_point = 0;
    const std::size_t consumed = decode_sequence(text, index, code_point);
    if (consumed == 0) {
      out.clear();
      return false;
    }
    out.push_back(code_point);
    index += consumed;
  }
  return true;
}

}  // namespace detail
}  // namespace tenant_registry
