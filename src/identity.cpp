// Control Plane Epoch 1.0.0 - Summon Software Labs
// Identity, text, and UTF-8 validation.
//
// All validation happens at the construction boundary: a value that exists in
// the system has already been validated, so downstream code never re-checks and
// never normalizes. External input that fails validation is rejected with a
// stable code instead of being repaired into something plausible.
#include <cstdint>
#include <string>

#include "control_plane_epoch/identity.hpp"

namespace dccp::epoch {
namespace {

[[nodiscard]] bool is_ascii_alphanumeric(char character) noexcept {
  return (character >= '0' && character <= '9') || (character >= 'A' && character <= 'Z') ||
         (character >= 'a' && character <= 'z');
}

[[nodiscard]] bool is_identifier_character(char character) noexcept {
  return is_ascii_alphanumeric(character) || character == '.' || character == '_' || character == '-';
}

[[nodiscard]] std::string describe_offset(std::size_t offset) {
  return "at byte offset " + std::to_string(offset);
}

}  // namespace

bool is_valid_utf8(std::string_view text) noexcept {
  std::size_t index = 0;
  while (index < text.size()) {
    const auto lead = static_cast<unsigned char>(text[index]);
    if (lead < 0x80u) {
      ++index;
      continue;
    }

    std::size_t continuation_count = 0;
    std::uint32_t code_point = 0;
    if ((lead & 0xE0u) == 0xC0u) {
      continuation_count = 1;
      code_point = lead & 0x1Fu;
    } else if ((lead & 0xF0u) == 0xE0u) {
      continuation_count = 2;
      code_point = lead & 0x0Fu;
    } else if ((lead & 0xF8u) == 0xF0u) {
      continuation_count = 3;
      code_point = lead & 0x07u;
    } else {
      return false;
    }

    if (index + continuation_count >= text.size()) {
      return false;
    }
    for (std::size_t offset = 1; offset <= continuation_count; ++offset) {
      const auto continuation = static_cast<unsigned char>(text[index + offset]);
      if ((continuation & 0xC0u) != 0x80u) {
        return false;
      }
      code_point = (code_point << 6) | (continuation & 0x3Fu);
    }

    const std::uint32_t minimum = (continuation_count == 1) ? 0x80u : (continuation_count == 2 ? 0x800u : 0x10000u);
    if (code_point < minimum) {
      return false;
    }
    if (code_point > 0x10FFFFu) {
      return false;
    }
    if (code_point >= 0xD800u && code_point <= 0xDFFFu) {
      return false;
    }
    index += continuation_count + 1;
  }
  return true;
}

Result<std::string> validate_identifier(std::string_view text, std::size_t max_length, std::string_view what) {
  if (text.empty()) {
    return Explanation(ErrorCode::IdentifierEmpty, std::string(what) + " is empty");
  }
  if (text.size() > max_length) {
    return Explanation(ErrorCode::IdentifierTooLong, std::string(what) + " is " + std::to_string(text.size()) +
                                                         " bytes, maximum is " + std::to_string(max_length));
  }
  if (!is_ascii_alphanumeric(text.front())) {
    return Explanation(ErrorCode::InvalidIdentifierSyntax,
                       std::string(what) + " must start with an ASCII letter or digit, " + describe_offset(0));
  }
  for (std::size_t index = 0; index < text.size(); ++index) {
    if (!is_identifier_character(text[index])) {
      return Explanation(ErrorCode::InvalidIdentifierSyntax,
                         std::string(what) + " contains a character outside [A-Za-z0-9._-] " +
                             describe_offset(index));
    }
  }
  return std::string(text);
}

Result<std::string> validate_text(std::string_view text, std::size_t max_length, std::string_view what) {
  if (text.size() > max_length) {
    return Explanation(ErrorCode::TextTooLong, std::string(what) + " is " + std::to_string(text.size()) +
                                                   " bytes, maximum is " + std::to_string(max_length));
  }
  if (!is_valid_utf8(text)) {
    return Explanation(ErrorCode::TextInvalidUtf8, std::string(what) + " is not valid UTF-8");
  }
  for (std::size_t index = 0; index < text.size(); ++index) {
    const auto value = static_cast<unsigned char>(text[index]);
    if (value < 0x20u || value == 0x7Fu) {
      return Explanation(ErrorCode::TextControlCharacter,
                         std::string(what) + " contains a control character " + describe_offset(index));
    }
  }
  return std::string(text);
}

Result<ExternalRef> ExternalRef::parse(std::string_view kind, std::string_view value) {
  if (kind.empty()) {
    return Explanation(ErrorCode::ExternalReferenceInvalid, "external reference kind is empty");
  }
  if (value.empty()) {
    return Explanation(ErrorCode::ExternalReferenceInvalid, "external reference value is empty");
  }
  Result<std::string> validated_kind =
      validate_identifier(kind, max_external_reference_kind_length, "external reference kind");
  if (!validated_kind.has_value()) {
    return validated_kind.rejection();
  }
  Result<std::string> validated_value =
      validate_text(value, max_external_reference_length, "external reference value");
  if (!validated_value.has_value()) {
    return validated_value.rejection();
  }
  return ExternalRef::from_trusted(validated_kind.move_value(), validated_value.move_value());
}

}  // namespace dccp::epoch
