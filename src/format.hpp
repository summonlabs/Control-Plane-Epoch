// Control Plane Epoch 1.0.0 - Summon Software Labs
// Internal text formatting helpers shared by record rendering. Not installed.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace dccp::epoch::detail {

[[nodiscard]] inline std::string yes_no(bool value) { return value ? "yes" : "no"; }

[[nodiscard]] inline std::string quoted(std::string_view value) { return "\"" + std::string(value) + "\""; }

/// Renders an optional text field, using "-" for an absent value so that the
/// rendering stays single-line and deterministic.
[[nodiscard]] inline std::string or_dash(const std::string& value) { return value.empty() ? "-" : value; }

inline void append_field(std::string& target, std::string_view key, std::string_view value) {
  if (!target.empty()) {
    target.push_back(' ');
  }
  target.append(key);
  target.push_back('=');
  target.append(value);
}

}  // namespace dccp::epoch::detail
