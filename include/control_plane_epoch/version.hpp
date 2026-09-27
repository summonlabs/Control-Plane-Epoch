// Control Plane Epoch 1.0.0 - Summon Software Labs
// Version constants. The CMake project version is checked against this header
// at configure time, so the two can never disagree silently.
#pragma once

namespace dccp::epoch {

inline constexpr int version_major = 1;
inline constexpr int version_minor = 0;
inline constexpr int version_patch = 0;

/// Human-readable library version. Product code and tooling must not parse
/// this string; use the integer constants above.
inline constexpr char version_string[] = "1.0.0";

/// Durable image format version. A store written by a different format version
/// is refused rather than reinterpreted.
inline constexpr int durable_format_version = 1;

/// Canonical durable schema version carried inside the image payload.
inline constexpr int durable_schema_version = 1;

/// Framed transport protocol version.
inline constexpr int protocol_version = 1;

}  // namespace dccp::epoch
