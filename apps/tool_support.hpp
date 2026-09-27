// Control Plane Epoch 1.0.0 - Summon Software Labs
// Shared helpers for the first-party tools: deterministic output, exit-code
// mapping, endpoint parsing, and provenance construction.
#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "control_plane_epoch/control_plane_epoch.hpp"

namespace cpe_app {

/// Exit codes are stable and documented:
///   0  the command completed (including a domain rejection, which is reported
///      on stdout with its stable code)
///   1  infrastructure failure (I/O, integrity, protocol, configuration)
///   2  command-line usage error
///   3  the authority rejected the command
inline constexpr int exit_ok = 0;
inline constexpr int exit_infrastructure = 1;
inline constexpr int exit_usage = 2;
inline constexpr int exit_rejected = 3;

/// Prints one deterministic "key=value" line. Values never contain spaces
/// unless the caller quotes them explicitly.
void print_field(std::string_view key, std::string_view value);
void print_line(std::string_view text);

/// Prints a rejection in the canonical machine-readable form and returns the
/// exit code the tool should use.
int report_rejection(const dccp::epoch::Explanation& explanation);
int report_rejection(const dccp::epoch::ValidationOutcome& outcome);
int report_failure(const dccp::epoch::EpochError& error);

[[nodiscard]] std::string bool_token(bool value);
[[nodiscard]] std::string digest_or_dash(const dccp::epoch::Sha256Digest& digest);

/// Parses "host:port". Rejects a missing or malformed port.
struct Endpoint {
  std::string host;
  std::uint16_t port = 0;
};

[[nodiscard]] Endpoint parse_endpoint(const std::string& text);

/// Builds a provenance input from a source kind token and a source identifier.
[[nodiscard]] dccp::epoch::Result<dccp::epoch::ProvenanceInput> make_provenance(std::string_view kind_token,
                                                                               const std::string& source,
                                                                               const std::string& note);

/// Parses an incarnation identity from hexadecimal.
[[nodiscard]] dccp::epoch::Result<dccp::epoch::ControllerIncarnationId> parse_incarnation(const std::string& text);

/// Reads one line from standard input. Returns std::nullopt at end of input,
/// which is how a tool observes that its parent closed the pipe.
[[nodiscard]] std::optional<std::string> read_stdin_line();

/// Blocks until one line has been read from standard input. Used by the
/// controller tool to hold a token across an externally triggered state change
/// without relying on a timer.
void await_stdin_trigger();

}  // namespace cpe_app
