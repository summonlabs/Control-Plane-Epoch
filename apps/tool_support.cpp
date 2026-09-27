// Control Plane Epoch 1.0.0 - Summon Software Labs
// Shared helpers for the first-party tools.
#include "tool_support.hpp"

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>

#include "arguments.hpp"

namespace cpe_app {

void print_field(std::string_view key, std::string_view value) {
  std::cout << key << '=' << value << '\n';
  std::cout.flush();
}

void print_line(std::string_view text) {
  std::cout << text << '\n';
  std::cout.flush();
}

int report_rejection(const dccp::epoch::Explanation& explanation) {
  print_line("rejected code=" + std::string(explanation.token()) + " retryable=" + bool_token(explanation.retryable()) +
             " detail=" + (explanation.detail().empty() ? std::string("-") : explanation.detail()));
  return explanation.code() == dccp::epoch::ErrorCode::Ok ? exit_ok : exit_rejected;
}

int report_rejection(const dccp::epoch::ValidationOutcome& outcome) {
  if (outcome.accepted()) {
    print_line("validation accepted=true");
    return exit_ok;
  }
  print_line("validation accepted=false code=" + std::string(outcome.rejection()->token()) + " detail=" +
             (outcome.rejection()->detail().empty() ? std::string("-") : outcome.rejection()->detail()));
  return exit_rejected;
}

int report_failure(const dccp::epoch::EpochError& error) {
  print_line("failure code=" + std::string(error.explanation().token()) + " detail=" +
             (error.explanation().detail().empty() ? std::string("-") : error.explanation().detail()));
  return exit_infrastructure;
}

std::string bool_token(bool value) { return value ? "true" : "false"; }

std::string digest_or_dash(const dccp::epoch::Sha256Digest& digest) {
  return digest.is_zero() ? std::string("-") : digest.to_hex();
}

Endpoint parse_endpoint(const std::string& text) {
  const std::size_t colon = text.rfind(':');
  if (colon == std::string::npos) {
    throw UsageError("endpoint '" + text + "' must be written as host:port");
  }
  Endpoint endpoint;
  endpoint.host = text.substr(0, colon);
  const std::string port_text = text.substr(colon + 1);
  if (endpoint.host.empty() || port_text.empty() || port_text.size() > 5) {
    throw UsageError("endpoint '" + text + "' must be written as host:port");
  }
  unsigned int port = 0;
  for (const char character : port_text) {
    if (character < '0' || character > '9') {
      throw UsageError("endpoint '" + text + "' has a non-numeric port");
    }
    port = (port * 10u) + static_cast<unsigned int>(character - '0');
  }
  if (port == 0 || port > 65535u) {
    throw UsageError("endpoint '" + text + "' has a port outside 1..65535");
  }
  endpoint.port = static_cast<std::uint16_t>(port);
  return endpoint;
}

dccp::epoch::Result<dccp::epoch::ProvenanceInput> make_provenance(std::string_view kind_token,
                                                                 const std::string& source,
                                                                 const std::string& note) {
  using namespace dccp::epoch;
  Result<ProvenanceSourceKind> kind = parse_provenance_source_kind(kind_token);
  if (!kind.has_value()) {
    return kind.rejection();
  }
  Result<ProvenanceSourceId> parsed_source = ProvenanceSourceId::parse(source, "provenance source");
  if (!parsed_source.has_value()) {
    return parsed_source.rejection();
  }
  return ProvenanceInput::create(kind.value(), parsed_source.move_value(), std::nullopt, note);
}

dccp::epoch::Result<dccp::epoch::ControllerIncarnationId> parse_incarnation(const std::string& text) {
  return dccp::epoch::ControllerIncarnationId::from_hex(text);
}

std::optional<std::string> read_stdin_line() {
  std::string line;
  if (!std::getline(std::cin, line)) {
    return std::nullopt;
  }
  return line;
}

void await_stdin_trigger() {
  print_line("controller-awaiting-trigger");
  const std::optional<std::string> line = read_stdin_line();
  if (!line.has_value()) {
    print_line("controller-trigger-eof");
    std::exit(exit_ok);
  }
}

}  // namespace cpe_app
