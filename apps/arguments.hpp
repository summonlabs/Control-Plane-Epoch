// Control Plane Epoch 1.0.0 - Summon Software Labs
// Minimal, strict command-line parsing shared by the three first-party tools.
//
// Parsing is deliberately strict: an unknown option, a missing value, or a
// repeated option is a usage error rather than something that is ignored. No
// argument is ever interpreted as a path component, and nothing is executed.
#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace cpe_app {

/// Raised for any command-line problem. The tools print the message plus usage
/// and exit with status 2.
class UsageError : public std::runtime_error {
 public:
  explicit UsageError(const std::string& message) : std::runtime_error(message) {}
};

class Arguments {
 public:
  /// Parses argv. Options are "--name value" or "--name=value". Anything else is
  /// a positional argument.
  [[nodiscard]] static Arguments parse(int argc, const char* const* argv);

  [[nodiscard]] bool has(std::string_view name) const;
  [[nodiscard]] std::optional<std::string> get(std::string_view name) const;
  [[nodiscard]] std::string require(std::string_view name) const;

  /// Parses an unsigned option, rejecting signs, overflow, and trailing text.
  [[nodiscard]] std::optional<std::uint64_t> get_unsigned(std::string_view name) const;
  [[nodiscard]] std::uint64_t require_unsigned(std::string_view name, std::uint64_t default_value) const;

  /// Splits a comma-separated option into its parts, rejecting empty parts.
  [[nodiscard]] std::vector<std::string> require_list(std::string_view name) const;

  [[nodiscard]] const std::vector<std::string>& positionals() const noexcept { return positionals_; }

  /// Reads a file whose content is used as an argument value (for example an
  /// authority token persisted by a previous run). Bounded and fully validated
  /// by the caller; a missing or oversized file is a usage error.
  [[nodiscard]] static std::string read_argument_file(const std::string& path);

  /// Writes text to a file with exclusive creation plus atomic replace, so a
  /// reader never observes a partial value.
  static void write_argument_file(const std::string& path, std::string_view text);

 private:
  std::vector<std::pair<std::string, std::string>> options_;
  std::vector<std::string> positionals_;
};

}  // namespace cpe_app
