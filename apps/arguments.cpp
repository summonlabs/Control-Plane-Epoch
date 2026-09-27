// Control Plane Epoch 1.0.0 - Summon Software Labs
// Strict command-line parsing for the first-party tools.
#include "arguments.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>

namespace cpe_app {
namespace {

[[nodiscard]] bool is_option(std::string_view text) {
  return text.size() > 2 && text[0] == '-' && text[1] == '-';
}

}  // namespace

Arguments Arguments::parse(int argc, const char* const* argv) {
  Arguments arguments;
  for (int index = 1; index < argc; ++index) {
    const std::string_view token(argv[index]);
    if (!is_option(token)) {
      arguments.positionals_.emplace_back(token);
      continue;
    }

    const std::string name(token.substr(2));
    const std::size_t equals = name.find('=');
    std::string key = equals == std::string::npos ? name : name.substr(0, equals);
    std::string value;
    if (equals != std::string::npos) {
      value = name.substr(equals + 1);
    } else if (index + 1 < argc && !is_option(std::string_view(argv[index + 1]))) {
      value = argv[++index];
    }

    if (key.empty()) {
      throw UsageError("an option name is empty");
    }
    for (const auto& existing : arguments.options_) {
      if (existing.first == key) {
        throw UsageError("option --" + key + " was supplied more than once");
      }
    }
    arguments.options_.emplace_back(std::move(key), std::move(value));
  }
  return arguments;
}

bool Arguments::has(std::string_view name) const {
  for (const auto& option : options_) {
    if (option.first == name) {
      return true;
    }
  }
  return false;
}

std::optional<std::string> Arguments::get(std::string_view name) const {
  for (const auto& option : options_) {
    if (option.first == name) {
      return option.second;
    }
  }
  return std::nullopt;
}

std::string Arguments::require(std::string_view name) const {
  for (const auto& option : options_) {
    if (option.first == name) {
      if (option.second.empty()) {
        throw UsageError("option --" + std::string(name) + " requires a value");
      }
      return option.second;
    }
  }
  throw UsageError("option --" + std::string(name) + " is required");
}

std::optional<std::uint64_t> Arguments::get_unsigned(std::string_view name) const {
  const std::optional<std::string> text = get(name);
  if (!text.has_value()) {
    return std::nullopt;
  }
  if (text->empty() || text->size() > 20) {
    throw UsageError("option --" + std::string(name) + " is not an unsigned integer");
  }
  if (text->size() > 1 && text->front() == '0') {
    throw UsageError("option --" + std::string(name) + " must not have leading zeros");
  }
  std::uint64_t value = 0;
  for (const char character : *text) {
    if (character < '0' || character > '9') {
      throw UsageError("option --" + std::string(name) + " is not an unsigned integer");
    }
    const auto digit = static_cast<std::uint64_t>(character - '0');
    if (value > (UINT64_MAX - digit) / 10u) {
      throw UsageError("option --" + std::string(name) + " overflows an unsigned integer");
    }
    value = (value * 10u) + digit;
  }
  return value;
}

std::uint64_t Arguments::require_unsigned(std::string_view name, std::uint64_t default_value) const {
  const std::optional<std::uint64_t> value = get_unsigned(name);
  return value.has_value() ? *value : default_value;
}

std::vector<std::string> Arguments::require_list(std::string_view name) const {
  const std::string text = require(name);
  std::vector<std::string> parts;
  std::size_t start = 0;
  while (true) {
    const std::size_t comma = text.find(',', start);
    const std::string part =
        comma == std::string::npos ? text.substr(start) : text.substr(start, comma - start);
    if (part.empty()) {
      throw UsageError("option --" + std::string(name) + " contains an empty list element");
    }
    parts.push_back(part);
    if (comma == std::string::npos) {
      break;
    }
    start = comma + 1;
  }
  return parts;
}

std::string Arguments::read_argument_file(const std::string& path) {
  std::error_code error;
  const auto size = std::filesystem::file_size(path, error);
  if (error) {
    throw UsageError("could not read '" + path + "': " + error.message());
  }
  if (size > 64u * 1024u) {
    throw UsageError("'" + path + "' is larger than the accepted argument size");
  }
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    throw UsageError("could not open '" + path + "'");
  }
  std::string text(static_cast<std::size_t>(size), '\0');
  stream.read(text.data(), static_cast<std::streamsize>(text.size()));
  if (!stream && !stream.eof()) {
    throw UsageError("could not read '" + path + "'");
  }
  while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) {
    text.pop_back();
  }
  if (text.empty()) {
    throw UsageError("'" + path + "' is empty");
  }
  return text;
}

void Arguments::write_argument_file(const std::string& path, std::string_view text) {
  const std::filesystem::path target(path);
  const std::filesystem::path directory =
      target.has_parent_path() ? target.parent_path() : std::filesystem::path(".");
  const std::filesystem::path temporary = directory / (target.filename().string() + ".tmp");

  {
    std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
    if (!stream) {
      throw UsageError("could not create '" + temporary.string() + "'");
    }
    stream.write(text.data(), static_cast<std::streamsize>(text.size()));
    stream.put('\n');
    stream.flush();
    if (!stream) {
      throw UsageError("could not write '" + temporary.string() + "'");
    }
  }

  std::error_code error;
  std::filesystem::rename(temporary, target, error);
  if (error) {
    std::filesystem::remove(temporary, error);
    throw UsageError("could not publish '" + path + "'");
  }
}

}  // namespace cpe_app
