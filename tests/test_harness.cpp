// Control Plane Epoch 1.0.0 - Summon Software Labs
// Test harness implementation: registry, temporary directories, and real
// operating-system child processes.
#include "test_harness.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <iostream>
#include <random>
#include <sstream>

#include "control_plane_epoch/error.hpp"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <csignal>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace cpe_test {
namespace {

[[nodiscard]] std::string random_suffix() {
  std::random_device device;
  std::mt19937_64 generator(device());
  std::uniform_int_distribution<std::uint64_t> distribution;
  std::ostringstream stream;
  stream << std::hex << distribution(generator);
  return stream.str();
}

[[nodiscard]] std::string shell_join(const std::filesystem::path& executable,
                                     const std::vector<std::string>& arguments) {
  std::string command = "\"" + executable.string() + "\"";
  for (const std::string& argument : arguments) {
    command += " \"";
    command += argument;
    command += "\"";
  }
  return command;
}

}  // namespace

void fail(const char* file, int line, const std::string& expression, const std::string& detail) {
  std::ostringstream stream;
  stream << file << ':' << line << ": requirement failed: " << expression;
  if (!detail.empty()) {
    stream << " [" << detail << ']';
  }
  throw Failure(stream.str());
}

std::vector<TestCase>& registry() {
  static std::vector<TestCase> cases;
  return cases;
}

Registrar::Registrar(const char* suite, const char* name, std::function<void()> body) {
  registry().push_back(TestCase{suite, name, std::move(body)});
}

int run_all(const std::string& filter, const std::string& skip) {
  int failures = 0;
  int executed = 0;
  const auto& cases = registry();
  for (const TestCase& test : cases) {
    const std::string full = test.suite + "." + test.name;
    if (!filter.empty() && full.find(filter) == std::string::npos) {
      continue;
    }
    if (!skip.empty() && full.find(skip) != std::string::npos) {
      std::cout << "[skip] " << full << '\n';
      continue;
    }
    ++executed;
    try {
      test.body();
      std::cout << "[pass] " << full << '\n';
    } catch (const std::exception& error) {
      ++failures;
      std::cout << "[fail] " << full << ": " << error.what() << '\n';
    }
  }
  std::cout << "executed=" << executed << " failed=" << failures << '\n';
  std::cout.flush();
  if (executed == 0) {
    std::cout << "[fail] no test cases matched filter '" << filter << "'\n";
    return 1;
  }
  return failures;
}

TempDirectory::TempDirectory() {
  const std::filesystem::path base = std::filesystem::temp_directory_path();
  path_ = base / ("control-plane-epoch-test-" + random_suffix());
  std::error_code error;
  std::filesystem::create_directories(path_, error);
  if (error) {
    throw Failure("could not create temporary directory " + path_.string() + ": " + error.message());
  }
}

TempDirectory::~TempDirectory() {
  std::error_code error;
  std::filesystem::remove_all(path_, error);
}

std::filesystem::path TempDirectory::file(const std::string& name) const { return path_ / name; }

#if defined(_WIN32)

ChildProcess::ChildProcess(const std::filesystem::path& executable, const std::vector<std::string>& arguments) {
  SECURITY_ATTRIBUTES attributes{};
  attributes.nLength = sizeof(attributes);
  attributes.bInheritHandle = TRUE;

  HANDLE stdout_read = nullptr;
  HANDLE stdout_write = nullptr;
  HANDLE stdin_read = nullptr;
  HANDLE stdin_write = nullptr;
  if (::CreatePipe(&stdout_read, &stdout_write, &attributes, 0) == 0 ||
      ::CreatePipe(&stdin_read, &stdin_write, &attributes, 0) == 0) {
    throw Failure("could not create child pipes");
  }
  ::SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0);
  ::SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT, 0);

  std::string command = shell_join(executable, arguments);
  std::vector<char> mutable_command(command.begin(), command.end());
  mutable_command.push_back('\0');

  STARTUPINFOA startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdOutput = stdout_write;
  startup.hStdError = stdout_write;
  startup.hStdInput = stdin_read;

  PROCESS_INFORMATION process{};
  const BOOL created = ::CreateProcessA(nullptr, mutable_command.data(), nullptr, nullptr, TRUE,
                                        CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process);
  ::CloseHandle(stdout_write);
  ::CloseHandle(stdin_read);
  if (created == 0) {
    ::CloseHandle(stdout_read);
    ::CloseHandle(stdin_write);
    throw Failure("could not start " + executable.string() + " (error " +
                  std::to_string(::GetLastError()) + ")");
  }

  ::CloseHandle(process.hThread);
  process_ = process.hProcess;
  process_id_ = static_cast<std::uint32_t>(process.dwProcessId);
  stdout_read_ = stdout_read;
  stdin_write_ = stdin_write;
}

void ChildProcess::close_handles() noexcept {
  if (stdout_read_ != nullptr) {
    ::CloseHandle(static_cast<HANDLE>(stdout_read_));
    stdout_read_ = nullptr;
  }
  if (stdin_write_ != nullptr) {
    ::CloseHandle(static_cast<HANDLE>(stdin_write_));
    stdin_write_ = nullptr;
  }
}

ChildProcess::~ChildProcess() {
  if (process_ != nullptr) {
    if (!reaped_) {
      ::TerminateProcess(static_cast<HANDLE>(process_), 1);
      ::WaitForSingleObject(static_cast<HANDLE>(process_), INFINITE);
    }
    ::CloseHandle(static_cast<HANDLE>(process_));
    process_ = nullptr;
  }
  close_handles();
}

bool ChildProcess::exited() {
  if (reaped_) {
    return true;
  }
  if (process_ == nullptr) {
    return true;
  }
  const DWORD status = ::WaitForSingleObject(static_cast<HANDLE>(process_), 0);
  if (status == WAIT_OBJECT_0) {
    DWORD code = 0;
    ::GetExitCodeProcess(static_cast<HANDLE>(process_), &code);
    exit_code_ = static_cast<int>(code);
    exited_ = true;
    return true;
  }
  return false;
}

bool ChildProcess::fill_buffer() {
  if (stdout_read_ == nullptr) {
    return false;
  }
  char buffer[512];
  DWORD read = 0;
  if (::ReadFile(static_cast<HANDLE>(stdout_read_), buffer, sizeof(buffer), &read, nullptr) == 0) {
    return false;
  }
  if (read == 0) {
    return false;
  }
  pending_.append(buffer, read);
  return true;
}

std::optional<std::string> ChildProcess::read_line() {
  while (true) {
    const std::size_t position = pending_.find('\n');
    if (position != std::string::npos) {
      std::string line = pending_.substr(0, position);
      pending_.erase(0, position + 1);
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }
      return line;
    }
    if (!fill_buffer()) {
      return std::nullopt;
    }
  }
}

std::vector<std::string> ChildProcess::read_all_lines() {
  std::vector<std::string> lines;
  while (true) {
    const std::optional<std::string> line = read_line();
    if (!line.has_value()) {
      break;
    }
    lines.push_back(*line);
  }
  return lines;
}

void ChildProcess::write_line(const std::string& line) {
  if (stdin_write_ == nullptr) {
    throw Failure("the child's standard input is closed");
  }
  std::string text = line;
  text.push_back('\n');
  DWORD written = 0;
  if (::WriteFile(static_cast<HANDLE>(stdin_write_), text.data(), static_cast<DWORD>(text.size()), &written,
                  nullptr) == 0 ||
      written != text.size()) {
    throw Failure("could not write to the child's standard input");
  }
}

void ChildProcess::close_stdin() noexcept {
  if (stdin_write_ != nullptr) {
    ::CloseHandle(static_cast<HANDLE>(stdin_write_));
    stdin_write_ = nullptr;
  }
}

void ChildProcess::terminate() {
  if (process_ != nullptr && !reaped_) {
    ::TerminateProcess(static_cast<HANDLE>(process_), 1);
  }
}

int ChildProcess::wait() {
  if (reaped_) {
    return exit_code_;
  }
  if (process_ == nullptr) {
    return exit_code_;
  }
  ::WaitForSingleObject(static_cast<HANDLE>(process_), INFINITE);
  DWORD code = 0;
  ::GetExitCodeProcess(static_cast<HANDLE>(process_), &code);
  exit_code_ = static_cast<int>(code);
  exited_ = true;
  reaped_ = true;
  return exit_code_;
}

bool ChildProcess::running() { return !exited(); }

#else

ChildProcess::ChildProcess(const std::filesystem::path& executable, const std::vector<std::string>& arguments) {
  int stdout_pipe[2] = {-1, -1};
  int stdin_pipe[2] = {-1, -1};
  if (::pipe(stdout_pipe) != 0 || ::pipe(stdin_pipe) != 0) {
    throw Failure("could not create child pipes");
  }

  const pid_t pid = ::fork();
  if (pid < 0) {
    throw Failure("could not fork");
  }
  if (pid == 0) {
    ::dup2(stdin_pipe[0], STDIN_FILENO);
    ::dup2(stdout_pipe[1], STDOUT_FILENO);
    ::dup2(stdout_pipe[1], STDERR_FILENO);
    ::close(stdin_pipe[0]);
    ::close(stdin_pipe[1]);
    ::close(stdout_pipe[0]);
    ::close(stdout_pipe[1]);

    std::vector<char*> argv;
    std::string program = executable.string();
    argv.push_back(program.data());
    std::vector<std::string> storage = arguments;
    for (std::string& argument : storage) {
      argv.push_back(argument.data());
    }
    argv.push_back(nullptr);
    ::execv(program.c_str(), argv.data());
    ::_exit(127);
  }

  ::close(stdin_pipe[0]);
  ::close(stdout_pipe[1]);
  process_id_ = static_cast<std::uint32_t>(pid);
  stdout_read_ = reinterpret_cast<void*>(static_cast<std::intptr_t>(stdout_pipe[0]));
  stdin_write_ = reinterpret_cast<void*>(static_cast<std::intptr_t>(stdin_pipe[1]));
}

void ChildProcess::close_handles() noexcept {
  if (stdout_read_ != nullptr) {
    ::close(static_cast<int>(reinterpret_cast<std::intptr_t>(stdout_read_)));
    stdout_read_ = nullptr;
  }
  if (stdin_write_ != nullptr) {
    ::close(static_cast<int>(reinterpret_cast<std::intptr_t>(stdin_write_)));
    stdin_write_ = nullptr;
  }
}

ChildProcess::~ChildProcess() {
  if (!reaped_ && process_id_ != 0) {
    ::kill(static_cast<pid_t>(process_id_), SIGKILL);
    int status = 0;
    ::waitpid(static_cast<pid_t>(process_id_), &status, 0);
  }
  close_handles();
}

bool ChildProcess::exited() {
  if (reaped_) {
    return true;
  }
  int status = 0;
  const pid_t result = ::waitpid(static_cast<pid_t>(process_id_), &status, WNOHANG);
  if (result == static_cast<pid_t>(process_id_)) {
    exit_code_ = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
    exited_ = true;
    reaped_ = true;
    return true;
  }
  return false;
}

bool ChildProcess::fill_buffer() {
  if (stdout_read_ == nullptr) {
    return false;
  }
  char buffer[512];
  const ssize_t read = ::read(static_cast<int>(reinterpret_cast<std::intptr_t>(stdout_read_)), buffer,
                              sizeof(buffer));
  if (read <= 0) {
    return false;
  }
  pending_.append(buffer, static_cast<std::size_t>(read));
  return true;
}

std::optional<std::string> ChildProcess::read_line() {
  while (true) {
    const std::size_t position = pending_.find('\n');
    if (position != std::string::npos) {
      std::string line = pending_.substr(0, position);
      pending_.erase(0, position + 1);
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }
      return line;
    }
    if (!fill_buffer()) {
      return std::nullopt;
    }
  }
}

std::vector<std::string> ChildProcess::read_all_lines() {
  std::vector<std::string> lines;
  while (true) {
    const std::optional<std::string> line = read_line();
    if (!line.has_value()) {
      break;
    }
    lines.push_back(*line);
  }
  return lines;
}

void ChildProcess::write_line(const std::string& line) {
  if (stdin_write_ == nullptr) {
    throw Failure("the child's standard input is closed");
  }
  const int descriptor = static_cast<int>(reinterpret_cast<std::intptr_t>(stdin_write_));
  std::string text = line;
  text.push_back('\n');
  std::size_t offset = 0;
  while (offset < text.size()) {
    const ssize_t written = ::write(descriptor, text.data() + offset, text.size() - offset);
    if (written <= 0) {
      throw Failure("could not write to the child's standard input");
    }
    offset += static_cast<std::size_t>(written);
  }
}

void ChildProcess::close_stdin() noexcept {
  if (stdin_write_ != nullptr) {
    ::close(static_cast<int>(reinterpret_cast<std::intptr_t>(stdin_write_)));
    stdin_write_ = nullptr;
  }
}

void ChildProcess::terminate() {
  if (!reaped_ && process_id_ != 0) {
    ::kill(static_cast<pid_t>(process_id_), SIGKILL);
  }
}

int ChildProcess::wait() {
  if (reaped_) {
    return exit_code_;
  }
  int status = 0;
  ::waitpid(static_cast<pid_t>(process_id_), &status, 0);
  exit_code_ = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
  exited_ = true;
  reaped_ = true;
  return exit_code_;
}

bool ChildProcess::running() { return !exited(); }

#endif

}  // namespace cpe_test
