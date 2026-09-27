// Control Plane Epoch 1.0.0 - Summon Software Labs
// Minimal, dependency-free test harness.
//
// There is no watchdog and no timeout anywhere in this harness. A test that
// hangs is a defect and surfaces as a hang. Waiting for an external process is
// always a blocking wait: a process that never produces the expected line ends
// at end-of-input, which the test turns into an explicit assertion failure.
#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace cpe_test {

class Failure : public std::runtime_error {
 public:
  explicit Failure(const std::string& message) : std::runtime_error(message) {}
};

[[noreturn]] void fail(const char* file, int line, const std::string& expression, const std::string& detail);

struct TestCase {
  std::string suite;
  std::string name;
  std::function<void()> body;
};

std::vector<TestCase>& registry();

struct Registrar {
  Registrar(const char* suite, const char* name, std::function<void()> body);
};

/// Runs every registered case, optionally filtered by substring, optionally
/// skipping cases whose "suite.name" contains the skip substring. Returns the
/// number of failures, and treats "zero cases ran" as a failure.
int run_all(const std::string& filter, const std::string& skip = std::string());

/// Unique-per-process temporary directory under the operating system's temp
/// area. Identity uses operating-system entropy so concurrent test processes
/// never collide.
class TempDirectory {
 public:
  TempDirectory();
  ~TempDirectory();

  TempDirectory(const TempDirectory&) = delete;
  TempDirectory& operator=(const TempDirectory&) = delete;

  [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }
  [[nodiscard]] std::filesystem::path file(const std::string& name) const;

 private:
  std::filesystem::path path_;
};

/// Real operating-system child process with a captured stdout pipe and a writable
/// stdin pipe. The destructor always terminates and reaps the child, so a failing
/// assertion can never leave an orphan behind.
class ChildProcess {
 public:
  ChildProcess(const std::filesystem::path& executable, const std::vector<std::string>& arguments);
  ~ChildProcess();

  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;

  [[nodiscard]] bool running();
  [[nodiscard]] std::uint32_t process_id() const noexcept { return process_id_; }

  /// Blocks until one complete line of stdout is available. Returns std::nullopt
  /// at end of input, which is what a test sees when the child exits without
  /// producing the line it was waiting for.
  [[nodiscard]] std::optional<std::string> read_line();

  /// Blocks until every remaining line has been read.
  [[nodiscard]] std::vector<std::string> read_all_lines();

  /// Writes one line to the child's standard input. Blocking and unbuffered.
  void write_line(const std::string& line);

  /// Closes the child's standard input, which a child waiting for a trigger
  /// observes as end of input.
  void close_stdin() noexcept;

  /// Terminates the child with an unconditional operating-system termination
  /// path: no cooperative signal, exactly like a crash.
  void terminate();

  /// Blocks until the child exits and returns its exit code.
  int wait();

  /// True once the child has exited. Never blocks.
  [[nodiscard]] bool exited();

 private:
  void close_handles() noexcept;
  [[nodiscard]] bool fill_buffer();

  void* process_ = nullptr;
  void* stdout_read_ = nullptr;
  void* stdin_write_ = nullptr;
  std::uint32_t process_id_ = 0;
  bool exited_ = false;
  bool reaped_ = false;
  int exit_code_ = 0;
  std::string pending_;
};

/// Deterministic, seeded generator used by property and adversarial suites.
/// Every failure message that depends on it reports the seed, so a run is
/// reproducible from the reported value alone.
class DeterministicRandom {
 public:
  explicit DeterministicRandom(std::uint64_t seed)
      : state_(seed == 0 ? 0x9E3779B97F4A7C15ull : seed), seed_(seed == 0 ? 0x9E3779B97F4A7C15ull : seed) {}

  [[nodiscard]] std::uint64_t next() {
    state_ ^= state_ << 13;
    state_ ^= state_ >> 7;
    state_ ^= state_ << 17;
    return state_;
  }

  [[nodiscard]] std::uint64_t next_below(std::uint64_t bound) { return bound == 0 ? 0 : next() % bound; }
  [[nodiscard]] std::uint64_t seed() const noexcept { return seed_; }

 private:
  std::uint64_t state_;
  std::uint64_t seed_ = 0;
};

}  // namespace cpe_test

// Comparison operands are taken by value. Binding them by reference would leave a
// dangling reference whenever the expression yields a reference into a temporary,
// for example `authority.status().snapshot_digest()`, which is a real
// use-after-scope defect rather than a style question. Constant operands then make
// the condition constant, which MSVC reports as C4127; it is suppressed here
// because the comparison is exactly what the macro is for.
#if defined(_MSC_VER)
#define CPE_SUPPRESS_CONSTANT_CONDITION __pragma(warning(suppress : 4127))
#else
#define CPE_SUPPRESS_CONSTANT_CONDITION
#endif
#define CPE_TEST(suite, name)                                                                    \
  static void cpe_test_body_##suite##_##name();                                                  \
  static const ::cpe_test::Registrar cpe_test_registrar_##suite##_##name(#suite, #name,          \
                                                                        cpe_test_body_##suite##_##name); \
  static void cpe_test_body_##suite##_##name()

#define CPE_REQUIRE(expression)                        \
  do {                                                 \
    if (!(expression)) {                               \
      ::cpe_test::fail(__FILE__, __LINE__, #expression, ""); \
    }                                                  \
  } while (false)

#define CPE_REQUIRE_MSG(expression, detail)                          \
  do {                                                               \
    if (!(expression)) {                                             \
      ::cpe_test::fail(__FILE__, __LINE__, #expression, (detail));   \
    }                                                                \
  } while (false)

#define CPE_REQUIRE_EQ(lhs, rhs)                                                          \
  do {                                                                                    \
    const auto cpe_lhs = (lhs);                                                          \
    const auto cpe_rhs = (rhs);                                                          \
    CPE_SUPPRESS_CONSTANT_CONDITION                                                     \
    if (!(cpe_lhs == cpe_rhs)) {                                                          \
      ::cpe_test::fail(__FILE__, __LINE__, #lhs " == " #rhs, cpe_test::describe_mismatch(cpe_lhs, cpe_rhs)); \
    }                                                                                     \
  } while (false)

#define CPE_REQUIRE_THROWS_CODE(expression, expected_code)                                        \
  do {                                                                                            \
    bool cpe_threw = false;                                                                       \
    try {                                                                                         \
      (void)(expression);                                                                         \
    } catch (const ::dccp::epoch::EpochError& cpe_error) {                                         \
      cpe_threw = true;                                                                           \
      if (cpe_error.code() != (expected_code)) {                                                   \
        ::cpe_test::fail(__FILE__, __LINE__, #expression " throws " #expected_code,                \
                         std::string("actual code ") + std::string(cpe_error.explanation().token())); \
      }                                                                                           \
    }                                                                                             \
    if (!cpe_threw) {                                                                             \
      ::cpe_test::fail(__FILE__, __LINE__, #expression " throws", "no exception");                 \
    }                                                                                             \
  } while (false)

#define CPE_REQUIRE_NO_THROW(expression)                                                       \
  do {                                                                                         \
    try {                                                                                      \
      (void)(expression);                                                                      \
    } catch (const std::exception& cpe_error) {                                                \
      ::cpe_test::fail(__FILE__, __LINE__, #expression " does not throw", cpe_error.what());   \
    }                                                                                          \
  } while (false)




