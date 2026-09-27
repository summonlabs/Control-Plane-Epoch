// Control Plane Epoch 1.0.0 - Summon Software Labs
// Multiprocess authority and fencing proof.
//
// Every case in this file starts real operating-system processes: the authority
// runtime holds the store's exclusive writer lock and serves a real loopback
// socket, and each controller is an independent process with its own
// incarnation. Nothing here is simulated, and no timeout is used: a process that
// does not produce the line a case waits for ends at end-of-input, which the case
// turns into an explicit assertion failure with the collected output.
#include <algorithm>
#include <filesystem>
#include <string>
#include <vector>

#include "control_plane_epoch/control_plane_epoch.hpp"

#include "test_executables.hpp"
#include "test_support.hpp"

namespace {

using cpe_test::ChildProcess;
using cpe_test::Failure;
using cpe_test::TempDirectory;

constexpr const char* kDomain = "facility-alpha";
constexpr const char* kRoot = "authority-root";

[[nodiscard]] std::string join(const std::vector<std::string>& lines) {
  std::string text;
  for (const std::string& line : lines) {
    text += line;
    text += '\n';
  }
  return text;
}

/// Returns the value of `key` inside `line`. Only the line it is called with is
/// searched, so a key that also appears in a recovery report can never be
/// mistaken for the value the runtime reported at readiness.
[[nodiscard]] std::optional<std::string> field_of_line(const std::string& line, const std::string& key) {
  const std::string prefix = key + "=";
  {
    std::size_t position = line.find(prefix);
    while (position != std::string::npos) {
      const bool at_start = position == 0 || line[position - 1] == ' ';
      if (at_start) {
        const std::size_t value_start = position + prefix.size();
        const std::size_t value_end = line.find(' ', value_start);
        return line.substr(value_start, value_end == std::string::npos ? std::string::npos
                                                                      : value_end - value_start);
      }
      position = line.find(prefix, position + 1);
    }
  }
  return std::nullopt;
}

[[nodiscard]] std::optional<std::string> field_of(const std::vector<std::string>& lines,
                                                  const std::string& key) {
  const std::string prefix = key + "=";
  for (const std::string& line : lines) {
    std::size_t position = line.find(prefix);
    while (position != std::string::npos) {
      const bool at_start = position == 0 || line[position - 1] == ' ';
      if (at_start) {
        const std::size_t value_start = position + prefix.size();
        const std::size_t value_end = line.find(' ', value_start);
        return line.substr(value_start, value_end == std::string::npos ? std::string::npos
                                                                      : value_end - value_start);
      }
      position = line.find(prefix, position + 1);
    }
  }
  return std::nullopt;
}

[[nodiscard]] bool has_line_containing(const std::vector<std::string>& lines, const std::string& needle) {
  return std::any_of(lines.begin(), lines.end(),
                     [&needle](const std::string& line) { return line.find(needle) != std::string::npos; });
}

/// One running authority runtime process.
class AuthorityRuntime {
 public:
  AuthorityRuntime(const std::filesystem::path& store, const std::vector<std::string>& extra_arguments,
                   bool initialize) {
    std::vector<std::string> arguments{"--store", store.string(), "--bind", "127.0.0.1", "--port", "0"};
    if (initialize) {
      arguments.push_back("--init");
      arguments.push_back("--domain");
      arguments.push_back(kDomain);
      arguments.push_back("--root");
      arguments.push_back(kRoot);
      arguments.push_back("--scopes");
      arguments.push_back("authority.grant,authority.revoke,epoch.advance,facility.state");
    }
    arguments.insert(arguments.end(), extra_arguments.begin(), extra_arguments.end());

    process_ = std::make_unique<ChildProcess>(CONTROL_PLANE_EPOCH_AUTHORITY_EXE, arguments);
    while (true) {
      const std::optional<std::string> line = process_->read_line();
      if (!line.has_value()) {
        throw Failure("the authority runtime exited before reporting readiness:\n" + join(output_));
      }
      output_.push_back(*line);
      if (line->rfind("authority-ready ", 0) == 0) {
        break;
      }
      if (line->rfind("failure ", 0) == 0 || line->rfind("rejected ", 0) == 0) {
        throw Failure("the authority runtime refused to start:\n" + join(output_));
      }
    }

    ready_line_ = output_.back();
    const std::optional<std::string> endpoint = field_of_line(ready_line_, "endpoint");
    if (!endpoint.has_value()) {
      throw Failure("the authority runtime did not report an endpoint:\n" + join(output_));
    }
    endpoint_ = *endpoint;
    const std::optional<std::string> epoch = field_of_line(ready_line_, "epoch");
    if (epoch.has_value() && *epoch != "-") {
      initial_epoch_ = *epoch;
    }
  }

  ~AuthorityRuntime() {
    if (process_ != nullptr) {
      process_->terminate();
      process_->wait();
    }
  }

  AuthorityRuntime(const AuthorityRuntime&) = delete;
  AuthorityRuntime& operator=(const AuthorityRuntime&) = delete;

  [[nodiscard]] const std::string& endpoint() const { return endpoint_; }
  [[nodiscard]] const std::vector<std::string>& startup_output() const { return output_; }

  /// Value of `key` in the readiness line only, so a field that also appears in
  /// the recovery report can never be mistaken for the value reported at
  /// readiness.
  [[nodiscard]] std::optional<std::string> ready_field(const std::string& key) const {
    return field_of_line(ready_line_, key);
  }
  [[nodiscard]] ChildProcess& process() { return *process_; }

  /// Blocks until the runtime exits and returns its exit code.
  int wait() {
    const int code = process_->wait();
    output_.insert(output_.end(), pending_.begin(), pending_.end());
    return code;
  }

  /// Collects whatever the runtime has printed so far by waiting for its exit.
  [[nodiscard]] std::vector<std::string> collect_until_exit() {
    const std::vector<std::string> rest = process_->read_all_lines();
    output_.insert(output_.end(), rest.begin(), rest.end());
    return output_;
  }

 private:
  std::unique_ptr<ChildProcess> process_;
  std::vector<std::string> output_;
  std::vector<std::string> pending_;
  std::string endpoint_;
  std::string initial_epoch_;
  std::string ready_line_;
};

/// Runs one controller process to completion and returns its output.
[[nodiscard]] std::vector<std::string> run_controller(const std::string& endpoint,
                                                      const std::vector<std::string>& arguments) {
  std::vector<std::string> full{"--endpoint", endpoint};
  full.insert(full.end(), arguments.begin(), arguments.end());
  ChildProcess process(CONTROL_PLANE_EPOCH_CONTROLLER_EXE, full);
  const std::vector<std::string> lines = process.read_all_lines();
  const int code = process.wait();
  if (code != 0 && code != 3) {
    throw Failure("controller exited with code " + std::to_string(code) + ":\n" + join(lines));
  }
  return lines;
}

[[nodiscard]] std::vector<std::string> run_cli(const std::vector<std::string>& arguments) {
  ChildProcess process(CONTROL_PLANE_EPOCH_CLI_EXE, arguments);
  const std::vector<std::string> lines = process.read_all_lines();
  const int code = process.wait();
  if (code != 0 && code != 3 && code != 1) {
    throw Failure("cli exited with code " + std::to_string(code) + ":\n" + join(lines));
  }
  return lines;
}

/// Acquires the root's administrative authority over the wire and stores it in
/// the given token file. This is the domain's documented bootstrap path.
void acquire_root_authority(const std::string& endpoint, const std::filesystem::path& token_file) {
  const std::vector<std::string> lines = run_controller(
      endpoint, {"--controller", kRoot, "--action", "acquire", "--scopes",
                 "authority.grant,authority.revoke,epoch.advance", "--save-token", token_file.string()});
  if (!has_line_containing(lines, "authority-acquired")) {
    throw Failure("the authority root could not acquire administrative authority:\n" + join(lines));
  }
}

/// Registers a worker and acquires scoped mutation authority sponsored by the
/// root, persisting the token. Returns the controller's current incarnation.
void acquire_worker_authority(const std::string& endpoint, const std::string& controller,
                              const std::string& scopes, const std::filesystem::path& root_token,
                              const std::filesystem::path& worker_token) {
  const std::vector<std::string> lines =
      run_controller(endpoint, {"--controller", controller, "--action", "acquire", "--scopes", scopes,
                                "--sponsor-file", root_token.string(), "--save-token", worker_token.string()});
  if (!has_line_containing(lines, "authority-acquired")) {
    throw Failure("controller '" + controller + "' could not acquire authority:\n" + join(lines));
  }
}

}  // namespace

CPE_TEST(multiprocess, runtime_starts_initializes_and_stops_cleanly) {
  TempDirectory directory;
  const std::filesystem::path store = directory.file("store");

  // Three requests: hello, status, hello again in a second session.
  AuthorityRuntime runtime(store, {"--max-requests", "2"}, true);
  CPE_REQUIRE_MSG(has_line_containing(runtime.startup_output(), "authority-init accepted"),
                  join(runtime.startup_output()));
  CPE_REQUIRE_EQ(runtime.ready_field("domain").value_or(std::string()), std::string(kDomain));
  CPE_REQUIRE_EQ(runtime.ready_field("epoch").value_or(std::string()), std::string("1"));

  const std::vector<std::string> status =
      run_controller(runtime.endpoint(), {"--controller", "observer", "--action", "status"});
  CPE_REQUIRE_MSG(has_line_containing(status, "status initialized=yes"), join(status));
  CPE_REQUIRE_MSG(has_line_containing(status, "epoch=1"), join(status));

  const int exit_code = runtime.wait();
  CPE_REQUIRE_EQ(exit_code, 0);
  const std::vector<std::string> output = runtime.collect_until_exit();
  CPE_REQUIRE_MSG(has_line_containing(output, "authority-stopped served=2"), join(output));
  CPE_REQUIRE_MSG(has_line_containing(output, "active_connections=0"), join(output));

  // A clean shutdown releases the writer lock, so the store can be verified.
  const std::vector<std::string> verify = run_cli({"verify", "--store", store.string()});
  CPE_REQUIRE_MSG(has_line_containing(verify, "verified=yes"), join(verify));
}

CPE_TEST(multiprocess, authority_from_epoch_n_cannot_mutate_after_n_plus_one) {
  TempDirectory directory;
  const std::filesystem::path store = directory.file("store");
  const std::filesystem::path root_token = directory.file("root.token");
  const std::filesystem::path worker_token = directory.file("worker.token");

  AuthorityRuntime runtime(store, {"--max-requests", "0"}, true);
  const std::string endpoint = runtime.endpoint();

  acquire_root_authority(endpoint, root_token);
  acquire_worker_authority(endpoint, "controller-one", "facility.state,authority.grant", root_token,
                           worker_token);

  // At epoch N the worker's token authorizes a real mutation.
  const std::vector<std::string> before =
      run_controller(endpoint, {"--controller", "controller-one", "--action", "mutate", "--token-file",
                                worker_token.string(), "--scope", "facility.state"});
  CPE_REQUIRE_MSG(has_line_containing(before, "mutation accepted=true"), join(before));

  // Another authorized process advances the epoch.
  const std::vector<std::string> advance =
      run_controller(endpoint, {"--controller", kRoot, "--action", "advance", "--token-file",
                                root_token.string(), "--epoch", "1"});
  CPE_REQUIRE_MSG(has_line_containing(advance, "advance accepted=true base=1 new=2"), join(advance));

  // The old token can no longer mutate, and says exactly why.
  const std::vector<std::string> after =
      run_controller(endpoint, {"--controller", "controller-one", "--action", "mutate", "--token-file",
                                worker_token.string(), "--scope", "facility.state"});
  CPE_REQUIRE_MSG(has_line_containing(after, "mutation accepted=false code=epoch.fenced"), join(after));

  const std::vector<std::string> validation =
      run_controller(endpoint, {"--controller", "controller-one", "--action", "validate", "--token-file",
                                worker_token.string(), "--scope", "facility.state"});
  CPE_REQUIRE_MSG(has_line_containing(validation, "validation accepted=false code=epoch.fenced"),
                  join(validation));

  // The epoch really did move, and the transition fenced the previous grants.
  const std::vector<std::string> status =
      run_controller(endpoint, {"--controller", "observer", "--action", "status"});
  CPE_REQUIRE_MSG(has_line_containing(status, "epoch=2"), join(status));
  CPE_REQUIRE_MSG(has_line_containing(status, "live_grants=0"), join(status));
}

CPE_TEST(multiprocess, restarted_controller_cannot_reuse_persisted_state) {
  TempDirectory directory;
  const std::filesystem::path store = directory.file("store");
  const std::filesystem::path root_token = directory.file("root.token");
  const std::filesystem::path worker_token = directory.file("worker.token");

  AuthorityRuntime runtime(store, {"--max-requests", "0"}, true);
  const std::string endpoint = runtime.endpoint();
  acquire_root_authority(endpoint, root_token);

  // First boot: the controller registers and persists its own token locally.
  acquire_worker_authority(endpoint, "worker", "facility.state,authority.grant", root_token, worker_token);
  const std::vector<std::string> first =
      run_controller(endpoint, {"--controller", "worker", "--action", "mutate", "--token-file",
                                worker_token.string(), "--scope", "facility.state"});
  CPE_REQUIRE_MSG(has_line_containing(first, "mutation accepted=true"), join(first));

  // The process dies and a new boot registers afresh, which supersedes the
  // incarnation the previous boot belonged to. The token that boot persisted
  // locally is fenced even though nothing was revoked and no epoch advanced.
  const std::vector<std::string> restarted =
      run_controller(endpoint, {"--controller", "worker", "--action", "register"});
  CPE_REQUIRE_MSG(has_line_containing(restarted, "controller-registered"), join(restarted));
  CPE_REQUIRE_MSG(has_line_containing(restarted, "incarnation=2"), join(restarted));

  const std::vector<std::string> replay =
      run_controller(endpoint, {"--controller", "worker", "--action", "mutate", "--token-file",
                                worker_token.string(), "--scope", "facility.state"});
  CPE_REQUIRE_MSG(has_line_containing(replay, "mutation accepted=false code=incarnation.superseded"),
                  join(replay));

  // A fresh registration above the fenced incarnation can acquire again, which is
  // what keeps revocation and restart fencing monotonic without being permanent.
  acquire_worker_authority(endpoint, "worker", "facility.state,authority.grant", root_token, worker_token);
  const std::vector<std::string> recovered =
      run_controller(endpoint, {"--controller", "worker", "--action", "mutate", "--token-file",
                                worker_token.string(), "--scope", "facility.state"});
  CPE_REQUIRE_MSG(has_line_containing(recovered, "mutation accepted=true"), join(recovered));
}

CPE_TEST(multiprocess, concurrent_advancement_produces_exactly_one_successor) {
  TempDirectory directory;
  const std::filesystem::path store = directory.file("store");
  const std::filesystem::path root_token = directory.file("root.token");

  AuthorityRuntime runtime(store, {"--max-requests", "0"}, true);
  const std::string endpoint = runtime.endpoint();
  acquire_root_authority(endpoint, root_token);

  constexpr int kRacers = 4;
  std::vector<std::filesystem::path> tokens;
  for (int index = 0; index < kRacers; ++index) {
    const std::string controller = "racer-" + std::to_string(index);
    tokens.push_back(directory.file(controller + ".token"));
    acquire_worker_authority(endpoint, controller, "facility.state,epoch.advance", root_token, tokens.back());
  }

  // Every racer is started and held on a blocking read of its standard input, so
  // the race is released deliberately rather than by a timer.
  std::vector<std::unique_ptr<ChildProcess>> racers;
  for (int index = 0; index < kRacers; ++index) {
    const std::string controller = "racer-" + std::to_string(index);
    racers.push_back(std::make_unique<ChildProcess>(
        CONTROL_PLANE_EPOCH_CONTROLLER_EXE,
        std::vector<std::string>{"--endpoint", endpoint, "--controller", controller, "--action", "advance",
                                 "--token-file", tokens[static_cast<std::size_t>(index)].string(), "--epoch",
                                 "1", "--await-stdin"}));
    while (true) {
      const std::optional<std::string> line = racers.back()->read_line();
      CPE_REQUIRE_MSG(line.has_value(), "a racer exited before announcing that it was ready");
      if (line->find("controller-awaiting-trigger") != std::string::npos) {
        break;
      }
    }
  }
  for (const auto& racer : racers) {
    racer->write_line("go");
  }

  std::vector<std::vector<std::string>> results;
  int accepted = 0;
  int conflicts = 0;
  for (const auto& racer : racers) {
    std::vector<std::string> lines = racer->read_all_lines();
    const int code = racer->wait();
    CPE_REQUIRE_MSG(code == 0 || code == 3,
                    "a racer exited with code " + std::to_string(code) + ":\n" + join(lines));
    if (has_line_containing(lines, "advance accepted=true")) {
      ++accepted;
    }
    if (has_line_containing(lines, "code=epoch.conflict")) {
      ++conflicts;
      CPE_REQUIRE_MSG(has_line_containing(lines, "retryable=true"), join(lines));
    }
    results.push_back(std::move(lines));
  }

  // Exactly one committed successor per base epoch, and every loser was told why.
  CPE_REQUIRE_EQ(accepted, 1);
  CPE_REQUIRE_EQ(conflicts, kRacers - 1);

  const std::vector<std::string> status =
      run_controller(endpoint, {"--controller", "observer", "--action", "status"});
  CPE_REQUIRE_MSG(has_line_containing(status, "epoch=2"), join(status));
  CPE_REQUIRE_MSG(has_line_containing(status, "transitions=2"), join(status));
}

CPE_TEST(multiprocess, writer_lock_fences_a_second_writer_process) {
  TempDirectory directory;
  const std::filesystem::path store = directory.file("store");

  AuthorityRuntime runtime(store, {"--max-requests", "0"}, true);

  // A mutating command from another process must be refused: the runtime holds
  // the exclusive writer lock on the store.
  const std::vector<std::string> blocked =
      run_cli({"advance", "--store", store.string(), "--expected-epoch", "1", "--sponsor", "cpe1:mutation:x"});
  CPE_REQUIRE_MSG(has_line_containing(blocked, "code=persistence.store_locked"), join(blocked));

  // Read-only inspection is not blocked: it never takes the writer lock and never
  // writes, so it is safe against a live runtime.
  const std::vector<std::string> status = run_cli({"status", "--store", store.string()});
  CPE_REQUIRE_MSG(has_line_containing(status, "initialized=yes"), join(status));
  CPE_REQUIRE_MSG(has_line_containing(status, "epoch=1"), join(status));

  const std::vector<std::string> verify = run_cli({"verify", "--store", store.string()});
  CPE_REQUIRE_MSG(has_line_containing(verify, "verified=yes"), join(verify));
}

CPE_TEST(multiprocess, crash_recovery_never_rolls_the_epoch_back) {
  TempDirectory directory;
  const std::filesystem::path store = directory.file("store");
  const std::filesystem::path root_token = directory.file("root.token");

  std::string epoch_before_crash;
  {
    AuthorityRuntime runtime(store, {"--max-requests", "0"}, true);
    const std::string endpoint = runtime.endpoint();
    acquire_root_authority(endpoint, root_token);

    for (int round = 1; round <= 3; ++round) {
      const std::vector<std::string> advance =
          run_controller(endpoint, {"--controller", kRoot, "--action", "advance", "--token-file",
                                    root_token.string(), "--epoch", std::to_string(round)});
      CPE_REQUIRE_MSG(has_line_containing(advance, "advance accepted=true"), join(advance));
      acquire_root_authority(endpoint, root_token);
    }

    const std::vector<std::string> status =
        run_controller(endpoint, {"--controller", "observer", "--action", "status"});
    const std::optional<std::string> epoch = field_of(status, "epoch");
    CPE_REQUIRE_MSG(epoch.has_value(), join(status));
    epoch_before_crash = *epoch;
    CPE_REQUIRE_EQ(epoch_before_crash, std::string("4"));

    // Crash the runtime at an arbitrary point: an unconditional process
    // termination, with no chance to flush anything.
    runtime.process().terminate();
    const int exit_code = runtime.wait();
    CPE_REQUIRE_MSG(exit_code != 0, "the terminated runtime reported a clean exit");
  }

  // The store must still be authoritative, at an epoch not below the last
  // acknowledged one, with no leftover temporary files.
  const std::vector<std::string> verify = run_cli({"verify", "--store", store.string()});
  CPE_REQUIRE_MSG(has_line_containing(verify, "verified=yes"), join(verify));
  CPE_REQUIRE_MSG(has_line_containing(verify, "transition_chain_verified=yes"), join(verify));
  const std::optional<std::string> recovered_epoch = field_of(verify, "epoch");
  CPE_REQUIRE_MSG(recovered_epoch.has_value(), join(verify));
  CPE_REQUIRE_MSG(std::stoull(*recovered_epoch) >= std::stoull(epoch_before_crash),
                  "the epoch rolled back after a crash: " + *recovered_epoch + " < " + epoch_before_crash);

  int stale_temporaries = 0;
  for (const std::filesystem::directory_entry& entry : std::filesystem::directory_iterator(store)) {
    if (entry.path().filename().string().find(".tmp.") != std::string::npos) {
      ++stale_temporaries;
    }
  }
  CPE_REQUIRE_EQ(stale_temporaries, 0);

  // A fresh runtime over the same directory serves the recovered state, and
  // re-acquiring authority in the recovered epoch works.
  const std::filesystem::path new_root_token = directory.file("root-after-crash.token");
  AuthorityRuntime restarted(store, {"--max-requests", "0"}, false);
  CPE_REQUIRE_MSG(has_line_containing(restarted.startup_output(), "outcome=opened-clean"),
                  join(restarted.startup_output()));
  CPE_REQUIRE_EQ(restarted.ready_field("epoch").value_or(std::string()), epoch_before_crash);
  acquire_root_authority(restarted.endpoint(), new_root_token);
  const std::vector<std::string> advance =
      run_controller(restarted.endpoint(), {"--controller", kRoot, "--action", "advance", "--token-file",
                                            new_root_token.string(), "--epoch", epoch_before_crash});
  CPE_REQUIRE_MSG(has_line_containing(advance, "advance accepted=true"), join(advance));
}

CPE_TEST(multiprocess, revocation_is_visible_to_every_other_process) {
  TempDirectory directory;
  const std::filesystem::path store = directory.file("store");
  const std::filesystem::path root_token = directory.file("root.token");
  const std::filesystem::path worker_token = directory.file("worker.token");

  AuthorityRuntime runtime(store, {"--max-requests", "0"}, true);
  const std::string endpoint = runtime.endpoint();
  acquire_root_authority(endpoint, root_token);
  acquire_worker_authority(endpoint, "worker", "facility.state,authority.grant", root_token, worker_token);

  const std::vector<std::string> accepted =
      run_controller(endpoint, {"--controller", "worker", "--action", "mutate", "--token-file",
                                worker_token.string(), "--scope", "facility.state"});
  CPE_REQUIRE_MSG(has_line_containing(accepted, "mutation accepted=true"), join(accepted));

  // Another authorized process revokes the worker's authority over the wire.
  const std::vector<std::string> revocation =
      run_controller(endpoint, {"--controller", kRoot, "--action", "revoke", "--token-file",
                                root_token.string(), "--target", "controller", "--target-controller", "worker",
                                "--reason", "suspected_stale_authority"});
  CPE_REQUIRE_MSG(has_line_containing(revocation, "revocation accepted=true"), join(revocation));
  CPE_REQUIRE_MSG(has_line_containing(revocation, "fenced_grants="), join(revocation));

  // Every other process now sees the revocation, including the revoked one.
  const std::vector<std::string> blocked =
      run_controller(endpoint, {"--controller", "worker", "--action", "mutate", "--token-file",
                                worker_token.string(), "--scope", "facility.state"});
  CPE_REQUIRE_MSG(has_line_containing(blocked, "mutation accepted=false code=authority.revoked"), join(blocked));

  // Revocation is monotonic but not permanent: re-registering above the fence and
  // acquiring again with a sponsor restores authority, and the old token stays
  // fenced forever.
  acquire_worker_authority(endpoint, "worker", "facility.state,authority.grant", root_token, worker_token);
  const std::vector<std::string> restored =
      run_controller(endpoint, {"--controller", "worker", "--action", "mutate", "--token-file",
                                worker_token.string(), "--scope", "facility.state"});
  CPE_REQUIRE_MSG(has_line_containing(restored, "mutation accepted=true"), join(restored));

  const std::vector<std::string> status =
      run_controller(endpoint, {"--controller", "observer", "--action", "status"});
  CPE_REQUIRE_MSG(has_line_containing(status, "epoch=1"), join(status));
}

CPE_TEST(multiprocess, read_only_runtime_serves_reads_and_refuses_mutations) {
  TempDirectory directory;
  const std::filesystem::path store = directory.file("store");

  const std::vector<std::string> initialized = run_cli(
      {"init", "--store", store.string(), "--domain", kDomain, "--root", kRoot, "--scopes",
       "authority.grant,authority.revoke,epoch.advance,facility.state"});
  CPE_REQUIRE_MSG(has_line_containing(initialized, "initialized"), join(initialized));

  // A read-only runtime takes no writer lock and serves inspection.
  AuthorityRuntime runtime(store, {"--max-requests", "0", "--read-only"}, false);
  CPE_REQUIRE_MSG(has_line_containing(runtime.startup_output(), "outcome=read-only-inspection") ||
                      has_line_containing(runtime.startup_output(), "outcome=opened-clean"),
                  join(runtime.startup_output()));

  const std::vector<std::string> status =
      run_controller(runtime.endpoint(), {"--controller", "observer", "--action", "status"});
  CPE_REQUIRE_MSG(has_line_containing(status, "status initialized=yes"), join(status));
  CPE_REQUIRE_MSG(has_line_containing(status, "open_mode=read-only"), join(status));

  // A mutating request is refused by the same check a local consumer would hit.
  const std::vector<std::string> refused =
      run_controller(runtime.endpoint(), {"--controller", "newcomer", "--action", "register"});
  CPE_REQUIRE_MSG(has_line_containing(refused, "code=internal.unsupported_operation"), join(refused));

  // The read-only runtime never held the writer lock, so a second read-only
  // reader can serve the same store at the same time.
  const std::vector<std::string> verify = run_cli({"verify", "--store", store.string()});
  CPE_REQUIRE_MSG(has_line_containing(verify, "verified=yes"), join(verify));
}





