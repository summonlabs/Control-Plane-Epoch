// Control Plane Epoch 1.0.0 - Summon Software Labs
// Benchmark harness: completed in-memory operations versus completed durable
// operations.
//
// Scope and honesty
// -----------------
// Every number printed here is a single-host, single-process measurement taken
// on this machine, in this process, against a store in the operating system's
// temporary directory. There is no network, no loopback client, no
// multi-process concurrency, and no distributed consensus anywhere in this
// repository. The measurements are not a hardware characterization and must not
// be read as production capacity.
//
//   * In-memory work (token validation) is separated from durable work and is
//     reported as explicitly NOT including any durability cost: validation takes
//     the authority mutex and reads authoritative in-memory state; it performs
//     no commit, no flush, and no file I/O.
//   * Durable work is measured around calls that only return after the store has
//     published the new generation AND the durable floor: temporary write,
//     device flush, read-back verification, atomic publish, retention of the
//     superseded generation, and floor publication. The durability cost is
//     therefore inside the measured interval.
//
// Only operations the authority ACCEPTED (completed) are counted. If any
// measured operation is rejected, the benchmark reports the rejection and fails
// instead of reporting a rate. After the measurements, the store is reopened and
// verified with inspect_store().
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "control_plane_epoch/control_plane_epoch.hpp"

namespace {

using namespace dccp::epoch;
using Clock = std::chrono::steady_clock;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#if defined(NDEBUG)
constexpr std::string_view kBuildType = "Release";
#else
constexpr std::string_view kBuildType = "Debug";
#endif

#if defined(_MSC_VER)
constexpr std::string_view kCompiler = "msvc";
#else
constexpr std::string_view kCompiler = "unknown";
#endif

[[nodiscard]] std::string compiler_detail() {
  std::string detail(kCompiler);
#if defined(_MSC_VER)
  detail += " _MSC_VER=" + std::to_string(_MSC_VER);
#endif
#if defined(_MSC_FULL_VER)
  detail += " _MSC_FULL_VER=" + std::to_string(_MSC_FULL_VER);
#endif
#if defined(_MSVC_LANG)
  detail += " _MSVC_LANG=" + std::to_string(_MSVC_LANG);
#endif
  detail += " __cplusplus=" + std::to_string(__cplusplus);
  return detail;
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

[[nodiscard]] std::filesystem::path prepare_store_directory() {
  const std::filesystem::path directory =
      std::filesystem::temp_directory_path() / "control-plane-epoch-benchmarks";
  std::error_code ignored;
  std::filesystem::remove_all(directory, ignored);
  std::filesystem::create_directories(directory, ignored);
  return directory;
}

[[noreturn]] void fail(const std::string& message) { throw std::runtime_error(message); }

template <class T>
[[nodiscard]] T unwrap(Result<T> result, std::string_view what) {
  if (!result.has_value()) {
    fail(std::string(what) + " was rejected with " + std::string(result.rejection().token()) + ": " +
         result.rejection().detail());
  }
  return result.move_value();
}

[[nodiscard]] ScopeName scope(std::string_view name) {
  return unwrap(ScopeName::parse(name, "scope name"), name);
}

[[nodiscard]] AuthorityScopeSet scope_set(std::vector<std::string_view> names) {
  std::vector<ScopeName> scopes;
  scopes.reserve(names.size());
  for (const std::string_view name : names) {
    scopes.push_back(scope(name));
  }
  return unwrap(AuthorityScopeSet::create(std::move(scopes)), "scope set");
}

[[nodiscard]] ProvenanceInput provenance(ProvenanceSourceKind kind, std::string_view source) {
  return unwrap(ProvenanceInput::from_source(kind, source), "provenance");
}

[[nodiscard]] std::string number(double value, int precision) {
  std::ostringstream stream;
  stream << std::fixed << std::setprecision(precision) << value;
  return stream.str();
}

/// Nearest-rank percentile of a copy of the supplied values. The rank is
/// ceil(p/100 * n), clamped into range, which is exact for the sample counts
/// this harness reports. With few samples a high percentile is close to the
/// worst sample; the sample count is always printed next to it.
[[nodiscard]] double percentile(std::vector<double> values, double rank_percent) {
  if (values.empty()) {
    return 0.0;
  }
  std::sort(values.begin(), values.end());
  const double rank = rank_percent / 100.0 * static_cast<double>(values.size());
  std::size_t index = static_cast<std::size_t>(std::ceil(rank));
  if (index > 0) {
    index -= 1;
  }
  if (index >= values.size()) {
    index = values.size() - 1;
  }
  return values[index];
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

/// One measured metric: the exact number of completed operations, the number of
/// timed samples those operations were split into, and the per-sample rates and
/// per-operation latencies derived from the monotonic clock.
struct Measurement {
  std::string metric;
  std::string durability;
  std::string includes;
  std::uint64_t operations = 0;
  std::uint64_t warmup_operations = 0;
  std::size_t samples = 0;
  double total_seconds = 0.0;
  std::vector<double> sample_rates;
  std::vector<double> sample_latency_us;

  [[nodiscard]] double rate_total() const { return total_seconds > 0.0 ? static_cast<double>(operations) / total_seconds : 0.0; }
  [[nodiscard]] double rate_min() const { return percentile(sample_rates, 0.0); }
  [[nodiscard]] double rate_median() const { return percentile(sample_rates, 50.0); }
  [[nodiscard]] double rate_p99() const { return percentile(sample_rates, 99.0); }
  [[nodiscard]] double latency_min_us() const { return percentile(sample_latency_us, 0.0); }
  [[nodiscard]] double latency_median_us() const { return percentile(sample_latency_us, 50.0); }
  [[nodiscard]] double latency_p99_us() const { return percentile(sample_latency_us, 99.0); }
  [[nodiscard]] double latency_max_us() const { return percentile(sample_latency_us, 100.0); }

  void report() const {
    std::cout << "metric=" << metric << " durability=" << durability << " operations=" << operations
              << " warmup_operations=" << warmup_operations << " samples=" << samples
              << " ops_per_second_total=" << number(rate_total(), 1)
              << " ops_per_second_min=" << number(rate_min(), 1)
              << " ops_per_second_median=" << number(rate_median(), 1)
              << " ops_per_second_p99=" << number(rate_p99(), 1)
              << " latency_min_us=" << number(latency_min_us(), 3)
              << " latency_median_us=" << number(latency_median_us(), 3)
              << " latency_p99_us=" << number(latency_p99_us(), 3)
              << " latency_max_us=" << number(latency_max_us(), 3) << " includes=\"" << includes << "\"\n";
  }
};

/// Times one sample of `operations` completed operations and accumulates the
/// derived rate and latency.
template <class Operation>
void run_sample(Measurement& measurement, std::uint64_t operations, Operation&& operation) {
  const Clock::time_point start = Clock::now();
  operation();
  const Clock::time_point end = Clock::now();
  const double seconds = std::chrono::duration<double>(end - start).count();
  if (seconds <= 0.0) {
    fail("the monotonic clock did not advance during a measured sample");
  }
  measurement.operations += operations;
  measurement.samples += 1;
  measurement.total_seconds += seconds;
  measurement.sample_rates.push_back(static_cast<double>(operations) / seconds);
  measurement.sample_latency_us.push_back(seconds / static_cast<double>(operations) * 1'000'000.0);
}

// ---------------------------------------------------------------------------
// Store fixture
// ---------------------------------------------------------------------------

/// One authority over one freshly prepared store, plus the domain's
/// administrative root identity.
class BenchFixture {
 public:
  BenchFixture(const std::filesystem::path& directory, std::string_view domain_text, std::string_view root_text)
      : directory_(directory),
        root_id_(unwrap(ControllerId::parse(root_text, "benchmark root"), "authority root")) {
    authority_ = open(directory_, RecoveryPolicy::RefuseOnDamage);

    InitializeDomainRequest request;
    request.domain = unwrap(FacilityAuthorityDomainId::parse(domain_text, "benchmark domain"), "domain");
    request.authority_root = root_id_;
    for (const std::string_view name : {authority_grant_scope().view(), authority_revoke_scope().view(),
                                        epoch_advance_scope().view(), std::string_view("facility.inventory")}) {
      request.scopes.push_back(scope(name));
    }
    request.provenance = provenance(ProvenanceSourceKind::Initialization, "benchmark");
    (void)unwrap(authority_->initialize(std::move(request)), "domain initialization");
  }

  [[nodiscard]] static std::unique_ptr<ControlPlaneEpochAuthority> open(const std::filesystem::path& directory,
                                                                       RecoveryPolicy policy) {
    StoreOpenOptions options;
    options.directory = directory;
    options.mode = StoreOpenMode::ReadWrite;
    options.recovery_policy = policy;
    return std::make_unique<ControlPlaneEpochAuthority>(options);
  }

  [[nodiscard]] ControlPlaneEpochAuthority& authority() { return *authority_; }
  [[nodiscard]] const std::filesystem::path& directory() const { return directory_; }
  [[nodiscard]] const ControllerId& root() const { return root_id_; }

  /// Closes the authority, exactly as a restarted process would.
  void close() { authority_.reset(); }

  /// Replaces the open authority with a freshly opened one over the same
  /// directory. The caller times this call to measure reopen and recovery.
  void reopen(RecoveryPolicy policy = RecoveryPolicy::RefuseOnDamage) {
    authority_.reset();
    authority_ = open(directory_, policy);
  }

 private:
  std::filesystem::path directory_;
  ControllerId root_id_;
  std::unique_ptr<ControlPlaneEpochAuthority> authority_;
};

/// Acquires the reserved administrative scopes for the authority root through
/// the documented standing-root path and returns the mutation token.
[[nodiscard]] MutationAuthority standing_root_authority(ControlPlaneEpochAuthority& authority,
                                                        const ControllerRecord& root_record,
                                                        std::vector<std::string_view> scopes) {
  AcquireAuthorityRequest request;
  request.controller = ControllerId::from_trusted("authority-root");
  request.incarnation = root_record.incarnation_id();
  request.scopes = scope_set(std::move(scopes));
  request.provenance = provenance(ProvenanceSourceKind::Operator, "facility-operator");
  const AuthorityGrantView view = unwrap(authority.acquire_authority(std::move(request)), "standing-root authority");
  if (!view.mutation_authority().has_value()) {
    fail("the authority root acquired no mutation authority");
  }
  return *view.mutation_authority();
}

}  // namespace

int main() {
  using namespace dccp::epoch;

  try {
    const std::filesystem::path directory = prepare_store_directory();
    std::cout << "benchmark=control_plane_epoch_benchmarks\n";
    std::cout << "store=" << directory.string() << '\n';
    std::cout << "configuration build_type=" << kBuildType << " compiler=\"" << compiler_detail() << "\"\n";
    std::cout << "scope=\"single-host single-process in-process durable store; no network, no loopback client, no "
                 "multi-process concurrency, no distributed consensus; timings use std::chrono::steady_clock only\"\n";
    std::cout << "counting=\"only operations the authority accepted (completed) are counted; a rejected operation "
                 "aborts the benchmark\"\n";

    BenchFixture fixture(directory, "facility-alpha", "authority-root");

    // -- Setup: one scoped grant for a worker controller. --------------------
    const ControllerRecord root_record =
        unwrap(fixture.authority().controller_record(fixture.root()), "authority root record");
    const MutationAuthority root_authority = standing_root_authority(
        fixture.authority(), root_record,
        {authority_grant_scope().view(), authority_revoke_scope().view(), epoch_advance_scope().view()});

    RegisterControllerRequest worker_register;
    worker_register.controller = unwrap(ControllerId::parse("worker-1", "controller"), "controller");
    worker_register.provenance = provenance(ProvenanceSourceKind::Controller, "worker-1");
    const ControllerRegistration worker =
        unwrap(fixture.authority().register_controller(std::move(worker_register)), "worker registration");
    AcquireAuthorityRequest worker_acquire;
    worker_acquire.controller = worker.controller();
    worker_acquire.incarnation = worker.incarnation_id();
    worker_acquire.scopes = scope_set({std::string_view("facility.inventory")});
    worker_acquire.sponsor = root_authority;
    worker_acquire.provenance = provenance(ProvenanceSourceKind::Controller, "worker-1");
    const AuthorityGrantView worker_grant =
        unwrap(fixture.authority().acquire_authority(std::move(worker_acquire)), "worker authority");
    if (!worker_grant.mutation_authority().has_value()) {
      fail("the worker acquired no mutation authority");
    }
    const MutationAuthority worker_token = *worker_grant.mutation_authority();
    const ScopeName inventory = scope("facility.inventory");
    std::cout << "setup durable_generation=" << fixture.authority().status().durable_generation().to_string()
              << " epoch=" << fixture.authority().current_epoch().to_string()
              << " snapshot_bytes=" << fixture.authority().accounting().snapshot_bytes() << '\n';

    // -- 1. In-memory token validation (no durability cost at all). ----------
    constexpr std::uint64_t kValidationOperationsPerSample = 4000;
    constexpr std::size_t kValidationSamples = 25;
    constexpr std::uint64_t kValidationWarmup = 200;
    Measurement validation;
    validation.metric = "validate_mutation_in_memory";
    validation.durability = "in-memory";
    validation.includes =
        "authority mutex plus in-memory authoritative state only: no commit, no flush, no atomic publish, no file "
        "I/O; this rate explicitly EXCLUDES all durability cost";
    validation.warmup_operations = kValidationWarmup;
    for (std::uint64_t index = 0; index < kValidationWarmup; ++index) {
      if (!fixture.authority().validate_mutation(worker_token, inventory).accepted()) {
        fail("an in-memory validation was rejected during warm-up");
      }
    }
    for (std::size_t sample = 0; sample < kValidationSamples; ++sample) {
      run_sample(validation, kValidationOperationsPerSample, [&] {
        for (std::uint64_t index = 0; index < kValidationOperationsPerSample; ++index) {
          if (!fixture.authority().validate_mutation(worker_token, inventory).accepted()) {
            fail("an in-memory validation was rejected");
          }
        }
      });
    }
    validation.report();
    std::cout << "in-memory-vs-durable=\"the validate_mutation_in_memory rate above includes NO durability cost "
                 "(no commit, no flush, no atomic publish, no file I/O) and is therefore not comparable with the "
                 "durable rates that follow\"\n";

    // -- 2. Durable controller registrations. --------------------------------
    constexpr std::uint64_t kRegistrationOperationsPerSample = 20;
    constexpr std::size_t kRegistrationSamples = 7;
    Measurement registrations;
    registrations.metric = "register_controller_durable";
    registrations.durability = "durable";
    registrations.includes =
        "durable commit of one controller registration: exclusive temp write, device flush, read-back verify, "
        "atomic publish, retained previous generation, floor publish";
    for (std::size_t sample = 0; sample < kRegistrationSamples; ++sample) {
      run_sample(registrations, kRegistrationOperationsPerSample, [&] {
        for (std::uint64_t index = 0; index < kRegistrationOperationsPerSample; ++index) {
          const std::uint64_t ordinal = static_cast<std::uint64_t>(sample) * kRegistrationOperationsPerSample + index;
          RegisterControllerRequest request;
          request.controller = unwrap(
              ControllerId::parse("bench-register-" + std::to_string(ordinal), "controller"), "controller");
          request.provenance = provenance(ProvenanceSourceKind::Controller, "benchmark");
          const ControllerRegistration registration =
              unwrap(fixture.authority().register_controller(std::move(request)), "registration");
          if (registration.replayed() || registration.incarnation_number().value() != 1) {
            fail("a measured registration was not a fresh incarnation 1");
          }
        }
      });
    }
    registrations.report();

    // -- 3. Durable revocations. ---------------------------------------------
    // Each measured revocation fences exactly one live grant. The registration
    // and the grant that the revocation targets are set up outside the measured
    // interval; the revocation call itself includes the full durable commit.
    constexpr std::uint64_t kRevocationOperationsPerSample = 15;
    constexpr std::size_t kRevocationSamples = 7;
    Measurement revocations;
    revocations.metric = "revoke_authority_durable";
    revocations.durability = "durable";
    revocations.includes =
        "durable commit of one grant revocation that fences one live grant: exclusive temp write, device flush, "
        "read-back verify, atomic publish, retained previous generation, floor publish; excludes the registration and "
        "the grant of the revocation target";
    for (std::size_t sample = 0; sample < kRevocationSamples; ++sample) {
      for (std::uint64_t index = 0; index < kRevocationOperationsPerSample; ++index) {
        const std::uint64_t ordinal = static_cast<std::uint64_t>(sample) * kRevocationOperationsPerSample + index;
        RegisterControllerRequest register_request;
        register_request.controller =
            unwrap(ControllerId::parse("bench-revoke-" + std::to_string(ordinal), "controller"), "controller");
        register_request.provenance = provenance(ProvenanceSourceKind::Controller, "benchmark");
        const ControllerRegistration registration =
            unwrap(fixture.authority().register_controller(std::move(register_request)), "revocation target");
        AcquireAuthorityRequest acquire_request;
        acquire_request.controller = registration.controller();
        acquire_request.incarnation = registration.incarnation_id();
        acquire_request.scopes = scope_set({std::string_view("facility.inventory")});
        acquire_request.sponsor = root_authority;
        acquire_request.provenance = provenance(ProvenanceSourceKind::Controller, "benchmark");
        const AuthorityGrantView target =
            unwrap(fixture.authority().acquire_authority(std::move(acquire_request)), "revocation target grant");
        const GrantId target_grant = target.record().id();
        const ControllerId target_controller = registration.controller();

        run_sample(revocations, 1, [&] {
          RevokeAuthorityRequest revoke_request;
          revoke_request.target = RevocationTarget::grant(target_grant, target_controller);
          revoke_request.reason = RevocationReason::OperatorRequest;
          revoke_request.authority = root_authority;
          revoke_request.provenance = provenance(ProvenanceSourceKind::Operator, "benchmark");
          const RevocationRecord record =
              unwrap(fixture.authority().revoke_authority(std::move(revoke_request)), "revocation");
          if (record.replayed() || record.fenced_grant_count() != 1) {
            fail("a measured revocation did not fence exactly one live grant");
          }
        });
      }
    }
    revocations.report();

    // -- 4. Durable epoch advancements. --------------------------------------
    // Each measured advancement commits one successor epoch and fences every
    // live grant of the base epoch. The epoch.advance precondition (a live grant
    // in the current epoch) has to be re-established after every advancement,
    // because advancement clears the grants of the base epoch; that
    // re-acquisition is set up outside the measured interval and its cost is not
    // part of the reported advancement rate.
    constexpr std::uint64_t kAdvanceOperationsPerSample = 15;
    constexpr std::size_t kAdvanceSamples = 7;
    Measurement advancements;
    advancements.metric = "advance_epoch_durable";
    advancements.durability = "durable";
    advancements.includes =
        "durable commit of one epoch transition INCLUDING the flush, the atomic publish, the retained previous "
        "generation and the durable floor publication; excludes re-acquiring the epoch.advance grant that the next "
        "transition requires";
    for (std::size_t sample = 0; sample < kAdvanceSamples; ++sample) {
      for (std::uint64_t index = 0; index < kAdvanceOperationsPerSample; ++index) {
        const ControllerRecord current_root =
            unwrap(fixture.authority().controller_record(fixture.root()), "authority root record");
        const MutationAuthority advance_authority = standing_root_authority(
            fixture.authority(), current_root, {authority_grant_scope().view(), epoch_advance_scope().view()});
        const Epoch base = fixture.authority().current_epoch();
        run_sample(advancements, 1, [&] {
          AdvanceEpochRequest advance_request;
          advance_request.expected_current = base;
          advance_request.authority = advance_authority;
          advance_request.reason = EpochTransitionReason::Fencing;
          advance_request.provenance = provenance(ProvenanceSourceKind::Operator, "benchmark");
          const EpochTransitionRecord transition =
              unwrap(fixture.authority().advance_epoch(std::move(advance_request)), "epoch advancement");
          if (transition.new_epoch() != fixture.authority().current_epoch() ||
              transition.base_epoch() != base) {
            fail("a measured advancement did not commit exactly one successor epoch");
          }
        });
      }
    }
    advancements.report();

    const AuthorityStatus measured_status = fixture.authority().status();
    std::cout << "state-after-measurement epoch=" << measured_status.epoch().to_string()
              << " durable_generation=" << measured_status.durable_generation().to_string()
              << " controllers=" << measured_status.controller_count()
              << " live_grants=" << measured_status.live_grant_count()
              << " transitions=" << measured_status.transition_count()
              << " revocations=" << measured_status.revocation_count()
              << " snapshot_bytes=" << fixture.authority().accounting().snapshot_bytes() << '\n';

    // -- 5. Store reopen and recovery. ---------------------------------------
    // Each sample closes the authority (releasing the writer lock exactly as an
    // exiting process does) and times opening the same directory again, which
    // reads every durable artifact, verifies it, and applies the recovery policy.
    constexpr std::size_t kReopenSamples = 20;
    Measurement reopens;
    reopens.metric = "store_reopen_recovery";
    reopens.durability = "durable";
    reopens.includes =
        "opening the store directory: writer lock acquisition, retirement of interrupted temporary files, read and "
        "integrity verification of the current generation, the retained previous generation and the floor, then "
        "recovery-policy application";
    for (std::size_t sample = 0; sample < kReopenSamples; ++sample) {
      fixture.close();
      run_sample(reopens, 1, [&] { fixture.reopen(RecoveryPolicy::RefuseOnDamage); });
    }
    reopens.report();
    std::cout << "reopen-recovery-outcome=" << recovery_outcome_token(fixture.authority().recovery().outcome())
              << '\n';

    // -- 6. Integrity check after the measurement. ---------------------------
    fixture.close();
    const StoreInspection inspection = inspect_store(directory);
    std::cout << "integrity " << inspection.to_string() << '\n';
    std::cout << "integrity-verified=" << (inspection.verified() ? "yes" : "no")
              << " transition_chain_verified=" << (inspection.transition_chain_verified() ? "yes" : "no") << '\n';
    if (!inspection.verified() || !inspection.transition_chain_verified()) {
      fail("the store did not verify after the measurement");
    }
    std::cout << "done=control_plane_epoch_benchmarks\n";
    return 0;
  } catch (const EpochError& error) {
    std::cerr << "failure: " << error.explanation().to_string() << '\n';
    return 1;
  } catch (const std::exception& error) {
    std::cerr << "failure: " << error.what() << '\n';
    return 1;
  }
}
