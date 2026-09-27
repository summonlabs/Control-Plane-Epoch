// Control Plane Epoch 1.0.0 - Summon Software Labs
// Public durable-store surface: how the authority is opened, what recovery did,
// and how an operator verifies a store without mutating it.
//
// The raw persistence structures are internal. Consumers never read or write
// image layouts; they open a store, observe a recovery report, and use the
// strongly typed authority API on top of it.
#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "control_plane_epoch/digest.hpp"
#include "control_plane_epoch/epoch.hpp"
#include "control_plane_epoch/error.hpp"
#include "control_plane_epoch/identity.hpp"
#include "control_plane_epoch/limits.hpp"

namespace dccp::epoch {

namespace detail {
class AuthorityStore;
}

/// How a store directory is opened.
enum class StoreOpenMode : std::uint32_t {
  /// Exclusive: takes the process-wide writer lock, may recover and commit.
  ReadWrite = 1,
  /// Non-exclusive: reads and verifies one consistent generation, never writes,
  /// never takes the writer lock, and never quarantines anything.
  ReadOnly = 2,
};

/// What the opener does when the current durable generation is unusable.
enum class RecoveryPolicy : std::uint32_t {
  /// Refuse to open. Nothing is written and nothing is repaired implicitly.
  RefuseOnDamage = 1,
  /// Adopt the retained previous generation and republish it as the live one.
  ///
  /// The floor rule is not negotiable: the previous generation is adopted only
  /// when it is at or above the durable floor in both generation and epoch.
  /// Because the floor is published with the same generation as the live file, an
  /// acknowledged commit leaves the previous generation below the floor, and
  /// adopting it would roll the epoch backwards and resurrect authority that
  /// advancement permanently fenced. In that situation this policy refuses with
  /// integrity.generation_below_floor, exactly like RefuseOnDamage.
  ///
  /// The policy therefore helps in the one window where the floor legitimately
  /// lags the live file (an interrupted commit between publishing the generation
  /// and publishing the floor): there the retained generation is at the floor and
  /// can be adopted and republished instead of reinitializing the domain. For a
  /// damaged live file whose floor is current, the operator paths are to refuse
  /// and inspect, or to reinitialize the domain explicitly.
  AdoptPreviousGeneration = 2,
  /// Quarantine damaged files and initialize a fresh durable instance of the
  /// domain at an epoch strictly above every recoverable floor value. Requires
  /// an explicit operator assertion (see asserted_epoch_floor) whenever no floor
  /// value can be read at all.
  ReinitializeDomain = 3,
};

[[nodiscard]] std::string_view store_open_mode_token(StoreOpenMode mode) noexcept;
[[nodiscard]] std::string_view recovery_policy_token(RecoveryPolicy policy) noexcept;
[[nodiscard]] Result<StoreOpenMode> parse_store_open_mode(std::string_view token);
[[nodiscard]] Result<RecoveryPolicy> parse_recovery_policy(std::string_view token);

/// What actually happened when the store was opened.
enum class RecoveryOutcome : std::uint32_t {
  /// The current generation verified and was adopted unchanged.
  OpenedClean = 1,
  /// The current generation was unusable; the previous generation satisfied the
  /// durable floor and was adopted.
  AdoptedPreviousGeneration = 2,
  /// Damaged state was quarantined and a fresh durable instance was created
  /// above the recoverable floor.
  ReinitializedDamagedStore = 3,
  /// Read-only inspection of the current generation.
  ReadOnlyInspection = 4,
};

[[nodiscard]] std::string_view recovery_outcome_token(RecoveryOutcome outcome) noexcept;

/// Options for opening a store.
struct StoreOpenOptions {
  std::filesystem::path directory;

  StoreOpenMode mode = StoreOpenMode::ReadWrite;
  RecoveryPolicy recovery_policy = RecoveryPolicy::RefuseOnDamage;

  /// Operator assertion of the highest epoch ever issued by this domain. Used
  /// only with RecoveryPolicy::ReinitializeDomain, and only when no durable
  /// floor value can be read: the fresh instance starts above
  /// max(readable floor, this assertion). A value below a readable floor is
  /// rejected, never clamped.
  std::optional<std::uint64_t> asserted_epoch_floor;

  /// Bound on the snapshot this instance will encode and publish. Callers may
  /// lower it, never raise it above limits::max_snapshot_bytes. It governs what
  /// the writer may produce, including the temporary file it verifies before
  /// publishing. Reading is governed instead by the compile-time maximum
  /// limits::max_snapshot_bytes, so a generation that was validly published under
  /// a larger bound still opens rather than stranding the domain.
  std::size_t max_snapshot_bytes = ::dccp::epoch::max_snapshot_bytes;
};

/// Report describing what opening the store did. Always available after a
/// successful open, including the clean case.
///
/// A store that has never been initialized has no domain, no epoch, and no
/// durable generation. Those are reported as absent rather than as a sentinel
/// value, so "no authority exists here yet" can never be mistaken for authority
/// at epoch zero.
class RecoveryReport {
 public:
  RecoveryReport() = default;

  [[nodiscard]] RecoveryOutcome outcome() const noexcept { return outcome_; }
  [[nodiscard]] bool has_domain() const noexcept { return has_domain_; }
  [[nodiscard]] const FacilityAuthorityDomainId& domain() const noexcept { return domain_; }
  [[nodiscard]] const std::optional<DomainInstanceNumber>& domain_instance() const noexcept {
    return domain_instance_;
  }
  [[nodiscard]] const std::optional<Epoch>& epoch() const noexcept { return epoch_; }
  [[nodiscard]] const std::optional<DurableGeneration>& durable_generation() const noexcept {
    return durable_generation_;
  }
  [[nodiscard]] const Sha256Digest& snapshot_digest() const noexcept { return snapshot_digest_; }
  [[nodiscard]] const std::optional<Sha256Digest>& floor_digest() const noexcept { return floor_digest_; }

  /// Files that failed validation during recovery.
  [[nodiscard]] const std::vector<std::string>& damaged_files() const noexcept { return damaged_files_; }

  /// Files moved aside by a reinitializing recovery, as store-relative paths.
  [[nodiscard]] const std::vector<std::string>& quarantined_files() const noexcept { return quarantined_files_; }

  /// Concise, deterministic explanation of the outcome.
  [[nodiscard]] const std::string& detail() const noexcept { return detail_; }
  [[nodiscard]] std::string to_string() const;

  friend bool operator==(const RecoveryReport& lhs, const RecoveryReport& rhs) noexcept {
    return lhs.outcome_ == rhs.outcome_ && lhs.has_domain_ == rhs.has_domain_ && lhs.domain_ == rhs.domain_ &&
           lhs.domain_instance_ == rhs.domain_instance_ && lhs.epoch_ == rhs.epoch_ &&
           lhs.durable_generation_ == rhs.durable_generation_ && lhs.snapshot_digest_ == rhs.snapshot_digest_ &&
           lhs.floor_digest_ == rhs.floor_digest_ && lhs.damaged_files_ == rhs.damaged_files_ &&
           lhs.quarantined_files_ == rhs.quarantined_files_ && lhs.detail_ == rhs.detail_;
  }

 private:
  friend struct StoreReportFactory;
  friend class detail::AuthorityStore;

  RecoveryOutcome outcome_ = RecoveryOutcome::OpenedClean;
  bool has_domain_ = false;
  FacilityAuthorityDomainId domain_;
  std::optional<DomainInstanceNumber> domain_instance_;
  std::optional<Epoch> epoch_;
  std::optional<DurableGeneration> durable_generation_;
  Sha256Digest snapshot_digest_;
  std::optional<Sha256Digest> floor_digest_;
  std::vector<std::string> damaged_files_;
  std::vector<std::string> quarantined_files_;
  std::string detail_;
};

/// Result of one durable commit.
class DurableCommitReport {
 public:
  DurableCommitReport() = default;

  [[nodiscard]] DurableGeneration generation() const noexcept { return generation_; }
  [[nodiscard]] Epoch epoch() const noexcept { return epoch_; }
  [[nodiscard]] const Sha256Digest& snapshot_digest() const noexcept { return snapshot_digest_; }
  [[nodiscard]] std::uint64_t bytes_written() const noexcept { return bytes_written_; }

  /// True when a previous generation was retained as the fallback copy.
  [[nodiscard]] bool retained_previous_generation() const noexcept { return retained_previous_generation_; }

  [[nodiscard]] std::string to_string() const;

  friend bool operator==(const DurableCommitReport& lhs, const DurableCommitReport& rhs) noexcept {
    return lhs.generation_ == rhs.generation_ && lhs.epoch_ == rhs.epoch_ &&
           lhs.snapshot_digest_ == rhs.snapshot_digest_ && lhs.bytes_written_ == rhs.bytes_written_ &&
           lhs.retained_previous_generation_ == rhs.retained_previous_generation_;
  }

 private:
  friend struct StoreReportFactory;
  friend class detail::AuthorityStore;

  DurableGeneration generation_;
  Epoch epoch_;
  Sha256Digest snapshot_digest_;
  std::uint64_t bytes_written_ = 0;
  bool retained_previous_generation_ = false;
};

/// Read-only verification of one store directory. Produced without taking the
/// writer lock, so it is safe to run against a live authority.
///
/// As with the recovery report, a directory that holds no authority domain yet
/// reports its domain, epoch, and generation as absent rather than as zero.
class StoreInspection {
 public:
  StoreInspection() = default;

  [[nodiscard]] bool verified() const noexcept { return verified_; }
  [[nodiscard]] bool read_only_safe() const noexcept { return read_only_safe_; }
  [[nodiscard]] bool store_initialized() const noexcept { return store_initialized_; }

  [[nodiscard]] const FacilityAuthorityDomainId& domain() const noexcept { return domain_; }
  [[nodiscard]] const std::optional<DomainInstanceNumber>& domain_instance() const noexcept {
    return domain_instance_;
  }
  [[nodiscard]] const std::optional<Epoch>& epoch() const noexcept { return epoch_; }
  [[nodiscard]] const std::optional<DurableGeneration>& durable_generation() const noexcept {
    return durable_generation_;
  }
  [[nodiscard]] std::uint64_t controller_count() const noexcept { return controller_count_; }
  [[nodiscard]] std::uint64_t live_grant_count() const noexcept { return live_grant_count_; }
  [[nodiscard]] std::uint64_t transition_count() const noexcept { return transition_count_; }
  [[nodiscard]] std::uint64_t revocation_count() const noexcept { return revocation_count_; }
  [[nodiscard]] std::uint64_t idempotency_record_count() const noexcept { return idempotency_record_count_; }
  [[nodiscard]] std::uint64_t snapshot_bytes() const noexcept { return snapshot_bytes_; }
  [[nodiscard]] const Sha256Digest& snapshot_digest() const noexcept { return snapshot_digest_; }
  [[nodiscard]] const std::optional<Epoch>& floor_epoch() const noexcept { return floor_epoch_; }
  [[nodiscard]] const std::optional<DurableGeneration>& floor_generation() const noexcept {
    return floor_generation_;
  }
  [[nodiscard]] bool transition_chain_verified() const noexcept { return transition_chain_verified_; }

  /// Deterministic problem list; empty when the store is fully usable. A
  /// non-empty list with verified() == false means the store must not be
  /// treated as authoritative.
  [[nodiscard]] const std::vector<std::string>& problems() const noexcept { return problems_; }

  [[nodiscard]] std::string to_string() const;

 private:
  friend struct StoreReportFactory;
  friend class detail::AuthorityStore;

  bool verified_ = false;
  bool read_only_safe_ = false;
  bool store_initialized_ = false;
  FacilityAuthorityDomainId domain_;
  std::optional<DomainInstanceNumber> domain_instance_;
  std::optional<Epoch> epoch_;
  std::optional<DurableGeneration> durable_generation_;
  std::uint64_t controller_count_ = 0;
  std::uint64_t live_grant_count_ = 0;
  std::uint64_t transition_count_ = 0;
  std::uint64_t revocation_count_ = 0;
  std::uint64_t idempotency_record_count_ = 0;
  std::uint64_t snapshot_bytes_ = 0;
  Sha256Digest snapshot_digest_;
  std::optional<Epoch> floor_epoch_;
  std::optional<DurableGeneration> floor_generation_;
  bool transition_chain_verified_ = false;
  std::vector<std::string> problems_;
};

/// Verifies a store directory read-only: integrity of the current generation,
/// the retained previous generation when present, the durable floor, and the
/// transition chain. Never writes, never locks, never repairs.
[[nodiscard]] StoreInspection inspect_store(const std::filesystem::path& directory);

/// Well-known file names inside a store directory, exposed for operators and
/// tooling so that no consumer has to guess layouts. These are the only names
/// this repository owns inside a store directory.
struct StoreLayout {
  static constexpr std::string_view lock_file = "authority.lock";
  static constexpr std::string_view snapshot_file = "authority.state";
  static constexpr std::string_view previous_snapshot_file = "authority.state.prev";
  static constexpr std::string_view floor_file = "authority.floor";
  static constexpr std::string_view quarantine_directory = "quarantine";
  static constexpr std::string_view snapshot_artifact_extension = ".cpesnap";
};

}  // namespace dccp::epoch


