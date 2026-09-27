// Control Plane Epoch 1.0.0 - Summon Software Labs
// Immutable inspection views: status, accounting, and paged ledgers.
//
// Every paged call defines its iteration order explicitly and returns records
// in that order. Pages are bounded so that inspection can never be used to make
// the authority allocate without limit.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "control_plane_epoch/authority.hpp"
#include "control_plane_epoch/digest.hpp"
#include "control_plane_epoch/epoch.hpp"
#include "control_plane_epoch/error.hpp"
#include "control_plane_epoch/identity.hpp"
#include "control_plane_epoch/incarnation.hpp"
#include "control_plane_epoch/store.hpp"
#include "control_plane_epoch/transition.hpp"

namespace dccp::epoch {

namespace detail {
class AuthorityCore;
class ClientCore;
}

/// Point-in-time status of one authority domain. Immutable and self-consistent:
/// it is produced under the authority's lock, so no field can change while a
/// caller reads the snapshot.
class AuthorityStatus {
 public:
  AuthorityStatus() = default;

  [[nodiscard]] const FacilityAuthorityDomainId& domain() const noexcept { return domain_; }
  [[nodiscard]] DomainInstanceNumber domain_instance() const noexcept { return domain_instance_; }
  [[nodiscard]] Epoch epoch() const noexcept { return epoch_; }
  [[nodiscard]] DurableGeneration durable_generation() const noexcept { return durable_generation_; }

  /// Controller that holds the domain's standing administrative authority. It
  /// is fixed at initialization and cannot be changed by any API call.
  [[nodiscard]] const ControllerId& authority_root() const noexcept { return authority_root_; }

  [[nodiscard]] std::uint64_t controller_count() const noexcept { return controller_count_; }
  [[nodiscard]] std::uint64_t live_grant_count() const noexcept { return live_grant_count_; }
  [[nodiscard]] std::uint64_t mutation_grant_count() const noexcept { return mutation_grant_count_; }
  [[nodiscard]] std::uint64_t observation_grant_count() const noexcept { return observation_grant_count_; }

  /// Declared scopes in ascending canonical order.
  [[nodiscard]] const std::vector<ScopeName>& declared_scopes() const noexcept { return declared_scopes_; }

  [[nodiscard]] std::uint64_t transition_count() const noexcept { return transition_count_; }
  [[nodiscard]] std::uint64_t revocation_count() const noexcept { return revocation_count_; }
  [[nodiscard]] std::uint64_t idempotency_record_count() const noexcept { return idempotency_record_count_; }

  [[nodiscard]] const Sha256Digest& snapshot_digest() const noexcept { return snapshot_digest_; }
  [[nodiscard]] const Sha256Digest& transition_chain_head() const noexcept { return transition_chain_head_; }
  [[nodiscard]] RecoveryOutcome recovery_outcome() const noexcept { return recovery_outcome_; }
  [[nodiscard]] StoreOpenMode open_mode() const noexcept { return open_mode_; }
  [[nodiscard]] bool initialized() const noexcept { return initialized_; }

  [[nodiscard]] std::string to_string() const;

  friend bool operator==(const AuthorityStatus& lhs, const AuthorityStatus& rhs) noexcept {
    return lhs.domain_ == rhs.domain_ && lhs.domain_instance_ == rhs.domain_instance_ && lhs.epoch_ == rhs.epoch_ &&
           lhs.durable_generation_ == rhs.durable_generation_ && lhs.authority_root_ == rhs.authority_root_ &&
           lhs.controller_count_ == rhs.controller_count_ && lhs.live_grant_count_ == rhs.live_grant_count_ &&
           lhs.mutation_grant_count_ == rhs.mutation_grant_count_ &&
           lhs.observation_grant_count_ == rhs.observation_grant_count_ &&
           lhs.transition_count_ == rhs.transition_count_ && lhs.revocation_count_ == rhs.revocation_count_ &&
           lhs.initialized_ == rhs.initialized_;
  }

 private:
  friend class ControlPlaneEpochAuthority;
  friend class detail::AuthorityCore;
  friend class detail::ClientCore;

  FacilityAuthorityDomainId domain_;
  DomainInstanceNumber domain_instance_;
  Epoch epoch_;
  DurableGeneration durable_generation_;
  ControllerId authority_root_;
  std::uint64_t controller_count_ = 0;
  std::uint64_t live_grant_count_ = 0;
  std::uint64_t mutation_grant_count_ = 0;
  std::uint64_t observation_grant_count_ = 0;
  std::vector<ScopeName> declared_scopes_;
  std::uint64_t transition_count_ = 0;
  std::uint64_t revocation_count_ = 0;
  std::uint64_t idempotency_record_count_ = 0;
  Sha256Digest snapshot_digest_;
  Sha256Digest transition_chain_head_;
  RecoveryOutcome recovery_outcome_ = RecoveryOutcome::OpenedClean;
  StoreOpenMode open_mode_ = StoreOpenMode::ReadWrite;
  bool initialized_ = false;
};

/// Resource accounting for the authority. Provided so that callers can prove
/// that bounded structures stay bounded and that nothing leaks across repeated
/// start/stop cycles.
class AuthorityAccounting {
 public:
  AuthorityAccounting() = default;

  [[nodiscard]] std::uint64_t controller_records() const noexcept { return controller_records_; }
  [[nodiscard]] std::uint64_t grant_records() const noexcept { return grant_records_; }
  [[nodiscard]] std::uint64_t live_grant_records() const noexcept { return live_grant_records_; }
  [[nodiscard]] std::uint64_t transition_records_retained() const noexcept { return transition_records_retained_; }
  [[nodiscard]] std::uint64_t transition_records_trimmed() const noexcept { return transition_records_trimmed_; }
  [[nodiscard]] std::uint64_t revocation_records_retained() const noexcept { return revocation_records_retained_; }
  [[nodiscard]] std::uint64_t revocation_records_trimmed() const noexcept { return revocation_records_trimmed_; }
  [[nodiscard]] std::uint64_t idempotency_records() const noexcept { return idempotency_records_; }
  [[nodiscard]] std::uint64_t idempotency_records_evicted() const noexcept { return idempotency_records_evicted_; }
  [[nodiscard]] std::uint64_t snapshot_bytes() const noexcept { return snapshot_bytes_; }
  [[nodiscard]] bool retained_previous_generation() const noexcept { return retained_previous_generation_; }

  [[nodiscard]] std::string to_string() const;

  friend bool operator==(const AuthorityAccounting& lhs, const AuthorityAccounting& rhs) noexcept {
    return lhs.controller_records_ == rhs.controller_records_ && lhs.grant_records_ == rhs.grant_records_ &&
           lhs.live_grant_records_ == rhs.live_grant_records_ &&
           lhs.transition_records_retained_ == rhs.transition_records_retained_ &&
           lhs.transition_records_trimmed_ == rhs.transition_records_trimmed_ &&
           lhs.revocation_records_retained_ == rhs.revocation_records_retained_ &&
           lhs.revocation_records_trimmed_ == rhs.revocation_records_trimmed_ &&
           lhs.idempotency_records_ == rhs.idempotency_records_ &&
           lhs.idempotency_records_evicted_ == rhs.idempotency_records_evicted_ &&
           lhs.snapshot_bytes_ == rhs.snapshot_bytes_;
  }

 private:
  friend class ControlPlaneEpochAuthority;
  friend class detail::AuthorityCore;
  friend class detail::ClientCore;

  std::uint64_t controller_records_ = 0;
  std::uint64_t grant_records_ = 0;
  std::uint64_t live_grant_records_ = 0;
  std::uint64_t transition_records_retained_ = 0;
  std::uint64_t transition_records_trimmed_ = 0;
  std::uint64_t revocation_records_retained_ = 0;
  std::uint64_t revocation_records_trimmed_ = 0;
  std::uint64_t idempotency_records_ = 0;
  std::uint64_t idempotency_records_evicted_ = 0;
  std::uint64_t snapshot_bytes_ = 0;
  bool retained_previous_generation_ = false;
};

/// Page of controller records, ascending by controller identifier.
class ControllerPage {
 public:
  ControllerPage() = default;

  [[nodiscard]] const std::vector<ControllerRecord>& records() const noexcept { return records_; }
  [[nodiscard]] std::uint64_t total_count() const noexcept { return total_count_; }
  [[nodiscard]] std::uint64_t offset() const noexcept { return offset_; }

  friend bool operator==(const ControllerPage& lhs, const ControllerPage& rhs) noexcept {
    return lhs.records_ == rhs.records_ && lhs.total_count_ == rhs.total_count_ && lhs.offset_ == rhs.offset_;
  }

 private:
  friend class ControlPlaneEpochAuthority;
  friend class detail::AuthorityCore;
  friend class detail::ClientCore;

  std::vector<ControllerRecord> records_;
  std::uint64_t total_count_ = 0;
  std::uint64_t offset_ = 0;
};

/// Page of grants, ascending by grant identifier.
class GrantPage {
 public:
  GrantPage() = default;

  [[nodiscard]] const std::vector<AuthorityGrantRecord>& records() const noexcept { return records_; }
  [[nodiscard]] std::uint64_t total_count() const noexcept { return total_count_; }
  [[nodiscard]] std::uint64_t offset() const noexcept { return offset_; }
  [[nodiscard]] Epoch epoch() const noexcept { return epoch_; }

  friend bool operator==(const GrantPage& lhs, const GrantPage& rhs) noexcept {
    return lhs.records_ == rhs.records_ && lhs.total_count_ == rhs.total_count_ && lhs.offset_ == rhs.offset_ &&
           lhs.epoch_ == rhs.epoch_;
  }

 private:
  friend class ControlPlaneEpochAuthority;
  friend class detail::AuthorityCore;
  friend class detail::ClientCore;

  std::vector<AuthorityGrantRecord> records_;
  std::uint64_t total_count_ = 0;
  std::uint64_t offset_ = 0;
  Epoch epoch_;
};

/// Page of revocations, ascending by revocation sequence.
class RevocationPage {
 public:
  RevocationPage() = default;

  [[nodiscard]] const std::vector<RevocationRecord>& records() const noexcept { return records_; }
  [[nodiscard]] std::uint64_t total_count() const noexcept { return total_count_; }
  [[nodiscard]] std::uint64_t first_retained_sequence() const noexcept { return first_retained_sequence_; }
  [[nodiscard]] std::uint64_t trimmed_count() const noexcept { return trimmed_count_; }
  [[nodiscard]] const Sha256Digest& chain_head() const noexcept { return chain_head_; }

  friend bool operator==(const RevocationPage& lhs, const RevocationPage& rhs) noexcept {
    return lhs.records_ == rhs.records_ && lhs.total_count_ == rhs.total_count_ &&
           lhs.first_retained_sequence_ == rhs.first_retained_sequence_ && lhs.trimmed_count_ == rhs.trimmed_count_ &&
           lhs.chain_head_ == rhs.chain_head_;
  }

 private:
  friend class ControlPlaneEpochAuthority;
  friend class detail::AuthorityCore;
  friend class detail::ClientCore;

  std::vector<RevocationRecord> records_;
  std::uint64_t total_count_ = 0;
  std::uint64_t first_retained_sequence_ = 0;
  std::uint64_t trimmed_count_ = 0;
  Sha256Digest chain_head_;
};

}  // namespace dccp::epoch

