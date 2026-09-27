// Control Plane Epoch 1.0.0 - Summon Software Labs
// The single authoritative control-plane epoch service of one facility
// authority domain.
//
// Concurrency model
// -----------------
// One instance owns one durable store directory and is protected by one
// non-recursive mutex. Every public method takes that mutex once, performs its
// work, and returns; no callback, listener, or user-supplied function is ever
// invoked while the mutex is held, so re-entrancy is impossible by
// construction. The process-wide exclusive writer lock of the store directory is
// acquired once in the constructor and released once in close()/destruction;
// individual commits never re-acquire it, so there is no file-lock inversion
// between the in-process mutex and the operating-system lock.
//
// Durability model
// ----------------
// Every accepted state change is committed transactionally before it is
// reported as accepted: build image, write exclusive temporary file, flush to
// the device, re-read and verify, publish atomically, retain the superseded
// generation as the fallback, then publish the durable floor. A commit is
// reported successful only after both the new generation and the floor are
// durable, which is what makes rollback below the floor impossible.
#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>

#include "control_plane_epoch/authority.hpp"
#include "control_plane_epoch/commands.hpp"
#include "control_plane_epoch/digest.hpp"
#include "control_plane_epoch/epoch.hpp"
#include "control_plane_epoch/error.hpp"
#include "control_plane_epoch/identity.hpp"
#include "control_plane_epoch/incarnation.hpp"
#include "control_plane_epoch/inspection.hpp"
#include "control_plane_epoch/recovery.hpp"
#include "control_plane_epoch/store.hpp"
#include "control_plane_epoch/transition.hpp"

namespace dccp::epoch {

namespace detail {
class AuthorityCore;
}

class ControlPlaneEpochAuthority {
 public:
  /// Opens (and, when needed, recovers) the durable authority store described
  /// by the options. Throws EpochError on infrastructure failure: unreadable or
  /// damaged state under RecoveryPolicy::RefuseOnDamage, a store directory held
  /// by another writer process, invalid paths, or failed I/O. Expected domain
  /// outcomes are reported through Result, never through exceptions.
  explicit ControlPlaneEpochAuthority(const StoreOpenOptions& options);
  ~ControlPlaneEpochAuthority();

  ControlPlaneEpochAuthority(const ControlPlaneEpochAuthority&) = delete;
  ControlPlaneEpochAuthority& operator=(const ControlPlaneEpochAuthority&) = delete;
  ControlPlaneEpochAuthority(ControlPlaneEpochAuthority&& other) noexcept;
  ControlPlaneEpochAuthority& operator=(ControlPlaneEpochAuthority&& other) noexcept;

  /// What opening the store did. Throws EpochError(StoreNotFound) once the
  /// authority has been closed, like every other operation on a closed
  /// authority; it never returns a report that describes released state.
  [[nodiscard]] const RecoveryReport& recovery() const;

  /// True once a domain exists in the store (initialized here or recovered).
  [[nodiscard]] bool initialized() const noexcept;

  /// Creates the authority domain. Rejected with ErrorCode::StoreAlreadyInitialized
  /// when a domain already exists. In read-only mode this is rejected with
  /// ErrorCode::UnsupportedOperation.
  [[nodiscard]] Status initialize(InitializeDomainRequest request);

  // -- Reads ---------------------------------------------------------------

  [[nodiscard]] AuthorityStatus status() const;
  [[nodiscard]] AuthorityAccounting accounting() const;
  [[nodiscard]] Epoch current_epoch() const;

  /// Report of the most recent successful durable commit, if this instance has
  /// committed anything yet. Reports the published generation, epoch, snapshot
  /// digest, byte count, and whether a fallback generation was retained.
  [[nodiscard]] std::optional<DurableCommitReport> last_commit() const;

  // -- Lifecycle -----------------------------------------------------------

  [[nodiscard]] Result<ControllerRegistration> register_controller(RegisterControllerRequest request);
  [[nodiscard]] Result<AuthorityGrantView> acquire_authority(AcquireAuthorityRequest request);
  [[nodiscard]] Result<EpochTransitionRecord> advance_epoch(AdvanceEpochRequest request);
  [[nodiscard]] Result<RevocationRecord> revoke_authority(RevokeAuthorityRequest request);

  // -- Validation ----------------------------------------------------------

  /// Validates a mutation authority against durable state for one scope.
  ///
  /// Check order is fixed and documented: domain, token integrity, epoch,
  /// grant existence, authority class, revocation, incarnation currency, then
  /// scope coverage. The first failing check determines the rejection code.
  [[nodiscard]] ValidationOutcome validate_mutation(const MutationAuthority& authority, const ScopeName& scope);

  /// Validates an observation authority. Identical ladder to mutation
  /// validation, against observation grants.
  [[nodiscard]] ValidationOutcome validate_observation(const ObservationAuthority& authority, const ScopeName& scope);

  /// Qualifies state recovered by a consumer. Never reports state produced
  /// under a fenced epoch or a superseded incarnation as current.
  [[nodiscard]] Result<RecoveryQualification> qualify_recovered_state(const RecoveredStateClaim& claim);

  // -- Inspection ----------------------------------------------------------

  [[nodiscard]] Result<EpochHistoryPage> history(const HistoryQuery& query) const;
  [[nodiscard]] Result<RevocationPage> revocations(const RevocationQuery& query) const;
  [[nodiscard]] Result<ControllerPage> controllers(const ControllerQuery& query) const;
  [[nodiscard]] Result<GrantPage> grants(const GrantQuery& query) const;

  [[nodiscard]] Result<ControllerRecord> controller_record(const ControllerId& controller) const;
  [[nodiscard]] Result<AuthorityGrantRecord> grant_record(GrantId grant_id) const;

  // -- Snapshots -----------------------------------------------------------

  /// Writes a verified, self-contained copy of the current durable generation to
  /// the given path using exclusive create plus atomic replace. Throws
  /// EpochError on I/O failure.
  void write_snapshot_artifact(const std::filesystem::path& path) const;

  /// Releases the writer lock and closes the store. Idempotent. After close()
  /// every operation is rejected with ErrorCode::StoreNotFound rather than
  /// silently succeeding against released state.
  void close() noexcept;
  [[nodiscard]] bool closed() const noexcept;

 private:
  std::unique_ptr<detail::AuthorityCore> core_;
};

}  // namespace dccp::epoch
