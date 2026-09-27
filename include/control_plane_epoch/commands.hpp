// Control Plane Epoch 1.0.0 - Summon Software Labs
// Mutation commands.
//
// Every state-changing operation is expressed as an explicit, validated command
// value. Commands never carry raw persistence structures, and a command that
// changes authoritative state always carries provenance plus, optionally, an
// idempotency key so that a retry cannot be applied twice.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "control_plane_epoch/authority.hpp"
#include "control_plane_epoch/epoch.hpp"
#include "control_plane_epoch/error.hpp"
#include "control_plane_epoch/identity.hpp"
#include "control_plane_epoch/incarnation.hpp"
#include "control_plane_epoch/limits.hpp"
#include "control_plane_epoch/provenance.hpp"
#include "control_plane_epoch/transition.hpp"

namespace dccp::epoch {

/// Creates an authority domain: the epoch is set to its initial value, the
/// declared scopes become the domain's scope vocabulary, and the authority root
/// is registered as the first incarnation with a grant covering every declared
/// scope.
///
/// The three reserved administrative scopes (authority.grant, authority.revoke,
/// epoch.advance) must be declared. A domain that cannot grant, revoke, or
/// advance would be unadministrable, so initialization rejects it.
struct InitializeDomainRequest {
  FacilityAuthorityDomainId domain;
  std::vector<ScopeName> scopes;
  ControllerId authority_root;
  ProvenanceInput provenance;
};

/// Registers a controller and returns a fresh incarnation.
///
/// Registration confers identity only, never authority: it is the discovery
/// step every controller performs after boot. It is bounded by
/// limits::max_controllers. Registering a controller that is already registered
/// supersedes its previous incarnation, permanently fencing any authority bound
/// to that earlier incarnation.
struct RegisterControllerRequest {
  ControllerId controller;
  ProvenanceInput provenance;
  std::optional<IdempotencyKey> idempotency;
};

/// Issues a scoped, epoch-bound authority grant.
///
/// The sponsor must present a currently valid mutation authority covering the
/// reserved scope authority.grant, except for the domain's authority root
/// acquiring reserved administrative scopes, which is the documented bootstrap
/// path. A grant is bound to the epoch in which it is issued and is fenced the
/// moment the epoch advances.
struct AcquireAuthorityRequest {
  AuthorityClass authority_class = AuthorityClass::Mutation;
  ControllerId controller;
  ControllerIncarnationId incarnation;
  AuthorityScopeSet scopes;
  std::optional<MutationAuthority> sponsor;
  ProvenanceInput provenance;
  std::optional<IdempotencyKey> idempotency;
};

/// Advances the epoch to exactly one successor of expected_current.
///
/// The expected value is a precondition, not a hint: if the authoritative epoch
/// is no longer expected_current the command is rejected with
/// ErrorCode::EpochConflict, which is what makes concurrent advancement resolve
/// to exactly one committed successor per base epoch.
struct AdvanceEpochRequest {
  Epoch expected_current;
  MutationAuthority authority;
  EpochTransitionReason reason = EpochTransitionReason::OperatorRequest;
  ProvenanceInput provenance;
  std::optional<IdempotencyKey> idempotency;
};

/// What a revocation command fences.
class RevocationTarget {
 public:
  RevocationTarget() = default;

  /// Fences every incarnation of the controller up to and including its current
  /// incarnation.
  [[nodiscard]] static RevocationTarget controller_all(ControllerId controller) {
    return RevocationTarget(std::move(controller), std::nullopt, std::nullopt);
  }

  /// Fences every incarnation of the controller up to and including the given
  /// incarnation number. Re-registration above that number is unaffected, which
  /// is what makes revocation monotonic without being permanent.
  [[nodiscard]] static RevocationTarget controller_through(ControllerId controller, IncarnationNumber through) {
    return RevocationTarget(std::move(controller), through, std::nullopt);
  }

  /// Fences exactly one grant.
  [[nodiscard]] static RevocationTarget grant(GrantId grant_id, ControllerId owner) {
    return RevocationTarget(std::move(owner), std::nullopt, grant_id);
  }

  [[nodiscard]] RevocationTargetKind kind() const noexcept {
    return grant_.has_value() ? RevocationTargetKind::Grant : RevocationTargetKind::ControllerIncarnations;
  }
  [[nodiscard]] const ControllerId& controller() const noexcept { return controller_; }
  [[nodiscard]] const std::optional<IncarnationNumber>& through_incarnation() const noexcept {
    return through_incarnation_;
  }
  [[nodiscard]] const std::optional<GrantId>& grant() const noexcept { return grant_; }

  [[nodiscard]] std::string to_string() const;

  friend bool operator==(const RevocationTarget& lhs, const RevocationTarget& rhs) noexcept {
    return lhs.controller_ == rhs.controller_ && lhs.through_incarnation_ == rhs.through_incarnation_ &&
           lhs.grant_ == rhs.grant_;
  }

 private:
  RevocationTarget(ControllerId controller, std::optional<IncarnationNumber> through, std::optional<GrantId> grant)
      : controller_(std::move(controller)), through_incarnation_(through), grant_(grant) {}

  ControllerId controller_;
  std::optional<IncarnationNumber> through_incarnation_;
  std::optional<GrantId> grant_;
};

/// Revokes authority. Requires a currently valid mutation authority covering the
/// reserved scope authority.revoke.
///
/// Revocation is monotonic within its scope: once a grant or an incarnation is
/// fenced, no later command can un-fence it. Repeating a revocation that is
/// already fully in force is accepted and returns the existing record marked as
/// replayed, so retries are safe.
struct RevokeAuthorityRequest {
  RevocationTarget target;
  RevocationReason reason = RevocationReason::OperatorRequest;
  MutationAuthority authority;
  ProvenanceInput provenance;
  std::optional<IdempotencyKey> idempotency;
};

/// Query for the epoch transition ledger.
struct HistoryQuery {
  /// First sequence to return. Absent means "from the oldest retained record".
  std::optional<TransitionSequence> from_sequence;
  std::size_t limit = max_page_size;
};

/// Query for the revocation ledger.
struct RevocationQuery {
  std::optional<RevocationSequence> from_sequence;
  std::size_t limit = max_page_size;
};

/// Query for registered controllers.
struct ControllerQuery {
  /// First controller identifier to return. Absent means "from the lowest".
  std::optional<ControllerId> from_controller;
  std::size_t limit = max_page_size;
};

/// Query for grants of the current epoch.
struct GrantQuery {
  std::optional<GrantId> from_grant;
  std::size_t limit = max_page_size;
};

}  // namespace dccp::epoch
