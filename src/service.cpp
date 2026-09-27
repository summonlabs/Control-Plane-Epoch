// Control Plane Epoch 1.0.0 - Summon Software Labs
// Public service facade over the internal authority core.
#include "control_plane_epoch/service.hpp"

#include <utility>

#include "core.hpp"

namespace dccp::epoch {

ControlPlaneEpochAuthority::ControlPlaneEpochAuthority(const StoreOpenOptions& options)
    : core_(std::make_unique<detail::AuthorityCore>(options)) {}

ControlPlaneEpochAuthority::~ControlPlaneEpochAuthority() = default;

ControlPlaneEpochAuthority::ControlPlaneEpochAuthority(ControlPlaneEpochAuthority&& other) noexcept = default;

ControlPlaneEpochAuthority& ControlPlaneEpochAuthority::operator=(ControlPlaneEpochAuthority&& other) noexcept =
    default;

const RecoveryReport& ControlPlaneEpochAuthority::recovery() const {
  if (core_ == nullptr) {
    throw EpochError(ErrorCode::StoreNotFound, "the authority is closed");
  }
  return core_->recovery();
}

bool ControlPlaneEpochAuthority::initialized() const noexcept {
  if (core_ == nullptr) {
    return false;
  }
  return core_->initialized();
}

Status ControlPlaneEpochAuthority::initialize(InitializeDomainRequest request) {
  if (core_ == nullptr) {
    throw EpochError(ErrorCode::StoreNotFound, "the authority is closed");
  }
  return core_->initialize(std::move(request));
}

AuthorityStatus ControlPlaneEpochAuthority::status() const { return core_->status(); }

AuthorityAccounting ControlPlaneEpochAuthority::accounting() const { return core_->accounting(); }

Epoch ControlPlaneEpochAuthority::current_epoch() const { return core_->current_epoch(); }

std::optional<DurableCommitReport> ControlPlaneEpochAuthority::last_commit() const {
  if (core_ == nullptr) {
    return std::nullopt;
  }
  return core_->last_commit();
}

Result<ControllerRegistration> ControlPlaneEpochAuthority::register_controller(RegisterControllerRequest request) {
  if (core_ == nullptr) {
    throw EpochError(ErrorCode::StoreNotFound, "the authority is closed");
  }
  return core_->register_controller(std::move(request));
}

Result<AuthorityGrantView> ControlPlaneEpochAuthority::acquire_authority(AcquireAuthorityRequest request) {
  if (core_ == nullptr) {
    throw EpochError(ErrorCode::StoreNotFound, "the authority is closed");
  }
  return core_->acquire_authority(std::move(request));
}

Result<EpochTransitionRecord> ControlPlaneEpochAuthority::advance_epoch(AdvanceEpochRequest request) {
  if (core_ == nullptr) {
    throw EpochError(ErrorCode::StoreNotFound, "the authority is closed");
  }
  return core_->advance_epoch(std::move(request));
}

Result<RevocationRecord> ControlPlaneEpochAuthority::revoke_authority(RevokeAuthorityRequest request) {
  if (core_ == nullptr) {
    throw EpochError(ErrorCode::StoreNotFound, "the authority is closed");
  }
  return core_->revoke_authority(std::move(request));
}

ValidationOutcome ControlPlaneEpochAuthority::validate_mutation(const MutationAuthority& authority,
                                                                const ScopeName& scope) {
  if (core_ == nullptr) {
    throw EpochError(ErrorCode::StoreNotFound, "the authority is closed");
  }
  return core_->validate_mutation(authority, scope);
}

ValidationOutcome ControlPlaneEpochAuthority::validate_observation(const ObservationAuthority& authority,
                                                                   const ScopeName& scope) {
  if (core_ == nullptr) {
    throw EpochError(ErrorCode::StoreNotFound, "the authority is closed");
  }
  return core_->validate_observation(authority, scope);
}

Result<RecoveryQualification> ControlPlaneEpochAuthority::qualify_recovered_state(
    const RecoveredStateClaim& claim) {
  if (core_ == nullptr) {
    throw EpochError(ErrorCode::StoreNotFound, "the authority is closed");
  }
  return core_->qualify_recovered_state(claim);
}

Result<EpochHistoryPage> ControlPlaneEpochAuthority::history(const HistoryQuery& query) const {
  return core_->history(query);
}

Result<RevocationPage> ControlPlaneEpochAuthority::revocations(const RevocationQuery& query) const {
  return core_->revocations(query);
}

Result<ControllerPage> ControlPlaneEpochAuthority::controllers(const ControllerQuery& query) const {
  return core_->controllers(query);
}

Result<GrantPage> ControlPlaneEpochAuthority::grants(const GrantQuery& query) const {
  return core_->grants(query);
}

Result<ControllerRecord> ControlPlaneEpochAuthority::controller_record(const ControllerId& controller) const {
  return core_->controller_record(controller);
}

Result<AuthorityGrantRecord> ControlPlaneEpochAuthority::grant_record(GrantId grant_id) const {
  return core_->grant_record(grant_id);
}

void ControlPlaneEpochAuthority::write_snapshot_artifact(const std::filesystem::path& path) const {
  if (core_ == nullptr) {
    throw EpochError(ErrorCode::StoreNotFound, "the authority is closed");
  }
  core_->write_snapshot_artifact(path);
}

void ControlPlaneEpochAuthority::close() noexcept {
  if (core_ != nullptr) {
    core_->close();
  }
}

bool ControlPlaneEpochAuthority::closed() const noexcept { return core_ == nullptr || core_->closed(); }

}  // namespace dccp::epoch
