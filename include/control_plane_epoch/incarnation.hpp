// Control Plane Epoch 1.0.0 - Summon Software Labs
// Controller incarnations.
//
// A controller identity is stable across restarts. A controller *incarnation*
// is not: every registration of a controller produces a fresh, strictly higher
// incarnation number and therefore a fresh incarnation identity. Authority is
// always bound to an incarnation, so a restarted controller cannot regain
// authority by reloading tokens it persisted locally.
#pragma once

#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "control_plane_epoch/digest.hpp"
#include "control_plane_epoch/epoch.hpp"
#include "control_plane_epoch/error.hpp"
#include "control_plane_epoch/identity.hpp"
#include "control_plane_epoch/provenance.hpp"

namespace dccp::epoch {

namespace detail {
struct RecordFactory;
}

/// Identity of one controller boot within one facility authority domain.
///
/// Derived deterministically from (domain, controller, incarnation number), so
/// it is reproducible from durable state and cannot be confused with any other
/// identity in the system.
class ControllerIncarnationId {
 public:
  ControllerIncarnationId() = default;

  [[nodiscard]] static ControllerIncarnationId derive(const FacilityAuthorityDomainId& domain,
                                                      const ControllerId& controller,
                                                      IncarnationNumber number);
  [[nodiscard]] static Result<ControllerIncarnationId> from_hex(std::string_view text);
  [[nodiscard]] static ControllerIncarnationId from_digest(Sha256Digest digest) noexcept {
    return ControllerIncarnationId(digest);
  }

  [[nodiscard]] const Sha256Digest& digest() const noexcept { return digest_; }
  [[nodiscard]] bool is_zero() const noexcept { return digest_.is_zero(); }
  [[nodiscard]] std::string to_hex() const { return digest_.to_hex(); }

  friend bool operator==(const ControllerIncarnationId& lhs, const ControllerIncarnationId& rhs) noexcept {
    return lhs.digest_ == rhs.digest_;
  }
  friend bool operator!=(const ControllerIncarnationId& lhs, const ControllerIncarnationId& rhs) noexcept {
    return !(lhs == rhs);
  }
  friend std::strong_ordering operator<=>(const ControllerIncarnationId& lhs,
                                          const ControllerIncarnationId& rhs) noexcept {
    return lhs.digest_ < rhs.digest_ ? std::strong_ordering::less
                                     : (lhs.digest_ == rhs.digest_ ? std::strong_ordering::equal
                                                                   : std::strong_ordering::greater);
  }

 private:
  explicit ControllerIncarnationId(Sha256Digest digest) noexcept : digest_(digest) {}

  Sha256Digest digest_;
};

/// Lifecycle state of one controller incarnation.
///
/// Legal transitions:
///   Current    -> Superseded   (a higher incarnation of the same controller registered)
///   Current    -> Revoked      (controller revocation covering this incarnation)
///   Superseded -> Revoked      (controller revocation covering this incarnation)
/// No other transition exists, and none is reversible.
enum class IncarnationState : std::uint32_t {
  Current = 1,
  Superseded = 2,
  Revoked = 3,
};

inline constexpr std::uint32_t max_incarnation_state = 3;

[[nodiscard]] std::string_view incarnation_state_token(IncarnationState state) noexcept;
[[nodiscard]] Result<IncarnationState> parse_incarnation_state(std::string_view token);

/// Immutable view of a controller's most recent incarnation as recorded in the
/// authoritative state. Older incarnations are always superseded; that rule is
/// derived from the incarnation number and is not stored per incarnation.
class ControllerRecord {
 public:
  ControllerRecord() = default;

  [[nodiscard]] const ControllerId& controller() const noexcept { return controller_; }
  [[nodiscard]] IncarnationNumber incarnation_number() const noexcept { return incarnation_number_; }
  [[nodiscard]] const ControllerIncarnationId& incarnation_id() const noexcept { return incarnation_id_; }
  [[nodiscard]] IncarnationState incarnation_state() const noexcept { return incarnation_state_; }

  /// Number of registrations accepted for this controller, including the first.
  [[nodiscard]] std::uint64_t registration_count() const noexcept { return registration_count_; }

  [[nodiscard]] Epoch first_registered_epoch() const noexcept { return first_registered_epoch_; }
  [[nodiscard]] Epoch latest_registered_epoch() const noexcept { return latest_registered_epoch_; }

  /// Highest incarnation fenced by a controller-level revocation, if any. A
  /// controller re-registers above this value to become authoritative again,
  /// which is what makes revocation monotonic without being permanent.
  [[nodiscard]] const std::optional<IncarnationNumber>& revocation_through_incarnation() const noexcept {
    return revocation_through_incarnation_;
  }

  [[nodiscard]] const ProvenanceRecord& latest_registration_provenance() const noexcept {
    return latest_registration_provenance_;
  }

  [[nodiscard]] const Sha256Digest& record_digest() const noexcept { return record_digest_; }

  [[nodiscard]] bool is_authoritative_incarnation() const noexcept {
    return incarnation_state_ == IncarnationState::Current;
  }

  [[nodiscard]] std::string to_string() const;

  friend bool operator==(const ControllerRecord& lhs, const ControllerRecord& rhs) noexcept {
    return lhs.controller_ == rhs.controller_ && lhs.incarnation_number_ == rhs.incarnation_number_ &&
           lhs.incarnation_id_ == rhs.incarnation_id_ && lhs.incarnation_state_ == rhs.incarnation_state_ &&
           lhs.registration_count_ == rhs.registration_count_ &&
           lhs.first_registered_epoch_ == rhs.first_registered_epoch_ &&
           lhs.latest_registered_epoch_ == rhs.latest_registered_epoch_ &&
           lhs.revocation_through_incarnation_ == rhs.revocation_through_incarnation_ &&
           lhs.latest_registration_provenance_ == rhs.latest_registration_provenance_;
  }
  friend bool operator!=(const ControllerRecord& lhs, const ControllerRecord& rhs) noexcept { return !(lhs == rhs); }

 private:
  friend struct detail::RecordFactory;

  ControllerId controller_;
  IncarnationNumber incarnation_number_;
  ControllerIncarnationId incarnation_id_;
  IncarnationState incarnation_state_ = IncarnationState::Current;
  std::uint64_t registration_count_ = 0;
  Epoch first_registered_epoch_;
  Epoch latest_registered_epoch_;
  std::optional<IncarnationNumber> revocation_through_incarnation_;
  ProvenanceRecord latest_registration_provenance_;
  Sha256Digest record_digest_;
};

/// Result of an accepted controller registration.
class ControllerRegistration {
 public:
  ControllerRegistration() = default;

  [[nodiscard]] const ControllerId& controller() const noexcept { return controller_; }
  [[nodiscard]] IncarnationNumber incarnation_number() const noexcept { return incarnation_number_; }
  [[nodiscard]] const ControllerIncarnationId& incarnation_id() const noexcept { return incarnation_id_; }
  [[nodiscard]] Epoch epoch() const noexcept { return epoch_; }
  [[nodiscard]] RegistrationSequence sequence() const noexcept { return sequence_; }

  /// True when this registration is the recorded outcome of an earlier
  /// identical request replayed under the same idempotency key.
  [[nodiscard]] bool replayed() const noexcept { return replayed_; }

  [[nodiscard]] const ProvenanceRecord& provenance() const noexcept { return provenance_; }
  [[nodiscard]] std::string to_string() const;

  friend bool operator==(const ControllerRegistration& lhs, const ControllerRegistration& rhs) noexcept {
    return lhs.controller_ == rhs.controller_ && lhs.incarnation_number_ == rhs.incarnation_number_ &&
           lhs.incarnation_id_ == rhs.incarnation_id_ && lhs.epoch_ == rhs.epoch_ && lhs.sequence_ == rhs.sequence_ &&
           lhs.replayed_ == rhs.replayed_;
  }
  friend bool operator!=(const ControllerRegistration& lhs, const ControllerRegistration& rhs) noexcept {
    return !(lhs == rhs);
  }

 private:
  friend struct detail::RecordFactory;

  ControllerId controller_;
  IncarnationNumber incarnation_number_;
  ControllerIncarnationId incarnation_id_;
  Epoch epoch_;
  RegistrationSequence sequence_;
  bool replayed_ = false;
  ProvenanceRecord provenance_;
};

}  // namespace dccp::epoch
