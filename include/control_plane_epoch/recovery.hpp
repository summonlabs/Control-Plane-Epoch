// Control Plane Epoch 1.0.0 - Summon Software Labs
// Qualification of recovered state.
//
// Persisted dynamic evidence does not become fresh because a process restarted.
// A consumer that recovers facility state produced under some earlier authority
// presents a claim, and the authority qualifies it against current durable
// state into exactly one verdict. "Current" is never inferred, and state
// produced under a fenced epoch is never reported as current.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "control_plane_epoch/digest.hpp"
#include "control_plane_epoch/epoch.hpp"
#include "control_plane_epoch/error.hpp"
#include "control_plane_epoch/identity.hpp"
#include "control_plane_epoch/incarnation.hpp"

namespace dccp::epoch {

/// Verdict for a piece of recovered state. Numeric values are stable.
enum class RecoveredStateVerdict : std::uint32_t {
  /// Produced by the current incarnation, under the current epoch, with
  /// authority over the claimed scope. Usable as current authoritative state.
  Current = 1,
  /// Produced under an epoch that is no longer current, by an incarnation that
  /// is still the producer's current incarnation. The data is not authoritative
  /// now but nothing proves it wrong; it must be revalidated before use.
  Stale = 2,
  /// Produced by an incarnation that has been superseded or revoked. The data
  /// is permanently fenced and must not be treated as authoritative.
  Superseded = 3,
  /// Produced under an earlier epoch by the incarnation that is still current
  /// and still holds authority over the claimed scope. The writer survived the
  /// epoch change, so the data may be reconcilable, but only after explicit
  /// re-attestation. It is never silently current.
  NeedsReconciliation = 4,
  /// The claim cannot be trusted at all: it names a different domain, a future
  /// epoch, an unknown incarnation, or a scope the producer never held.
  Rejected = 5,
};

inline constexpr std::uint32_t max_recovered_state_verdict = 5;

[[nodiscard]] std::string_view recovered_state_verdict_token(RecoveredStateVerdict verdict) noexcept;
[[nodiscard]] Result<RecoveredStateVerdict> parse_recovered_state_verdict(std::string_view token);

/// A consumer's claim about recovered state. Every field is untrusted input and
/// is validated before it is used.
class RecoveredStateClaim {
 public:
  RecoveredStateClaim() = default;

  [[nodiscard]] static Result<RecoveredStateClaim> create(FacilityAuthorityDomainId domain, Epoch producing_epoch,
                                                          ControllerId producer,
                                                          ControllerIncarnationId producer_incarnation,
                                                          ScopeName scope, Sha256Digest content_digest);

  [[nodiscard]] const FacilityAuthorityDomainId& domain() const noexcept { return domain_; }
  [[nodiscard]] Epoch producing_epoch() const noexcept { return producing_epoch_; }
  [[nodiscard]] const ControllerId& producer() const noexcept { return producer_; }
  [[nodiscard]] const ControllerIncarnationId& producer_incarnation() const noexcept { return producer_incarnation_; }
  [[nodiscard]] const ScopeName& scope() const noexcept { return scope_; }
  [[nodiscard]] const Sha256Digest& content_digest() const noexcept { return content_digest_; }

  [[nodiscard]] std::string to_string() const;

  friend bool operator==(const RecoveredStateClaim& lhs, const RecoveredStateClaim& rhs) noexcept {
    return lhs.domain_ == rhs.domain_ && lhs.producing_epoch_ == rhs.producing_epoch_ &&
           lhs.producer_ == rhs.producer_ && lhs.producer_incarnation_ == rhs.producer_incarnation_ &&
           lhs.scope_ == rhs.scope_ && lhs.content_digest_ == rhs.content_digest_;
  }

 private:
  FacilityAuthorityDomainId domain_;
  Epoch producing_epoch_;
  ControllerId producer_;
  ControllerIncarnationId producer_incarnation_;
  ScopeName scope_;
  Sha256Digest content_digest_;
};

/// Deterministic qualification of one recovered-state claim.
class RecoveryQualification {
 public:
  RecoveryQualification() = default;

  RecoveryQualification(RecoveredStateVerdict verdict, Explanation explanation,
                        std::optional<GrantId> matching_grant, bool requires_revalidation)
      : verdict_(verdict),
        explanation_(std::move(explanation)),
        matching_grant_(matching_grant),
        requires_revalidation_(requires_revalidation) {}

  [[nodiscard]] RecoveredStateVerdict verdict() const noexcept { return verdict_; }
  [[nodiscard]] const Explanation& explanation() const noexcept { return explanation_; }
  [[nodiscard]] ErrorCode code() const noexcept { return explanation_.code(); }

  /// Grant in the current epoch that covers the claimed scope for the producer,
  /// when one exists. This is evidence, not authority.
  [[nodiscard]] const std::optional<GrantId>& matching_grant() const noexcept { return matching_grant_; }

  /// True when the state may be used only after explicit re-attestation by a
  /// currently authorized writer.
  [[nodiscard]] bool requires_revalidation() const noexcept { return requires_revalidation_; }

  [[nodiscard]] bool usable_as_current() const noexcept { return verdict_ == RecoveredStateVerdict::Current; }

  [[nodiscard]] std::string to_string() const;

  friend bool operator==(const RecoveryQualification& lhs, const RecoveryQualification& rhs) noexcept {
    return lhs.verdict_ == rhs.verdict_ && lhs.explanation_ == rhs.explanation_ &&
           lhs.matching_grant_ == rhs.matching_grant_ && lhs.requires_revalidation_ == rhs.requires_revalidation_;
  }

 private:
  RecoveredStateVerdict verdict_ = RecoveredStateVerdict::Rejected;
  Explanation explanation_;
  std::optional<GrantId> matching_grant_;
  bool requires_revalidation_ = true;
};

}  // namespace dccp::epoch
