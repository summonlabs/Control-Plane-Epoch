// Control Plane Epoch 1.0.0 - Summon Software Labs
// Remote controller client.
//
// One client owns one connection and issues one request at a time. Operating
// system level blocking is used throughout: the client never times a request
// out, and a peer that dies mid-frame produces an explicit
// EpochError(SocketClosed) or EpochError(FrameTruncated) rather than a
// half-applied result. Results and rejections are the same types a local
// consumer uses.
#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "control_plane_epoch/commands.hpp"
#include "control_plane_epoch/error.hpp"
#include "control_plane_epoch/incarnation.hpp"
#include "control_plane_epoch/inspection.hpp"
#include "control_plane_epoch/limits.hpp"
#include "control_plane_epoch/recovery.hpp"
#include "control_plane_epoch/transition.hpp"

namespace dccp::epoch {

namespace detail {
class ClientCore;
}

/// What the authority reported in its handshake.
class AuthorityEndpointInfo {
 public:
  AuthorityEndpointInfo() = default;

  [[nodiscard]] std::uint16_t protocol_version() const noexcept { return protocol_version_; }
  [[nodiscard]] const FacilityAuthorityDomainId& domain() const noexcept { return domain_; }
  [[nodiscard]] DomainInstanceNumber domain_instance() const noexcept { return domain_instance_; }
  [[nodiscard]] Epoch epoch() const noexcept { return epoch_; }
  [[nodiscard]] DurableGeneration durable_generation() const noexcept { return durable_generation_; }
  [[nodiscard]] bool initialized() const noexcept { return initialized_; }

  [[nodiscard]] std::string to_string() const;

  friend bool operator==(const AuthorityEndpointInfo& lhs, const AuthorityEndpointInfo& rhs) noexcept {
    return lhs.protocol_version_ == rhs.protocol_version_ && lhs.domain_ == rhs.domain_ &&
           lhs.domain_instance_ == rhs.domain_instance_ && lhs.epoch_ == rhs.epoch_ &&
           lhs.durable_generation_ == rhs.durable_generation_ && lhs.initialized_ == rhs.initialized_;
  }

 private:
  friend class EpochAuthorityClient;
  friend class detail::ClientCore;

  std::uint16_t protocol_version_ = 0;
  FacilityAuthorityDomainId domain_;
  DomainInstanceNumber domain_instance_;
  Epoch epoch_;
  DurableGeneration durable_generation_;
  bool initialized_ = false;
};

struct ClientOptions {
  std::string host = "127.0.0.1";
  std::uint16_t port = 0;
  std::size_t max_frame_payload_bytes = ::dccp::epoch::max_frame_payload_bytes;

  /// When set, the handshake fails with ErrorCode::ProtocolDomainMismatch if the
  /// authority serves a different domain. Client processes that already hold
  /// tokens should always set it: authority tokens are domain-bound.
  std::optional<FacilityAuthorityDomainId> expected_domain;
};

class EpochAuthorityClient {
 public:
  /// Connects and performs the version/domain handshake. Throws EpochError on
  /// connection, framing, or handshake failure.
  explicit EpochAuthorityClient(const ClientOptions& options);
  ~EpochAuthorityClient();

  EpochAuthorityClient(const EpochAuthorityClient&) = delete;
  EpochAuthorityClient& operator=(const EpochAuthorityClient&) = delete;

  [[nodiscard]] const AuthorityEndpointInfo& endpoint() const noexcept;

  [[nodiscard]] Result<ControllerRegistration> register_controller(RegisterControllerRequest request);
  [[nodiscard]] Result<AuthorityGrantView> acquire_authority(AcquireAuthorityRequest request);
  [[nodiscard]] ValidationOutcome validate_mutation(const MutationAuthority& authority, const ScopeName& scope);
  [[nodiscard]] ValidationOutcome validate_observation(const ObservationAuthority& authority, const ScopeName& scope);
  [[nodiscard]] Result<EpochTransitionRecord> advance_epoch(AdvanceEpochRequest request);
  [[nodiscard]] Result<RevocationRecord> revoke_authority(RevokeAuthorityRequest request);
  [[nodiscard]] Result<RecoveryQualification> qualify_recovered_state(const RecoveredStateClaim& claim);

  [[nodiscard]] Result<AuthorityStatus> status();
  [[nodiscard]] Result<EpochHistoryPage> history(const HistoryQuery& query);
  [[nodiscard]] Result<RevocationPage> revocations(const RevocationQuery& query);
  [[nodiscard]] Result<ControllerPage> controllers(const ControllerQuery& query);
  [[nodiscard]] Result<GrantPage> grants(const GrantQuery& query);

  /// Requests served on this connection so far.
  [[nodiscard]] std::uint64_t request_count() const noexcept;

  void close() noexcept;
  [[nodiscard]] bool closed() const noexcept;

 private:
  std::unique_ptr<detail::ClientCore> core_;
};

}  // namespace dccp::epoch
