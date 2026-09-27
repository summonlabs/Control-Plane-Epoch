// Control Plane Epoch 1.0.0 - Summon Software Labs
// Internal wire payload codecs. Not installed.
//
// Payloads are canonical: the same request always encodes to the same bytes, so
// a payload digest is a meaningful identity for a request. Decoding validates
// every bound before allocating, and raises EpochError with a protocol code for
// any malformed payload.
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "control_plane_epoch/authority.hpp"
#include "control_plane_epoch/commands.hpp"
#include "control_plane_epoch/digest.hpp"
#include "control_plane_epoch/epoch.hpp"
#include "control_plane_epoch/error.hpp"
#include "control_plane_epoch/incarnation.hpp"
#include "control_plane_epoch/inspection.hpp"
#include "control_plane_epoch/recovery.hpp"
#include "control_plane_epoch/transition.hpp"

#include "encoding.hpp"
#include "records.hpp"

namespace dccp::epoch::detail {

using Payload = std::vector<std::byte>;

struct HelloPayload {
  std::uint16_t protocol_version = 0;
  std::uint16_t max_frame_payload_bytes = 0;
};

struct HelloResponsePayload {
  std::uint16_t protocol_version = 0;
  std::uint16_t max_frame_payload_bytes = 0;
  std::string domain;
  std::uint64_t domain_instance = 0;
  std::uint64_t epoch = 0;
  std::uint64_t generation = 0;
  bool initialized = false;
};

struct ErrorPayload {
  ErrorCode code = ErrorCode::Ok;
  std::string detail;
};

struct ValidationPayload {
  bool accepted = false;
  ErrorCode code = ErrorCode::Ok;
  std::string detail;
};

struct QualificationPayload {
  RecoveredStateVerdict verdict = RecoveredStateVerdict::Rejected;
  ErrorCode code = ErrorCode::Ok;
  std::string detail;
  std::optional<std::uint64_t> matching_grant;
  bool requires_revalidation = false;
};

struct ValidateRequestPayload {
  std::string token;
  std::string scope;
};

struct PagePayload {
  std::uint64_t total_count = 0;
  std::uint64_t first_retained = 0;
  std::uint64_t trimmed_count = 0;
  Sha256Digest anchor;
  Sha256Digest chain_head;
};

struct StatusPayload {
  std::string domain;
  std::uint64_t domain_instance = 0;
  std::uint64_t epoch = 0;
  std::uint64_t generation = 0;
  std::string authority_root;
  std::uint64_t controller_count = 0;
  std::uint64_t live_grant_count = 0;
  std::uint64_t mutation_grant_count = 0;
  std::uint64_t observation_grant_count = 0;
  std::vector<std::string> declared_scopes;
  std::uint64_t transition_count = 0;
  std::uint64_t revocation_count = 0;
  std::uint64_t idempotency_record_count = 0;
  Sha256Digest snapshot_digest;
  Sha256Digest transition_chain_head;
  RecoveryOutcome recovery_outcome = RecoveryOutcome::OpenedClean;
  StoreOpenMode open_mode = StoreOpenMode::ReadWrite;
};

struct HistoryRequestPayload {
  std::optional<std::uint64_t> from_sequence;
  std::uint64_t limit = 0;
};

struct HistoryResponsePayload {
  PagePayload page;
  std::vector<TransitionData> records;
};

struct RevocationsRequestPayload {
  std::optional<std::uint64_t> from_sequence;
  std::uint64_t limit = 0;
};

struct RevocationsResponsePayload {
  PagePayload page;
  std::vector<RevocationData> records;
};

struct ControllersRequestPayload {
  std::optional<std::string> from_controller;
  std::uint64_t limit = 0;
};

struct ControllersResponsePayload {
  std::uint64_t total_count = 0;
  std::vector<ControllerData> records;
};

struct GrantsRequestPayload {
  std::optional<std::uint64_t> from_grant;
  std::uint64_t limit = 0;
};

struct GrantsResponsePayload {
  std::uint64_t total_count = 0;
  std::uint64_t epoch = 0;
  std::vector<GrantData> records;
};

// -- provenance and idempotency helpers -------------------------------------

void encode_provenance_input(CanonicalWriter& writer, const ProvenanceInput& input);
[[nodiscard]] ProvenanceInput decode_provenance_input(CanonicalReader& reader);
void encode_idempotency_key(CanonicalWriter& writer, const IdempotencyKey& key);
[[nodiscard]] IdempotencyKey decode_idempotency_key(CanonicalReader& reader);

// -- encode / decode pairs --------------------------------------------------

[[nodiscard]] Payload encode_hello_request(const HelloPayload& payload);
[[nodiscard]] HelloPayload decode_hello_request(std::span<const std::byte> payload);
[[nodiscard]] Payload encode_hello_response(const HelloResponsePayload& payload);
[[nodiscard]] HelloResponsePayload decode_hello_response(std::span<const std::byte> payload);

[[nodiscard]] Payload encode_error(const ErrorPayload& payload);
[[nodiscard]] ErrorPayload decode_error(std::span<const std::byte> payload);

[[nodiscard]] Payload encode_validation(const ValidationPayload& payload);
[[nodiscard]] ValidationPayload decode_validation(std::span<const std::byte> payload);
[[nodiscard]] Payload encode_qualification(const QualificationPayload& payload);
[[nodiscard]] QualificationPayload decode_qualification(std::span<const std::byte> payload);

[[nodiscard]] Payload encode_register_request(const RegisterControllerRequest& request);
[[nodiscard]] RegisterControllerRequest decode_register_request(std::span<const std::byte> payload);
[[nodiscard]] Payload encode_register_response(const ControllerRegistration& registration);
[[nodiscard]] ControllerRegistration decode_register_response(std::span<const std::byte> payload);

[[nodiscard]] Payload encode_acquire_request(const AcquireAuthorityRequest& request);
[[nodiscard]] AcquireAuthorityRequest decode_acquire_request(std::span<const std::byte> payload);
[[nodiscard]] Payload encode_acquire_response(const GrantData& grant);
[[nodiscard]] GrantData decode_acquire_response(std::span<const std::byte> payload);

[[nodiscard]] Payload encode_validate_request(const ValidateRequestPayload& request);
[[nodiscard]] ValidateRequestPayload decode_validate_request(std::span<const std::byte> payload);

[[nodiscard]] Payload encode_advance_request(const AdvanceEpochRequest& request);
[[nodiscard]] AdvanceEpochRequest decode_advance_request(std::span<const std::byte> payload);
[[nodiscard]] Payload encode_transition_response(const TransitionData& transition);
[[nodiscard]] TransitionData decode_transition_response(std::span<const std::byte> payload);

[[nodiscard]] Payload encode_revoke_request(const RevokeAuthorityRequest& request);
[[nodiscard]] RevokeAuthorityRequest decode_revoke_request(std::span<const std::byte> payload);
[[nodiscard]] Payload encode_revocation_response(const RevocationData& revocation);
[[nodiscard]] RevocationData decode_revocation_response(std::span<const std::byte> payload);

[[nodiscard]] Payload encode_qualify_request(const RecoveredStateClaim& claim);
[[nodiscard]] RecoveredStateClaim decode_qualify_request(std::span<const std::byte> payload);

[[nodiscard]] Payload encode_status(const StatusPayload& payload);
[[nodiscard]] StatusPayload decode_status(std::span<const std::byte> payload);

[[nodiscard]] Payload encode_history_request(const HistoryRequestPayload& payload);
[[nodiscard]] HistoryRequestPayload decode_history_request(std::span<const std::byte> payload);
[[nodiscard]] Payload encode_history_response(const HistoryResponsePayload& payload);
[[nodiscard]] HistoryResponsePayload decode_history_response(std::span<const std::byte> payload);

[[nodiscard]] Payload encode_revocations_request(const RevocationsRequestPayload& payload);
[[nodiscard]] RevocationsRequestPayload decode_revocations_request(std::span<const std::byte> payload);
[[nodiscard]] Payload encode_revocations_response(const RevocationsResponsePayload& payload);
[[nodiscard]] RevocationsResponsePayload decode_revocations_response(std::span<const std::byte> payload);

[[nodiscard]] Payload encode_controllers_request(const ControllersRequestPayload& payload);
[[nodiscard]] ControllersRequestPayload decode_controllers_request(std::span<const std::byte> payload);
[[nodiscard]] Payload encode_controllers_response(const ControllersResponsePayload& payload);
[[nodiscard]] ControllersResponsePayload decode_controllers_response(std::span<const std::byte> payload);

[[nodiscard]] Payload encode_grants_request(const GrantsRequestPayload& payload);
[[nodiscard]] GrantsRequestPayload decode_grants_request(std::span<const std::byte> payload);
[[nodiscard]] Payload encode_grants_response(const GrantsResponsePayload& payload);
[[nodiscard]] GrantsResponsePayload decode_grants_response(std::span<const std::byte> payload);

}  // namespace dccp::epoch::detail

