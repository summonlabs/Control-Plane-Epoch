// Control Plane Epoch 1.0.0 - Summon Software Labs
// Stable error catalogue: machine tokens, fixed categories, fixed summaries.
#include "control_plane_epoch/error.hpp"

#include <string>

namespace dccp::epoch {
namespace {

struct CodeInfo {
  std::string_view token;
  std::string_view summary;
  ErrorCategory category;
  bool retryable;
};

constexpr CodeInfo kOk{"ok", "accepted", ErrorCategory::Success, false};

constexpr CodeInfo info_for(ErrorCode code) {
  switch (code) {
    case ErrorCode::Ok:
      return kOk;

    // Identity and text
    case ErrorCode::InvalidIdentifierSyntax:
      return {"identity.invalid_syntax", "the identifier is not a valid stable identifier",
              ErrorCategory::Identity, false};
    case ErrorCode::IdentifierTooLong:
      return {"identity.too_long", "the identifier exceeds its maximum length", ErrorCategory::Identity, false};
    case ErrorCode::IdentifierEmpty:
      return {"identity.empty", "the identifier is empty", ErrorCategory::Identity, false};
    case ErrorCode::ExternalReferenceInvalid:
      return {"identity.external_reference_invalid", "the external reference is malformed",
              ErrorCategory::Identity, false};
    case ErrorCode::TextInvalidUtf8:
      return {"identity.text_invalid_utf8", "the text is not valid UTF-8", ErrorCategory::Identity, false};
    case ErrorCode::TextTooLong:
      return {"identity.text_too_long", "the text exceeds its maximum length", ErrorCategory::Identity, false};
    case ErrorCode::TextControlCharacter:
      return {"identity.text_control_character", "the text contains a control character",
              ErrorCategory::Identity, false};
    case ErrorCode::DigestInvalidHex:
      return {"identity.digest_invalid_hex", "the digest text is not 64 hexadecimal characters",
              ErrorCategory::Identity, false};

    // Epoch
    case ErrorCode::EpochZero:
      return {"epoch.zero", "epoch value 0 is not a committed epoch", ErrorCategory::Authority, false};
    case ErrorCode::EpochExhausted:
      return {"epoch.exhausted", "the epoch is at its maximum value and cannot advance",
              ErrorCategory::Limit, false};
    case ErrorCode::EpochConflict:
      return {"epoch.conflict", "the authoritative epoch is not the expected epoch",
              ErrorCategory::Authority, true};
    case ErrorCode::EpochFenced:
      return {"epoch.fenced", "the token belongs to an epoch that has been permanently fenced",
              ErrorCategory::Authority, false};
    case ErrorCode::EpochUnknown:
      return {"epoch.unknown", "the token names an epoch this domain never committed",
              ErrorCategory::Authority, false};
    case ErrorCode::CounterExhausted:
      return {"counter.exhausted", "the counter is at its maximum value", ErrorCategory::Limit, false};

    // Authority
    case ErrorCode::ScopeUnknown:
      return {"authority.scope_unknown", "the scope is not declared by this authority domain",
              ErrorCategory::Authority, false};
    case ErrorCode::ScopeDuplicate:
      return {"authority.scope_duplicate", "the scope list contains a duplicate", ErrorCategory::Authority, false};
    case ErrorCode::SponsorRequired:
      return {"authority.sponsor_required", "the requested authority requires a sponsoring authority",
              ErrorCategory::Authority, false};
    case ErrorCode::DomainMismatch:
      return {"authority.domain_mismatch", "the token belongs to a different authority domain",
              ErrorCategory::Authority, false};
    case ErrorCode::TokenTampered:
      return {"authority.token_tampered", "the token does not match its own claims",
              ErrorCategory::Authority, false};
    case ErrorCode::TokenMalformed:
      return {"authority.token_malformed", "the token text is malformed", ErrorCategory::Authority, false};
    case ErrorCode::UnknownGrant:
      return {"authority.unknown_grant", "no grant with that identifier exists in the current epoch",
              ErrorCategory::Authority, false};
    case ErrorCode::AuthorityClassMismatch:
      return {"authority.class_mismatch", "the grant authorizes a different class of authority",
              ErrorCategory::Authority, false};
    case ErrorCode::AuthorityRevoked:
      return {"authority.revoked", "the authority has been revoked and is permanently fenced",
              ErrorCategory::Authority, false};
    case ErrorCode::ScopeNotGranted:
      return {"authority.scope_not_granted", "the authority does not cover the required scope",
              ErrorCategory::Authority, false};
    case ErrorCode::RootAuthorityRequired:
      return {"authority.root_required", "only the authority root may perform this operation without a sponsor",
              ErrorCategory::Authority, false};
    case ErrorCode::ClaimsMismatch:
      return {"authority.claims_mismatch", "the token claims do not match the stored grant",
              ErrorCategory::Authority, false};

    // Controllers and incarnations
    case ErrorCode::ControllerUnknown:
      return {"controller.unknown", "the controller is not registered in this domain",
              ErrorCategory::Authority, false};
    case ErrorCode::ControllerRootImmutable:
      return {"controller.root_immutable", "the authority root cannot be replaced",
              ErrorCategory::Authority, false};
    case ErrorCode::IncarnationUnknown:
      return {"incarnation.unknown", "the incarnation is not the controller's current incarnation",
              ErrorCategory::Authority, false};
    case ErrorCode::IncarnationSuperseded:
      return {"incarnation.superseded", "a newer incarnation of the controller has been registered",
              ErrorCategory::Authority, false};

    // Revocation
    case ErrorCode::RevocationUnknownTarget:
      return {"revocation.unknown_target", "the revocation target does not exist",
              ErrorCategory::Authority, false};

    // Idempotency
    case ErrorCode::IdempotencyConflict:
      return {"idempotency.conflict", "the idempotency key was already used for a different command",
              ErrorCategory::Authority, false};

    // Recovered state
    case ErrorCode::RecoveredCurrent:
      return {"recovery.current", "the recovered state was produced under current authority",
              ErrorCategory::Recovery, false};
    case ErrorCode::RecoveredStale:
      return {"recovery.stale", "the recovered state was produced under an epoch that is no longer current",
              ErrorCategory::Recovery, false};
    case ErrorCode::RecoveredSuperseded:
      return {"recovery.superseded", "the producing incarnation has been superseded or revoked",
              ErrorCategory::Recovery, false};
    case ErrorCode::RecoveredNeedsReconciliation:
      return {"recovery.needs_reconciliation",
              "the producing incarnation survived the epoch change; the state requires re-attestation",
              ErrorCategory::Recovery, false};
    case ErrorCode::RecoveredRejectedFutureEpoch:
      return {"recovery.rejected_future_epoch", "the claim names an epoch this domain never committed",
              ErrorCategory::Recovery, false};
    case ErrorCode::RecoveredRejectedUnknownIncarnation:
      return {"recovery.rejected_unknown_incarnation", "the claim names an unknown controller incarnation",
              ErrorCategory::Recovery, false};
    case ErrorCode::RecoveredRejectedNoAuthority:
      return {"recovery.rejected_no_authority", "the producer never held authority over the claimed scope",
              ErrorCategory::Recovery, false};
    case ErrorCode::RecoveredRejectedDomainMismatch:
      return {"recovery.rejected_domain_mismatch", "the claim names a different authority domain",
              ErrorCategory::Recovery, false};

    // Persistence
    case ErrorCode::StoreNotFound:
      return {"persistence.store_not_found", "the store directory does not exist or is not usable",
              ErrorCategory::Persistence, false};
    case ErrorCode::StoreLocked:
      return {"persistence.store_locked", "another process holds the exclusive writer lock",
              ErrorCategory::Persistence, true};
    case ErrorCode::StoreAlreadyInitialized:
      return {"persistence.already_initialized", "the store already contains an authority domain",
              ErrorCategory::Persistence, false};
    case ErrorCode::StoreNotInitialized:
      return {"persistence.not_initialized", "the store does not contain an authority domain yet",
              ErrorCategory::Persistence, false};
    case ErrorCode::CommitFailed:
      return {"persistence.commit_failed", "the durable commit did not complete",
              ErrorCategory::Persistence, true};
    case ErrorCode::AssertedEpochFloorRequired:
      return {"persistence.asserted_epoch_floor_required",
              "reinitializing a store with no readable floor requires an explicit epoch assertion",
              ErrorCategory::Persistence, false};
    case ErrorCode::AssertedEpochFloorTooLow:
      return {"persistence.asserted_epoch_floor_too_low",
              "the asserted epoch floor is below a floor value that is still readable",
              ErrorCategory::Persistence, false};
    case ErrorCode::SnapshotMissing:
      return {"persistence.snapshot_missing", "no durable generation is present",
              ErrorCategory::Persistence, false};
    case ErrorCode::PublishFailed:
      return {"persistence.publish_failed", "the atomic publish step failed", ErrorCategory::Persistence, true};
    case ErrorCode::TempCreateFailed:
      return {"persistence.temp_create_failed", "the exclusive temporary file could not be created",
              ErrorCategory::Persistence, true};
    case ErrorCode::SyncFailed:
      return {"persistence.sync_failed", "the durable flush to the device failed",
              ErrorCategory::Persistence, true};
    case ErrorCode::PathInvalid:
      return {"persistence.path_invalid", "the supplied path is not usable", ErrorCategory::Persistence, false};
    case ErrorCode::PermissionDenied:
      return {"persistence.permission_denied", "the operating system denied access", ErrorCategory::Persistence,
              false};
    case ErrorCode::QuarantineFailed:
      return {"persistence.quarantine_failed", "damaged state could not be moved into quarantine",
              ErrorCategory::Persistence, false};
    case ErrorCode::DurableLimitsExceeded:
      return {"persistence.limits_exceeded", "the durable image exceeds a configured bound",
              ErrorCategory::Limit, false};
    case ErrorCode::FloorMissing:
      return {"persistence.floor_missing",
              "a durable generation exists but its epoch floor is missing: rollback cannot be excluded",
              ErrorCategory::Persistence, false};

    // Integrity
    case ErrorCode::MagicMismatch:
      return {"integrity.magic_mismatch", "the file magic does not match this format",
              ErrorCategory::Integrity, false};
    case ErrorCode::FormatVersionUnsupported:
      return {"integrity.format_version_unsupported", "the durable format version is not supported",
              ErrorCategory::Integrity, false};
    case ErrorCode::SchemaUnsupported:
      return {"integrity.schema_unsupported", "the durable schema version is not supported",
              ErrorCategory::Integrity, false};
    case ErrorCode::Truncated:
      return {"integrity.truncated", "the encoded data ends before its declared length",
              ErrorCategory::Integrity, false};
    case ErrorCode::DigestMismatch:
      return {"integrity.digest_mismatch", "the stored digest does not match the stored content",
              ErrorCategory::Integrity, false};
    case ErrorCode::SizeMismatch:
      return {"integrity.size_mismatch", "the declared size does not match the actual size",
              ErrorCategory::Integrity, false};
    case ErrorCode::ChainBroken:
      return {"integrity.chain_broken", "the record chain does not link to its predecessor",
              ErrorCategory::Integrity, false};
    case ErrorCode::GenerationBelowFloor:
      return {"integrity.generation_below_floor", "the generation is below the durable floor",
              ErrorCategory::Integrity, false};
    case ErrorCode::EpochBelowFloor:
      return {"integrity.epoch_below_floor", "the epoch is below the durable floor", ErrorCategory::Integrity,
              false};
    case ErrorCode::CountMismatch:
      return {"integrity.count_mismatch", "a declared count does not match the encoded records",
              ErrorCategory::Integrity, false};
    case ErrorCode::IntegrityLimitExceeded:
      return {"integrity.limit_exceeded", "an encoded count or length exceeds its bound",
              ErrorCategory::Integrity, false};
    case ErrorCode::EnumOutOfDomain:
      return {"integrity.enum_out_of_domain", "an encoded enumeration value is outside its domain",
              ErrorCategory::Integrity, false};
    case ErrorCode::TrailingBytes:
      return {"integrity.trailing_bytes", "the encoded data has bytes after its declared end",
              ErrorCategory::Integrity, false};
    case ErrorCode::OrderingViolation:
      return {"integrity.ordering_violation", "the encoded records are not in canonical order",
              ErrorCategory::Integrity, false};
    case ErrorCode::DuplicateKey:
      return {"integrity.duplicate_key", "the encoded data contains a duplicate key", ErrorCategory::Integrity,
              false};
    case ErrorCode::ArithmeticOverflow:
      return {"integrity.arithmetic_overflow", "a checked size computation overflowed", ErrorCategory::Integrity,
              false};

    // Protocol
    case ErrorCode::FrameMagic:
      return {"protocol.frame_magic", "the frame magic is wrong", ErrorCategory::Protocol, false};
    case ErrorCode::ProtocolVersionUnsupported:
      return {"protocol.version_unsupported", "the protocol version is not supported", ErrorCategory::Protocol,
              false};
    case ErrorCode::FrameTooLarge:
      return {"protocol.frame_too_large", "the frame exceeds the negotiated size bound", ErrorCategory::Protocol,
              false};
    case ErrorCode::FrameTruncated:
      return {"protocol.frame_truncated", "the frame ended before its declared length", ErrorCategory::Protocol,
              false};
    case ErrorCode::FrameDigestMismatch:
      return {"protocol.frame_digest_mismatch", "the frame payload digest does not match", ErrorCategory::Protocol,
              false};
    case ErrorCode::MessageTypeUnknown:
      return {"protocol.message_type_unknown", "the message type is not known", ErrorCategory::Protocol, false};
    case ErrorCode::RequestIdMismatch:
      return {"protocol.request_id_mismatch", "the response does not answer the outstanding request",
              ErrorCategory::Protocol, false};
    case ErrorCode::ProtocolDomainMismatch:
      return {"protocol.domain_mismatch", "the authority serves a different domain than expected",
              ErrorCategory::Protocol, false};
    case ErrorCode::MalformedPayload:
      return {"protocol.malformed_payload", "the payload is not valid for this message type",
              ErrorCategory::Protocol, false};
    case ErrorCode::HandshakeRequired:
      return {"protocol.handshake_required", "a handshake must complete before other requests",
              ErrorCategory::Protocol, false};
    case ErrorCode::HandshakeRejected:
      return {"protocol.handshake_rejected", "the handshake was rejected", ErrorCategory::Protocol, false};

    // I/O
    case ErrorCode::ConnectFailed:
      return {"io.connect_failed", "the connection could not be established", ErrorCategory::Io, true};
    case ErrorCode::ReadFailed:
      return {"io.read_failed", "the read failed", ErrorCategory::Io, true};
    case ErrorCode::WriteFailed:
      return {"io.write_failed", "the write failed", ErrorCategory::Io, true};
    case ErrorCode::ListenFailed:
      return {"io.listen_failed", "the listener could not be bound", ErrorCategory::Io, false};
    case ErrorCode::SocketClosed:
      return {"io.socket_closed", "the peer closed the connection", ErrorCategory::Io, true};

    // Server
    case ErrorCode::ServerStopping:
      return {"server.stopping", "the authority runtime is shutting down", ErrorCategory::Io, true};
    case ErrorCode::ServerBusy:
      return {"server.busy", "the authority runtime is at its connection bound", ErrorCategory::Io, true};
    case ErrorCode::ServerNotRunning:
      return {"server.not_running", "the authority runtime is not running", ErrorCategory::Io, false};
    case ErrorCode::ServerAlreadyRunning:
      return {"server.already_running", "the authority runtime is already running", ErrorCategory::Io, false};

    // Limits
    case ErrorCode::ControllerLimitReached:
      return {"limit.controller_count", "the domain has reached its controller bound", ErrorCategory::Limit, true};
    case ErrorCode::GrantLimitReached:
      return {"limit.grant_count", "the epoch has reached its live grant bound", ErrorCategory::Limit, true};
    case ErrorCode::PageLimitExceeded:
      return {"limit.page_size", "the requested page size exceeds the bound", ErrorCategory::Limit, false};
    case ErrorCode::SizeLimitExceeded:
      return {"limit.size_exceeded", "the supplied value exceeds a bound", ErrorCategory::Limit, false};
    case ErrorCode::ConnectionLimitReached:
      return {"limit.connection_count", "the runtime is at its connection bound", ErrorCategory::Limit, true};

    // Configuration and internal
    case ErrorCode::InvalidOption:
      return {"config.invalid_option", "a configuration value is invalid", ErrorCategory::Configuration, false};
    case ErrorCode::InvalidArgument:
      return {"config.invalid_argument", "an argument is invalid", ErrorCategory::Configuration, false};
    case ErrorCode::InvariantViolation:
      return {"internal.invariant_violation", "an internal invariant was violated", ErrorCategory::Internal, false};
    case ErrorCode::UnsupportedOperation:
      return {"internal.unsupported_operation", "the operation is not supported in this mode",
              ErrorCategory::Internal, false};
  }
  return {"internal.unknown_code", "the error code is not in the catalogue", ErrorCategory::Internal, false};
}

}  // namespace

std::string_view error_token(ErrorCode code) noexcept { return info_for(code).token; }
std::string_view error_summary(ErrorCode code) noexcept { return info_for(code).summary; }
ErrorCategory error_category(ErrorCode code) noexcept { return info_for(code).category; }
bool error_retryable(ErrorCode code) noexcept { return info_for(code).retryable; }

Result<ErrorCode> parse_error_code(std::string_view token) {
  static constexpr ErrorCode kAllCodes[] = {
      ErrorCode::Ok,
      ErrorCode::InvalidIdentifierSyntax,
      ErrorCode::IdentifierTooLong,
      ErrorCode::IdentifierEmpty,
      ErrorCode::ExternalReferenceInvalid,
      ErrorCode::TextInvalidUtf8,
      ErrorCode::TextTooLong,
      ErrorCode::TextControlCharacter,
      ErrorCode::DigestInvalidHex,
      ErrorCode::EpochZero,
      ErrorCode::EpochExhausted,
      ErrorCode::EpochConflict,
      ErrorCode::EpochFenced,
      ErrorCode::EpochUnknown,
      ErrorCode::CounterExhausted,
      ErrorCode::ScopeUnknown,
      ErrorCode::ScopeDuplicate,
      ErrorCode::SponsorRequired,
      ErrorCode::DomainMismatch,
      ErrorCode::TokenTampered,
      ErrorCode::TokenMalformed,
      ErrorCode::UnknownGrant,
      ErrorCode::AuthorityClassMismatch,
      ErrorCode::AuthorityRevoked,
      ErrorCode::ScopeNotGranted,
      ErrorCode::RootAuthorityRequired,
      ErrorCode::ClaimsMismatch,
      ErrorCode::ControllerUnknown,
      ErrorCode::ControllerRootImmutable,
      ErrorCode::IncarnationUnknown,
      ErrorCode::IncarnationSuperseded,
      ErrorCode::RevocationUnknownTarget,
      ErrorCode::IdempotencyConflict,
      ErrorCode::RecoveredCurrent,
      ErrorCode::RecoveredStale,
      ErrorCode::RecoveredSuperseded,
      ErrorCode::RecoveredNeedsReconciliation,
      ErrorCode::RecoveredRejectedFutureEpoch,
      ErrorCode::RecoveredRejectedUnknownIncarnation,
      ErrorCode::RecoveredRejectedNoAuthority,
      ErrorCode::RecoveredRejectedDomainMismatch,
      ErrorCode::StoreNotFound,
      ErrorCode::StoreLocked,
      ErrorCode::StoreAlreadyInitialized,
      ErrorCode::StoreNotInitialized,
      ErrorCode::CommitFailed,
      ErrorCode::AssertedEpochFloorRequired,
      ErrorCode::AssertedEpochFloorTooLow,
      ErrorCode::SnapshotMissing,
      ErrorCode::PublishFailed,
      ErrorCode::TempCreateFailed,
      ErrorCode::SyncFailed,
      ErrorCode::PathInvalid,
      ErrorCode::PermissionDenied,
      ErrorCode::QuarantineFailed,
      ErrorCode::DurableLimitsExceeded,
      ErrorCode::FloorMissing,
      ErrorCode::MagicMismatch,
      ErrorCode::FormatVersionUnsupported,
      ErrorCode::SchemaUnsupported,
      ErrorCode::Truncated,
      ErrorCode::DigestMismatch,
      ErrorCode::SizeMismatch,
      ErrorCode::ChainBroken,
      ErrorCode::GenerationBelowFloor,
      ErrorCode::EpochBelowFloor,
      ErrorCode::CountMismatch,
      ErrorCode::IntegrityLimitExceeded,
      ErrorCode::EnumOutOfDomain,
      ErrorCode::TrailingBytes,
      ErrorCode::OrderingViolation,
      ErrorCode::DuplicateKey,
      ErrorCode::ArithmeticOverflow,
      ErrorCode::FrameMagic,
      ErrorCode::ProtocolVersionUnsupported,
      ErrorCode::FrameTooLarge,
      ErrorCode::FrameTruncated,
      ErrorCode::FrameDigestMismatch,
      ErrorCode::MessageTypeUnknown,
      ErrorCode::RequestIdMismatch,
      ErrorCode::ProtocolDomainMismatch,
      ErrorCode::MalformedPayload,
      ErrorCode::HandshakeRequired,
      ErrorCode::HandshakeRejected,
      ErrorCode::ConnectFailed,
      ErrorCode::ReadFailed,
      ErrorCode::WriteFailed,
      ErrorCode::ListenFailed,
      ErrorCode::SocketClosed,
      ErrorCode::ServerStopping,
      ErrorCode::ServerBusy,
      ErrorCode::ServerNotRunning,
      ErrorCode::ServerAlreadyRunning,
      ErrorCode::ControllerLimitReached,
      ErrorCode::GrantLimitReached,
      ErrorCode::PageLimitExceeded,
      ErrorCode::SizeLimitExceeded,
      ErrorCode::ConnectionLimitReached,
      ErrorCode::InvalidOption,
      ErrorCode::InvalidArgument,
      ErrorCode::InvariantViolation,
      ErrorCode::UnsupportedOperation,
  };

  for (const ErrorCode code : kAllCodes) {
    if (error_token(code) == token) {
      return code;
    }
  }
  return Explanation(ErrorCode::InvalidArgument, "unknown error code token '" + std::string(token) + "'");
}

std::string_view error_category_token(ErrorCategory category) noexcept {
  switch (category) {
    case ErrorCategory::Success:
      return "success";
    case ErrorCategory::Identity:
      return "identity";
    case ErrorCategory::Limit:
      return "limit";
    case ErrorCategory::Persistence:
      return "persistence";
    case ErrorCategory::Integrity:
      return "integrity";
    case ErrorCategory::Protocol:
      return "protocol";
    case ErrorCategory::Io:
      return "io";
    case ErrorCategory::Configuration:
      return "configuration";
    case ErrorCategory::Authority:
      return "authority";
    case ErrorCategory::Recovery:
      return "recovery";
    case ErrorCategory::Internal:
      return "internal";
  }
  return "internal";
}

std::string Explanation::to_string() const {
  std::string text(error_token(code_));
  text += ": ";
  text += error_summary(code_);
  if (!detail_.empty()) {
    text += " [";
    text += detail_;
    text += ']';
  }
  return text;
}

EpochError::EpochError(Explanation explanation)
    : std::runtime_error(explanation.to_string()), explanation_(std::move(explanation)) {}

EpochError::EpochError(ErrorCode code, std::string detail) : EpochError(Explanation(code, std::move(detail))) {}

std::string ValidationOutcome::to_string() const {
  if (!rejection_.has_value()) {
    return "accepted";
  }
  return std::string("rejected: ") + rejection_->to_string();
}

}  // namespace dccp::epoch
