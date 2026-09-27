// Control Plane Epoch 1.0.0 - Summon Software Labs
// Explanation suite.
//
// Rejection outcomes are the library's machine-readable contract: a caller
// branches on them, an operator compares them across runs, and a log line is
// diffed between deploys. That only works if every code has exactly one stable
// token, one fixed category, one fixed retryability, and one deterministic
// rendering.
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "test_support.hpp"

namespace {

using dccp::epoch::ErrorCategory;
using dccp::epoch::ErrorCode;
using dccp::epoch::EpochError;
using dccp::epoch::Explanation;
using dccp::epoch::Result;
using dccp::epoch::Status;
using dccp::epoch::Unit;
using dccp::epoch::ValidationOutcome;

/// Every code in the public catalogue. The list is deliberately exhaustive:
/// a code that can be returned but has no token would break wire round-tripping,
/// and a token that is not unique would make two different failures
/// indistinguishable in a log.
constexpr ErrorCode kAllCodes[] = {
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

struct CodeExpectation {
  ErrorCode code;
  ErrorCategory category;
  bool retryable;
};

}  // namespace

CPE_TEST(explanation, every_code_has_a_unique_token_and_round_trips) {
  std::vector<std::string> tokens;
  tokens.reserve(std::size(kAllCodes));
  for (const ErrorCode code : kAllCodes) {
    const std::string_view token = dccp::epoch::error_token(code);
    const std::string_view summary = dccp::epoch::error_summary(code);
    const std::string label = std::to_string(static_cast<std::uint32_t>(code));

    CPE_REQUIRE_MSG(!token.empty(), "code " + label + " has no token");
    CPE_REQUIRE_MSG(!summary.empty(), "code " + label + " has no summary");
    CPE_REQUIRE_MSG(token.find(' ') == std::string_view::npos, "token for code " + label + " contains a space");
    CPE_REQUIRE_MSG(summary.find('\n') == std::string_view::npos, "summary for code " + label + " is multi-line");
    CPE_REQUIRE_MSG(code == ErrorCode::Ok || token.find('.') != std::string_view::npos,
                    "token '" + std::string(token) + "' is not namespaced");

    // The inverse mapping is exact, in both directions.
    const Result<ErrorCode> parsed = dccp::epoch::parse_error_code(token);
    CPE_REQUIRE_MSG(parsed.has_value(), "token '" + std::string(token) + "' does not parse back");
    CPE_REQUIRE_EQ(parsed.value(), code);

    // An explanation with no detail renders as "token: summary", so the same
    // code always produces the same first line.
    const Explanation explanation(code);
    CPE_REQUIRE_EQ(explanation.token(), token);
    CPE_REQUIRE_EQ(explanation.summary(), summary);
    CPE_REQUIRE_EQ(explanation.code(), code);
    CPE_REQUIRE_EQ(explanation.category(), dccp::epoch::error_category(code));
    CPE_REQUIRE_EQ(explanation.retryable(), dccp::epoch::error_retryable(code));
    CPE_REQUIRE_EQ(explanation.is_ok(), code == ErrorCode::Ok);
    CPE_REQUIRE_EQ(explanation.to_string(), std::string(token) + ": " + std::string(summary));

    tokens.emplace_back(token);
  }

  for (std::size_t index = 0; index < tokens.size(); ++index) {
    for (std::size_t other = index + 1; other < tokens.size(); ++other) {
      CPE_REQUIRE_MSG(tokens[index] != tokens[other],
                      "codes " + std::to_string(static_cast<std::uint32_t>(kAllCodes[index])) + " and " +
                          std::to_string(static_cast<std::uint32_t>(kAllCodes[other])) +
                          " share the token '" + tokens[index] + "'");
    }
  }
  CPE_REQUIRE_EQ(tokens.size(), std::size(kAllCodes));
}

CPE_TEST(explanation, tokens_are_case_sensitive_and_unknown_tokens_are_rejected) {
  // Tokens cross process boundaries, so an unknown token is a caller error and
  // must be reported rather than mapped onto a plausible code.
  for (const std::string_view unknown : {std::string_view(), std::string_view("no.such.token"),
                                         std::string_view("authority"), std::string_view("authority."),
                                         std::string_view("authority.revoked "), std::string_view(" ok"),
                                         std::string_view("Authority.Revoked"), std::string_view("EPOCH.FENCED"),
                                         std::string_view("epoch.fenced\n"), std::string_view("203")}) {
    const Result<ErrorCode> parsed = dccp::epoch::parse_error_code(unknown);
    CPE_REQUIRE_MSG(!parsed.has_value(), "unknown token '" + std::string(unknown) + "' was accepted");
    CPE_REQUIRE_EQ(parsed.rejection().code(), ErrorCode::InvalidArgument);
  }
  const std::string_view token = dccp::epoch::error_token(ErrorCode::AuthorityRevoked);
  CPE_REQUIRE_EQ(token, std::string_view("authority.revoked"));
  CPE_REQUIRE_EQ(dccp::epoch::error_token(ErrorCode::EpochFenced), std::string_view("epoch.fenced"));
  CPE_REQUIRE_EQ(dccp::epoch::error_token(ErrorCode::Ok), std::string_view("ok"));
}

CPE_TEST(explanation, categories_and_retryability_are_fixed) {
  // Retryability is a promise about state, not about effort: a retryable code
  // means the identical request may succeed against unchanged state (a lost
  // race), and a non-retryable code means repeating the request cannot help
  // without an external state change.
  const CodeExpectation expectations[] = {
      {ErrorCode::Ok, ErrorCategory::Success, false},
      {ErrorCode::InvalidIdentifierSyntax, ErrorCategory::Identity, false},
      {ErrorCode::IdentifierEmpty, ErrorCategory::Identity, false},
      {ErrorCode::TextControlCharacter, ErrorCategory::Identity, false},
      {ErrorCode::EpochZero, ErrorCategory::Authority, false},
      {ErrorCode::EpochExhausted, ErrorCategory::Limit, false},
      {ErrorCode::EpochConflict, ErrorCategory::Authority, true},
      {ErrorCode::EpochFenced, ErrorCategory::Authority, false},
      {ErrorCode::EpochUnknown, ErrorCategory::Authority, false},
      {ErrorCode::TokenTampered, ErrorCategory::Authority, false},
      {ErrorCode::TokenMalformed, ErrorCategory::Authority, false},
      {ErrorCode::ScopeNotGranted, ErrorCategory::Authority, false},
      {ErrorCode::AuthorityRevoked, ErrorCategory::Authority, false},
      {ErrorCode::ClaimsMismatch, ErrorCategory::Authority, false},
      {ErrorCode::IncarnationSuperseded, ErrorCategory::Authority, false},
      {ErrorCode::RevocationUnknownTarget, ErrorCategory::Authority, false},
      {ErrorCode::StoreLocked, ErrorCategory::Persistence, true},
      {ErrorCode::CommitFailed, ErrorCategory::Persistence, true},
      {ErrorCode::StoreNotInitialized, ErrorCategory::Persistence, false},
      {ErrorCode::DurableLimitsExceeded, ErrorCategory::Limit, false},
      {ErrorCode::DigestMismatch, ErrorCategory::Integrity, false},
      {ErrorCode::EnumOutOfDomain, ErrorCategory::Integrity, false},
      {ErrorCode::FrameTooLarge, ErrorCategory::Protocol, false},
      {ErrorCode::ConnectFailed, ErrorCategory::Io, true},
      {ErrorCode::ServerStopping, ErrorCategory::Io, true},
      {ErrorCode::ControllerLimitReached, ErrorCategory::Limit, true},
      {ErrorCode::InvalidOption, ErrorCategory::Configuration, false},
      {ErrorCode::InvariantViolation, ErrorCategory::Internal, false},
      {ErrorCode::UnsupportedOperation, ErrorCategory::Internal, false},
  };
  for (const CodeExpectation& expectation : expectations) {
    const Explanation explanation(expectation.code);
    CPE_REQUIRE_EQ(explanation.category(), expectation.category);
    CPE_REQUIRE_EQ(explanation.retryable(), expectation.retryable);
    CPE_REQUIRE_EQ(dccp::epoch::error_category(expectation.code), expectation.category);
    CPE_REQUIRE_EQ(dccp::epoch::error_retryable(expectation.code), expectation.retryable);
  }

  // Category tokens are stable too: a category is reported by token, never by
  // its numeric value.
  CPE_REQUIRE_EQ(dccp::epoch::error_category_token(ErrorCategory::Success), std::string_view("success"));
  CPE_REQUIRE_EQ(dccp::epoch::error_category_token(ErrorCategory::Identity), std::string_view("identity"));
  CPE_REQUIRE_EQ(dccp::epoch::error_category_token(ErrorCategory::Limit), std::string_view("limit"));
  CPE_REQUIRE_EQ(dccp::epoch::error_category_token(ErrorCategory::Persistence), std::string_view("persistence"));
  CPE_REQUIRE_EQ(dccp::epoch::error_category_token(ErrorCategory::Integrity), std::string_view("integrity"));
  CPE_REQUIRE_EQ(dccp::epoch::error_category_token(ErrorCategory::Protocol), std::string_view("protocol"));
  CPE_REQUIRE_EQ(dccp::epoch::error_category_token(ErrorCategory::Io), std::string_view("io"));
  CPE_REQUIRE_EQ(dccp::epoch::error_category_token(ErrorCategory::Configuration), std::string_view("configuration"));
  CPE_REQUIRE_EQ(dccp::epoch::error_category_token(ErrorCategory::Authority), std::string_view("authority"));
  CPE_REQUIRE_EQ(dccp::epoch::error_category_token(ErrorCategory::Recovery), std::string_view("recovery"));
  CPE_REQUIRE_EQ(dccp::epoch::error_category_token(ErrorCategory::Internal), std::string_view("internal"));
}

CPE_TEST(explanation, explanations_are_equal_and_render_deterministically) {
  // Identical inputs produce byte-identical explanations, which is what makes a
  // rejection outcome comparable between two runs of the same scenario.
  const Explanation first(ErrorCode::EpochFenced, "token epoch 1 was fenced when epoch 2 committed");
  const Explanation second(ErrorCode::EpochFenced, "token epoch 1 was fenced when epoch 2 committed");
  CPE_REQUIRE(first == second);
  CPE_REQUIRE_EQ(first.to_string(), second.to_string());
  CPE_REQUIRE_EQ(first.to_string(),
                 std::string("epoch.fenced: the token belongs to an epoch that has been permanently fenced "
                             "[token epoch 1 was fenced when epoch 2 committed]"));

  // A different detail is a different explanation, and detail is the only
  // variable part: code, token, summary, and category never drift.
  const Explanation other(ErrorCode::EpochFenced, "token epoch 1 was fenced when epoch 3 committed");
  CPE_REQUIRE(first != other);
  CPE_REQUIRE(first.to_string() != other.to_string());
  CPE_REQUIRE_EQ(other.code(), first.code());
  CPE_REQUIRE_EQ(other.token(), first.token());
  CPE_REQUIRE_EQ(other.summary(), first.summary());

  // With no detail the rendering drops the bracketed context entirely.
  const Explanation bare(ErrorCode::AuthorityRevoked);
  CPE_REQUIRE_EQ(bare.to_string(),
                 std::string("authority.revoked: the authority has been revoked and is permanently fenced"));
  CPE_REQUIRE_EQ(Explanation(ErrorCode::Ok).to_string(), std::string("ok: accepted"));
  CPE_REQUIRE_EQ(Explanation().code(), ErrorCode::Ok);
  CPE_REQUIRE(Explanation() == Explanation(ErrorCode::Ok));
  CPE_REQUIRE_EQ(Explanation().to_string(), std::string("ok: accepted"));
}

CPE_TEST(explanation, epoch_error_carries_its_explanation) {
  // Infrastructure failure is the only channel that throws, and the thrown
  // value must carry the same machine-readable explanation the Result channel
  // would have carried.
  const Explanation explanation(ErrorCode::DigestMismatch, "snapshot digest does not match its content");
  try {
    throw EpochError(explanation);
  } catch (const EpochError& error) {
    CPE_REQUIRE_EQ(error.code(), ErrorCode::DigestMismatch);
    CPE_REQUIRE(error.explanation() == explanation);
    CPE_REQUIRE_EQ(error.explanation().to_string(), explanation.to_string());
    CPE_REQUIRE_EQ(std::string(error.what()), explanation.to_string());
    CPE_REQUIRE(std::string(error.what()).find("integrity.digest_mismatch") != std::string::npos);
    CPE_REQUIRE(std::string(error.what()).find("snapshot digest does not match its content") != std::string::npos);
  }

  // The two-argument constructor is the same value as the Explanation form, and
  // the type remains catchable as a standard exception.
  try {
    throw EpochError(ErrorCode::EpochFenced, "token epoch 1 is fenced");
  } catch (const std::runtime_error& error) {
    const std::string text(error.what());
    CPE_REQUIRE(text.find("epoch.fenced") != std::string::npos);
    CPE_REQUIRE(text.find("[token epoch 1 is fenced]") != std::string::npos);
  }
}

CPE_TEST(explanation, validation_outcome_and_result_rendering) {
  const ValidationOutcome accepted = ValidationOutcome::accept();
  CPE_REQUIRE(accepted.accepted());
  CPE_REQUIRE(static_cast<bool>(accepted));
  CPE_REQUIRE_EQ(accepted.code(), ErrorCode::Ok);
  CPE_REQUIRE(!accepted.rejection().has_value());
  CPE_REQUIRE_EQ(accepted.to_string(), std::string("accepted"));

  const Explanation rejection(ErrorCode::AuthorityRevoked, "grant 4 was revoked by revocation 2");
  const ValidationOutcome rejected = ValidationOutcome::reject(rejection);
  CPE_REQUIRE(!rejected.accepted());
  CPE_REQUIRE(!static_cast<bool>(rejected));
  CPE_REQUIRE_EQ(rejected.code(), ErrorCode::AuthorityRevoked);
  CPE_REQUIRE(rejected.rejection().has_value());
  CPE_REQUIRE(*rejected.rejection() == rejection);
  CPE_REQUIRE_EQ(rejected.to_string(), std::string("rejected: ") + rejection.to_string());
  // Two rejections built from equal explanations render identically.
  CPE_REQUIRE_EQ(ValidationOutcome::reject(Explanation(rejection)).to_string(), rejected.to_string());

  // Result and ValidationOutcome split the two channels cleanly: a rejection is
  // a value, and reading the value of a rejection is an internal defect rather
  // than a fabricated default.
  const Result<int> value(7);
  CPE_REQUIRE(value.has_value());
  CPE_REQUIRE(static_cast<bool>(value));
  CPE_REQUIRE_EQ(value.value(), 7);
  CPE_REQUIRE(value.rejection().is_ok());
  CPE_REQUIRE_EQ(value.code(), ErrorCode::Ok);

  Result<int> failed(Explanation(ErrorCode::InvariantViolation, "no value was produced"));
  CPE_REQUIRE(!failed.has_value());
  CPE_REQUIRE_EQ(failed.code(), ErrorCode::InvariantViolation);
  CPE_REQUIRE_EQ(failed.rejection().to_string(),
                 std::string("internal.invariant_violation: an internal invariant was violated "
                             "[no value was produced]"));
  CPE_REQUIRE_THROWS_CODE(failed.value(), ErrorCode::InvariantViolation);
  CPE_REQUIRE_THROWS_CODE(failed.move_value(), ErrorCode::InvariantViolation);

  const Status status(Unit{});
  CPE_REQUIRE(status.has_value());
  CPE_REQUIRE(status.value() == Unit{});
  const Status rejected_status(Explanation(ErrorCode::UnsupportedOperation, "read-only authority"));
  CPE_REQUIRE(!rejected_status.has_value());
  CPE_REQUIRE_EQ(rejected_status.rejection().code(), ErrorCode::UnsupportedOperation);
}
