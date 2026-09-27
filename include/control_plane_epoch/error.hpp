// Control Plane Epoch 1.0.0 - Summon Software Labs
// Stable, machine-readable error and rejection catalogue.
//
// Two error channels are used by this library and the split is deliberate:
//
//   * Result<T> / ValidationOutcome carry all *domain* outcomes that a caller
//     is expected to handle: stale epochs, revoked authority, conflicting
//     advancement, exhausted limits, idempotency conflicts, recovery verdicts.
//   * EpochError is thrown only for *infrastructure* failures: I/O errors,
//     integrity failures in durable or framed data, configuration mistakes,
//     and internal invariant violations.
//
// Every code has a stable machine token ("authority.revoked"), a fixed
// category, a fixed retryability flag, and a fixed human summary. For identical
// inputs and identical state the produced Explanation is byte-identical, which
// is what makes rejection outcomes testable and log-comparable.
#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace dccp::epoch {

enum class ErrorCategory : std::uint32_t {
  Success = 0,
  Identity = 1,
  Limit = 2,
  Persistence = 3,
  Integrity = 4,
  Protocol = 5,
  Io = 6,
  Configuration = 7,
  Authority = 8,
  Recovery = 9,
  Internal = 10,
};

/// Stable catalog of every outcome this repository can report.
enum class ErrorCode : std::uint32_t {
  Ok = 0,

  // Identity and text ------------------------------------------------------
  InvalidIdentifierSyntax = 100,
  IdentifierTooLong = 101,
  IdentifierEmpty = 102,
  ExternalReferenceInvalid = 103,
  TextInvalidUtf8 = 104,
  TextTooLong = 105,
  TextControlCharacter = 106,
  DigestInvalidHex = 107,

  // Epoch ------------------------------------------------------------------
  EpochZero = 200,
  EpochExhausted = 201,
  EpochConflict = 202,
  EpochFenced = 203,
  EpochUnknown = 204,
  CounterExhausted = 205,

  // Authority --------------------------------------------------------------
  ScopeUnknown = 300,
  ScopeDuplicate = 301,
  SponsorRequired = 302,
  DomainMismatch = 303,
  TokenTampered = 304,
  TokenMalformed = 305,
  UnknownGrant = 306,
  AuthorityClassMismatch = 307,
  AuthorityRevoked = 308,
  ScopeNotGranted = 309,
  RootAuthorityRequired = 310,
  ClaimsMismatch = 311,

  // Controllers and incarnations -------------------------------------------
  ControllerUnknown = 400,
  ControllerRootImmutable = 401,
  IncarnationUnknown = 402,
  IncarnationSuperseded = 403,

  // Revocation -------------------------------------------------------------
  RevocationUnknownTarget = 500,

  // Idempotency ------------------------------------------------------------
  IdempotencyConflict = 600,

  // Recovered state qualification -----------------------------------------
  RecoveredCurrent = 700,
  RecoveredStale = 701,
  RecoveredSuperseded = 702,
  RecoveredNeedsReconciliation = 703,
  RecoveredRejectedFutureEpoch = 704,
  RecoveredRejectedUnknownIncarnation = 705,
  RecoveredRejectedNoAuthority = 706,
  RecoveredRejectedDomainMismatch = 707,

  // Persistence ------------------------------------------------------------
  StoreNotFound = 800,
  StoreLocked = 801,
  StoreAlreadyInitialized = 802,
  StoreNotInitialized = 803,
  CommitFailed = 804,
  AssertedEpochFloorRequired = 805,
  AssertedEpochFloorTooLow = 806,
  SnapshotMissing = 807,
  PublishFailed = 808,
  TempCreateFailed = 809,
  SyncFailed = 810,
  PathInvalid = 811,
  PermissionDenied = 812,
  QuarantineFailed = 813,
  DurableLimitsExceeded = 814,
  FloorMissing = 815,

  // Integrity --------------------------------------------------------------
  MagicMismatch = 900,
  FormatVersionUnsupported = 901,
  SchemaUnsupported = 902,
  Truncated = 903,
  DigestMismatch = 904,
  SizeMismatch = 905,
  ChainBroken = 906,
  GenerationBelowFloor = 907,
  EpochBelowFloor = 908,
  CountMismatch = 909,
  IntegrityLimitExceeded = 910,
  EnumOutOfDomain = 911,
  TrailingBytes = 912,
  OrderingViolation = 913,
  DuplicateKey = 914,
  ArithmeticOverflow = 915,

  // Protocol ---------------------------------------------------------------
  FrameMagic = 1000,
  ProtocolVersionUnsupported = 1001,
  FrameTooLarge = 1002,
  FrameTruncated = 1003,
  FrameDigestMismatch = 1004,
  MessageTypeUnknown = 1005,
  RequestIdMismatch = 1006,
  ProtocolDomainMismatch = 1007,
  MalformedPayload = 1008,
  HandshakeRequired = 1009,
  HandshakeRejected = 1010,

  // I/O --------------------------------------------------------------------
  ConnectFailed = 1100,
  ReadFailed = 1101,
  WriteFailed = 1102,
  ListenFailed = 1103,
  SocketClosed = 1104,

  // Runtime service --------------------------------------------------------
  ServerStopping = 1200,
  ServerBusy = 1201,
  ServerNotRunning = 1202,
  ServerAlreadyRunning = 1203,

  // Limits -----------------------------------------------------------------
  ControllerLimitReached = 1300,
  GrantLimitReached = 1301,
  PageLimitExceeded = 1302,
  SizeLimitExceeded = 1303,
  ConnectionLimitReached = 1304,

  // Configuration ----------------------------------------------------------
  InvalidOption = 1400,
  InvalidArgument = 1401,

  // Internal ---------------------------------------------------------------
  InvariantViolation = 1500,
  UnsupportedOperation = 1501,
};

/// Stable machine token, for example "authority.revoked". Never localized and
/// never renumbered; new codes are appended with new tokens.
[[nodiscard]] std::string_view error_token(ErrorCode code) noexcept;

/// Fixed human summary for a code. Concise, English, no variable content.
[[nodiscard]] std::string_view error_summary(ErrorCode code) noexcept;

[[nodiscard]] ErrorCategory error_category(ErrorCode code) noexcept;
[[nodiscard]] std::string_view error_category_token(ErrorCategory category) noexcept;

/// True when retrying the identical request against unchanged state may
/// legitimately succeed (for example a lost advancement race).
[[nodiscard]] bool error_retryable(ErrorCode code) noexcept;

/// Deterministic explanation of one outcome: stable code, fixed summary, and
/// caller-supplied context that is derived only from the request and the
/// authoritative state involved.
class Explanation {
 public:
  Explanation() noexcept : code_(ErrorCode::Ok) {}
  explicit Explanation(ErrorCode code) : code_(code) {}
  Explanation(ErrorCode code, std::string detail) : code_(code), detail_(std::move(detail)) {}

  [[nodiscard]] ErrorCode code() const noexcept { return code_; }
  [[nodiscard]] ErrorCategory category() const noexcept { return error_category(code_); }
  [[nodiscard]] std::string_view token() const noexcept { return error_token(code_); }
  [[nodiscard]] std::string_view summary() const noexcept { return error_summary(code_); }
  [[nodiscard]] bool retryable() const noexcept { return error_retryable(code_); }
  [[nodiscard]] bool is_ok() const noexcept { return code_ == ErrorCode::Ok; }
  [[nodiscard]] const std::string& detail() const noexcept { return detail_; }

  /// "authority.revoked: the presented authority is revoked [detail]"
  [[nodiscard]] std::string to_string() const;

  friend bool operator==(const Explanation& lhs, const Explanation& rhs) {
    return lhs.code_ == rhs.code_ && lhs.detail_ == rhs.detail_;
  }
  friend bool operator!=(const Explanation& lhs, const Explanation& rhs) { return !(lhs == rhs); }

 private:
  ErrorCode code_ = ErrorCode::Ok;
  std::string detail_;
};

/// Infrastructure failure. Thrown for I/O, integrity, configuration, and
/// internal invariant failures; never for an expected domain rejection.
class EpochError : public std::runtime_error {
 public:
  explicit EpochError(Explanation explanation);
  EpochError(ErrorCode code, std::string detail);

  [[nodiscard]] const Explanation& explanation() const noexcept { return explanation_; }
  [[nodiscard]] ErrorCode code() const noexcept { return explanation_.code(); }

 private:
  Explanation explanation_;
};

/// Placeholder for commands that produce no value but can be rejected.
struct Unit {
  friend bool operator==(Unit, Unit) noexcept { return true; }
};

/// Value-or-rejection result. A rejection always carries an Explanation.
template <class T>
class Result {
 public:
  Result(T value) : value_(std::move(value)) {}
  Result(Explanation rejection) : rejection_(std::move(rejection)) {}

  [[nodiscard]] bool has_value() const noexcept { return value_.has_value(); }
  [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }

  /// Precondition: has_value(). A violation is an internal defect and raises
  /// EpochError(InvariantViolation) rather than returning a fabricated value.
  [[nodiscard]] T& value() {
    if (!value_.has_value()) {
      throw EpochError(ErrorCode::InvariantViolation, "Result::value() on a rejection");
    }
    return *value_;
  }
  [[nodiscard]] const T& value() const {
    if (!value_.has_value()) {
      throw EpochError(ErrorCode::InvariantViolation, "Result::value() on a rejection");
    }
    return *value_;
  }
  [[nodiscard]] T&& move_value() {
    if (!value_.has_value()) {
      throw EpochError(ErrorCode::InvariantViolation, "Result::move_value() on a rejection");
    }
    return std::move(*value_);
  }

  /// Rejection explanation. Returns an Ok explanation for an accepted result.
  [[nodiscard]] const Explanation& rejection() const noexcept {
    static const Explanation ok{};
    return rejection_.has_value() ? *rejection_ : ok;
  }
  [[nodiscard]] ErrorCode code() const noexcept { return rejection().code(); }

 private:
  std::optional<T> value_;
  std::optional<Explanation> rejection_;
};

using Status = Result<Unit>;

/// Inverse of error_token(). Used when a stable token crosses the wire or a
/// process boundary, so that codes are never carried as bare integers.
[[nodiscard]] Result<ErrorCode> parse_error_code(std::string_view token);

/// Outcome of an authority or token validation. Accept carries no explanation;
/// reject always carries exactly one.
class ValidationOutcome {
 public:
  static ValidationOutcome accept() noexcept { return ValidationOutcome(); }
  static ValidationOutcome reject(Explanation explanation) { return ValidationOutcome(std::move(explanation)); }

  [[nodiscard]] bool accepted() const noexcept { return !rejection_.has_value(); }
  [[nodiscard]] explicit operator bool() const noexcept { return accepted(); }
  [[nodiscard]] const std::optional<Explanation>& rejection() const noexcept { return rejection_; }
  [[nodiscard]] ErrorCode code() const noexcept {
    return rejection_.has_value() ? rejection_->code() : ErrorCode::Ok;
  }
  [[nodiscard]] std::string to_string() const;

 private:
  ValidationOutcome() = default;
  explicit ValidationOutcome(Explanation rejection) : rejection_(std::move(rejection)) {}

  std::optional<Explanation> rejection_;
};

}  // namespace dccp::epoch
