// Control Plane Epoch 1.0.0 - Summon Software Labs
// Suite: protocol.
//
// Invariant under test: the framed transport is a total, conservative function
// of the bytes that arrived. Every rejection is a stable protocol code produced
// before any payload is materialized, and a frame that survives decoding
// reproduces exactly the header and payload that were encoded.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <vector>

#include "test_support.hpp"

#include "control_plane_epoch/version.hpp"

#include "encoding.hpp"
#include "records.hpp"
#include "wire.hpp"

namespace {

using namespace cpe_test;
using namespace dccp::epoch;
using dccp::epoch::detail::Payload;

constexpr std::size_t kVersionOffset = 4;
constexpr std::size_t kTypeOffset = 6;
constexpr std::size_t kFlagsOffset = 8;
constexpr std::size_t kRequestIdOffset = 12;
constexpr std::size_t kLengthOffset = 20;
constexpr std::size_t kDigestOffset = 24;

[[nodiscard]] std::array<std::byte, 2> little_u16(std::uint16_t value) {
  return {static_cast<std::byte>(value & 0xFFu), static_cast<std::byte>((value >> 8u) & 0xFFu)};
}

[[nodiscard]] std::array<std::byte, 4> little_u32(std::uint32_t value) {
  return {static_cast<std::byte>(value & 0xFFu), static_cast<std::byte>((value >> 8u) & 0xFFu),
          static_cast<std::byte>((value >> 16u) & 0xFFu), static_cast<std::byte>((value >> 24u) & 0xFFu)};
}

void patch(std::vector<std::byte>& bytes, std::size_t offset, std::span<const std::byte> replacement) {
  if (offset + replacement.size() > bytes.size()) {
    throw Failure("patch is outside the frame");
  }
  std::copy(replacement.begin(), replacement.end(), bytes.begin() + static_cast<std::ptrdiff_t>(offset));
}

[[nodiscard]] Frame make_frame(MessageType type, std::uint64_t request_id, const std::vector<std::byte>& payload) {
  FrameHeader header;
  header.version = static_cast<std::uint16_t>(protocol_version);
  header.type = type;
  header.flags = 0;
  header.request_id = request_id;
  header.payload_length = static_cast<std::uint32_t>(payload.size());
  header.payload_digest = sha256(std::span<const std::byte>(payload));
  return Frame(header, payload);
}

[[nodiscard]] std::vector<std::byte> encode_or_fail(const Frame& frame,
                                                    std::size_t bound = max_frame_payload_bytes) {
  std::vector<std::byte> out;
  auto status = encode_frame(frame, out, bound);
  if (!status.has_value()) {
    throw Failure("encode_frame rejected a well-formed frame: " + status.rejection().to_string());
  }
  return out;
}

[[nodiscard]] Frame decode_or_fail(std::span<const std::byte> bytes,
                                   std::size_t bound = max_frame_payload_bytes) {
  auto decoded = decode_frame(bytes, bound);
  if (!decoded.has_value()) {
    throw Failure("decode_frame rejected a well-formed frame: " + decoded.rejection().to_string());
  }
  return decoded.move_value();
}

/// Every rejection must be a plain Result rejection carrying exactly one code.
void require_frame_rejection(std::span<const std::byte> bytes, ErrorCode expected,
                             std::size_t bound = max_frame_payload_bytes) {
  auto decoded = decode_frame(bytes, bound);
  CPE_REQUIRE_MSG(!decoded.has_value(), "a damaged frame decoded successfully");
  CPE_REQUIRE_MSG(decoded.rejection().code() == expected,
                  std::string("expected ") + std::string(error_token(expected)) + " but observed " +
                      std::string(error_token(decoded.rejection().code())) + ": " + decoded.rejection().detail());
  CPE_REQUIRE_MSG(decoded.rejection().category() == ErrorCategory::Protocol,
                  "a frame rejection must be a protocol-category outcome");
}

[[nodiscard]] std::vector<std::byte> payload_of(std::string_view text) {
  std::vector<std::byte> bytes(text.size());
  std::transform(text.begin(), text.end(), bytes.begin(),
                 [](char value) { return static_cast<std::byte>(static_cast<unsigned char>(value)); });
  return bytes;
}

/// Leading length-prefixed text field of a payload whose first field is text
/// (an error response). Used to assert the exact token that crosses the wire.
[[nodiscard]] std::string leading_text_field(const Payload& payload) {
  dccp::epoch::detail::CanonicalReader reader(std::span<const std::byte>(payload), 4096);
  return reader.text();
}

/// Error token of a validation payload: a leading accepted flag, then the token
/// only when the outcome is a rejection.
[[nodiscard]] std::string validation_token(const Payload& payload) {
  dccp::epoch::detail::CanonicalReader reader(std::span<const std::byte>(payload), 4096);
  if (reader.boolean()) {
    return std::string();
  }
  return reader.text();
}

/// Error token of a qualification payload: a leading verdict, then the token.
[[nodiscard]] std::string qualification_token(const Payload& payload) {
  dccp::epoch::detail::CanonicalReader reader(std::span<const std::byte>(payload), 4096);
  (void)reader.u32();
  return reader.text();
}

[[nodiscard]] std::vector<MessageType> message_vocabulary() {
  return {MessageType::HelloRequest,
          MessageType::HelloResponse,
          MessageType::RegisterControllerRequest,
          MessageType::RegisterControllerResponse,
          MessageType::AcquireAuthorityRequest,
          MessageType::AcquireAuthorityResponse,
          MessageType::ValidateMutationRequest,
          MessageType::ValidateMutationResponse,
          MessageType::ValidateObservationRequest,
          MessageType::ValidateObservationResponse,
          MessageType::AdvanceEpochRequest,
          MessageType::AdvanceEpochResponse,
          MessageType::RevokeRequest,
          MessageType::RevokeResponse,
          MessageType::QualifyRecoveredStateRequest,
          MessageType::QualifyRecoveredStateResponse,
          MessageType::StatusRequest,
          MessageType::StatusResponse,
          MessageType::HistoryRequest,
          MessageType::HistoryResponse,
          MessageType::RevocationsRequest,
          MessageType::RevocationsResponse,
          MessageType::ControllersRequest,
          MessageType::ControllersResponse,
          MessageType::GrantsRequest,
          MessageType::GrantsResponse,
          MessageType::ErrorResponse};
}

}  // namespace

// ---------------------------------------------------------------------------
// Frame codec
// ---------------------------------------------------------------------------

CPE_TEST(protocol, frame_round_trip_reproduces_every_header_field) {
  CPE_REQUIRE_EQ(frame_header_bytes, 56u);
  CPE_REQUIRE_EQ(static_cast<std::uint16_t>(protocol_version), 1u);

  const Payload payload = payload_of("register-controller:ctrl-a");
  const Frame frame = make_frame(MessageType::RegisterControllerRequest, 0x0102030405060708ull, payload);
  const std::vector<std::byte> bytes = encode_or_fail(frame);

  // Layout is part of the protocol: magic, version, type, flags, request id,
  // declared length, payload digest, payload.
  CPE_REQUIRE_EQ(bytes.size(), frame_header_bytes + payload.size());
  CPE_REQUIRE(bytes[0] == std::byte{'C'});
  CPE_REQUIRE(bytes[1] == std::byte{'P'});
  CPE_REQUIRE(bytes[2] == std::byte{'E'});
  CPE_REQUIRE(bytes[3] == std::byte{'1'});
  const std::array<std::byte, 2> version_bytes = little_u16(static_cast<std::uint16_t>(protocol_version));
  const std::array<std::byte, 4> length_bytes = little_u32(static_cast<std::uint32_t>(payload.size()));
  CPE_REQUIRE(std::equal(version_bytes.begin(), version_bytes.end(),
                         bytes.begin() + static_cast<std::ptrdiff_t>(kVersionOffset)));
  CPE_REQUIRE(std::equal(length_bytes.begin(), length_bytes.end(),
                         bytes.begin() + static_cast<std::ptrdiff_t>(kLengthOffset)));
  const Sha256Digest payload_digest = sha256(std::span<const std::byte>(payload));
  CPE_REQUIRE(std::equal(payload_digest.bytes().begin(), payload_digest.bytes().end(),
                         bytes.begin() + static_cast<std::ptrdiff_t>(kDigestOffset)));

  const Frame decoded = decode_or_fail(bytes);
  CPE_REQUIRE_EQ(decoded.header().version, static_cast<std::uint16_t>(protocol_version));
  CPE_REQUIRE(decoded.header().type == MessageType::RegisterControllerRequest);
  CPE_REQUIRE_EQ(decoded.header().flags, 0u);
  CPE_REQUIRE_EQ(decoded.header().request_id, 0x0102030405060708ull);
  CPE_REQUIRE_EQ(decoded.header().payload_length, static_cast<std::uint32_t>(payload.size()));
  CPE_REQUIRE_EQ(decoded.header().payload_digest, payload_digest);
  CPE_REQUIRE(decoded.payload() == payload);

  // The empty payload is a legal frame and is distinguished by its digest.
  const Frame empty = make_frame(MessageType::StatusRequest, 1, {});
  const Frame empty_decoded = decode_or_fail(encode_or_fail(empty));
  CPE_REQUIRE(empty_decoded.payload().empty());
  CPE_REQUIRE_EQ(empty_decoded.header().payload_length, 0u);
  CPE_REQUIRE_EQ(empty_decoded.header().payload_digest, sha256(std::string_view{}));
  CPE_REQUIRE_EQ(encode_or_fail(empty).size(), frame_header_bytes);
}

CPE_TEST(protocol, randomised_frames_round_trip_exactly) {
  const std::uint64_t seed = 0x5EED1234ull;
  DeterministicRandom random(seed);
  const std::vector<MessageType> vocabulary = message_vocabulary();

  for (int iteration = 0; iteration < 64; ++iteration) {
    const MessageType type = vocabulary[static_cast<std::size_t>(random.next_below(vocabulary.size()))];
    const std::uint64_t request_id = random.next();
    const std::size_t length = static_cast<std::size_t>(random.next_below(600));
    Payload payload(length);
    for (std::size_t index = 0; index < length; ++index) {
      payload[index] = static_cast<std::byte>(random.next() & 0xFFu);
    }
    const Frame frame = make_frame(type, request_id, payload);
    const std::vector<std::byte> bytes = encode_or_fail(frame);
    const Frame decoded = decode_or_fail(bytes);
    CPE_REQUIRE_MSG(decoded.header().type == type, "seed=" + std::to_string(random.seed()));
    CPE_REQUIRE_MSG(decoded.header().request_id == request_id, "seed=" + std::to_string(random.seed()));
    CPE_REQUIRE_MSG(decoded.payload() == payload, "seed=" + std::to_string(random.seed()));
    CPE_REQUIRE_MSG(decoded.header().payload_digest == sha256(std::span<const std::byte>(payload)),
                    "seed=" + std::to_string(random.seed()));
  }
}

CPE_TEST(protocol, every_frame_damage_is_rejected_with_its_exact_code) {
  const Payload payload = payload_of("hello-from-a-remote-controller");
  const std::vector<std::byte> good =
      encode_or_fail(make_frame(MessageType::HelloRequest, 42, payload));
  const Frame intact = decode_or_fail(good);
  CPE_REQUIRE(intact.payload() == payload);
  CPE_REQUIRE_EQ(intact.payload().size(), payload.size());

  // Wrong magic.
  {
    std::vector<std::byte> bytes = good;
    bytes[0] = std::byte{'X'};
    require_frame_rejection(bytes, ErrorCode::FrameMagic);
  }

  // Unsupported protocol version (both above and below the supported one).
  for (const unsigned int version : {0u, 2u, 99u}) {
    std::vector<std::byte> bytes = good;
    const std::array<std::byte, 2> encoded = little_u16(static_cast<std::uint16_t>(version));
    patch(bytes, kVersionOffset, encoded);
    require_frame_rejection(bytes, ErrorCode::ProtocolVersionUnsupported);
  }

  // Reserved flags must be zero.
  for (const std::uint32_t flags : {1u, 0x80000000u, 0xFFFFFFFFu}) {
    std::vector<std::byte> bytes = good;
    const std::array<std::byte, 4> encoded = little_u32(flags);
    patch(bytes, kFlagsOffset, encoded);
    require_frame_rejection(bytes, ErrorCode::MalformedPayload);
  }

  // Unknown message type.
  for (const unsigned int type : {0u, 3u, 9u, 34u, 89u, 91u, 65535u}) {
    std::vector<std::byte> bytes = good;
    const std::array<std::byte, 2> encoded = little_u16(static_cast<std::uint16_t>(type));
    patch(bytes, kTypeOffset, encoded);
    require_frame_rejection(bytes, ErrorCode::MessageTypeUnknown);
  }

  // Declared length above the negotiated bound.
  for (const std::uint32_t length : {static_cast<std::uint32_t>(max_frame_payload_bytes) + 1u, 0x0FFFFFFFu,
                                     0x7FFFFFFFu, 0xFFFFFFFFu}) {
    std::vector<std::byte> bytes = good;
    const std::array<std::byte, 4> encoded = little_u32(length);
    patch(bytes, kLengthOffset, encoded);
    require_frame_rejection(bytes, ErrorCode::FrameTooLarge);
  }

  // Truncation, below the header and inside the payload.
  {
    std::vector<std::byte> bytes = good;
    bytes.resize(frame_header_bytes - 1);
    require_frame_rejection(bytes, ErrorCode::FrameTruncated);
  }
  for (const std::size_t removed : {std::size_t{1}, std::size_t{7}, payload.size()}) {
    std::vector<std::byte> bytes = good;
    bytes.resize(bytes.size() - removed);
    require_frame_rejection(bytes, ErrorCode::FrameTruncated);
  }
  require_frame_rejection(std::span<const std::byte>{}, ErrorCode::FrameTruncated);

  // Payload digest mismatch: a flipped payload byte keeps every length intact,
  // so only the digest can detect it.
  {
    std::vector<std::byte> bytes = good;
    bytes.back() ^= std::byte{0x01};
    require_frame_rejection(bytes, ErrorCode::FrameDigestMismatch);
  }

  // A payload that is internally consistent but declared larger than the
  // caller's own bound is still refused.
  require_frame_rejection(good, ErrorCode::FrameTooLarge, payload.size() - 1);
  CPE_REQUIRE(decode_frame(good, payload.size()).has_value());
}

CPE_TEST(protocol, a_hostile_declared_length_is_rejected_without_materializing_a_payload) {
  // A header-only buffer that claims four gigabytes. The rejection must be a
  // protocol bound violation, which is only reachable if the length is checked
  // before anything is allocated for it. If the reader allocated first, this
  // would raise a bad_alloc (or be killed) instead of returning a Result.
  const Payload payload = payload_of("x");
  const std::vector<std::byte> good = encode_or_fail(make_frame(MessageType::HelloRequest, 1, payload));

  for (const std::uint32_t hostile : {0xFFFFFFFFu, 0xFFFFFFFEu, 0x80000000u,
                                      static_cast<std::uint32_t>(max_frame_payload_bytes) + 1024u}) {
    std::vector<std::byte> bytes(good.begin(), good.begin() + static_cast<std::ptrdiff_t>(frame_header_bytes));
    const std::array<std::byte, 4> encoded = little_u32(hostile);
    patch(bytes, kLengthOffset, encoded);

    auto decoded = decode_frame(bytes);
    CPE_REQUIRE(!decoded.has_value());
    CPE_REQUIRE_EQ(decoded.rejection().code(), ErrorCode::FrameTooLarge);
    CPE_REQUIRE(decoded.rejection().detail().find("exceeds the bound") != std::string::npos);

    // The same hostile header with a lower caller bound is refused as well, and
    // the reported bound is the caller's.
    auto tighter = decode_frame(bytes, 8);
    CPE_REQUIRE(!tighter.has_value());
    CPE_REQUIRE_EQ(tighter.rejection().code(), ErrorCode::FrameTooLarge);
  }

  // Encoding refuses an oversized payload instead of producing a frame no
  // reader would accept.
  std::vector<std::byte> out;
  Payload oversized(static_cast<std::size_t>(max_frame_payload_bytes) + 1u, std::byte{0});
  auto status = encode_frame(make_frame(MessageType::HelloRequest, 1, oversized), out);
  CPE_REQUIRE(!status.has_value());
  CPE_REQUIRE_EQ(status.rejection().code(), ErrorCode::FrameTooLarge);
  CPE_REQUIRE(out.empty());
}

CPE_TEST(protocol, message_type_vocabulary_round_trips_through_its_tokens) {
  const std::vector<MessageType> vocabulary = message_vocabulary();
  CPE_REQUIRE_EQ(vocabulary.size(), 27u);
  CPE_REQUIRE_EQ(max_message_type, 90u);
  CPE_REQUIRE_EQ(static_cast<std::uint16_t>(MessageType::HelloRequest), 1u);
  CPE_REQUIRE_EQ(static_cast<std::uint16_t>(MessageType::ErrorResponse), 90u);

  std::set<std::string> tokens;
  for (const MessageType type : vocabulary) {
    const std::string_view token = message_type_token(type);
    CPE_REQUIRE(token != "unknown");
    CPE_REQUIRE(!token.empty());
    tokens.emplace(token);
    auto parsed = parse_message_type(static_cast<std::uint16_t>(type));
    CPE_REQUIRE(parsed.has_value());
    CPE_REQUIRE(parsed.value() == type);
    CPE_REQUIRE_EQ(std::string(message_type_token(parsed.value())), std::string(token));
  }
  // Tokens are a one-to-one vocabulary, so a token identifies exactly one type.
  CPE_REQUIRE_EQ(tokens.size(), vocabulary.size());

  for (const unsigned int unknown : {0u, 3u, 9u, 34u, 89u, 91u, 1000u, 65535u}) {
    auto parsed = parse_message_type(static_cast<std::uint16_t>(unknown));
    CPE_REQUIRE(!parsed.has_value());
    CPE_REQUIRE_EQ(parsed.rejection().code(), ErrorCode::MessageTypeUnknown);
  }
  CPE_REQUIRE_EQ(message_type_token(static_cast<MessageType>(0xFFFFu)), std::string_view("unknown"));
}

// ---------------------------------------------------------------------------
// Per-message payloads
// ---------------------------------------------------------------------------

CPE_TEST(protocol, error_and_qualification_payloads_carry_stable_tokens) {
  // An error crosses the wire as its stable machine token, never as a number,
  // so a peer compiled against a different catalogue version cannot silently
  // reinterpret it.
  detail::ErrorPayload error;
  error.code = ErrorCode::AuthorityRevoked;
  error.detail = "grant 7 was revoked by revocation 3";
  const Payload error_bytes = detail::encode_error(error);
  CPE_REQUIRE_EQ(leading_text_field(error_bytes), std::string(error_token(ErrorCode::AuthorityRevoked)));
  CPE_REQUIRE_EQ(leading_text_field(error_bytes), std::string("authority.revoked"));
  const detail::ErrorPayload decoded_error = detail::decode_error(error_bytes);
  CPE_REQUIRE(decoded_error.code == ErrorCode::AuthorityRevoked);
  CPE_REQUIRE_EQ(decoded_error.detail, error.detail);

  // A rejected validation carries its token only when it is a rejection, so an
  // accepted outcome stays one byte.
  detail::ValidationPayload accepted;
  accepted.accepted = true;
  const Payload accepted_bytes = detail::encode_validation(accepted);
  CPE_REQUIRE_EQ(accepted_bytes.size(), 1u);
  CPE_REQUIRE(detail::decode_validation(accepted_bytes).accepted);

  detail::ValidationPayload rejected;
  rejected.accepted = false;
  rejected.code = ErrorCode::ScopeNotGranted;
  rejected.detail = "grant 7 does not cover scope 'facility.topology'";
  const Payload rejected_bytes = detail::encode_validation(rejected);
  CPE_REQUIRE_EQ(validation_token(rejected_bytes), std::string("authority.scope_not_granted"));
  const detail::ValidationPayload decoded_rejection = detail::decode_validation(rejected_bytes);
  CPE_REQUIRE(!decoded_rejection.accepted);
  CPE_REQUIRE(decoded_rejection.code == ErrorCode::ScopeNotGranted);
  CPE_REQUIRE_EQ(decoded_rejection.detail, rejected.detail);

  // A qualification carries the verdict, the explanation token, the matching
  // grant (when there is one) and the revalidation flag.
  detail::QualificationPayload reconcilable;
  reconcilable.verdict = RecoveredStateVerdict::NeedsReconciliation;
  reconcilable.code = ErrorCode::RecoveredNeedsReconciliation;
  reconcilable.detail = "produced in epoch 1";
  reconcilable.matching_grant = 7;
  reconcilable.requires_revalidation = true;
  const Payload reconcilable_bytes = detail::encode_qualification(reconcilable);
  CPE_REQUIRE_EQ(qualification_token(reconcilable_bytes), std::string("recovery.needs_reconciliation"));
  const detail::QualificationPayload decoded_reconcilable = detail::decode_qualification(reconcilable_bytes);
  CPE_REQUIRE(decoded_reconcilable.verdict == RecoveredStateVerdict::NeedsReconciliation);
  CPE_REQUIRE(decoded_reconcilable.code == ErrorCode::RecoveredNeedsReconciliation);
  CPE_REQUIRE_EQ(decoded_reconcilable.detail, reconcilable.detail);
  CPE_REQUIRE(decoded_reconcilable.matching_grant.has_value());
  CPE_REQUIRE_EQ(*decoded_reconcilable.matching_grant, 7u);
  CPE_REQUIRE(decoded_reconcilable.requires_revalidation);

  detail::QualificationPayload rejection;
  rejection.verdict = RecoveredStateVerdict::Rejected;
  rejection.code = ErrorCode::RecoveredRejectedFutureEpoch;
  rejection.detail = "the claim names an epoch this domain never committed";
  rejection.matching_grant = std::nullopt;
  rejection.requires_revalidation = false;
  const detail::QualificationPayload decoded_rejection_payload =
      detail::decode_qualification(detail::encode_qualification(rejection));
  CPE_REQUIRE(decoded_rejection_payload.verdict == RecoveredStateVerdict::Rejected);
  CPE_REQUIRE(decoded_rejection_payload.code == ErrorCode::RecoveredRejectedFutureEpoch);
  CPE_REQUIRE(!decoded_rejection_payload.matching_grant.has_value());
  CPE_REQUIRE(!decoded_rejection_payload.requires_revalidation);

  // A payload naming a token outside the catalogue is refused rather than
  // mapped onto an unrelated code.
  {
    detail::CanonicalWriter writer(4096);
    writer.u32(static_cast<std::uint32_t>(RecoveredStateVerdict::Current));
    writer.text("recovery.not_a_real_token");
    writer.text("");
    writer.boolean(false);
    writer.boolean(false);
    const Payload malformed = writer.take();
    CPE_REQUIRE_THROWS_CODE(detail::decode_qualification(malformed), ErrorCode::MalformedPayload);
    CPE_REQUIRE_EQ(qualification_token(malformed), std::string("recovery.not_a_real_token"));
  }
  // A verdict outside its domain is refused before the token is even read.
  {
    detail::CanonicalWriter writer(4096);
    writer.u32(0);
    writer.text("recovery.current");
    writer.text("");
    writer.boolean(false);
    writer.boolean(false);
    CPE_REQUIRE_THROWS_CODE(detail::decode_qualification(writer.take()), ErrorCode::MalformedPayload);
  }
}

CPE_TEST(protocol, request_and_response_payloads_round_trip) {
  TestAuthority fixture;
  const ControllerRegistration registered = fixture.register_controller("ctrl-a");
  const ControllerIncarnationId incarnation = registered.incarnation_id();
  const MutationAuthority root = fixture.root_authority();
  const AuthorityGrantView grant = fixture.acquire("ctrl-a", incarnation, {"facility.inventory"}, root);

  // Registration request.
  {
    RegisterControllerRequest request;
    request.controller = controller_id("ctrl-b");
    request.provenance = provenance_input("ctrl-b");
    request.idempotency = IdempotencyKey::create(controller_id("ctrl-b"),
                                                 ControllerIncarnationId::derive(domain_id(fixture.domain()),
                                                                                 controller_id("ctrl-b"),
                                                                                 IncarnationNumber::from_trusted(1)),
                                                 OperationSequence::from_trusted(3))
                              .value();
    const RegisterControllerRequest decoded = detail::decode_register_request(detail::encode_register_request(request));
    CPE_REQUIRE_EQ(decoded.controller, request.controller);
    CPE_REQUIRE(decoded.provenance == request.provenance);
    CPE_REQUIRE(decoded.idempotency.has_value());
    CPE_REQUIRE(*decoded.idempotency == *request.idempotency);
  }

  // Registration response, produced by the real authority.
  {
    const ControllerRegistration decoded =
        detail::decode_register_response(detail::encode_register_response(registered));
    CPE_REQUIRE(decoded == registered);
    CPE_REQUIRE_EQ(decoded.incarnation_id(), incarnation);
  }

  // Acquisition request and response.
  {
    AcquireAuthorityRequest request;
    request.authority_class = AuthorityClass::Mutation;
    request.controller = controller_id("ctrl-a");
    request.incarnation = incarnation;
    request.scopes = scope_set({"facility.inventory", "facility.topology"});
    request.sponsor = root;
    request.provenance = provenance_input("ctrl-a");
    const AcquireAuthorityRequest decoded =
        detail::decode_acquire_request(detail::encode_acquire_request(request));
    CPE_REQUIRE(decoded.authority_class == request.authority_class);
    CPE_REQUIRE_EQ(decoded.controller, request.controller);
    CPE_REQUIRE_EQ(decoded.incarnation, request.incarnation);
    CPE_REQUIRE(decoded.scopes == request.scopes);
    CPE_REQUIRE(decoded.sponsor.has_value());
    CPE_REQUIRE(*decoded.sponsor == *request.sponsor);
    CPE_REQUIRE(decoded.provenance == request.provenance);
    CPE_REQUIRE(!decoded.idempotency.has_value());

    const detail::GrantData grant_data = detail::to_data(grant.record());
    const detail::GrantData decoded_grant = detail::decode_acquire_response(detail::encode_acquire_response(grant_data));
    auto view = detail::to_grant_view(decoded_grant, domain_id(fixture.domain()));
    CPE_REQUIRE(view.has_value());
    CPE_REQUIRE(view.value().record() == grant.record());
    CPE_REQUIRE(view.value().mutation_authority() == grant.mutation_authority());
    CPE_REQUIRE_EQ(view.value().record().record_digest(), grant.record().record_digest());
  }

  // Revocation request and response, in both target shapes. The grant is
  // revoked before the epoch advances, because an advancement fences every
  // grant of the base epoch and the revocation would have no target left.
  RevokeAuthorityRequest request;
  request.target = RevocationTarget::grant(grant.record().id(), controller_id("ctrl-a"));
  request.reason = RevocationReason::OperatorRequest;
  request.authority = root;
  request.provenance = provenance_input("operator");
  auto revocation = fixture.authority().revoke_authority(request);
  CPE_REQUIRE(revocation.has_value());
  {
    const RevokeAuthorityRequest decoded = detail::decode_revoke_request(detail::encode_revoke_request(request));
    CPE_REQUIRE(decoded.target == request.target);
    CPE_REQUIRE(decoded.target.kind() == RevocationTargetKind::Grant);
    CPE_REQUIRE(decoded.reason == request.reason);
    CPE_REQUIRE(decoded.authority == request.authority);
    CPE_REQUIRE(decoded.provenance == request.provenance);

    RevokeAuthorityRequest controller_target = request;
    controller_target.target = RevocationTarget::controller_all(controller_id("ctrl-a"));
    const RevokeAuthorityRequest decoded_controller =
        detail::decode_revoke_request(detail::encode_revoke_request(controller_target));
    CPE_REQUIRE(decoded_controller.target == controller_target.target);
    CPE_REQUIRE(decoded_controller.target.kind() == RevocationTargetKind::ControllerIncarnations);
    CPE_REQUIRE(!decoded_controller.target.through_incarnation().has_value());

    const detail::RevocationData decoded_revocation = detail::decode_revocation_response(
        detail::encode_revocation_response(detail::to_data(revocation.value())));
    CPE_REQUIRE(detail::RecordFactory::make_revocation(decoded_revocation) == revocation.value());
  }

  // Advancement request and response.
  const EpochTransitionRecord transition = fixture.advance(Epoch::initial(), root);
  {
    AdvanceEpochRequest advance_request;
    advance_request.expected_current = Epoch::initial();
    advance_request.authority = root;
    advance_request.reason = EpochTransitionReason::OperatorRequest;
    advance_request.provenance = provenance_input("operator");
    const AdvanceEpochRequest decoded =
        detail::decode_advance_request(detail::encode_advance_request(advance_request));
    CPE_REQUIRE_EQ(decoded.expected_current.value(), advance_request.expected_current.value());
    CPE_REQUIRE(decoded.authority == advance_request.authority);
    CPE_REQUIRE(decoded.reason == advance_request.reason);
    CPE_REQUIRE(decoded.provenance == advance_request.provenance);

    const detail::TransitionData decoded_transition = detail::decode_transition_response(
        detail::encode_transition_response(detail::to_data(transition)));
    CPE_REQUIRE(detail::RecordFactory::make_transition(decoded_transition) == transition);
  }

  const MutationAuthority root_again = fixture.root_authority();

  // Recovered-state qualification request.
  {
    auto claim = RecoveredStateClaim::create(domain_id(fixture.domain()), Epoch::initial(), controller_id("ctrl-a"),
                                             incarnation, scope_name("facility.inventory"),
                                             digest_of("recovered-payload"));
    CPE_REQUIRE(claim.has_value());
    const RecoveredStateClaim decoded =
        detail::decode_qualify_request(detail::encode_qualify_request(claim.value()));
    CPE_REQUIRE(decoded == claim.value());
  }

  // Token validation request.
  {
    detail::ValidateRequestPayload payload;
    payload.token = root_again.to_string();
    payload.scope = "authority.revoke";
    const detail::ValidateRequestPayload decoded =
        detail::decode_validate_request(detail::encode_validate_request(payload));
    CPE_REQUIRE_EQ(decoded.token, payload.token);
    CPE_REQUIRE_EQ(decoded.scope, payload.scope);
    auto parsed = MutationAuthority::parse(decoded.token);
    CPE_REQUIRE(parsed.has_value());
    CPE_REQUIRE(parsed.value() == root_again);
  }

  // Handshake payloads.
  {
    detail::HelloPayload hello;
    hello.protocol_version = static_cast<std::uint16_t>(protocol_version);
    hello.max_frame_payload_bytes = static_cast<std::uint16_t>(max_frame_payload_bytes % 65536u);
    const detail::HelloPayload decoded_hello = detail::decode_hello_request(detail::encode_hello_request(hello));
    CPE_REQUIRE_EQ(decoded_hello.protocol_version, hello.protocol_version);
    CPE_REQUIRE_EQ(decoded_hello.max_frame_payload_bytes, hello.max_frame_payload_bytes);

    detail::HelloResponsePayload response;
    response.protocol_version = static_cast<std::uint16_t>(protocol_version);
    response.max_frame_payload_bytes = hello.max_frame_payload_bytes;
    response.domain = fixture.domain();
    response.domain_instance = fixture.authority().status().domain_instance().value();
    response.epoch = fixture.authority().status().epoch().value();
    response.generation = fixture.authority().status().durable_generation().value();
    response.initialized = true;
    const detail::HelloResponsePayload decoded_response =
        detail::decode_hello_response(detail::encode_hello_response(response));
    CPE_REQUIRE_EQ(decoded_response.protocol_version, response.protocol_version);
    CPE_REQUIRE_EQ(decoded_response.domain, response.domain);
    CPE_REQUIRE_EQ(decoded_response.domain_instance, response.domain_instance);
    CPE_REQUIRE_EQ(decoded_response.epoch, response.epoch);
    CPE_REQUIRE_EQ(decoded_response.generation, response.generation);
    CPE_REQUIRE(decoded_response.initialized);
  }

  // Status payload, taken from the live authority.
  {
    const AuthorityStatus status = fixture.authority().status();
    detail::StatusPayload payload;
    payload.domain = status.domain().str();
    payload.domain_instance = status.domain_instance().value();
    payload.epoch = status.epoch().value();
    payload.generation = status.durable_generation().value();
    payload.authority_root = status.authority_root().str();
    payload.controller_count = status.controller_count();
    payload.live_grant_count = status.live_grant_count();
    payload.mutation_grant_count = status.mutation_grant_count();
    payload.observation_grant_count = status.observation_grant_count();
    for (const ScopeName& scope : status.declared_scopes()) {
      payload.declared_scopes.push_back(scope.str());
    }
    payload.transition_count = status.transition_count();
    payload.revocation_count = status.revocation_count();
    payload.idempotency_record_count = status.idempotency_record_count();
    payload.snapshot_digest = status.snapshot_digest();
    payload.transition_chain_head = status.transition_chain_head();
    payload.recovery_outcome = status.recovery_outcome();

    const detail::StatusPayload decoded = detail::decode_status(detail::encode_status(payload));
    CPE_REQUIRE_EQ(decoded.domain, payload.domain);
    CPE_REQUIRE_EQ(decoded.domain_instance, payload.domain_instance);
    CPE_REQUIRE_EQ(decoded.epoch, payload.epoch);
    CPE_REQUIRE_EQ(decoded.generation, payload.generation);
    CPE_REQUIRE_EQ(decoded.authority_root, payload.authority_root);
    CPE_REQUIRE_EQ(decoded.controller_count, payload.controller_count);
    CPE_REQUIRE_EQ(decoded.live_grant_count, payload.live_grant_count);
    CPE_REQUIRE_EQ(decoded.mutation_grant_count, payload.mutation_grant_count);
    CPE_REQUIRE_EQ(decoded.observation_grant_count, payload.observation_grant_count);
    CPE_REQUIRE(decoded.declared_scopes == payload.declared_scopes);
    CPE_REQUIRE_EQ(decoded.transition_count, payload.transition_count);
    CPE_REQUIRE_EQ(decoded.revocation_count, payload.revocation_count);
    CPE_REQUIRE_EQ(decoded.idempotency_record_count, payload.idempotency_record_count);
    CPE_REQUIRE_EQ(decoded.snapshot_digest, payload.snapshot_digest);
    CPE_REQUIRE_EQ(decoded.transition_chain_head, payload.transition_chain_head);
    CPE_REQUIRE(decoded.recovery_outcome == payload.recovery_outcome);
  }

  // Ledger requests and responses.
  {
    detail::HistoryRequestPayload history_request;
    history_request.from_sequence = 1;
    history_request.limit = max_page_size;
    const detail::HistoryRequestPayload decoded =
        detail::decode_history_request(detail::encode_history_request(history_request));
    CPE_REQUIRE(decoded.from_sequence.has_value());
    CPE_REQUIRE_EQ(*decoded.from_sequence, 1u);
    CPE_REQUIRE_EQ(decoded.limit, static_cast<std::uint64_t>(max_page_size));

    detail::HistoryResponsePayload history_response;
    history_response.page.total_count = 2;
    history_response.page.first_retained = 1;
    history_response.page.trimmed_count = 0;
    history_response.page.chain_head = transition.record_digest();
    history_response.records.push_back(detail::to_data(transition));
    const detail::HistoryResponsePayload decoded_history =
        detail::decode_history_response(detail::encode_history_response(history_response));
    CPE_REQUIRE_EQ(decoded_history.page.total_count, 2u);
    CPE_REQUIRE_EQ(decoded_history.page.chain_head, transition.record_digest());
    CPE_REQUIRE_EQ(decoded_history.records.size(), 1u);
    CPE_REQUIRE(detail::RecordFactory::make_transition(decoded_history.records.front()) == transition);

    detail::RevocationsRequestPayload revocations_request;
    revocations_request.limit = 1;
    const detail::RevocationsRequestPayload decoded_revocations_request =
        detail::decode_revocations_request(detail::encode_revocations_request(revocations_request));
    CPE_REQUIRE(!decoded_revocations_request.from_sequence.has_value());
    CPE_REQUIRE_EQ(decoded_revocations_request.limit, 1u);

    detail::RevocationsResponsePayload revocations_response;
    revocations_response.page.total_count = 1;
    revocations_response.page.first_retained = 1;
    revocations_response.page.chain_head = revocation.value().record_digest();
    revocations_response.records.push_back(detail::to_data(revocation.value()));
    const detail::RevocationsResponsePayload decoded_revocations =
        detail::decode_revocations_response(detail::encode_revocations_response(revocations_response));
    CPE_REQUIRE_EQ(decoded_revocations.records.size(), 1u);
    CPE_REQUIRE(detail::RecordFactory::make_revocation(decoded_revocations.records.front()) == revocation.value());

    detail::ControllersRequestPayload controllers_request;
    controllers_request.from_controller = "authority-root";
    controllers_request.limit = max_page_size;
    const detail::ControllersRequestPayload decoded_controllers_request =
        detail::decode_controllers_request(detail::encode_controllers_request(controllers_request));
    CPE_REQUIRE(decoded_controllers_request.from_controller.has_value());
    CPE_REQUIRE_EQ(*decoded_controllers_request.from_controller, std::string("authority-root"));

    const ControllerRecord controller_record = fixture.authority().controller_record(controller_id("ctrl-a")).value();
    detail::ControllersResponsePayload controllers_response;
    controllers_response.total_count = 2;
    controllers_response.records.push_back(detail::to_data(controller_record));
    const detail::ControllersResponsePayload decoded_controllers =
        detail::decode_controllers_response(detail::encode_controllers_response(controllers_response));
    CPE_REQUIRE_EQ(decoded_controllers.total_count, 2u);
    CPE_REQUIRE_EQ(decoded_controllers.records.size(), 1u);
    CPE_REQUIRE(detail::RecordFactory::make_controller(decoded_controllers.records.front()) == controller_record);

    detail::GrantsRequestPayload grants_request;
    grants_request.from_grant = 1;
    grants_request.limit = 1;
    const detail::GrantsRequestPayload decoded_grants_request =
        detail::decode_grants_request(detail::encode_grants_request(grants_request));
    CPE_REQUIRE(decoded_grants_request.from_grant.has_value());
    CPE_REQUIRE_EQ(*decoded_grants_request.from_grant, 1u);
    CPE_REQUIRE_EQ(decoded_grants_request.limit, 1u);

    detail::GrantsResponsePayload grants_response;
    grants_response.total_count = 1;
    grants_response.epoch = fixture.authority().current_epoch().value();
    grants_response.records.push_back(detail::to_data(grant.record()));
    const detail::GrantsResponsePayload decoded_grants =
        detail::decode_grants_response(detail::encode_grants_response(grants_response));
    CPE_REQUIRE_EQ(decoded_grants.total_count, 1u);
    CPE_REQUIRE_EQ(decoded_grants.epoch, grants_response.epoch);
    CPE_REQUIRE_EQ(decoded_grants.records.size(), 1u);
    auto decoded_view = detail::to_grant_view(decoded_grants.records.front(), domain_id(fixture.domain()));
    CPE_REQUIRE(decoded_view.has_value());
    CPE_REQUIRE(decoded_view.value().record() == grant.record());
  }

  // The full stack end to end: a request payload inside a frame.
  {
    const Payload payload = detail::encode_validate_request(detail::ValidateRequestPayload{
        root_again.to_string(), "authority.revoke"});
    const std::vector<std::byte> bytes = encode_or_fail(make_frame(MessageType::ValidateMutationRequest, 9, payload));
    const Frame decoded = decode_or_fail(bytes);
    CPE_REQUIRE(decoded.header().type == MessageType::ValidateMutationRequest);
    const detail::ValidateRequestPayload decoded_request = detail::decode_validate_request(decoded.payload());
    auto parsed = MutationAuthority::parse(decoded_request.token);
    CPE_REQUIRE(parsed.has_value());
    CPE_REQUIRE(parsed.value() == root_again);
    CPE_REQUIRE_EQ(decoded_request.scope, std::string("authority.revoke"));
  }
}
