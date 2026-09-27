// Control Plane Epoch 1.0.0 - Summon Software Labs
// Framed transport: message vocabulary and frame codec.
#include "control_plane_epoch/protocol.hpp"

#include <array>
#include <cstring>

#include "image.hpp"

namespace dccp::epoch {
namespace {

constexpr std::array<std::byte, 4> kFrameMagic{std::byte{'C'}, std::byte{'P'}, std::byte{'E'}, std::byte{'1'}};
constexpr std::uint32_t kAllowedFlags = 0;

struct TypeToken {
  MessageType type;
  std::string_view token;
};

constexpr std::array<TypeToken, 27> kTypeTokens{{
    {MessageType::HelloRequest, "hello_request"},
    {MessageType::HelloResponse, "hello_response"},
    {MessageType::RegisterControllerRequest, "register_controller_request"},
    {MessageType::RegisterControllerResponse, "register_controller_response"},
    {MessageType::AcquireAuthorityRequest, "acquire_authority_request"},
    {MessageType::AcquireAuthorityResponse, "acquire_authority_response"},
    {MessageType::ValidateMutationRequest, "validate_mutation_request"},
    {MessageType::ValidateMutationResponse, "validate_mutation_response"},
    {MessageType::ValidateObservationRequest, "validate_observation_request"},
    {MessageType::ValidateObservationResponse, "validate_observation_response"},
    {MessageType::AdvanceEpochRequest, "advance_epoch_request"},
    {MessageType::AdvanceEpochResponse, "advance_epoch_response"},
    {MessageType::RevokeRequest, "revoke_request"},
    {MessageType::RevokeResponse, "revoke_response"},
    {MessageType::QualifyRecoveredStateRequest, "qualify_recovered_state_request"},
    {MessageType::QualifyRecoveredStateResponse, "qualify_recovered_state_response"},
    {MessageType::StatusRequest, "status_request"},
    {MessageType::StatusResponse, "status_response"},
    {MessageType::HistoryRequest, "history_request"},
    {MessageType::HistoryResponse, "history_response"},
    {MessageType::RevocationsRequest, "revocations_request"},
    {MessageType::RevocationsResponse, "revocations_response"},
    {MessageType::ControllersRequest, "controllers_request"},
    {MessageType::ControllersResponse, "controllers_response"},
    {MessageType::GrantsRequest, "grants_request"},
    {MessageType::GrantsResponse, "grants_response"},
    {MessageType::ErrorResponse, "error_response"},
}};

}  // namespace

std::string_view message_type_token(MessageType type) noexcept {
  for (const TypeToken& entry : kTypeTokens) {
    if (entry.type == type) {
      return entry.token;
    }
  }
  return "unknown";
}

Result<MessageType> parse_message_type(std::uint16_t value) {
  for (const TypeToken& entry : kTypeTokens) {
    if (static_cast<std::uint16_t>(entry.type) == value) {
      return entry.type;
    }
  }
  return Explanation(ErrorCode::MessageTypeUnknown, "message type " + std::to_string(value) + " is not known");
}

Status encode_frame(const Frame& frame, std::vector<std::byte>& out, std::size_t max_payload_bytes) {
  if (frame.payload().size() > max_payload_bytes) {
    return Explanation(ErrorCode::FrameTooLarge, "payload of " + std::to_string(frame.payload().size()) +
                                                     " bytes exceeds the bound of " +
                                                     std::to_string(max_payload_bytes));
  }
  if (frame.payload().size() > UINT32_MAX) {
    return Explanation(ErrorCode::FrameTooLarge, "payload exceeds the encodable length");
  }

  detail::FileEnvelope unused_envelope;  // keeps the header layout in one place
  (void)unused_envelope;

  const std::size_t total = frame_header_bytes + frame.payload().size();
  out.clear();
  out.reserve(total);
  out.insert(out.end(), kFrameMagic.begin(), kFrameMagic.end());

  detail::CanonicalWriter writer(frame_header_bytes);
  writer.u16(frame.header().version);
  writer.u16(static_cast<std::uint16_t>(frame.header().type));
  writer.u32(frame.header().flags);
  writer.u64(frame.header().request_id);
  writer.u32(static_cast<std::uint32_t>(frame.payload().size()));
  writer.digest(sha256(std::span<const std::byte>(frame.payload())));
  const std::vector<std::byte>& header_tail = writer.data();
  out.insert(out.end(), header_tail.begin(), header_tail.end());
  out.insert(out.end(), frame.payload().begin(), frame.payload().end());
  return Unit{};
}

Result<Frame> decode_frame(std::span<const std::byte> bytes, std::size_t max_payload_bytes) {
  if (bytes.size() < frame_header_bytes) {
    return Explanation(ErrorCode::FrameTruncated, "frame is shorter than its header");
  }
  if (!std::equal(kFrameMagic.begin(), kFrameMagic.end(), bytes.begin())) {
    return Explanation(ErrorCode::FrameMagic, "frame magic is not CPE1");
  }

  detail::CanonicalReader reader(bytes.subspan(kFrameMagic.size(), frame_header_bytes - kFrameMagic.size()), 64);
  FrameHeader header;
  try {
    header.version = reader.u16();
    header.type = static_cast<MessageType>(reader.u16());
    header.flags = reader.u32();
    header.request_id = reader.u64();
    header.payload_length = reader.u32();
    header.payload_digest = reader.digest();
    reader.expect_end();
  } catch (const EpochError& error) {
    return Explanation(ErrorCode::FrameTruncated, error.explanation().detail());
  }

  if (header.version != static_cast<std::uint16_t>(protocol_version)) {
    return Explanation(ErrorCode::ProtocolVersionUnsupported,
                       "frame protocol version " + std::to_string(header.version) + " is not supported");
  }
  if ((header.flags & ~kAllowedFlags) != 0) {
    return Explanation(ErrorCode::MalformedPayload, "frame declares unsupported flags");
  }
  Result<MessageType> type = parse_message_type(static_cast<std::uint16_t>(header.type));
  if (!type.has_value()) {
    return type.rejection();
  }
  header.type = type.value();

  if (header.payload_length > max_payload_bytes || header.payload_length > max_frame_payload_bytes) {
    return Explanation(ErrorCode::FrameTooLarge, "frame payload length " + std::to_string(header.payload_length) +
                                                     " exceeds the bound of " + std::to_string(max_payload_bytes));
  }
  const std::size_t expected = frame_header_bytes + header.payload_length;
  if (bytes.size() != expected) {
    return Explanation(ErrorCode::FrameTruncated, "frame is " + std::to_string(bytes.size()) +
                                                      " bytes but declares " + std::to_string(expected));
  }

  std::vector<std::byte> payload(bytes.begin() + static_cast<std::ptrdiff_t>(frame_header_bytes), bytes.end());
  if (sha256(std::span<const std::byte>(payload)) != header.payload_digest) {
    return Explanation(ErrorCode::FrameDigestMismatch, "frame payload digest does not match its content");
  }
  return Frame(header, std::move(payload));
}

}  // namespace dccp::epoch
