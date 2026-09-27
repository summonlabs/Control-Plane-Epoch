// Control Plane Epoch 1.0.0 - Summon Software Labs
// Minimal framed transport for remote controllers.
//
// This repository implements one authoritative epoch service with multiple
// cooperating client processes. It is deliberately NOT a distributed consensus
// protocol, and nothing in this repository claims consensus, quorum, or
// leader election. There is exactly one writer of one durable store, enforced
// by an exclusive operating-system lock; remote clients are request/response
// consumers of that single authority.
//
// Frame layout (all integers little-endian):
//
//   offset  size  field
//   0       4     magic 'C','P','E','1'
//   4       2     protocol version
//   6       2     message type
//   8       4     flags (reserved, must be zero)
//   12      8     request identifier (echoed by the response)
//   20      4     payload length
//   24      32    SHA-256 of the payload
//   56      N     payload
//
// A frame is rejected before allocation when the declared payload length
// exceeds the negotiated bound, when the magic or version is wrong, or when the
// payload digest does not match the bytes that arrived.
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "control_plane_epoch/digest.hpp"
#include "control_plane_epoch/error.hpp"
#include "control_plane_epoch/limits.hpp"
#include "control_plane_epoch/version.hpp"

namespace dccp::epoch {

/// Message types. Numeric values are part of the wire protocol and never change.
enum class MessageType : std::uint16_t {
  HelloRequest = 1,
  HelloResponse = 2,
  RegisterControllerRequest = 10,
  RegisterControllerResponse = 11,
  AcquireAuthorityRequest = 12,
  AcquireAuthorityResponse = 13,
  ValidateMutationRequest = 14,
  ValidateMutationResponse = 15,
  ValidateObservationRequest = 16,
  ValidateObservationResponse = 17,
  AdvanceEpochRequest = 18,
  AdvanceEpochResponse = 19,
  RevokeRequest = 20,
  RevokeResponse = 21,
  QualifyRecoveredStateRequest = 22,
  QualifyRecoveredStateResponse = 23,
  StatusRequest = 24,
  StatusResponse = 25,
  HistoryRequest = 26,
  HistoryResponse = 27,
  RevocationsRequest = 28,
  RevocationsResponse = 29,
  ControllersRequest = 30,
  ControllersResponse = 31,
  GrantsRequest = 32,
  GrantsResponse = 33,
  ErrorResponse = 90,
};

inline constexpr std::uint16_t max_message_type = 90;

[[nodiscard]] std::string_view message_type_token(MessageType type) noexcept;
[[nodiscard]] Result<MessageType> parse_message_type(std::uint16_t value);

/// Header of one frame.
struct FrameHeader {
  std::uint16_t version = static_cast<std::uint16_t>(protocol_version);
  MessageType type = MessageType::ErrorResponse;
  std::uint32_t flags = 0;
  std::uint64_t request_id = 0;
  std::uint32_t payload_length = 0;
  Sha256Digest payload_digest;
};

/// Encoded frame: header plus payload bytes.
class Frame {
 public:
  Frame() = default;
  Frame(FrameHeader header, std::vector<std::byte> payload)
      : header_(header), payload_(std::move(payload)) {}

  [[nodiscard]] const FrameHeader& header() const noexcept { return header_; }
  [[nodiscard]] const std::vector<std::byte>& payload() const noexcept { return payload_; }

 private:
  FrameHeader header_;
  std::vector<std::byte> payload_;
};

/// Encodes one frame, verifying magic-independent invariants (payload length
/// bound, header/payload agreement) before allocating.
[[nodiscard]] Status encode_frame(const Frame& frame, std::vector<std::byte>& out,
                                 std::size_t max_payload_bytes = max_frame_payload_bytes);

/// Decodes one complete frame from an exact-size buffer. Rejects a wrong magic,
/// an unsupported protocol version, non-zero reserved flags, an oversized
/// declared length, a length that does not match the buffer, and a payload
/// digest mismatch. Every rejection is an EpochError with a stable code.
[[nodiscard]] Result<Frame> decode_frame(std::span<const std::byte> bytes,
                                        std::size_t max_payload_bytes = max_frame_payload_bytes);

/// Bytes in an encoded frame header.
inline constexpr std::size_t frame_header_bytes = 56;

}  // namespace dccp::epoch
