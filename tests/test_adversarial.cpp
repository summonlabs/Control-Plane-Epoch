// Control Plane Epoch 1.0.0 - Summon Software Labs
// Adversarial suite: hostile and malformed input must be rejected safely and
// deterministically, with no crash, no partial state change, and no unbounded
// allocation.
//
// Every rejection is asserted by exact ErrorCode, and every deterministic
// rejection is asserted twice: the same hostile input must produce the same
// code and the same explanation on every attempt. Domain commands are checked
// against the full rendered status before and after, so a refused command that
// leaves any trace is caught immediately.
//
// White-box access to the canonical codec, the durable image format, and the
// durability fault seam is deliberate: those are exactly the layers a hostile
// peer or a damaged disk reaches, and they are not reachable through the public
// API by construction.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "test_support.hpp"

#include "encoding.hpp"
#include "fault.hpp"
#include "image.hpp"
#include "wire.hpp"

namespace {

using cpe_test::controller_id;
using cpe_test::default_scopes;
using cpe_test::domain_id;
using cpe_test::provenance_input;
using cpe_test::scope_name;
using cpe_test::scope_set;

using dccp::epoch::AuthorityClaims;
using dccp::epoch::AuthorityGrantView;
using dccp::epoch::AuthorityStatus;
using dccp::epoch::ControllerIncarnationId;
using dccp::epoch::ControlPlaneEpochAuthority;
using dccp::epoch::Epoch;
using dccp::epoch::EpochError;
using dccp::epoch::ErrorCode;
using dccp::epoch::FacilityAuthorityDomainId;
using dccp::epoch::Frame;
using dccp::epoch::FrameHeader;
using dccp::epoch::GrantId;
using dccp::epoch::HistoryQuery;
using dccp::epoch::IncarnationNumber;
using dccp::epoch::MessageType;
using dccp::epoch::MutationAuthority;
using dccp::epoch::ObservationAuthority;
using dccp::epoch::Result;
using dccp::epoch::RevocationTarget;
using dccp::epoch::RevokeAuthorityRequest;
using dccp::epoch::ScopeName;
using dccp::epoch::StoreInspection;
using dccp::epoch::StoreOpenMode;
using dccp::epoch::StoreOpenOptions;
using dccp::epoch::ValidationOutcome;

using dccp::epoch::detail::CanonicalWriter;
using dccp::epoch::detail::DurableFaultPoint;

/// Rejects a hostile payload twice and asserts the exact code both times.
template <class Decode>
void require_payload_rejected(Decode decode, std::span<const std::byte> payload, ErrorCode expected,
                              const std::string& what) {
  ErrorCode first_code = ErrorCode::Ok;
  std::string first_detail;
  bool first_threw = false;
  try {
    (void)decode(payload);
  } catch (const EpochError& error) {
    first_threw = true;
    first_code = error.code();
    first_detail = error.explanation().to_string();
  }
  CPE_REQUIRE_MSG(first_threw, what + ": a hostile payload must be rejected");
  CPE_REQUIRE_MSG(first_code == expected,
                  what + ": rejected with " + std::string(error_token(first_code)) + " instead of " +
                      std::string(error_token(expected)) + " [" + first_detail + "]");

  ErrorCode second_code = ErrorCode::Ok;
  std::string second_detail;
  bool second_threw = false;
  try {
    (void)decode(payload);
  } catch (const EpochError& error) {
    second_threw = true;
    second_code = error.code();
    second_detail = error.explanation().to_string();
  }
  CPE_REQUIRE_MSG(second_threw && second_code == first_code && second_detail == first_detail,
                  what + ": a repeated hostile payload must be rejected identically");
}

/// Rejects a hostile frame twice and asserts the exact code both times. Frames
/// are rejected through Result, never through an exception.
void require_frame_rejected(const std::vector<std::byte>& bytes, ErrorCode expected, const std::string& what) {
  const Result<Frame> first = dccp::epoch::decode_frame(bytes);
  CPE_REQUIRE_MSG(!first.has_value(), what + ": a hostile frame must be rejected");
  CPE_REQUIRE_MSG(first.code() == expected, what + ": rejected with " + std::string(error_token(first.code())) +
                                                 " instead of " + std::string(error_token(expected)));
  const Result<Frame> second = dccp::epoch::decode_frame(bytes);
  CPE_REQUIRE_MSG(!second.has_value() && second.code() == first.code() &&
                      second.rejection().to_string() == first.rejection().to_string(),
                  what + ": a repeated hostile frame must be rejected identically");
}

/// Rejects a hostile token text twice and asserts the exact code both times.
void require_token_rejected(const std::string& text, ErrorCode expected, const std::string& what) {
  const Result<MutationAuthority> first = MutationAuthority::parse(text);
  CPE_REQUIRE_MSG(!first.has_value(), what + ": a hostile token text must be rejected");
  CPE_REQUIRE_MSG(first.code() == expected, what + ": rejected with " + std::string(error_token(first.code())) +
                                                 " instead of " + std::string(error_token(expected)));
  const Result<MutationAuthority> second = MutationAuthority::parse(text);
  CPE_REQUIRE_MSG(!second.has_value() && second.code() == first.code() &&
                      second.rejection().to_string() == first.rejection().to_string(),
                  what + ": a repeated hostile token text must be rejected identically");
}

void store_u32(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value) {
  for (std::size_t index = 0; index < 4; ++index) {
    bytes[offset + index] = static_cast<std::byte>((value >> (8u * index)) & 0xFFu);
  }
}

[[nodiscard]] std::vector<std::string> split_fields(const std::string& text) {
  std::vector<std::string> fields;
  std::size_t start = 0;
  while (true) {
    const std::size_t position = text.find(':', start);
    if (position == std::string::npos) {
      fields.push_back(text.substr(start));
      return fields;
    }
    fields.push_back(text.substr(start, position - start));
    start = position + 1;
  }
}

[[nodiscard]] std::string join_fields(const std::vector<std::string>& fields) {
  std::string text;
  for (const std::string& field : fields) {
    if (!text.empty()) {
      text.push_back(':');
    }
    text.append(field);
  }
  return text;
}

/// Replaces one canonical token field, so every hostile variant below is a
/// single-field mutation of a token that the library itself produced.
[[nodiscard]] std::string with_field(const std::string& text, std::size_t index, const std::string& value) {
  std::vector<std::string> fields = split_fields(text);
  if (index >= fields.size()) {
    throw cpe_test::Failure("token text has fewer fields than the mutation expects");
  }
  fields[index] = value;
  return join_fields(fields);
}

[[nodiscard]] MutationAuthority craft_mutation_token(const FacilityAuthorityDomainId& domain, std::uint64_t epoch,
                                                     const std::string& controller,
                                                     const ControllerIncarnationId& incarnation, std::uint64_t grant,
                                                     const std::vector<std::string>& scopes) {
  Result<AuthorityClaims> claims =
      AuthorityClaims::create(domain, Epoch::from_trusted(epoch), controller_id(controller), incarnation,
                              GrantId::from_trusted(grant), scope_set(scopes));
  if (!claims.has_value()) {
    throw cpe_test::Failure("could not craft claims: " + claims.rejection().to_string());
  }
  return MutationAuthority::from_claims(claims.move_value());
}

[[nodiscard]] ObservationAuthority craft_observation_token(const FacilityAuthorityDomainId& domain,
                                                           std::uint64_t epoch, const std::string& controller,
                                                           const ControllerIncarnationId& incarnation,
                                                           std::uint64_t grant,
                                                           const std::vector<std::string>& scopes) {
  Result<AuthorityClaims> claims =
      AuthorityClaims::create(domain, Epoch::from_trusted(epoch), controller_id(controller), incarnation,
                              GrantId::from_trusted(grant), scope_set(scopes));
  if (!claims.has_value()) {
    throw cpe_test::Failure("could not craft claims: " + claims.rejection().to_string());
  }
  return ObservationAuthority::from_claims(claims.move_value());
}

[[nodiscard]] dccp::epoch::RegisterControllerRequest registration_request(const std::string& controller) {
  dccp::epoch::RegisterControllerRequest request;
  request.controller = controller_id(controller);
  request.provenance = provenance_input(controller, dccp::epoch::ProvenanceSourceKind::Controller);
  return request;
}

[[nodiscard]] dccp::epoch::InitializeDomainRequest initialization_request(const std::string& domain,
                                                                         const std::string& root) {
  dccp::epoch::InitializeDomainRequest request;
  request.domain = domain_id(domain);
  request.authority_root = controller_id(root);
  request.provenance = provenance_input("test-initialization", dccp::epoch::ProvenanceSourceKind::Initialization);
  for (const std::string& scope : default_scopes()) {
    request.scopes.push_back(scope_name(scope));
  }
  return request;
}

/// Names present in a directory, sorted, so a rejection can be shown to have
/// left the store exactly as it was.
[[nodiscard]] std::vector<std::string> directory_entries(const std::filesystem::path& directory) {
  std::vector<std::string> names;
  std::error_code error;
  std::filesystem::directory_iterator iterator(directory, error);
  if (error) {
    return names;
  }
  for (const std::filesystem::directory_entry& entry : iterator) {
    names.push_back(entry.path().filename().string());
  }
  std::sort(names.begin(), names.end());
  return names;
}

/// Repository-owned temporary names: "<base>.tmp.<pid>.<counter>".
[[nodiscard]] std::vector<std::string> temporary_names(const std::filesystem::path& directory) {
  std::vector<std::string> names;
  for (const std::string& name : directory_entries(directory)) {
    if (name.find(".tmp.") != std::string::npos) {
      names.push_back(name);
    }
  }
  return names;
}

void write_bytes(const std::filesystem::path& path, const std::vector<std::byte>& bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!stream) {
    throw cpe_test::Failure("could not write " + path.string());
  }
  stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  stream.close();
  if (!stream) {
    throw cpe_test::Failure("could not finish writing " + path.string());
  }
}

[[nodiscard]] std::vector<std::byte> read_bytes(const std::filesystem::path& path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    throw cpe_test::Failure("could not read " + path.string());
  }
  std::vector<std::byte> bytes;
  char buffer[4096];
  while (stream) {
    stream.read(buffer, static_cast<std::streamsize>(sizeof(buffer)));
    const std::streamsize count = stream.gcount();
    for (std::streamsize index = 0; index < count; ++index) {
      bytes.push_back(static_cast<std::byte>(buffer[index]));
    }
  }
  return bytes;
}

/// The exact 64-byte durable envelope header, so a hostile length field can be
/// placed where the reader will find it.
[[nodiscard]] std::vector<std::byte> envelope_header(std::uint32_t declared_payload_length, std::uint64_t generation,
                                                     std::uint64_t epoch) {
  std::vector<std::byte> bytes;
  const std::array<std::byte, 4> magic{std::byte{'C'}, std::byte{'P'}, std::byte{'E'}, std::byte{'1'}};
  bytes.insert(bytes.end(), magic.begin(), magic.end());
  CanonicalWriter writer(dccp::epoch::detail::envelope_header_bytes);
  writer.u16(static_cast<std::uint16_t>(dccp::epoch::durable_format_version));
  writer.u16(static_cast<std::uint16_t>(dccp::epoch::durable_schema_version));
  writer.u32(0);
  writer.u64(generation);
  writer.u64(epoch);
  writer.u32(declared_payload_length);
  writer.digest(dccp::epoch::Sha256Digest::zero());
  const std::vector<std::byte>& tail = writer.data();
  bytes.insert(bytes.end(), tail.begin(), tail.end());
  return bytes;
}

}  // namespace

// ---------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------

CPE_TEST(adversarial, hostile_frames_are_rejected_with_stable_codes) {
  const std::vector<std::byte> payload{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
  FrameHeader header;
  header.type = MessageType::StatusRequest;
  header.request_id = 7;
  const Frame valid(header, payload);
  std::vector<std::byte> bytes;
  CPE_REQUIRE(dccp::epoch::encode_frame(valid, bytes).has_value());
  CPE_REQUIRE_EQ(bytes.size(), dccp::epoch::frame_header_bytes + payload.size());

  // Baseline: the same bytes decode to exactly what was encoded.
  const Result<Frame> decoded = dccp::epoch::decode_frame(bytes);
  CPE_REQUIRE_MSG(decoded.has_value(), "a well-formed frame must decode");
  CPE_REQUIRE_EQ(decoded.value().header().request_id, std::uint64_t{7});
  CPE_REQUIRE_EQ(decoded.value().payload().size(), payload.size());

  // Shorter than its own header.
  require_frame_rejected(std::vector<std::byte>(bytes.begin(), bytes.begin() + 55), ErrorCode::FrameTruncated,
                         "a frame shorter than its header");
  require_frame_rejected(std::vector<std::byte>{}, ErrorCode::FrameTruncated, "an empty frame");

  // Wrong magic: never confused with a readable frame.
  std::vector<std::byte> magic = bytes;
  magic[0] = std::byte{'X'};
  require_frame_rejected(magic, ErrorCode::FrameMagic, "a frame with foreign magic");

  // Unsupported protocol version, including the largest possible one.
  FrameHeader versioned = header;
  versioned.version = 0xFFFF;
  std::vector<std::byte> version_bytes;
  CPE_REQUIRE(dccp::epoch::encode_frame(Frame(versioned, payload), version_bytes).has_value());
  require_frame_rejected(version_bytes, ErrorCode::ProtocolVersionUnsupported, "an unsupported protocol version");

  // Reserved flags must be zero.
  FrameHeader flagged = header;
  flagged.flags = 1;
  std::vector<std::byte> flag_bytes;
  CPE_REQUIRE(dccp::epoch::encode_frame(Frame(flagged, payload), flag_bytes).has_value());
  require_frame_rejected(flag_bytes, ErrorCode::MalformedPayload, "a frame with reserved flags set");

  // Message type outside the catalogue, including the largest possible value.
  FrameHeader typed = header;
  typed.type = static_cast<MessageType>(999);
  std::vector<std::byte> typed_bytes;
  CPE_REQUIRE(dccp::epoch::encode_frame(Frame(typed, payload), typed_bytes).has_value());
  require_frame_rejected(typed_bytes, ErrorCode::MessageTypeUnknown, "a message type out of domain");
  FrameHeader zero_typed = header;
  zero_typed.type = static_cast<MessageType>(0);
  std::vector<std::byte> zero_typed_bytes;
  CPE_REQUIRE(dccp::epoch::encode_frame(Frame(zero_typed, payload), zero_typed_bytes).has_value());
  require_frame_rejected(zero_typed_bytes, ErrorCode::MessageTypeUnknown, "message type zero");

  // A declared payload length near UINT32_MAX is refused before allocation: the
  // bound is checked against the length field, never against a buffer.
  constexpr std::size_t kLengthOffset = 20;  // magic 4 + version 2 + type 2 + flags 4 + request id 8
  std::vector<std::byte> huge = bytes;
  store_u32(huge, kLengthOffset, 0xFFFFFFFFu);
  require_frame_rejected(huge, ErrorCode::FrameTooLarge, "a declared payload length of 0xFFFFFFFF");
  std::vector<std::byte> near_huge = bytes;
  store_u32(near_huge, kLengthOffset, static_cast<std::uint32_t>(dccp::epoch::max_frame_payload_bytes + 1));
  require_frame_rejected(near_huge, ErrorCode::FrameTooLarge, "a declared payload length just above the bound");

  // A declared length that disagrees with the bytes that arrived, in both
  // directions: truncated body and appended junk.
  std::vector<std::byte> short_body = bytes;
  store_u32(short_body, kLengthOffset, static_cast<std::uint32_t>(payload.size() + 1));
  require_frame_rejected(short_body, ErrorCode::FrameTruncated, "a frame whose body is one byte short");
  std::vector<std::byte> trailing = bytes;
  trailing.push_back(std::byte{0x00});
  require_frame_rejected(trailing, ErrorCode::FrameTruncated, "a frame with a byte appended after its payload");

  // Payload digest mismatch: a single flipped payload bit must be caught.
  std::vector<std::byte> flipped = bytes;
  flipped[dccp::epoch::frame_header_bytes] = std::byte{0x7F};
  require_frame_rejected(flipped, ErrorCode::FrameDigestMismatch, "a frame with a corrupted payload");

  // The encoder refuses to produce an over-bound frame at all, and leaves the
  // caller's buffer untouched.
  std::vector<std::byte> bound_probe;
  const std::vector<std::byte> oversized(dccp::epoch::max_frame_payload_bytes + 1, std::byte{0});
  const Result<dccp::epoch::Unit> encoded =
      dccp::epoch::encode_frame(Frame(header, oversized), bound_probe, dccp::epoch::max_frame_payload_bytes);
  CPE_REQUIRE_MSG(!encoded.has_value() && encoded.code() == ErrorCode::FrameTooLarge,
                  "encoding an over-bound frame must be refused");
  CPE_REQUIRE_MSG(bound_probe.empty(), "a refused frame encoding must not write into the output buffer");

  // Enumeration parsers reject everything outside their domain.
  CPE_REQUIRE(dccp::epoch::parse_message_type(999).code() == ErrorCode::MessageTypeUnknown);
  CPE_REQUIRE(dccp::epoch::parse_message_type(0).code() == ErrorCode::MessageTypeUnknown);
  CPE_REQUIRE(dccp::epoch::parse_authority_class("").code() == ErrorCode::EnumOutOfDomain);
  CPE_REQUIRE(dccp::epoch::parse_authority_class("mutation ").code() == ErrorCode::EnumOutOfDomain);
  CPE_REQUIRE(dccp::epoch::parse_revocation_target_kind("nope").code() == ErrorCode::EnumOutOfDomain);
  CPE_REQUIRE(dccp::epoch::parse_revocation_reason("nope").code() == ErrorCode::EnumOutOfDomain);
  CPE_REQUIRE(dccp::epoch::parse_incarnation_state("").code() == ErrorCode::EnumOutOfDomain);
  CPE_REQUIRE(dccp::epoch::parse_provenance_source_kind("nope").code() == ErrorCode::EnumOutOfDomain);
  CPE_REQUIRE(dccp::epoch::parse_epoch_transition_reason("nope").code() == ErrorCode::EnumOutOfDomain);
  // Store configuration tokens are configuration, not wire enumerations, so an
  // unknown one is an invalid option rather than an out-of-domain enum.
  CPE_REQUIRE(dccp::epoch::parse_store_open_mode("nope").code() == ErrorCode::InvalidOption);
  CPE_REQUIRE(dccp::epoch::parse_recovery_policy("nope").code() == ErrorCode::InvalidOption);
  CPE_REQUIRE(dccp::epoch::parse_error_code("authority.nonexistent").code() != ErrorCode::Ok);
}

// ---------------------------------------------------------------------------
// Wire payloads
// ---------------------------------------------------------------------------

CPE_TEST(adversarial, hostile_payloads_are_rejected_with_stable_codes) {
  const FacilityAuthorityDomainId domain = domain_id();
  const ControllerIncarnationId incarnation =
      ControllerIncarnationId::derive(domain, controller_id("worker-a"), IncarnationNumber::from_trusted(1));
  constexpr std::size_t kPayloadLimit = 1u << 20;

  const auto decode_registration = [](std::span<const std::byte> payload) {
    return dccp::epoch::detail::decode_register_request(payload);
  };
  const auto decode_acquire = [](std::span<const std::byte> payload) {
    return dccp::epoch::detail::decode_acquire_request(payload);
  };
  const auto decode_advance = [](std::span<const std::byte> payload) {
    return dccp::epoch::detail::decode_advance_request(payload);
  };
  const auto decode_revoke = [](std::span<const std::byte> payload) {
    return dccp::epoch::detail::decode_revoke_request(payload);
  };
  const auto decode_validate = [](std::span<const std::byte> payload) {
    return dccp::epoch::detail::decode_validate_request(payload);
  };
  const auto decode_hello = [](std::span<const std::byte> payload) {
    return dccp::epoch::detail::decode_hello_request(payload);
  };
  const auto decode_error_payload = [](std::span<const std::byte> payload) {
    return dccp::epoch::detail::decode_error(payload);
  };
  const auto decode_qualification = [](std::span<const std::byte> payload) {
    return dccp::epoch::detail::decode_qualification(payload);
  };

  // -- registration requests ----------------------------------------------
  dccp::epoch::RegisterControllerRequest valid_registration = registration_request("worker-a");
  const std::vector<std::byte> registration_bytes = dccp::epoch::detail::encode_register_request(valid_registration);
  CPE_REQUIRE(!registration_bytes.empty());

  require_payload_rejected(decode_registration, std::span<const std::byte>(), ErrorCode::Truncated,
                           "an empty registration payload");

  std::vector<std::byte> trailing = registration_bytes;
  trailing.push_back(std::byte{0x00});
  require_payload_rejected(decode_registration, trailing, ErrorCode::TrailingBytes,
                           "a registration payload with a trailing byte");

  std::vector<std::byte> truncated = registration_bytes;
  truncated.resize(truncated.size() - 1);
  require_payload_rejected(decode_registration, truncated, ErrorCode::Truncated,
                           "a registration payload truncated by one byte");

  // A text length near UINT32_MAX is refused before any buffer is created.
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.u32(0xFFFFFFFFu);
    require_payload_rejected(decode_registration, writer.data(), ErrorCode::IntegrityLimitExceeded,
                             "a text field declaring 0xFFFFFFFF bytes");
  }
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.u32(static_cast<std::uint32_t>(dccp::epoch::max_frame_payload_bytes) + 1u);
    require_payload_rejected(decode_registration, writer.data(), ErrorCode::IntegrityLimitExceeded,
                             "a text field declaring more than the frame bound");
  }
  // An in-bound declared length with no body is a truncation, not a length
  // attack: the two checks stay distinguishable.
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.u32(64);
    require_payload_rejected(decode_registration, writer.data(), ErrorCode::Truncated,
                             "a declared in-bound length with no body");
  }

  // Empty and hostile required texts.
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.text("");
    require_payload_rejected(decode_registration, writer.data(), ErrorCode::IdentifierEmpty,
                             "an empty controller identifier");
  }
  {
    const std::string with_nul("work\0er", 7);
    CanonicalWriter writer(kPayloadLimit);
    writer.text(with_nul);
    require_payload_rejected(decode_registration, writer.data(), ErrorCode::InvalidIdentifierSyntax,
                             "a controller identifier with an embedded NUL");
  }
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.text("-leading-dash");
    require_payload_rejected(decode_registration, writer.data(), ErrorCode::InvalidIdentifierSyntax,
                             "a controller identifier with a leading dash");
  }
  {
    std::string invalid_utf8("work");
    invalid_utf8.push_back(static_cast<char>(0xC3));
    invalid_utf8.push_back(static_cast<char>(0x28));
    CanonicalWriter writer(kPayloadLimit);
    writer.text(invalid_utf8);
    require_payload_rejected(decode_registration, writer.data(), ErrorCode::InvalidIdentifierSyntax,
                             "a controller identifier with invalid UTF-8");
  }
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.text(std::string(dccp::epoch::max_identifier_length + 1, 'a'));
    require_payload_rejected(decode_registration, writer.data(), ErrorCode::IdentifierTooLong,
                             "an over-long controller identifier");
  }

  // Provenance fields: enum out of domain, empty source, hostile notes.
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.text("worker-a");
    writer.u32(0);  // provenance kind 0 is outside the domain
    writer.text("op");
    writer.boolean(false);
    writer.text("");
    require_payload_rejected(decode_registration, writer.data(), ErrorCode::MalformedPayload,
                             "a provenance kind of zero");
  }
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.text("worker-a");
    writer.u32(static_cast<std::uint32_t>(dccp::epoch::max_provenance_source_kind) + 1u);
    writer.text("op");
    writer.boolean(false);
    writer.text("");
    require_payload_rejected(decode_registration, writer.data(), ErrorCode::MalformedPayload,
                             "a provenance kind above the domain");
  }
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.text("worker-a");
    writer.u32(static_cast<std::uint32_t>(dccp::epoch::ProvenanceSourceKind::Controller));
    writer.text("");
    writer.boolean(false);
    writer.text("");
    require_payload_rejected(decode_registration, writer.data(), ErrorCode::IdentifierEmpty,
                             "an empty provenance source");
  }
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.text("worker-a");
    writer.u32(static_cast<std::uint32_t>(dccp::epoch::ProvenanceSourceKind::Controller));
    writer.text("op");
    writer.boolean(false);
    writer.text(std::string("bad\nnote"));
    require_payload_rejected(decode_registration, writer.data(), ErrorCode::TextControlCharacter,
                             "a provenance note with a control character");
  }
  {
    std::string invalid_note("note");
    invalid_note.push_back(static_cast<char>(0xE2));
    invalid_note.push_back(static_cast<char>(0x28));
    invalid_note.push_back(static_cast<char>(0xA1));
    CanonicalWriter writer(kPayloadLimit);
    writer.text("worker-a");
    writer.u32(static_cast<std::uint32_t>(dccp::epoch::ProvenanceSourceKind::Controller));
    writer.text("op");
    writer.boolean(false);
    writer.text(invalid_note);
    require_payload_rejected(decode_registration, writer.data(), ErrorCode::TextInvalidUtf8,
                             "a provenance note with invalid UTF-8");
  }
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.text("worker-a");
    writer.u32(static_cast<std::uint32_t>(dccp::epoch::ProvenanceSourceKind::Controller));
    writer.text("op");
    writer.boolean(false);
    writer.text(std::string(dccp::epoch::max_note_length + 1, 'n'));
    require_payload_rejected(decode_registration, writer.data(), ErrorCode::TextTooLong,
                             "an over-long provenance note");
  }
  // A boolean field that is neither 0 nor 1 is an enumeration violation, not a
  // truthy value.
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.text("worker-a");
    writer.u32(static_cast<std::uint32_t>(dccp::epoch::ProvenanceSourceKind::Controller));
    writer.text("op");
    writer.u8(2);
    writer.text("");
    require_payload_rejected(decode_registration, writer.data(), ErrorCode::EnumOutOfDomain,
                             "a boolean field with value 2");
  }
  // Idempotency: a zero incarnation digest and a zero sequence are both refused.
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.text("worker-a");
    writer.u32(static_cast<std::uint32_t>(dccp::epoch::ProvenanceSourceKind::Controller));
    writer.text("op");
    writer.boolean(false);
    writer.text("");
    writer.boolean(true);
    writer.text("worker-a");
    writer.digest(dccp::epoch::Sha256Digest::zero());
    writer.u64(1);
    require_payload_rejected(decode_registration, writer.data(), ErrorCode::MalformedPayload,
                             "an idempotency key with a zero incarnation digest");
  }
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.text("worker-a");
    writer.u32(static_cast<std::uint32_t>(dccp::epoch::ProvenanceSourceKind::Controller));
    writer.text("op");
    writer.boolean(false);
    writer.text("");
    writer.boolean(true);
    writer.text("worker-a");
    writer.digest(incarnation.digest());
    writer.u64(0);
    require_payload_rejected(decode_registration, writer.data(), ErrorCode::MalformedPayload,
                             "an idempotency key with sequence zero");
  }

  // -- acquisition requests -----------------------------------------------
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.u32(99);  // authority class outside the domain
    writer.text("worker-a");
    writer.digest(incarnation.digest());
    writer.u32(1);
    writer.text("facility.inventory");
    writer.boolean(false);
    writer.u32(static_cast<std::uint32_t>(dccp::epoch::ProvenanceSourceKind::Controller));
    writer.text("worker-a");
    writer.boolean(false);
    writer.text("");
    writer.boolean(false);
    require_payload_rejected(decode_acquire, writer.data(), ErrorCode::MalformedPayload,
                             "an authority class out of domain");
  }
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.u32(0xFFFFFFFFu);
    writer.text("worker-a");
    writer.digest(incarnation.digest());
    writer.u32(1);
    writer.text("facility.inventory");
    writer.boolean(false);
    writer.u32(static_cast<std::uint32_t>(dccp::epoch::ProvenanceSourceKind::Controller));
    writer.text("worker-a");
    writer.boolean(false);
    writer.text("");
    writer.boolean(false);
    require_payload_rejected(decode_acquire, writer.data(), ErrorCode::MalformedPayload,
                             "a negative-looking authority class");
  }
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.u32(1);
    writer.text("worker-a");
    writer.digest(dccp::epoch::Sha256Digest::zero());
    writer.u32(1);
    writer.text("facility.inventory");
    writer.boolean(false);
    writer.u32(static_cast<std::uint32_t>(dccp::epoch::ProvenanceSourceKind::Controller));
    writer.text("worker-a");
    writer.boolean(false);
    writer.text("");
    writer.boolean(false);
    require_payload_rejected(decode_acquire, writer.data(), ErrorCode::MalformedPayload,
                             "a zero incarnation digest");
  }
  // A scope list over the bound is refused before any element is materialized.
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.u32(1);
    writer.text("worker-a");
    writer.digest(incarnation.digest());
    writer.u32(static_cast<std::uint32_t>(dccp::epoch::max_scopes_per_authority) + 1u);
    require_payload_rejected(decode_acquire, writer.data(), ErrorCode::FrameTooLarge,
                             "a scope list above the bound");
  }
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.u32(1);
    writer.text("worker-a");
    writer.digest(incarnation.digest());
    writer.u32(0xFFFFFFFFu);
    require_payload_rejected(decode_acquire, writer.data(), ErrorCode::FrameTooLarge,
                             "a scope list declaring 0xFFFFFFFF entries");
  }
  // Duplicate and empty scope entries.
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.u32(1);
    writer.text("worker-a");
    writer.digest(incarnation.digest());
    writer.u32(2);
    writer.text("facility.inventory");
    writer.text("facility.inventory");
    require_payload_rejected(decode_acquire, writer.data(), ErrorCode::ScopeDuplicate,
                             "a duplicate scope entry");
  }
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.u32(1);
    writer.text("worker-a");
    writer.digest(incarnation.digest());
    writer.u32(1);
    writer.text("");
    require_payload_rejected(decode_acquire, writer.data(), ErrorCode::IdentifierEmpty, "an empty scope name");
  }
  // A malformed sponsor token is a token rejection, not a crash.
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.u32(1);
    writer.text("worker-a");
    writer.digest(incarnation.digest());
    writer.u32(1);
    writer.text("facility.inventory");
    writer.boolean(true);
    writer.text("cpe1:mutation:not-a-token");
    require_payload_rejected(decode_acquire, writer.data(), ErrorCode::TokenMalformed,
                             "a sponsor token with the wrong field count");
  }
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.u32(1);
    writer.text("worker-a");
    writer.digest(incarnation.digest());
    writer.u32(1);
    writer.text("facility.inventory");
    writer.boolean(true);
    writer.text(with_field(craft_mutation_token(domain, 1, "worker-a", incarnation, 1, {"facility.inventory"})
                               .to_string(),
                           8, std::string(64, 'a')));
    require_payload_rejected(decode_acquire, writer.data(), ErrorCode::TokenTampered,
                             "a sponsor token with a fabricated fencing digest");
  }

  // -- epoch advancement ---------------------------------------------------
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.u64(0);  // expected epoch zero
    require_payload_rejected(decode_advance, writer.data(), ErrorCode::MalformedPayload,
                             "a zero expected epoch");
  }
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.u64(1);
    writer.text("cpe1:mutation:facility-alpha:1:worker-a:nothex:1:facility.inventory:0");
    require_payload_rejected(decode_advance, writer.data(), ErrorCode::DigestInvalidHex,
                             "an advancement token with a non-hex incarnation");
  }
  // A negative-looking 64-bit epoch is not interpreted as negative: it decodes
  // as an ordinary unsigned value, so the authority rejects it as a conflict
  // instead of clamping or wrapping it.
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.u64(UINT64_MAX);
    writer.text(craft_mutation_token(domain, 1, "worker-a", incarnation, 1, {"facility.inventory"}).to_string());
    writer.u32(static_cast<std::uint32_t>(dccp::epoch::EpochTransitionReason::OperatorRequest));
    writer.u32(static_cast<std::uint32_t>(dccp::epoch::ProvenanceSourceKind::Operator));
    writer.text("operator");
    writer.boolean(false);
    writer.text("");
    writer.boolean(false);
    const dccp::epoch::AdvanceEpochRequest request = dccp::epoch::detail::decode_advance_request(writer.data());
    CPE_REQUIRE_MSG(request.expected_current.value() == UINT64_MAX,
                    "a sign-looking 64-bit epoch must decode as an unsigned value, never as a negative one");
    // The decoded token must be byte-identical to the token its own text form
    // parses back to. The parsed value is bound to a named local on purpose:
    // binding a reference directly to Result::value() of a temporary would leave
    // that reference dangling once the temporary is destroyed, which is a test
    // defect rather than a library one.
    const Result<MutationAuthority> round_trip = MutationAuthority::parse(request.authority.to_string());
    CPE_REQUIRE_MSG(round_trip.has_value(),
                    "a decoded token must render to text that parses again: " +
                        round_trip.rejection().to_string());
    CPE_REQUIRE_MSG(round_trip.value() == request.authority,
                    "a decoded token must survive a text round trip unchanged");
    CPE_REQUIRE_EQ(round_trip.value().to_string(), request.authority.to_string());
  }

  // -- revocation ----------------------------------------------------------
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.u32(9);  // target kind out of domain
    require_payload_rejected(decode_revoke, writer.data(), ErrorCode::MalformedPayload,
                             "a revocation target kind out of domain");
  }
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.u32(static_cast<std::uint32_t>(dccp::epoch::RevocationTargetKind::Grant));
    writer.text("worker-a");
    writer.boolean(true);
    writer.u64(1);
    writer.boolean(true);
    writer.u64(4);
    require_payload_rejected(decode_revoke, writer.data(), ErrorCode::MalformedPayload,
                             "a grant revocation that also carries a fence");
  }
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.u32(static_cast<std::uint32_t>(dccp::epoch::RevocationTargetKind::ControllerIncarnations));
    writer.text("worker-a");
    writer.boolean(false);
    writer.boolean(true);
    writer.u64(4);
    require_payload_rejected(decode_revoke, writer.data(), ErrorCode::MalformedPayload,
                             "a controller revocation that names a grant");
  }
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.u32(static_cast<std::uint32_t>(dccp::epoch::RevocationTargetKind::Grant));
    writer.text("worker-a");
    writer.boolean(false);
    writer.boolean(false);
    require_payload_rejected(decode_revoke, writer.data(), ErrorCode::MalformedPayload,
                             "a grant revocation that names no grant");
  }
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.u32(static_cast<std::uint32_t>(dccp::epoch::RevocationTargetKind::ControllerIncarnations));
    writer.text("worker-a");
    writer.boolean(true);
    writer.u64(0);
    writer.boolean(false);
    require_payload_rejected(decode_revoke, writer.data(), ErrorCode::MalformedPayload,
                             "a revocation fence of zero");
  }
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.u32(static_cast<std::uint32_t>(dccp::epoch::RevocationTargetKind::ControllerIncarnations));
    writer.text("worker-a");
    writer.boolean(false);
    writer.boolean(false);
    writer.u32(static_cast<std::uint32_t>(dccp::epoch::max_revocation_reason) + 1u);
    require_payload_rejected(decode_revoke, writer.data(), ErrorCode::MalformedPayload,
                             "a revocation reason above the domain");
  }

  // -- validation and handshake --------------------------------------------
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.text("cpe1:mutation:not-a-token");
    writer.text("facility.inventory");
    const dccp::epoch::detail::ValidateRequestPayload request =
        dccp::epoch::detail::decode_validate_request(writer.data());
    CPE_REQUIRE_EQ(request.token, std::string("cpe1:mutation:not-a-token"));
    CPE_REQUIRE_EQ(request.scope, std::string("facility.inventory"));
  }
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.text("token");
    writer.text("-bad-scope");
    require_payload_rejected(decode_validate, writer.data(), ErrorCode::InvalidIdentifierSyntax,
                             "a validation request with a hostile scope name");
  }
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.u16(1);
    writer.u16(1024);
    writer.u8(0x00);
    require_payload_rejected(decode_hello, writer.data(), ErrorCode::TrailingBytes,
                             "a hello request with a trailing byte");
  }
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.u16(1);
    require_payload_rejected(decode_hello, writer.data(), ErrorCode::Truncated,
                             "a hello request truncated inside a field");
  }
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.text("not.a.code");
    writer.text("");
    require_payload_rejected(decode_error_payload, writer.data(), ErrorCode::MalformedPayload,
                             "an error payload naming an unknown error token");
  }
  {
    CanonicalWriter writer(kPayloadLimit);
    writer.u32(0);  // recovered state verdict out of domain
    require_payload_rejected(decode_qualification, writer.data(), ErrorCode::MalformedPayload,
                             "a qualification verdict out of domain");
  }
}

// ---------------------------------------------------------------------------
// Token texts
// ---------------------------------------------------------------------------

CPE_TEST(adversarial, hostile_token_texts_are_rejected_deterministically) {
  const FacilityAuthorityDomainId domain = domain_id();
  const ControllerIncarnationId incarnation =
      ControllerIncarnationId::derive(domain, controller_id("worker-a"), IncarnationNumber::from_trusted(1));
  const MutationAuthority valid =
      craft_mutation_token(domain, 1, "worker-a", incarnation, 4, {"facility.inventory", "facility.topology"});
  const std::string text = valid.to_string();
  CPE_REQUIRE_EQ(split_fields(text).size(), std::size_t{9});

  // The canonical text round-trips exactly, which is what makes every mutation
  // below a single, well-understood deviation.
  const Result<MutationAuthority> reparsed = MutationAuthority::parse(text);
  CPE_REQUIRE_MSG(reparsed.has_value(), "the canonical token text must parse: " + reparsed.rejection().to_string());
  CPE_REQUIRE_MSG(reparsed.value() == valid, "a reparsed token must equal the token that produced the text");
  CPE_REQUIRE_EQ(reparsed.value().to_string(), text);

  // Field count and prefix.
  const std::vector<std::string> fields = split_fields(text);
  const std::vector<std::string> short_fields(fields.begin(), fields.end() - 1);
  require_token_rejected(join_fields(short_fields), ErrorCode::TokenMalformed, "a token with eight fields");
  std::vector<std::string> long_fields = fields;
  long_fields.push_back("extra");
  require_token_rejected(join_fields(long_fields), ErrorCode::TokenMalformed, "a token with ten fields");
  require_token_rejected(with_field(text, 0, "cpe2"), ErrorCode::TokenMalformed, "a token with a foreign prefix");
  require_token_rejected(with_field(text, 0, "cpe1:extra"), ErrorCode::TokenMalformed,
                         "a token with an extra separator");
  require_token_rejected(text + ":", ErrorCode::TokenMalformed, "a token with a trailing separator");

  // Digests: non-hex, wrong length, and a zero incarnation.
  require_token_rejected(with_field(text, 5, std::string(64, 'z')), ErrorCode::DigestInvalidHex,
                         "a token with a non-hex incarnation digest");
  require_token_rejected(with_field(text, 5, "abc"), ErrorCode::DigestInvalidHex,
                         "a token with a short incarnation digest");
  require_token_rejected(with_field(text, 8, std::string(63, 'a')), ErrorCode::DigestInvalidHex,
                         "a token with a short fencing digest");
  require_token_rejected(with_field(text, 8, std::string(64, 'g')), ErrorCode::DigestInvalidHex,
                         "a token with a non-hex fencing digest");
  require_token_rejected(with_field(text, 5, std::string(64, '0')), ErrorCode::InvalidArgument,
                         "a token with a zero incarnation digest");

  // Numeric fields: leading zeros, values past UINT64_MAX, and zero itself.
  require_token_rejected(with_field(text, 3, "01"), ErrorCode::TokenMalformed, "an epoch with a leading zero");
  require_token_rejected(with_field(text, 6, "007"), ErrorCode::TokenMalformed,
                         "a grant identifier with a leading zero");
  require_token_rejected(with_field(text, 3, "99999999999999999999"), ErrorCode::TokenMalformed,
                         "an epoch past the 64-bit range");
  require_token_rejected(with_field(text, 6, "99999999999999999999"), ErrorCode::TokenMalformed,
                         "a grant identifier past the 64-bit range");
  require_token_rejected(with_field(text, 3, "0"), ErrorCode::EpochZero, "an epoch of zero");
  require_token_rejected(with_field(text, 6, "0"), ErrorCode::InvalidArgument, "a grant identifier of zero");
  require_token_rejected(with_field(text, 3, "-1"), ErrorCode::TokenMalformed, "a negative-looking epoch");

  // Hostile text fields: embedded NUL, invalid UTF-8, empty.
  require_token_rejected(with_field(text, 2, std::string("dom\0ain", 7)), ErrorCode::InvalidIdentifierSyntax,
                         "a domain with an embedded NUL");
  require_token_rejected(with_field(text, 4, std::string("work\0er", 7)), ErrorCode::InvalidIdentifierSyntax,
                         "a controller with an embedded NUL");
  require_token_rejected(with_field(text, 2, std::string("\xC3\x28")), ErrorCode::InvalidIdentifierSyntax,
                         "a domain with invalid UTF-8");
  require_token_rejected(with_field(text, 2, ""), ErrorCode::IdentifierEmpty, "an empty domain");
  require_token_rejected(with_field(text, 4, ""), ErrorCode::IdentifierEmpty, "an empty controller");
  require_token_rejected(with_field(text, 7, ""), ErrorCode::TokenMalformed, "an empty scope set field");

  // Scope sets: non-canonical order, duplicates, and empty entries.
  require_token_rejected(with_field(text, 7, "facility.topology+facility.inventory"), ErrorCode::TokenMalformed,
                         "a scope set in descending order");
  require_token_rejected(with_field(text, 7, "facility.inventory+facility.inventory"), ErrorCode::ScopeDuplicate,
                         "a scope set with a duplicate scope");
  require_token_rejected(with_field(text, 7, "+"), ErrorCode::IdentifierEmpty,
                         "a scope set with an empty entry");

  // Reordered fields: every field is individually valid, so the text parses
  // structurally and is then rejected because its claims cannot have produced
  // the fencing digest it carries.
  std::vector<std::string> reordered = fields;
  std::swap(reordered[2], reordered[4]);
  require_token_rejected(join_fields(reordered), ErrorCode::TokenTampered,
                         "a token with the domain and controller fields swapped");
  std::vector<std::string> swapped_numbers = fields;
  std::swap(swapped_numbers[3], swapped_numbers[6]);
  require_token_rejected(join_fields(swapped_numbers), ErrorCode::TokenTampered,
                         "a token with the epoch and grant fields swapped");

  // A well-formed token with a fabricated fencing digest, and the same claims
  // presented as the other authority class.
  require_token_rejected(with_field(text, 8, std::string(64, 'a')), ErrorCode::TokenTampered,
                         "a token with a fabricated fencing digest");
  const std::string class_swapped = with_field(text, 1, "observation");
  const Result<ObservationAuthority> as_observation = ObservationAuthority::parse(class_swapped);
  CPE_REQUIRE_MSG(!as_observation.has_value() && as_observation.code() == ErrorCode::TokenTampered,
                  "the fencing digest must be bound to the authority class");
  require_token_rejected(class_swapped, ErrorCode::AuthorityClassMismatch,
                         "an observation token presented as mutation authority");
  require_token_rejected(with_field(text, 1, "bogus"), ErrorCode::EnumOutOfDomain,
                         "a token naming an unknown authority class");

  // An observation-class token built for an observation grant is well formed;
  // the point here is that the class is part of the claims, not a free label.
  const ObservationAuthority observation = craft_observation_token(domain, 1, "worker-a", incarnation, 4,
                                                                   {"facility.inventory"});
  CPE_REQUIRE_MSG(observation.verify_integrity().accepted(), "an observation token must be internally consistent");
  CPE_REQUIRE_MSG(MutationAuthority::parse(observation.to_string()).code() == ErrorCode::AuthorityClassMismatch,
                  "an observation token text must never parse as mutation authority");
}

CPE_TEST(adversarial, consistent_claims_that_match_nothing_are_rejected_by_the_store) {
  cpe_test::TestAuthority authority;
  const FacilityAuthorityDomainId domain = domain_id(authority.domain());
  const ControllerIncarnationId ghost_incarnation =
      ControllerIncarnationId::derive(domain, controller_id("ghost"), IncarnationNumber::from_trusted(1));
  const ScopeName inventory = scope_name("facility.inventory");
  const ScopeName topology = scope_name("facility.topology");

  // A token for a grant that was never issued: the fencing digest matches its
  // own claims, so integrity passes and only the store can reject it.
  {
    const std::string before = authority.authority().status().to_string();
    const MutationAuthority fabricated =
        craft_mutation_token(domain, 1, "ghost", ghost_incarnation, 9999, {"facility.inventory"});
    CPE_REQUIRE_MSG(fabricated.verify_integrity().accepted(), "a fabricated token must be internally consistent");
    CPE_REQUIRE_MSG(MutationAuthority::parse(fabricated.to_string()).has_value(),
                    "a fabricated but consistent token text must parse");
    const ValidationOutcome unknown = authority.authority().validate_mutation(fabricated, inventory);
    CPE_REQUIRE_MSG(unknown.code() == ErrorCode::UnknownGrant,
                    "a consistent token for an unknown grant must be rejected as an unknown grant");
    const ValidationOutcome repeated = authority.authority().validate_mutation(fabricated, inventory);
    CPE_REQUIRE_MSG(repeated.to_string() == unknown.to_string(),
                    "a repeated fabricated-token rejection must be identical");
    CPE_REQUIRE_MSG(authority.authority().status().to_string() == before,
                    "a rejected validation must not change the status");
  }

  // Set up two real grants: a mutation grant for a worker and an observation
  // grant for an observer. Every hostile claim below is derived from them, so
  // the store, not the codec, is what rejects the token.
  const dccp::epoch::ControllerRegistration worker = authority.register_controller("worker-a");
  const AuthorityGrantView worker_view =
      authority.acquire("worker-a", worker.incarnation_id(), {"facility.inventory"}, authority.root_authority());
  const MutationAuthority real = authority.mutation_authority_of(worker_view);
  const dccp::epoch::ControllerRegistration observer = authority.register_controller("observer");
  const AuthorityGrantView observer_view =
      authority.acquire("observer", observer.incarnation_id(), {"facility.topology"}, authority.root_authority(),
                        dccp::epoch::AuthorityClass::Observation);
  CPE_REQUIRE(observer_view.observation_authority().has_value());
  const ObservationAuthority observation = *observer_view.observation_authority();

  const std::string settled = authority.authority().status().to_string();
  const auto require_untouched = [&](const std::string& what) {
    CPE_REQUIRE_MSG(authority.authority().status().to_string() == settled, what + " changed the status");
  };

  // A real grant referenced with claims that do not match it.
  {
    const MutationAuthority wrong_incarnation =
        craft_mutation_token(domain, 1, "worker-a",
                             ControllerIncarnationId::derive(domain, controller_id("worker-a"),
                                                             IncarnationNumber::from_trusted(99)),
                             real.grant().value(), {"facility.inventory"});
    CPE_REQUIRE_MSG(authority.authority().validate_mutation(wrong_incarnation, inventory).code() ==
                        ErrorCode::ClaimsMismatch,
                    "a token whose incarnation does not match the stored grant must be a claims mismatch");
    require_untouched("a validation of a mismatched incarnation");
  }
  {
    const MutationAuthority wider_scopes = craft_mutation_token(
        domain, 1, "worker-a", real.incarnation(), real.grant().value(), {"facility.inventory", "facility.topology"});
    CPE_REQUIRE_MSG(authority.authority().validate_mutation(wider_scopes, inventory).code() ==
                        ErrorCode::ClaimsMismatch,
                    "a token whose scopes do not match the stored grant must be a claims mismatch");
    require_untouched("a validation of widened scopes");
  }
  {
    const MutationAuthority other_controller =
        craft_mutation_token(domain, 1, "ghost", real.incarnation(), real.grant().value(), {"facility.inventory"});
    CPE_REQUIRE_MSG(authority.authority().validate_mutation(other_controller, inventory).code() ==
                        ErrorCode::ClaimsMismatch,
                    "a token whose controller does not match the stored grant must be a claims mismatch");
    require_untouched("a validation of a mismatched controller");
  }
  {
    const FacilityAuthorityDomainId other_domain = domain_id("facility-beta");
    const MutationAuthority foreign_domain = craft_mutation_token(other_domain, 1, "worker-a", real.incarnation(),
                                                                  real.grant().value(), {"facility.inventory"});
    CPE_REQUIRE_MSG(authority.authority().validate_mutation(foreign_domain, inventory).code() ==
                        ErrorCode::DomainMismatch,
                    "a token of another domain must be refused before anything else is considered");
    require_untouched("a validation of a foreign domain");
  }
  {
    const MutationAuthority future =
        craft_mutation_token(domain, 42, "worker-a", real.incarnation(), real.grant().value(), {"facility.inventory"});
    CPE_REQUIRE_MSG(authority.authority().validate_mutation(future, inventory).code() == ErrorCode::EpochUnknown,
                    "a token naming an epoch that was never committed must be refused");
    require_untouched("a validation of a future epoch");
  }
  {
    // The correct claims for an observation grant, presented as mutation
    // authority: integrity is fine, the class is not.
    const MutationAuthority as_mutation = craft_mutation_token(domain, observation.epoch().value(),
                                                               observation.controller().str(), observation.incarnation(),
                                                               observation.grant().value(), {"facility.topology"});
    CPE_REQUIRE_MSG(authority.authority().validate_mutation(as_mutation, topology).code() ==
                        ErrorCode::AuthorityClassMismatch,
                    "an observation grant must never authorize a mutation");
    CPE_REQUIRE_MSG(authority.authority().validate_observation(observation, topology).accepted(),
                    "the genuine observation token must still validate");
    CPE_REQUIRE_MSG(authority.authority().validate_observation(observation, inventory).code() ==
                        ErrorCode::ScopeNotGranted,
                    "an observation grant must not cover a scope it never held");
    require_untouched("a validation across authority classes");
  }
  {
    // A hostile token text never even becomes a token, and a default-constructed
    // token is refused at the domain check.
    const Result<MutationAuthority> hostile = MutationAuthority::parse("cpe1:mutation:");
    CPE_REQUIRE_MSG(hostile.code() == ErrorCode::TokenMalformed, "a truncated token text must not parse");
    const ValidationOutcome missing_slot = authority.authority().validate_mutation(MutationAuthority{}, inventory);
    CPE_REQUIRE_MSG(missing_slot.code() == ErrorCode::DomainMismatch,
                    "a default-constructed token must be refused at the domain check");
    require_untouched("a validation of a default-constructed token");
  }

  // Only the deliberate setup commands changed anything.
  const AuthorityStatus final_status = authority.authority().status();
  CPE_REQUIRE_EQ(final_status.controller_count(), std::uint64_t{3});
  CPE_REQUIRE_EQ(final_status.epoch().value(), std::uint64_t{1});
  CPE_REQUIRE_EQ(final_status.revocation_count(), std::uint64_t{0});
  CPE_REQUIRE_EQ(final_status.transition_count(), std::uint64_t{1});
  CPE_REQUIRE_EQ(authority.authority().accounting().idempotency_records(), std::uint64_t{0});
}

// ---------------------------------------------------------------------------
// Store paths and unexpected files
// ---------------------------------------------------------------------------

CPE_TEST(adversarial, hostile_store_paths_are_rejected_without_side_effects) {
  // An empty directory string is a configuration error, never a silent no-op.
  {
    StoreOpenOptions options;
    options.directory = "";
    CPE_REQUIRE_THROWS_CODE(ControlPlaneEpochAuthority(options), ErrorCode::PathInvalid);
    CPE_REQUIRE_THROWS_CODE(ControlPlaneEpochAuthority(options), ErrorCode::PathInvalid);
  }
  // A bound outside its documented range is refused before anything is opened.
  {
    cpe_test::TempDirectory directory;
    StoreOpenOptions options;
    options.directory = directory.path();
    options.max_snapshot_bytes = 0;
    CPE_REQUIRE_THROWS_CODE(ControlPlaneEpochAuthority(options), ErrorCode::InvalidOption);
    options.max_snapshot_bytes = dccp::epoch::max_snapshot_bytes + 1;
    CPE_REQUIRE_THROWS_CODE(ControlPlaneEpochAuthority(options), ErrorCode::InvalidOption);
  }
  // A path that exists as a regular file is not a store directory.
  {
    cpe_test::TempDirectory directory;
    const std::filesystem::path file = directory.file("not-a-directory");
    std::ofstream stream(file, std::ios::binary);
    stream << "this is a file, not a store";
    stream.close();
    const auto size = std::filesystem::file_size(file);
    StoreOpenOptions options;
    options.directory = file;
    CPE_REQUIRE_THROWS_CODE(ControlPlaneEpochAuthority(options), ErrorCode::PathInvalid);
    StoreOpenOptions read_only = options;
    read_only.mode = StoreOpenMode::ReadOnly;
    CPE_REQUIRE_THROWS_CODE(ControlPlaneEpochAuthority(read_only), ErrorCode::PathInvalid);
    CPE_REQUIRE_MSG(std::filesystem::is_regular_file(file), "a refused open must not disturb the path");
    CPE_REQUIRE_EQ(std::filesystem::file_size(file), size);
  }
  // A non-existent directory opened read-only is refused without being created:
  // an observer never has a side effect.
  {
    cpe_test::TempDirectory directory;
    const std::filesystem::path missing = directory.file("never-created");
    StoreOpenOptions options;
    options.directory = missing;
    options.mode = StoreOpenMode::ReadOnly;
    CPE_REQUIRE_THROWS_CODE(ControlPlaneEpochAuthority(options), ErrorCode::StoreNotFound);
    CPE_REQUIRE_THROWS_CODE(ControlPlaneEpochAuthority(options), ErrorCode::StoreNotFound);
    CPE_REQUIRE_MSG(!std::filesystem::exists(missing), "a refused read-only open must not create the directory");
  }
  // A non-existent directory opened read-write is created, but it holds no
  // authority: no domain, no epoch, and no fabricated zero epoch either.
  {
    cpe_test::TempDirectory directory;
    const std::filesystem::path fresh = directory.file("fresh-store");
    StoreOpenOptions options;
    options.directory = fresh;
    ControlPlaneEpochAuthority authority(options);
    CPE_REQUIRE_MSG(std::filesystem::is_directory(fresh), "a writable open creates the store directory");
    CPE_REQUIRE_MSG(!authority.initialized(), "a fresh store holds no authority domain");
    CPE_REQUIRE_MSG(!authority.recovery().has_domain(), "a fresh store reports no domain");
    CPE_REQUIRE_MSG(!authority.recovery().epoch().has_value(), "a fresh store reports no epoch");
    CPE_REQUIRE_THROWS_CODE(authority.status(), ErrorCode::StoreNotInitialized);
    CPE_REQUIRE_THROWS_CODE(authority.current_epoch(), ErrorCode::StoreNotInitialized);
    const StoreInspection inspection = dccp::epoch::inspect_store(fresh);
    CPE_REQUIRE_MSG(!inspection.verified(), "an uninitialized store must not verify as authoritative");
    CPE_REQUIRE_MSG(!inspection.store_initialized(), "an uninitialized store reports no usable generation");
  }
  // A second writer on the same directory is refused by the exclusive lock, and
  // the refusal leaves the first writer fully operational.
  {
    cpe_test::TestAuthority authority;
    const std::string before = authority.authority().status().to_string();
    StoreOpenOptions options;
    options.directory = authority.store();
    CPE_REQUIRE_THROWS_CODE(ControlPlaneEpochAuthority(options), ErrorCode::StoreLocked);
    CPE_REQUIRE_THROWS_CODE(ControlPlaneEpochAuthority(options), ErrorCode::StoreLocked);
    CPE_REQUIRE_EQ(authority.authority().status().to_string(), before);
    (void)authority.register_controller("still-writable");
    CPE_REQUIRE_EQ(authority.authority().status().controller_count(), 2);
  }
  // inspect_store() refuses a path that is not a directory at all.
  {
    cpe_test::TempDirectory directory;
    CPE_REQUIRE_THROWS_CODE(dccp::epoch::inspect_store(""), ErrorCode::StoreNotFound);
    CPE_REQUIRE_THROWS_CODE(dccp::epoch::inspect_store(directory.file("absent")), ErrorCode::StoreNotFound);
    const std::filesystem::path file = directory.file("a-file");
    std::ofstream stream(file, std::ios::binary);
    stream << "x";
    stream.close();
    CPE_REQUIRE_THROWS_CODE(dccp::epoch::inspect_store(file), ErrorCode::PathInvalid);
  }
}

CPE_TEST(adversarial, unexpected_files_in_a_store_directory_are_ignored) {
  cpe_test::TestAuthority authority;
  (void)authority.register_controller("base-a");
  const AuthorityStatus before = authority.authority().status();
  const std::uint64_t before_epoch = before.epoch().value();
  const std::uint64_t before_generation = before.durable_generation().value();
  const std::string before_digest = before.snapshot_digest().to_hex();
  authority.close();

  // Foreign files: none of these names belongs to this repository, so none of
  // them may be read as state, repaired, or removed.
  const std::filesystem::path notes = authority.file("site-notes.txt");
  const std::filesystem::path backup = authority.file("authority.state.backup");
  const std::filesystem::path subdirectory = authority.file("operator-notes");
  {
    std::ofstream stream(notes, std::ios::binary);
    stream << "unrelated operator file";
  }
  {
    std::ofstream stream(backup, std::ios::binary);
    stream << "NOT A DURABLE GENERATION";
  }
  std::filesystem::create_directories(subdirectory);
  const std::vector<std::byte> snapshot_bytes = read_bytes(authority.file("authority.state"));

  authority.reopen();

  CPE_REQUIRE_MSG(authority.authority().recovery().outcome() == dccp::epoch::RecoveryOutcome::OpenedClean,
                  "foreign files must not disturb the recovery verdict");
  CPE_REQUIRE_MSG(authority.authority().recovery().damaged_files().empty(),
                  "a foreign file is not damaged durable state");
  const AuthorityStatus after = authority.authority().status();
  CPE_REQUIRE_EQ(after.epoch().value(), before_epoch);
  CPE_REQUIRE_EQ(after.durable_generation().value(), before_generation);
  CPE_REQUIRE_MSG(after.snapshot_digest().to_hex() == before_digest,
                  "the authoritative generation must be byte-identical after the reopen");
  CPE_REQUIRE_EQ(after.controller_count(), 2);

  // The foreign files are still there, untouched.
  CPE_REQUIRE_MSG(std::filesystem::exists(notes), "a foreign file must be ignored, not deleted");
  CPE_REQUIRE_MSG(std::filesystem::exists(backup), "a foreign file must be ignored, not quarantined");
  CPE_REQUIRE_MSG(std::filesystem::is_directory(subdirectory), "a foreign directory must be ignored");
  CPE_REQUIRE_MSG(read_bytes(authority.file("authority.state")) == snapshot_bytes,
                  "a reopen must not rewrite the live generation");

  // Read-only inspection agrees and reports no problem at all.
  const StoreInspection inspection = dccp::epoch::inspect_store(authority.store());
  CPE_REQUIRE_MSG(inspection.verified(), "a store with foreign files must still verify");
  CPE_REQUIRE_MSG(inspection.read_only_safe(), "a store with foreign files must still be read-only safe");
  CPE_REQUIRE_MSG(inspection.problems().empty(), "a foreign file is not a problem with the store");
  CPE_REQUIRE_EQ(inspection.epoch()->value(), before_epoch);

  // A file inside this repository's own temporary namespace is different: it is
  // the residue of an interrupted commit, so it is retired instead of being
  // mistaken for state. Nothing durable changes either way.
  authority.close();
  const std::filesystem::path stale = authority.file("authority.state.tmp.9999.1");
  {
    std::ofstream stream(stale, std::ios::binary);
    stream << "half-written generation";
  }
  authority.reopen();
  CPE_REQUIRE_MSG(!std::filesystem::exists(stale), "a stale temporary of this repository must be retired");
  CPE_REQUIRE_MSG(std::filesystem::exists(notes), "retiring a temporary must not touch foreign files");
  CPE_REQUIRE_EQ(authority.authority().status().epoch().value(), before_epoch);
  CPE_REQUIRE_MSG(authority.authority().status().snapshot_digest().to_hex() == before_digest,
                  "retiring a temporary must not change the authoritative generation");
  CPE_REQUIRE_MSG(temporary_names(authority.store()).empty(), "no temporary may survive a reopen");
}

// ---------------------------------------------------------------------------
// Oversized durable input
// ---------------------------------------------------------------------------

CPE_TEST(adversarial, oversized_durable_inputs_are_refused_without_allocation) {
  // A file larger than the snapshot bound is refused by the size check that
  // runs before any buffer is created, so a hostile or damaged file can never
  // drive an allocation. The file is extended by its length only, so the test
  // never writes 64 MiB of data.
  {
    cpe_test::TestAuthority authority;
    (void)authority.register_controller("base-a");
    const Epoch committed_epoch = authority.authority().status().epoch();
    const std::filesystem::path snapshot = authority.file("authority.state");
    authority.close();

    std::error_code error;
    std::filesystem::resize_file(snapshot, dccp::epoch::max_snapshot_bytes + 65, error);
    CPE_REQUIRE_MSG(!error, "could not extend the snapshot file: " + error.message());
    const auto extended_size = std::filesystem::file_size(snapshot);
    CPE_REQUIRE_EQ(extended_size, static_cast<std::uintmax_t>(dccp::epoch::max_snapshot_bytes + 65));

    StoreOpenOptions options;
    options.directory = authority.store();
    CPE_REQUIRE_THROWS_CODE(ControlPlaneEpochAuthority(options), ErrorCode::SizeLimitExceeded);
    CPE_REQUIRE_THROWS_CODE(ControlPlaneEpochAuthority(options), ErrorCode::SizeLimitExceeded);

    // Nothing was repaired, truncated, or quarantined by the refused open.
    CPE_REQUIRE_EQ(std::filesystem::file_size(snapshot), extended_size);
    CPE_REQUIRE_MSG(!std::filesystem::exists(authority.file("quarantine")),
                    "a refused open must not quarantine anything");

    // Read-only inspection reports the damage instead of throwing or allocating.
    const StoreInspection inspection = dccp::epoch::inspect_store(authority.store());
    CPE_REQUIRE_MSG(!inspection.verified(), "a store whose live file exceeds the bound must not verify");
    CPE_REQUIRE_MSG(!inspection.problems().empty(), "the oversized file must be reported as a problem");

    // The retained previous generation cannot be adopted: it sits below the
    // durable floor, so adopting it would roll the acknowledged epoch back.
    StoreOpenOptions adopt = options;
    adopt.recovery_policy = dccp::epoch::RecoveryPolicy::AdoptPreviousGeneration;
    CPE_REQUIRE_THROWS_CODE(ControlPlaneEpochAuthority(adopt), ErrorCode::GenerationBelowFloor);
    CPE_REQUIRE_EQ(std::filesystem::file_size(snapshot), extended_size);

    // A reinitializing recovery quarantines the damaged generation first, and a
    // file larger than the readable bound cannot even be read to be moved
    // aside, so the recovery is refused instead of being half applied. The
    // operator path is therefore: remove the unreadable file, then reinitialize.
    StoreOpenOptions reinitialize = options;
    reinitialize.recovery_policy = dccp::epoch::RecoveryPolicy::ReinitializeDomain;
    reinitialize.asserted_epoch_floor = committed_epoch.value();
    CPE_REQUIRE_THROWS_CODE(ControlPlaneEpochAuthority(reinitialize), ErrorCode::SizeLimitExceeded);
    CPE_REQUIRE_MSG(!std::filesystem::exists(authority.file("quarantine")),
                    "a refused reinitialization must not leave a partial quarantine behind");
    CPE_REQUIRE_EQ(std::filesystem::file_size(snapshot), extended_size);

    std::filesystem::remove(snapshot);
    ControlPlaneEpochAuthority recovered(reinitialize);
    CPE_REQUIRE_MSG(recovered.recovery().outcome() == dccp::epoch::RecoveryOutcome::ReinitializedDamagedStore,
                    "an asserted reinitialization must quarantine the damaged generation");
    CPE_REQUIRE_MSG(!recovered.initialized(), "a reinitialized store holds no domain until it is initialized");
    CPE_REQUIRE(recovered.initialize(initialization_request(authority.domain(), authority.root())).has_value());
    CPE_REQUIRE_MSG(recovered.status().epoch().value() > committed_epoch.value(),
                    "a reinitialized instance must start strictly above the recovered epoch");
    CPE_REQUIRE_MSG(std::filesystem::exists(authority.file("quarantine")),
                    "the damaged generation must be quarantined, not deleted");
  }

  // A declared payload length beyond the bound is refused by the length field
  // itself, before the payload is copied out of the file.
  {
    const std::vector<std::byte> header = envelope_header(0xFFFFFFFFu, 1, 1);
    CPE_REQUIRE_EQ(header.size(), dccp::epoch::detail::envelope_header_bytes);
    const auto decode = [](std::span<const std::byte> bytes) {
      return dccp::epoch::detail::decode_envelope(bytes, 1u << 20);
    };
    require_payload_rejected(decode, header, ErrorCode::IntegrityLimitExceeded,
                             "an envelope declaring 0xFFFFFFFF payload bytes");

    const std::vector<std::byte> just_over =
        envelope_header(static_cast<std::uint32_t>(dccp::epoch::max_snapshot_bytes) + 1u, 1, 1);
    require_payload_rejected(decode, just_over, ErrorCode::IntegrityLimitExceeded,
                             "an envelope declaring just over the snapshot bound");

    // A length that fits the bound but disagrees with the file is a size error,
    // so the two checks stay distinguishable.
    const std::vector<std::byte> mismatched = envelope_header(1024, 1, 1);
    require_payload_rejected(decode, mismatched, ErrorCode::SizeMismatch,
                             "an envelope whose declared payload is missing");
    require_payload_rejected(decode, std::span<const std::byte>(), ErrorCode::Truncated,
                             "an envelope shorter than its header");
    const std::vector<std::byte> zeroed(dccp::epoch::detail::envelope_header_bytes, std::byte{0});
    require_payload_rejected(decode, zeroed, ErrorCode::MagicMismatch, "an envelope with foreign magic");

    // The same hostile header, placed where the live generation lives, is
    // refused by the store with the same code and without touching the store.
    cpe_test::TestAuthority authority;
    (void)authority.register_controller("base-a");
    authority.close();
    write_bytes(authority.file("authority.state"), header);
    const std::vector<std::string> listing = directory_entries(authority.store());
    StoreOpenOptions options;
    options.directory = authority.store();
    CPE_REQUIRE_THROWS_CODE(ControlPlaneEpochAuthority(options), ErrorCode::IntegrityLimitExceeded);
    CPE_REQUIRE_THROWS_CODE(ControlPlaneEpochAuthority(options), ErrorCode::IntegrityLimitExceeded);
    CPE_REQUIRE_MSG(directory_entries(authority.store()) == listing,
                    "a refused open must not add or remove a single file");
    const StoreInspection inspection = dccp::epoch::inspect_store(authority.store());
    CPE_REQUIRE_MSG(!inspection.verified(), "a store with an over-declared generation must not verify");
    CPE_REQUIRE_MSG(!inspection.problems().empty(), "the over-declared length must be reported");
  }

  // The write path honours the configured bound: a store that cannot hold the
  // image refuses to initialize and publishes nothing at all.
  {
    cpe_test::TempDirectory directory;
    StoreOpenOptions tiny;
    tiny.directory = directory.path();
    tiny.max_snapshot_bytes = 256;
    ControlPlaneEpochAuthority authority(tiny);
    CPE_REQUIRE_THROWS_CODE(authority.initialize(initialization_request("facility-alpha", "authority-root")),
                            ErrorCode::DurableLimitsExceeded);
    CPE_REQUIRE_MSG(!authority.initialized(), "a refused initialization must not create a domain");
    CPE_REQUIRE_MSG(!std::filesystem::exists(directory.file("authority.state")),
                    "a refused initialization must not publish a generation");
    CPE_REQUIRE_MSG(!std::filesystem::exists(directory.file("authority.floor")),
                    "a refused initialization must not publish a floor");
    CPE_REQUIRE_MSG(temporary_names(directory.path()).empty(), "a refused commit leaves no temporary behind");

    // The same directory is still usable once the bound is realistic: nothing
    // partial was left behind by the refusal.
    authority.close();
    StoreOpenOptions proper;
    proper.directory = directory.path();
    ControlPlaneEpochAuthority retry(proper);
    CPE_REQUIRE(retry.initialize(initialization_request("facility-alpha", "authority-root")).has_value());
    CPE_REQUIRE_MSG(retry.initialized(), "the directory must be usable after a refused initialization");
    CPE_REQUIRE_EQ(retry.status().epoch().value(), std::uint64_t{1});
  }
}

// ---------------------------------------------------------------------------
// Durability fault injection
// ---------------------------------------------------------------------------

CPE_TEST(adversarial, durability_faults_leave_the_previous_generation_authoritative) {
  const DurableFaultPoint points[] = {DurableFaultPoint::AfterTempWrite, DurableFaultPoint::AfterTempVerify,
                                      DurableFaultPoint::AfterRetainPrevious, DurableFaultPoint::AfterPublish,
                                      DurableFaultPoint::AfterFloorWrite};

  for (const DurableFaultPoint point : points) {
    const std::string label(dccp::epoch::detail::durable_fault_point_token(point));
    dccp::epoch::detail::clear_durable_fault();
    CPE_REQUIRE_MSG(!dccp::epoch::detail::durable_fault_armed(), label + ": the seam must start unarmed");

    cpe_test::TestAuthority authority;
    (void)authority.register_controller("base-a");
    const AuthorityStatus before = authority.authority().status();
    const std::string before_text = before.to_string();

    dccp::epoch::detail::arm_durable_fault(point);
    CPE_REQUIRE_MSG(dccp::epoch::detail::durable_fault_armed(), label + ": arming must be observable");
    CPE_REQUIRE_THROWS_CODE(authority.authority().register_controller(registration_request("faulted")),
                            ErrorCode::CommitFailed);
    CPE_REQUIRE_MSG(!dccp::epoch::detail::durable_fault_armed(),
                    label + ": reaching the boundary must consume the arming");

    // The refused commit changed nothing observable, and left no temporary file
    // behind: the publication protocol either completed or never started.
    CPE_REQUIRE_MSG(authority.authority().status().to_string() == before_text,
                    label + ": a failed commit must not change the in-memory status");
    CPE_REQUIRE_MSG(temporary_names(authority.store()).empty(),
                    label + ": a failed commit must not leave a temporary file behind");

    authority.reopen();
    const AuthorityStatus after = authority.authority().status();
    CPE_REQUIRE_MSG(after.epoch().value() >= before.epoch().value(), label + ": the epoch must never roll back");
    CPE_REQUIRE_MSG(after.durable_generation().value() >= before.durable_generation().value(),
                    label + ": the durable generation must never roll back");

    const bool published_before_failure =
        point == DurableFaultPoint::AfterPublish || point == DurableFaultPoint::AfterFloorWrite;
    if (!published_before_failure) {
      // The failure happened before the atomic replace, so the previously
      // published generation is exactly what comes back.
      CPE_REQUIRE_MSG(after.to_string() == before_text,
                      label + ": the previously published generation must stay authoritative");
    } else {
      // The bytes were published before the failure, but the acknowledgements
      // were not: either the old state or the complete new state is
      // authoritative, never a half-written mixture.
      CPE_REQUIRE_MSG(after.controller_count() == before.controller_count() ||
                          after.controller_count() == before.controller_count() + 1,
                      label + ": reopening must yield the old state or the complete new state");
      if (after.controller_count() == before.controller_count() + 1) {
        const Result<dccp::epoch::ControllerRecord> faulted =
            authority.authority().controller_record(controller_id("faulted"));
        CPE_REQUIRE_MSG(faulted.has_value(), label + ": a published registration must be complete");
        CPE_REQUIRE_EQ(faulted.value().registration_count(), std::uint64_t{1});
        CPE_REQUIRE_MSG(faulted.value().is_authoritative_incarnation(),
                        label + ": a published registration must be the authoritative incarnation");
      } else {
        CPE_REQUIRE_MSG(!authority.authority().controller_record(controller_id("faulted")).has_value(),
                        label + ": an unpublished registration must not appear");
      }
    }

    // The store still verifies, and the audit trail still chains.
    const StoreInspection inspection = dccp::epoch::inspect_store(authority.store());
    CPE_REQUIRE_MSG(inspection.verified(), label + ": the settled store must verify: " + inspection.to_string());
    CPE_REQUIRE_MSG(inspection.problems().empty(), label + ": a settled store must have no problems");
    CPE_REQUIRE_MSG(inspection.transition_chain_verified(), label + ": the transition chain must verify");
    CPE_REQUIRE_EQ(inspection.epoch()->value(), after.epoch().value());
    CPE_REQUIRE_EQ(inspection.controller_count(), after.controller_count());
    CPE_REQUIRE_EQ(inspection.snapshot_digest(), after.snapshot_digest());
    CPE_REQUIRE_EQ(inspection.floor_epoch()->value(), after.epoch().value());
    CPE_REQUIRE_MSG(temporary_names(authority.store()).empty(), label + ": no temporary may survive a reopen");

    // The store is fully usable afterwards: a fault is a rejected command, not
    // a broken store.
    (void)authority.register_controller("after-fault");
    CPE_REQUIRE_EQ(authority.authority().status().controller_count(), after.controller_count() + 1);
    dccp::epoch::detail::clear_durable_fault();
  }
}

CPE_TEST(adversarial, arm_and_clear_cycles_leave_no_residual_state) {
  dccp::epoch::detail::clear_durable_fault();
  CPE_REQUIRE_MSG(!dccp::epoch::detail::durable_fault_armed(), "the seam must start unarmed");

  cpe_test::TestAuthority authority;
  const std::string before = authority.authority().status().to_string();

  // Arming and clearing is not a state change: the authority never learns about
  // the seam, so a long arm/clear history leaves no trace at all.
  const DurableFaultPoint points[] = {DurableFaultPoint::AfterTempWrite, DurableFaultPoint::AfterTempVerify,
                                      DurableFaultPoint::AfterRetainPrevious, DurableFaultPoint::AfterPublish,
                                      DurableFaultPoint::AfterFloorWrite};
  for (std::size_t cycle = 0; cycle < 40; ++cycle) {
    const DurableFaultPoint point = points[cycle % (sizeof(points) / sizeof(points[0]))];
    dccp::epoch::detail::arm_durable_fault(point, cycle % 3);
    CPE_REQUIRE_MSG(dccp::epoch::detail::durable_fault_armed(), "an armed seam must report itself armed");
    CPE_REQUIRE_EQ(authority.authority().status().to_string(), before);
    dccp::epoch::detail::clear_durable_fault();
    CPE_REQUIRE_MSG(!dccp::epoch::detail::durable_fault_armed(), "a cleared seam must report itself unarmed");
    CPE_REQUIRE_EQ(authority.authority().status().to_string(), before);
  }

  // Clearing twice, and arming with the None point, are both disarming.
  dccp::epoch::detail::clear_durable_fault();
  dccp::epoch::detail::clear_durable_fault();
  dccp::epoch::detail::arm_durable_fault(DurableFaultPoint::None, 7);
  CPE_REQUIRE_MSG(!dccp::epoch::detail::durable_fault_armed(), "the None point means disarmed");
  (void)authority.register_controller("after-cycles");
  CPE_REQUIRE_EQ(authority.authority().status().controller_count(), std::uint64_t{2});

  // A consumed fault leaves no residual arming: the next commit succeeds.
  dccp::epoch::detail::arm_durable_fault(DurableFaultPoint::AfterPublish);
  CPE_REQUIRE_THROWS_CODE(authority.authority().register_controller(registration_request("consumed")),
                          ErrorCode::CommitFailed);
  CPE_REQUIRE_MSG(!dccp::epoch::detail::durable_fault_armed(), "a consumed arming is gone");
  (void)authority.register_controller("after-consumed");
  CPE_REQUIRE_EQ(authority.authority().status().controller_count(), std::uint64_t{3});

  // skip_before defers the fault to the nth visit of the boundary, so a test can
  // let earlier commits through untouched and still land on exactly one.
  dccp::epoch::detail::arm_durable_fault(DurableFaultPoint::AfterTempWrite, 2);
  (void)authority.register_controller("skipped-0");
  CPE_REQUIRE_MSG(dccp::epoch::detail::durable_fault_armed(), "a skipped visit must not consume the arming");
  (void)authority.register_controller("skipped-1");
  CPE_REQUIRE_MSG(dccp::epoch::detail::durable_fault_armed(), "the second skipped visit must not consume it either");
  CPE_REQUIRE_THROWS_CODE(authority.authority().register_controller(registration_request("skipped-2")),
                          ErrorCode::CommitFailed);
  CPE_REQUIRE_MSG(!dccp::epoch::detail::durable_fault_armed(), "the third visit must consume the arming");
  CPE_REQUIRE_EQ(authority.authority().status().controller_count(), std::uint64_t{5});

  // The seam is thread-local: this thread's arming is invisible to another
  // thread, which is what keeps concurrent work independent of a test seam.
  dccp::epoch::detail::arm_durable_fault(DurableFaultPoint::AfterPublish);
  bool other_thread_armed = true;
  std::thread other([&other_thread_armed]() noexcept {
    other_thread_armed = dccp::epoch::detail::durable_fault_armed();
  });
  other.join();
  CPE_REQUIRE_MSG(!other_thread_armed, "the durability fault seam must be thread-local");
  dccp::epoch::detail::clear_durable_fault();
  CPE_REQUIRE_MSG(temporary_names(authority.store()).empty(), "no temporary may be left behind");
}

// ---------------------------------------------------------------------------
// Refused commands leave no trace
// ---------------------------------------------------------------------------

CPE_TEST(adversarial, refused_commands_never_change_status) {
  cpe_test::TestAuthority authority;
  const MutationAuthority admin = authority.root_authority();
  // A second domain, so "authority from elsewhere" is a different domain and
  // never accidentally interchangeable with this one.
  cpe_test::TestAuthority foreign_authority("facility-beta", "other-root");
  const MutationAuthority foreign_admin = foreign_authority.root_authority();

  const std::string before = authority.authority().status().to_string();
  const FacilityAuthorityDomainId domain = domain_id(authority.domain());
  const auto require_unchanged = [&](const std::string& what) {
    CPE_REQUIRE_MSG(authority.authority().status().to_string() == before, what + " changed the status");
  };

  // An unset expected epoch is a domain rejection, never an exception, and the
  // same unset command is rejected identically when repeated.
  {
    dccp::epoch::AdvanceEpochRequest request;
    request.expected_current = Epoch::from_trusted(0);
    request.authority = admin;
    request.provenance = provenance_input("operator");
    const Result<dccp::epoch::EpochTransitionRecord> stale = authority.authority().advance_epoch(request);
    CPE_REQUIRE_MSG(stale.code() == ErrorCode::EpochZero, "an unset expected epoch must be rejected as EpochZero");
    require_unchanged("an advancement with an unset expected epoch");
    const Result<dccp::epoch::EpochTransitionRecord> again = authority.authority().advance_epoch(request);
    CPE_REQUIRE_MSG(again.code() == stale.code() && again.rejection().to_string() == stale.rejection().to_string(),
                    "a repeated EpochZero rejection must be identical");
  }
  // An expected epoch that is not the authoritative one is a conflict, and the
  // conflict is reported as retryable.
  {
    dccp::epoch::AdvanceEpochRequest request;
    request.expected_current = Epoch::from_trusted(9);
    request.authority = admin;
    request.provenance = provenance_input("operator");
    const Result<dccp::epoch::EpochTransitionRecord> conflict = authority.authority().advance_epoch(request);
    CPE_REQUIRE_MSG(conflict.code() == ErrorCode::EpochConflict, "a stale expectation must be a conflict");
    CPE_REQUIRE_MSG(dccp::epoch::error_retryable(conflict.code()), "a lost race must be retryable");
    require_unchanged("an advancement with a conflicting expected epoch");
  }
  // Authority from another domain is refused at the domain check.
  {
    dccp::epoch::AdvanceEpochRequest request;
    request.expected_current = Epoch::from_trusted(1);
    request.authority = foreign_admin;
    request.provenance = provenance_input("operator");
    const Result<dccp::epoch::EpochTransitionRecord> cross = authority.authority().advance_epoch(request);
    CPE_REQUIRE_MSG(cross.code() == ErrorCode::DomainMismatch,
                    "authority from another domain must never be accepted here");
    require_unchanged("an advancement presented with foreign authority");
  }

  // Acquisitions that cannot succeed.
  {
    dccp::epoch::AcquireAuthorityRequest request;
    request.controller = controller_id("ghost");
    request.incarnation = ControllerIncarnationId::derive(domain, controller_id("ghost"),
                                                          IncarnationNumber::from_trusted(1));
    request.scopes = scope_set({"facility.inventory"});
    request.provenance = provenance_input("ghost");
    const Result<AuthorityGrantView> unknown = authority.authority().acquire_authority(request);
    CPE_REQUIRE_MSG(unknown.code() == ErrorCode::ControllerUnknown,
                    "an acquisition for an unregistered controller must name the controller");
    require_unchanged("an acquisition for an unregistered controller");
  }
  {
    dccp::epoch::AcquireAuthorityRequest request;
    request.controller = controller_id("worker-a");
    request.incarnation = ControllerIncarnationId::derive(domain, controller_id("worker-a"),
                                                          IncarnationNumber::from_trusted(1));
    request.provenance = provenance_input("worker-a");
    const Result<AuthorityGrantView> empty = authority.authority().acquire_authority(request);
    CPE_REQUIRE_MSG(empty.code() == ErrorCode::InvalidArgument,
                    "an acquisition covering no scope must be refused");
    require_unchanged("an acquisition covering no scope");
  }
  {
    dccp::epoch::AcquireAuthorityRequest request;
    request.controller = controller_id("worker-a");
    request.incarnation = ControllerIncarnationId::derive(domain, controller_id("worker-a"),
                                                          IncarnationNumber::from_trusted(1));
    request.scopes = scope_set({"facility.undeclared"});
    request.sponsor = admin;
    request.provenance = provenance_input("worker-a");
    const Result<AuthorityGrantView> undeclared = authority.authority().acquire_authority(request);
    CPE_REQUIRE_MSG(undeclared.code() == ErrorCode::ScopeUnknown,
                    "a scope the domain never declared must be refused");
    require_unchanged("an acquisition of an undeclared scope");
  }

  // Registrations with empty required text and missing provenance.
  {
    dccp::epoch::RegisterControllerRequest request;
    request.controller = dccp::epoch::ControllerId::from_trusted("");
    request.provenance = provenance_input("operator", dccp::epoch::ProvenanceSourceKind::Operator);
    const Result<dccp::epoch::ControllerRegistration> empty = authority.authority().register_controller(request);
    CPE_REQUIRE_MSG(empty.code() == ErrorCode::IdentifierEmpty, "an empty controller identifier must be refused");
    require_unchanged("a registration with an empty controller identifier");
  }
  {
    dccp::epoch::RegisterControllerRequest request;
    request.controller = controller_id("worker-a");
    const Result<dccp::epoch::ControllerRegistration> missing = authority.authority().register_controller(request);
    CPE_REQUIRE_MSG(missing.code() == ErrorCode::InvalidArgument,
                    "a registration without provenance must be refused");
    require_unchanged("a registration without provenance");
  }

  // Revocations of things that do not exist, and with foreign authority.
  {
    RevokeAuthorityRequest request;
    request.target = RevocationTarget::controller_all(controller_id("ghost"));
    request.authority = admin;
    request.provenance = provenance_input("operator");
    const Result<dccp::epoch::RevocationRecord> unknown = authority.authority().revoke_authority(request);
    CPE_REQUIRE_MSG(unknown.code() == ErrorCode::RevocationUnknownTarget,
                    "revoking an unregistered controller must be refused");
    require_unchanged("a revocation of an unregistered controller");
  }
  {
    RevokeAuthorityRequest request;
    request.target = RevocationTarget::grant(GrantId::from_trusted(4242), controller_id("ghost"));
    request.authority = admin;
    request.provenance = provenance_input("operator");
    const Result<dccp::epoch::RevocationRecord> unknown = authority.authority().revoke_authority(request);
    CPE_REQUIRE_MSG(unknown.code() == ErrorCode::RevocationUnknownTarget,
                    "revoking an unknown grant must be refused");
    require_unchanged("a revocation of an unknown grant");
  }
  {
    RevokeAuthorityRequest request;
    request.target = RevocationTarget::controller_all(controller_id("authority-root"));
    request.authority = foreign_admin;
    request.provenance = provenance_input("operator");
    const Result<dccp::epoch::RevocationRecord> foreign = authority.authority().revoke_authority(request);
    CPE_REQUIRE_MSG(foreign.code() == ErrorCode::DomainMismatch,
                    "a revocation presented with foreign authority must be refused");
    require_unchanged("a revocation presented with foreign authority");
  }

  // Page bounds are rejected, not clamped.
  {
    HistoryQuery zero_limit;
    zero_limit.limit = 0;
    CPE_REQUIRE_MSG(authority.authority().history(zero_limit).code() == ErrorCode::PageLimitExceeded,
                    "a zero page limit must be refused");
    HistoryQuery huge_limit;
    huge_limit.limit = dccp::epoch::max_page_size + 1;
    CPE_REQUIRE_MSG(authority.authority().history(huge_limit).code() == ErrorCode::PageLimitExceeded,
                    "a page limit above the bound must be refused");
    require_unchanged("an out-of-range page limit");
  }

  // A second initialization and an empty snapshot path are both refused.
  {
    CPE_REQUIRE_MSG(authority.authority()
                        .initialize(initialization_request("facility-gamma", "other-root"))
                        .code() == ErrorCode::StoreAlreadyInitialized,
                    "re-initializing an initialized store must be refused");
    require_unchanged("a second initialization");
    CPE_REQUIRE_THROWS_CODE(authority.authority().write_snapshot_artifact(""), ErrorCode::PathInvalid);
    require_unchanged("a snapshot artifact with an empty path");
  }
  // A store with no domain refuses everything domain-scoped instead of
  // inventing epoch zero.
  {
    cpe_test::TempDirectory directory;
    StoreOpenOptions options;
    options.directory = directory.path();
    ControlPlaneEpochAuthority fresh(options);
    CPE_REQUIRE_THROWS_CODE(fresh.register_controller(registration_request("worker-a")),
                            ErrorCode::StoreNotInitialized);
    CPE_REQUIRE_THROWS_CODE(fresh.status(), ErrorCode::StoreNotInitialized);
    CPE_REQUIRE_EQ(fresh.accounting().controller_records(), std::uint64_t{0});
    CPE_REQUIRE_MSG(!fresh.initialized(), "a refused command must not initialize the domain");
  }

  // The foreign authority was only ever a source of unusable authority: it must
  // be exactly as it was.
  CPE_REQUIRE_EQ(foreign_authority.authority().status().controller_count(), std::uint64_t{1});
  CPE_REQUIRE_EQ(foreign_authority.authority().status().transition_count(), std::uint64_t{1});
  CPE_REQUIRE_EQ(foreign_authority.authority().status().epoch().value(), std::uint64_t{1});
  CPE_REQUIRE_MSG(foreign_authority.authority().status().live_grant_count() >= 1,
                  "the foreign authority must still hold its own live grants");

  // After the whole battery, this authority is byte-identical to where it began.
  CPE_REQUIRE_EQ(authority.authority().status().to_string(), before);
  CPE_REQUIRE_EQ(authority.authority().status().controller_count(), std::uint64_t{1});
  CPE_REQUIRE_EQ(authority.authority().status().transition_count(), std::uint64_t{1});
  CPE_REQUIRE_EQ(authority.authority().status().revocation_count(), std::uint64_t{0});
  CPE_REQUIRE_EQ(authority.authority().accounting().idempotency_records(), std::uint64_t{0});
}
