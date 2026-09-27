// Control Plane Epoch 1.0.0 - Summon Software Labs
// Internal authoritative image and its canonical durable encoding.
//
// The image is the whole authoritative state of one facility authority domain:
// the domain identity, the current epoch, the durable generation, registered
// controller incarnations, the live grants of the current epoch, the revocation
// ledger, the epoch transition ledger, and the retained idempotency outcomes.
//
// Encoding is canonical and deterministic: identical images produce identical
// bytes, and therefore identical digests. Decoding validates every field
// against a bound and every collection against its canonical order before the
// data is trusted.
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "control_plane_epoch/version.hpp"

#include "records.hpp"

namespace dccp::epoch::detail {

/// Bounds applied while encoding and decoding an image.
struct ImageLimits {
  std::size_t max_bytes = max_snapshot_bytes;
  std::size_t max_controllers = ::dccp::epoch::max_controllers;
  std::size_t max_grants = max_grants_per_epoch;
  std::size_t max_transitions = max_transition_records;
  std::size_t max_revocations = max_revocation_records;
  std::size_t max_idempotency = max_idempotency_records;
};

/// The whole authoritative state of one domain.
struct AuthorityImage {
  std::uint32_t schema_version = static_cast<std::uint32_t>(durable_schema_version);
  std::string domain;
  std::uint64_t domain_instance = 0;
  std::uint64_t epoch = 0;
  std::uint64_t durable_generation = 0;
  std::string authority_root;

  /// Declared scopes, ascending.
  std::vector<std::string> declared_scopes;

  /// Registered controllers, ascending by controller identifier.
  std::vector<ControllerData> controllers;

  /// Grants of the current epoch, ascending by grant identifier. Grants never
  /// outlive their epoch, so this collection is emptied by every advancement.
  std::vector<GrantData> grants;

  /// Retained revocations, ascending by sequence.
  std::vector<RevocationData> revocations;
  std::uint64_t revocation_count = 0;
  std::uint64_t revocation_trimmed = 0;
  Sha256Digest revocation_anchor;

  /// Retained epoch transitions, ascending by sequence.
  std::vector<TransitionData> transitions;
  std::uint64_t transition_count = 0;
  std::uint64_t transition_trimmed = 0;
  Sha256Digest transition_anchor;

  /// Retained idempotency outcomes, ascending by (controller, incarnation, sequence).
  std::vector<IdempotencyData> idempotency;
  std::uint64_t idempotency_count = 0;
  std::uint64_t idempotency_evicted = 0;

  std::uint64_t next_grant_id = 1;
  std::uint64_t next_mutation_sequence = 1;
};

/// Canonical bytes of one image. Throws EpochError when the image exceeds a
/// configured bound.
[[nodiscard]] std::vector<std::byte> encode_image(const AuthorityImage& image, const ImageLimits& limits);

/// Decodes and fully verifies one image. Every failure raises EpochError with a
/// stable integrity code; nothing is repaired or normalized.
[[nodiscard]] AuthorityImage decode_image(std::span<const std::byte> payload, const ImageLimits& limits);

/// Verifies internal consistency of an already-decoded image: record digests,
/// ledger chains, canonical ordering, cross-references, and bounds.
void verify_image(const AuthorityImage& image, const ImageLimits& limits);

[[nodiscard]] ImageLimits default_image_limits();

// ---------------------------------------------------------------------------
// Durable file envelope
// ---------------------------------------------------------------------------

/// Bytes in the durable file header.
inline constexpr std::size_t envelope_header_bytes = 64;

/// One durable generation on disk: header plus canonical payload.
struct FileEnvelope {
  std::uint16_t format_version = static_cast<std::uint16_t>(durable_format_version);
  std::uint16_t schema_version = static_cast<std::uint16_t>(durable_schema_version);
  std::uint32_t flags = 0;
  std::uint64_t generation = 0;
  std::uint64_t epoch = 0;
  Sha256Digest payload_digest;
  std::vector<std::byte> payload;
};

[[nodiscard]] std::vector<std::byte> encode_envelope(const FileEnvelope& envelope, std::size_t max_total_bytes);
[[nodiscard]] FileEnvelope decode_envelope(std::span<const std::byte> bytes, std::size_t max_total_bytes);

/// Payload of the durable floor file: the highest generation and epoch that
/// have been acknowledged as durable, and the digest of the generation they
/// bound. The digest is zero when the store currently holds no generation, which
/// is the state a reinitialized store is in until its first commit.
struct FloorData {
  std::string domain;
  std::uint64_t domain_instance = 0;
  std::uint64_t epoch = 0;
  std::uint64_t generation = 0;
  Sha256Digest snapshot_digest;
};

[[nodiscard]] std::vector<std::byte> encode_floor(const FloorData& floor);
[[nodiscard]] FloorData decode_floor(std::span<const std::byte> payload);

}  // namespace dccp::epoch::detail
