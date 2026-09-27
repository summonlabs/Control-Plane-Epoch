// Control Plane Epoch 1.0.0 - Summon Software Labs
// Hard, non-negotiable resource bounds. Every externally influenced size,
// count, or length is checked against one of these values before allocation or
// mutation. Nothing in the library grows without a bound.
#pragma once

#include <cstddef>
#include <cstdint>

namespace dccp::epoch {

// ---------------------------------------------------------------------------
// Identity and text
// ---------------------------------------------------------------------------

/// Maximum length of any stable identifier (domain, controller, scope,
/// provenance source). Identifiers are ASCII, so bytes and characters agree.
inline constexpr std::size_t max_identifier_length = 96;

/// Maximum length of an external opaque reference value (for example an ASI or
/// DFI object identifier referenced by this repository).
inline constexpr std::size_t max_external_reference_length = 256;

/// Maximum length of the external reference kind tag.
inline constexpr std::size_t max_external_reference_kind_length = 32;

/// Maximum length of a human note carried in provenance.
inline constexpr std::size_t max_note_length = 256;

// ---------------------------------------------------------------------------
// Authority domain shape
// ---------------------------------------------------------------------------

/// Maximum number of scopes declared by an authority domain.
inline constexpr std::size_t max_declared_scopes = 256;

/// Maximum number of scopes a single authority grant may cover.
inline constexpr std::size_t max_scopes_per_authority = 64;

/// Maximum number of controller identities registered in a domain.
inline constexpr std::size_t max_controllers = 65536;

/// Maximum number of live authority grants within one epoch.
inline constexpr std::size_t max_grants_per_epoch = 65536;

/// Maximum number of retained epoch transition records. Older records are
/// trimmed; the retained chain stays verifiable through a durable anchor.
inline constexpr std::size_t max_transition_records = 4096;

/// Maximum number of retained revocation records (same trimming model).
inline constexpr std::size_t max_revocation_records = 4096;

/// Maximum number of retained idempotency outcomes. Idempotency is guaranteed
/// for the retained window only, and that limit is stated in the README.
inline constexpr std::size_t max_idempotency_records = 4096;

/// Maximum size of one retained idempotency result blob.
inline constexpr std::size_t max_idempotency_blob_bytes = 4096;

/// Maximum number of records returned by a single paged inspection call.
inline constexpr std::size_t max_page_size = 256;

// ---------------------------------------------------------------------------
// Durable state
// ---------------------------------------------------------------------------

/// Maximum bytes of one durable snapshot payload. The writer refuses to publish
/// an image larger than this and the reader refuses to allocate for a length
/// field above this bound.
inline constexpr std::size_t max_snapshot_bytes = 64u * 1024u * 1024u;

/// Maximum bytes of a store floor record.
inline constexpr std::size_t max_floor_bytes = 4096;

/// Maximum bytes of an importable or exportable snapshot artifact.
inline constexpr std::size_t max_snapshot_artifact_bytes = max_snapshot_bytes + 4096u;

// ---------------------------------------------------------------------------
// Framed transport
// ---------------------------------------------------------------------------

/// Maximum bytes of one frame payload.
inline constexpr std::size_t max_frame_payload_bytes = 1024u * 1024u;

/// Maximum total bytes of one encoded frame (header + payload + digest).
inline constexpr std::size_t max_frame_bytes = max_frame_payload_bytes + 64u;

/// Maximum number of connections a single authority runtime serves at once.
inline constexpr std::size_t max_server_connections = 128;

/// Maximum number of accepted-but-unstarted sessions queued by the runtime.
inline constexpr std::size_t max_server_queue_depth = 256;

/// Maximum number of worker threads an authority runtime may create.
inline constexpr std::uint32_t max_server_workers = 32;

/// Default worker count for an authority runtime.
inline constexpr std::uint32_t default_server_workers = 4;

/// Maximum requests served on one connection before the runtime requires the
/// client to reconnect. Bounds per-session resource growth.
inline constexpr std::uint64_t max_requests_per_connection = 1000000;

/// Maximum socket backlog used when binding.
inline constexpr int server_listen_backlog = 64;

}  // namespace dccp::epoch
