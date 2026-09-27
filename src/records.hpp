// Control Plane Epoch 1.0.0 - Summon Software Labs
// Internal record data model, canonical record encoding, and the factory that
// turns validated durable data into immutable public record views. Not
// installed: consumers never see these structures.
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "control_plane_epoch/authority.hpp"
#include "control_plane_epoch/digest.hpp"
#include "control_plane_epoch/epoch.hpp"
#include "control_plane_epoch/incarnation.hpp"
#include "control_plane_epoch/provenance.hpp"
#include "control_plane_epoch/recovery.hpp"
#include "control_plane_epoch/transition.hpp"
#include "encoding.hpp"

namespace dccp::epoch::detail {

// ---------------------------------------------------------------------------
// Durable data model
// ---------------------------------------------------------------------------

struct ProvenanceData {
  ProvenanceSourceKind kind = ProvenanceSourceKind::Initialization;
  std::string source;
  std::optional<ExternalRef> external;
  std::string note;
  std::uint64_t recorded_epoch = 0;
  std::uint64_t recorded_sequence = 0;
  Sha256Digest record_digest;
};

struct ControllerData {
  std::string controller;
  std::uint64_t incarnation_number = 0;
  Sha256Digest incarnation_id;
  IncarnationState incarnation_state = IncarnationState::Current;
  std::uint64_t registration_count = 0;
  std::uint64_t first_registered_epoch = 0;
  std::uint64_t latest_registered_epoch = 0;
  std::optional<std::uint64_t> revocation_through_incarnation;

  /// Most recent superseded incarnation identities, newest first. Bounded by
  /// max_superseded_incarnations, which is what lets a rejected token be
  /// attributed precisely without unbounded per-controller growth.
  std::vector<Sha256Digest> superseded_incarnations;

  ProvenanceData latest_registration_provenance;
  Sha256Digest record_digest;
};

/// State of one grant within its epoch. Epoch fencing is not stored: a grant is
/// implicitly fenced when the epoch advances, because grants never outlive the
/// epoch that issued them.
enum class GrantState : std::uint32_t {
  Live = 1,
  Superseded = 2,
  Revoked = 3,
};

inline constexpr std::uint32_t max_grant_state = 3;

struct GrantData {
  std::uint64_t id = 0;
  AuthorityClass authority_class = AuthorityClass::Mutation;
  std::uint64_t epoch = 0;
  std::string controller;
  std::uint64_t incarnation_number = 0;
  Sha256Digest incarnation_id;
  std::vector<std::string> scopes;
  std::uint64_t sequence = 0;
  GrantState state = GrantState::Live;
  std::optional<std::uint64_t> revoked_by_sequence;
  ProvenanceData provenance;
  Sha256Digest record_digest;
};

struct RevocationData {
  std::uint64_t sequence = 0;
  RevocationTargetKind target_kind = RevocationTargetKind::ControllerIncarnations;
  std::string controller;
  std::optional<std::uint64_t> through_incarnation;
  std::optional<std::uint64_t> grant;
  RevocationReason reason = RevocationReason::OperatorRequest;
  std::uint64_t epoch = 0;
  std::string issued_by;
  Sha256Digest issued_by_incarnation;
  std::uint64_t issued_by_grant = 0;
  std::uint64_t fenced_grant_count = 0;
  bool replayed = false;
  ProvenanceData provenance;
  Sha256Digest previous_record_digest;
  Sha256Digest record_digest;
};

struct TransitionData {
  std::uint64_t sequence = 0;
  bool origin = false;
  std::uint64_t base_epoch = 0;
  std::uint64_t new_epoch = 0;
  EpochTransitionReason reason = EpochTransitionReason::Genesis;
  std::string committed_by;
  Sha256Digest committed_by_incarnation;
  std::uint64_t committed_by_grant = 0;
  std::uint64_t fenced_grant_count = 0;
  std::uint64_t controller_count = 0;
  ProvenanceData provenance;
  Sha256Digest previous_record_digest;
  Sha256Digest record_digest;
};

struct IdempotencyData {
  std::string controller;
  Sha256Digest incarnation_id;
  std::uint64_t sequence = 0;
  Sha256Digest command_digest;
  std::vector<std::byte> result_blob;
};

/// Bounded number of superseded incarnation identities retained per controller.
inline constexpr std::size_t max_superseded_incarnations = 8;

// ---------------------------------------------------------------------------
// Record digests
// ---------------------------------------------------------------------------

[[nodiscard]] Sha256Digest compute_provenance_digest(const ProvenanceData& data);
[[nodiscard]] Sha256Digest compute_controller_digest(const ControllerData& data);
[[nodiscard]] Sha256Digest compute_grant_digest(const GrantData& data);
[[nodiscard]] Sha256Digest compute_revocation_digest(const RevocationData& data);
[[nodiscard]] Sha256Digest compute_transition_digest(const TransitionData& data);

/// Recomputes the record digest and compares it with the stored value.
void verify_record_digest(const ProvenanceData& data, std::string_view what);
void verify_record_digest(const ControllerData& data, std::string_view what);
void verify_record_digest(const GrantData& data, std::string_view what);
void verify_record_digest(const RevocationData& data, std::string_view what);
void verify_record_digest(const TransitionData& data, std::string_view what);

// ---------------------------------------------------------------------------
// Canonical record encoding
// ---------------------------------------------------------------------------

void encode_provenance(CanonicalWriter& writer, const ProvenanceData& data);
[[nodiscard]] ProvenanceData decode_provenance(CanonicalReader& reader);

void encode_controller(CanonicalWriter& writer, const ControllerData& data);
[[nodiscard]] ControllerData decode_controller(CanonicalReader& reader);

void encode_grant(CanonicalWriter& writer, const GrantData& data);
[[nodiscard]] GrantData decode_grant(CanonicalReader& reader);

void encode_revocation(CanonicalWriter& writer, const RevocationData& data);
[[nodiscard]] RevocationData decode_revocation(CanonicalReader& reader);

void encode_transition(CanonicalWriter& writer, const TransitionData& data);
[[nodiscard]] TransitionData decode_transition(CanonicalReader& reader);

/// Canonical encoding of a registration result, used for idempotency blobs so
/// that a replayed response is exactly the response that was recorded.
void encode_registration(CanonicalWriter& writer, const ControllerRegistration& record);
[[nodiscard]] ControllerRegistration decode_registration(CanonicalReader& reader, bool replayed);

// ---------------------------------------------------------------------------
// Public results as durable data, for idempotency result blobs
// ---------------------------------------------------------------------------

[[nodiscard]] ProvenanceData to_data(const ProvenanceRecord& record);
[[nodiscard]] ControllerData to_data(const ControllerRecord& record);
[[nodiscard]] GrantData to_data(const AuthorityGrantRecord& record);
[[nodiscard]] RevocationData to_data(const RevocationRecord& record);
[[nodiscard]] TransitionData to_data(const EpochTransitionRecord& record);
[[nodiscard]] ProvenanceData to_data(const ProvenanceInput& input, std::uint64_t epoch, std::uint64_t sequence);

/// Grants are reconstructed from their durable record; the token is re-derived
/// from the same claims, so a replayed grant response is byte-identical to the
/// original.
[[nodiscard]] Result<AuthorityGrantView> to_grant_view(const GrantData& data,
                                                       const FacilityAuthorityDomainId& domain);

// ---------------------------------------------------------------------------
// Record factory
// ---------------------------------------------------------------------------

struct RecordFactory {
  [[nodiscard]] static ProvenanceRecord make_provenance(const ProvenanceData& data);
  [[nodiscard]] static ControllerRecord make_controller(const ControllerData& data);
  [[nodiscard]] static ControllerRegistration make_registration(const ControllerData& controller,
                                                                const ProvenanceData& provenance);
  [[nodiscard]] static ControllerRegistration mark_replayed(ControllerRegistration record);
  [[nodiscard]] static AuthorityGrantRecord make_grant(const GrantData& data);
  [[nodiscard]] static EpochTransitionRecord make_transition(const TransitionData& data);
  [[nodiscard]] static RevocationRecord make_revocation(const RevocationData& data);
  [[nodiscard]] static RevocationRecord mark_replayed(RevocationRecord record);
  [[nodiscard]] static EpochHistoryPage make_history_page(std::vector<EpochTransitionRecord> records,
                                                          std::uint64_t total_count,
                                                          std::uint64_t first_retained_sequence,
                                                          std::uint64_t trimmed_count, Sha256Digest history_anchor,
                                                          Sha256Digest chain_head);
};

}  // namespace dccp::epoch::detail
