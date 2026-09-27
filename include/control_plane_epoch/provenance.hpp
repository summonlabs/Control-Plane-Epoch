// Control Plane Epoch 1.0.0 - Summon Software Labs
// Provenance: who caused an authoritative state change, from where, and under
// which epoch it was recorded. Provenance is attached to every accepted
// mutation, persisted with the authoritative state, and never inferred.
#pragma once

#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "control_plane_epoch/digest.hpp"
#include "control_plane_epoch/epoch.hpp"
#include "control_plane_epoch/error.hpp"
#include "control_plane_epoch/identity.hpp"

namespace dccp::epoch {

namespace detail {
struct RecordFactory;
}

/// Kind of source that caused a state change. Numeric values are durable.
enum class ProvenanceSourceKind : std::uint32_t {
  Initialization = 1,
  Controller = 2,
  Operator = 3,
  Recovery = 4,
  Import = 5,
};

inline constexpr std::uint32_t max_provenance_source_kind = 5;

[[nodiscard]] std::string_view provenance_source_kind_token(ProvenanceSourceKind kind) noexcept;
[[nodiscard]] Result<ProvenanceSourceKind> parse_provenance_source_kind(std::string_view token);

/// Validated provenance supplied by a caller. The note is bounded, control
/// characters are rejected, and the source identity must be a valid identifier.
class ProvenanceInput {
 public:
  ProvenanceInput() = default;

  [[nodiscard]] static Result<ProvenanceInput> create(ProvenanceSourceKind kind, ProvenanceSourceId source,
                                                      std::optional<ExternalRef> external, std::string_view note);

  [[nodiscard]] static Result<ProvenanceInput> from_source(ProvenanceSourceKind kind, std::string_view source);

  /// Source kind. Precondition: empty() is false. An empty provenance input is
  /// rejected by every command path before it is read, so reaching this
  /// accessor with no kind is a programming error and raises
  /// EpochError(InvalidArgument) rather than inventing a default.
  [[nodiscard]] ProvenanceSourceKind kind() const;
  [[nodiscard]] const ProvenanceSourceId& source() const noexcept { return source_; }
  [[nodiscard]] const std::optional<ExternalRef>& external() const noexcept { return external_; }
  [[nodiscard]] const std::string& note() const noexcept { return note_; }
  [[nodiscard]] bool empty() const noexcept { return !kind_.has_value(); }
  [[nodiscard]] std::string to_string() const;

  friend bool operator==(const ProvenanceInput& lhs, const ProvenanceInput& rhs) noexcept {
    return lhs.kind_ == rhs.kind_ && lhs.source_ == rhs.source_ && lhs.external_ == rhs.external_ &&
           lhs.note_ == rhs.note_;
  }

 private:
  std::optional<ProvenanceSourceKind> kind_;
  ProvenanceSourceId source_;
  std::optional<ExternalRef> external_;
  std::string note_;
};

/// Immutable provenance record as persisted with an authoritative state change.
class ProvenanceRecord {
 public:
  ProvenanceRecord() = default;

  [[nodiscard]] ProvenanceSourceKind kind() const noexcept { return kind_; }
  [[nodiscard]] const ProvenanceSourceId& source() const noexcept { return source_; }
  [[nodiscard]] const std::optional<ExternalRef>& external() const noexcept { return external_; }
  [[nodiscard]] const std::string& note() const noexcept { return note_; }

  /// Epoch in which the state change was recorded.
  [[nodiscard]] Epoch recorded_epoch() const noexcept { return recorded_epoch_; }

  /// Position of the change in the domain's global mutation ledger.
  [[nodiscard]] std::uint64_t recorded_sequence() const noexcept { return recorded_sequence_; }

  /// Digest over the canonical encoding of this record.
  [[nodiscard]] const Sha256Digest& record_digest() const noexcept { return record_digest_; }

  [[nodiscard]] std::string to_string() const;

  friend bool operator==(const ProvenanceRecord& lhs, const ProvenanceRecord& rhs) noexcept {
    return lhs.kind_ == rhs.kind_ && lhs.source_ == rhs.source_ && lhs.external_ == rhs.external_ &&
           lhs.note_ == rhs.note_ && lhs.recorded_epoch_ == rhs.recorded_epoch_ &&
           lhs.recorded_sequence_ == rhs.recorded_sequence_;
  }
  friend bool operator!=(const ProvenanceRecord& lhs, const ProvenanceRecord& rhs) noexcept { return !(lhs == rhs); }

 private:
  friend struct detail::RecordFactory;

  ProvenanceSourceKind kind_ = ProvenanceSourceKind::Initialization;
  ProvenanceSourceId source_;
  std::optional<ExternalRef> external_;
  std::string note_;
  Epoch recorded_epoch_;
  std::uint64_t recorded_sequence_ = 0;
  Sha256Digest record_digest_;
};

}  // namespace dccp::epoch
