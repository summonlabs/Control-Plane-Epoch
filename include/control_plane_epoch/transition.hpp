// Control Plane Epoch 1.0.0 - Summon Software Labs
// The epoch transition ledger.
//
// Every committed epoch advancement appends exactly one immutable record. Each
// record carries the digest of its predecessor, so the retained history forms a
// verifiable chain: truncation, reordering, or substitution anywhere in the
// retained window is detected rather than silently accepted. Records trimmed by
// the retention bound are represented by a durable anchor that the oldest
// retained record still chains to.
#pragma once

#include <cstdint>
#include <string>

#include "control_plane_epoch/authority.hpp"
#include "control_plane_epoch/digest.hpp"
#include "control_plane_epoch/epoch.hpp"
#include "control_plane_epoch/error.hpp"
#include "control_plane_epoch/identity.hpp"
#include "control_plane_epoch/incarnation.hpp"
#include "control_plane_epoch/provenance.hpp"

namespace dccp::epoch {

namespace detail {
struct RecordFactory;
}

/// Immutable view of one committed epoch transition.
class EpochTransitionRecord {
 public:
  EpochTransitionRecord() = default;

  [[nodiscard]] TransitionSequence sequence() const noexcept { return sequence_; }
  [[nodiscard]] Epoch base_epoch() const noexcept { return base_epoch_; }
  [[nodiscard]] Epoch new_epoch() const noexcept { return new_epoch_; }
  [[nodiscard]] EpochTransitionReason reason() const noexcept { return reason_; }

  /// Controller that committed the transition, and the incarnation and grant it
  /// presented. For the genesis record these identify the authority root.
  [[nodiscard]] const ControllerId& committed_by() const noexcept { return committed_by_; }
  [[nodiscard]] const ControllerIncarnationId& committed_by_incarnation() const noexcept {
    return committed_by_incarnation_;
  }
  [[nodiscard]] GrantId committed_by_grant() const noexcept { return committed_by_grant_; }

  /// Live mutation grants that this transition fenced by advancing the epoch.
  [[nodiscard]] std::uint64_t fenced_grant_count() const noexcept { return fenced_grant_count_; }

  /// Controllers that were registered at the base epoch. They keep their
  /// identities across the transition but must re-acquire authority.
  [[nodiscard]] std::uint64_t controller_count() const noexcept { return controller_count_; }

  [[nodiscard]] const ProvenanceRecord& provenance() const noexcept { return provenance_; }
  [[nodiscard]] const Sha256Digest& previous_record_digest() const noexcept { return previous_record_digest_; }
  [[nodiscard]] const Sha256Digest& record_digest() const noexcept { return record_digest_; }

  /// True for the record created when the authority domain was initialized or
  /// reinitialized; its base epoch is absent because no predecessor epoch
  /// existed in this durable instance.
  [[nodiscard]] bool is_origin() const noexcept { return origin_; }

  [[nodiscard]] std::string to_string() const;

  friend bool operator==(const EpochTransitionRecord& lhs, const EpochTransitionRecord& rhs) noexcept {
    return lhs.sequence_ == rhs.sequence_ && lhs.base_epoch_ == rhs.base_epoch_ && lhs.new_epoch_ == rhs.new_epoch_ &&
           lhs.reason_ == rhs.reason_ && lhs.committed_by_ == rhs.committed_by_ &&
           lhs.committed_by_incarnation_ == rhs.committed_by_incarnation_ &&
           lhs.committed_by_grant_ == rhs.committed_by_grant_ && lhs.origin_ == rhs.origin_ &&
           lhs.fenced_grant_count_ == rhs.fenced_grant_count_ && lhs.controller_count_ == rhs.controller_count_;
  }
  friend bool operator!=(const EpochTransitionRecord& lhs, const EpochTransitionRecord& rhs) noexcept {
    return !(lhs == rhs);
  }

 private:
  friend struct detail::RecordFactory;

  TransitionSequence sequence_;
  Epoch base_epoch_;
  Epoch new_epoch_;
  EpochTransitionReason reason_ = EpochTransitionReason::Genesis;
  ControllerId committed_by_;
  ControllerIncarnationId committed_by_incarnation_;
  GrantId committed_by_grant_;
  std::uint64_t fenced_grant_count_ = 0;
  std::uint64_t controller_count_ = 0;
  bool origin_ = false;
  ProvenanceRecord provenance_;
  Sha256Digest previous_record_digest_;
  Sha256Digest record_digest_;
};

/// One page of the transition ledger, in ascending sequence order.
class EpochHistoryPage {
 public:
  EpochHistoryPage() = default;

  [[nodiscard]] const std::vector<EpochTransitionRecord>& records() const noexcept { return records_; }
  [[nodiscard]] std::uint64_t total_count() const noexcept { return total_count_; }
  [[nodiscard]] std::uint64_t first_retained_sequence() const noexcept { return first_retained_sequence_; }
  [[nodiscard]] std::uint64_t trimmed_count() const noexcept { return trimmed_count_; }

  /// Digest of the most recent trimmed record, or zero when nothing was trimmed.
  [[nodiscard]] const Sha256Digest& history_anchor() const noexcept { return history_anchor_; }

  /// Digest of the newest retained record; zero for an empty ledger.
  [[nodiscard]] const Sha256Digest& chain_head() const noexcept { return chain_head_; }

  friend bool operator==(const EpochHistoryPage& lhs, const EpochHistoryPage& rhs) noexcept {
    return lhs.records_ == rhs.records_ && lhs.total_count_ == rhs.total_count_ &&
           lhs.first_retained_sequence_ == rhs.first_retained_sequence_ && lhs.trimmed_count_ == rhs.trimmed_count_ &&
           lhs.history_anchor_ == rhs.history_anchor_ && lhs.chain_head_ == rhs.chain_head_;
  }

 private:
  friend struct detail::RecordFactory;

  std::vector<EpochTransitionRecord> records_;
  std::uint64_t total_count_ = 0;
  std::uint64_t first_retained_sequence_ = 0;
  std::uint64_t trimmed_count_ = 0;
  Sha256Digest history_anchor_;
  Sha256Digest chain_head_;
};

}  // namespace dccp::epoch
