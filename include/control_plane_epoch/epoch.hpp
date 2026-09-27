// Control Plane Epoch 1.0.0 - Summon Software Labs
// The authoritative control-plane epoch value and its transition vocabulary.
#pragma once

#include <compare>
#include <cstdint>
#include <string>
#include <string_view>

#include "control_plane_epoch/error.hpp"

namespace dccp::epoch {

/// A committed control-plane epoch of one facility authority domain.
///
/// Epoch values are strictly monotonic and never reused. Zero is not a
/// committed epoch: an authority domain always has an epoch, and the first one
/// is 1. Absence is expressed with std::optional, never with a sentinel.
class Epoch {
 public:
  Epoch() = default;

  [[nodiscard]] static Epoch initial() noexcept { return Epoch(1); }
  [[nodiscard]] static Result<Epoch> from_value(std::uint64_t value) {
    if (value == 0) {
      return Explanation(ErrorCode::EpochZero, "epoch value 0 is not a committed epoch");
    }
    return Epoch(value);
  }

  /// Constructs from a value already validated by from_value(), successor(), or
  /// an integrity-checked durable image.
  [[nodiscard]] static Epoch from_trusted(std::uint64_t value) noexcept { return Epoch(value); }

  [[nodiscard]] std::uint64_t value() const noexcept { return value_; }
  [[nodiscard]] bool is_initial() const noexcept { return value_ == 1; }

  /// The only way an epoch may move forward: exactly one step, checked.
  [[nodiscard]] Result<Epoch> successor() const {
    if (value_ == UINT64_MAX) {
      return Explanation(ErrorCode::EpochExhausted, "epoch is at its maximum value");
    }
    return Epoch(value_ + 1);
  }

  [[nodiscard]] std::string to_string() const { return std::to_string(value_); }

  friend bool operator==(Epoch lhs, Epoch rhs) noexcept { return lhs.value_ == rhs.value_; }
  friend bool operator!=(Epoch lhs, Epoch rhs) noexcept { return !(lhs == rhs); }
  friend std::strong_ordering operator<=>(Epoch lhs, Epoch rhs) noexcept { return lhs.value_ <=> rhs.value_; }

 private:
  explicit Epoch(std::uint64_t value) noexcept : value_(value) {}

  std::uint64_t value_ = 0;
};

/// Why an epoch transition was committed. The reason is persisted, so the
/// numeric values are part of the durable schema and never change.
enum class EpochTransitionReason : std::uint32_t {
  Genesis = 1,
  OperatorRequest = 2,
  Fencing = 3,
  Recovery = 4,
  FacilityReconfiguration = 5,
};

inline constexpr std::uint32_t max_epoch_transition_reason = 5;

[[nodiscard]] std::string_view epoch_transition_reason_token(EpochTransitionReason reason) noexcept;
[[nodiscard]] Result<EpochTransitionReason> parse_epoch_transition_reason(std::string_view token);

}  // namespace dccp::epoch
