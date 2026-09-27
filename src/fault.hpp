// Control Plane Epoch 1.0.0 - Summon Software Labs
// Deterministic durability fault seam. Internal test seam; not installed and
// not reachable from the public API or from the wire protocol.
//
// Crash behaviour of a durable commit is only provable at exact boundaries:
// "power was lost somewhere between publishing the generation and publishing the
// floor". Waiting for a real crash to land in the right place is not a proof, so
// the store consults this seam at each durability boundary. The seam is
// thread-local, unarmed by default, and does nothing unless a test in this
// repository's own test binary arms it through the internal header. When armed it
// raises EpochError(CommitFailed) with the boundary named in the detail, which is
// an observable, deterministic stand-in for the process dying at that point.
// Tests then close the store and reopen it, exactly as a restart would.
#pragma once

#include <cstdint>
#include <string_view>

namespace dccp::epoch::detail {

/// Boundaries inside one durable commit, in execution order.
enum class DurableFaultPoint : std::uint32_t {
  None = 0,
  AfterTempWrite = 1,
  AfterTempVerify = 2,
  AfterRetainPrevious = 3,
  AfterPublish = 4,
  AfterFloorWrite = 5,
};

[[nodiscard]] std::string_view durable_fault_point_token(DurableFaultPoint point) noexcept;

/// Arms the seam: the next commit that reaches `point` (after skipping
/// `skip_before` occurrences) fails at that boundary. Passing
/// DurableFaultPoint::None disarms.
void arm_durable_fault(DurableFaultPoint point, std::uint64_t skip_before = 0);

void clear_durable_fault() noexcept;

[[nodiscard]] bool durable_fault_armed() noexcept;

/// Called by the store at each boundary. Throws when this boundary is the armed
/// one, and consumes the arming.
void reach_durable_fault_point(DurableFaultPoint point);

}  // namespace dccp::epoch::detail
