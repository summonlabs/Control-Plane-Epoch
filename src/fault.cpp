// Control Plane Epoch 1.0.0 - Summon Software Labs
// Deterministic durability fault seam.
#include "fault.hpp"

#include "control_plane_epoch/error.hpp"

namespace dccp::epoch::detail {
namespace {

struct FaultPlan {
  DurableFaultPoint point = DurableFaultPoint::None;
  std::uint64_t skip_before = 0;
};

thread_local FaultPlan g_plan{};

}  // namespace

std::string_view durable_fault_point_token(DurableFaultPoint point) noexcept {
  switch (point) {
    case DurableFaultPoint::None:
      return "none";
    case DurableFaultPoint::AfterTempWrite:
      return "after_temp_write";
    case DurableFaultPoint::AfterTempVerify:
      return "after_temp_verify";
    case DurableFaultPoint::AfterRetainPrevious:
      return "after_retain_previous";
    case DurableFaultPoint::AfterPublish:
      return "after_publish";
    case DurableFaultPoint::AfterFloorWrite:
      return "after_floor_write";
  }
  return "unknown";
}

void arm_durable_fault(DurableFaultPoint point, std::uint64_t skip_before) {
  g_plan.point = point;
  g_plan.skip_before = skip_before;
}

void clear_durable_fault() noexcept {
  g_plan.point = DurableFaultPoint::None;
  g_plan.skip_before = 0;
}

bool durable_fault_armed() noexcept { return g_plan.point != DurableFaultPoint::None; }

void reach_durable_fault_point(DurableFaultPoint point) {
  if (g_plan.point == DurableFaultPoint::None || g_plan.point != point) {
    return;
  }
  if (g_plan.skip_before > 0) {
    --g_plan.skip_before;
    return;
  }
  const std::string detail =
      std::string("injected durability fault ") + std::string(durable_fault_point_token(point));
  g_plan.point = DurableFaultPoint::None;
  g_plan.skip_before = 0;
  throw EpochError(ErrorCode::CommitFailed, detail);
}

}  // namespace dccp::epoch::detail
