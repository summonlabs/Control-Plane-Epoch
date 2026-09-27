// Control Plane Epoch 1.0.0 - Summon Software Labs
// Epoch transition reason vocabulary.
#include "control_plane_epoch/epoch.hpp"

#include <array>

namespace dccp::epoch {
namespace {

struct ReasonToken {
  EpochTransitionReason reason;
  std::string_view token;
};

constexpr std::array<ReasonToken, 5> kReasonTokens{{
    {EpochTransitionReason::Genesis, "genesis"},
    {EpochTransitionReason::OperatorRequest, "operator_request"},
    {EpochTransitionReason::Fencing, "fencing"},
    {EpochTransitionReason::Recovery, "recovery"},
    {EpochTransitionReason::FacilityReconfiguration, "facility_reconfiguration"},
}};

}  // namespace

std::string_view epoch_transition_reason_token(EpochTransitionReason reason) noexcept {
  for (const ReasonToken& entry : kReasonTokens) {
    if (entry.reason == reason) {
      return entry.token;
    }
  }
  return "unknown";
}

Result<EpochTransitionReason> parse_epoch_transition_reason(std::string_view token) {
  for (const ReasonToken& entry : kReasonTokens) {
    if (entry.token == token) {
      return entry.reason;
    }
  }
  return Explanation(ErrorCode::EnumOutOfDomain, "unknown epoch transition reason " + std::string(token));
}

}  // namespace dccp::epoch
