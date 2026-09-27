// Control Plane Epoch 1.0.0 - Summon Software Labs
// Command value rendering.
#include <string>

#include "control_plane_epoch/commands.hpp"
#include "format.hpp"

namespace dccp::epoch {

std::string RevocationTarget::to_string() const {
  std::string text;
  detail::append_field(text, "target", revocation_target_kind_token(kind()));
  detail::append_field(text, "controller", controller_.view());
  detail::append_field(text, "through_incarnation",
                       through_incarnation_.has_value() ? through_incarnation_->to_string() : std::string("-"));
  detail::append_field(text, "grant", grant_.has_value() ? grant_->to_string() : std::string("-"));
  return text;
}

}  // namespace dccp::epoch
