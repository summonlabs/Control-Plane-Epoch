// Control Plane Epoch 1.0.0 - Summon Software Labs
// Epoch transition rendering.
#include "control_plane_epoch/transition.hpp"

#include "format.hpp"

namespace dccp::epoch {

std::string EpochTransitionRecord::to_string() const {
  std::string text;
  detail::append_field(text, "transition", sequence_.to_string());
  detail::append_field(text, "base_epoch", origin_ ? std::string("-") : base_epoch_.to_string());
  detail::append_field(text, "new_epoch", new_epoch_.to_string());
  detail::append_field(text, "reason", epoch_transition_reason_token(reason_));
  detail::append_field(text, "committed_by", committed_by_.view());
  detail::append_field(text, "committed_by_incarnation", committed_by_incarnation_.to_hex());
  detail::append_field(text, "committed_by_grant", committed_by_grant_.to_string());
  detail::append_field(text, "fenced_grants", std::to_string(fenced_grant_count_));
  detail::append_field(text, "controllers", std::to_string(controller_count_));
  detail::append_field(text, "origin", detail::yes_no(origin_));
  detail::append_field(text, "previous_record_digest", previous_record_digest_.to_hex());
  detail::append_field(text, "record_digest", record_digest_.to_hex());
  return text;
}

}  // namespace dccp::epoch
