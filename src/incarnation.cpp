// Control Plane Epoch 1.0.0 - Summon Software Labs
// Controller incarnation identity, lifecycle tokens, and record rendering.
#include "control_plane_epoch/incarnation.hpp"

#include <array>

#include "encoding.hpp"
#include "format.hpp"

namespace dccp::epoch {
namespace {

struct StateToken {
  IncarnationState state;
  std::string_view token;
};

constexpr std::array<StateToken, 3> kStateTokens{{
    {IncarnationState::Current, "current"},
    {IncarnationState::Superseded, "superseded"},
    {IncarnationState::Revoked, "revoked"},
}};

/// Domain separation tag for incarnation derivation. Changing the derivation
/// requires a new tag, so old and new derivations can never collide.
constexpr std::string_view kIncarnationTag = "control-plane-epoch.incarnation.v1";

}  // namespace

ControllerIncarnationId ControllerIncarnationId::derive(const FacilityAuthorityDomainId& domain,
                                                        const ControllerId& controller,
                                                        IncarnationNumber number) {
  Sha256 hasher;
  detail::hash_text(hasher, kIncarnationTag);
  detail::hash_text(hasher, domain.view());
  detail::hash_text(hasher, controller.view());
  detail::hash_u64(hasher, number.value());
  return ControllerIncarnationId::from_digest(hasher.finish());
}

Result<ControllerIncarnationId> ControllerIncarnationId::from_hex(std::string_view text) {
  Result<Sha256Digest> digest = Sha256Digest::from_hex(text);
  if (!digest.has_value()) {
    return digest.rejection();
  }
  if (digest.value().is_zero()) {
    return Explanation(ErrorCode::InvalidArgument, "an incarnation identity is never the zero digest");
  }
  return ControllerIncarnationId::from_digest(digest.value());
}

std::string_view incarnation_state_token(IncarnationState state) noexcept {
  for (const StateToken& entry : kStateTokens) {
    if (entry.state == state) {
      return entry.token;
    }
  }
  return "unknown";
}

Result<IncarnationState> parse_incarnation_state(std::string_view token) {
  for (const StateToken& entry : kStateTokens) {
    if (entry.token == token) {
      return entry.state;
    }
  }
  return Explanation(ErrorCode::EnumOutOfDomain, "unknown incarnation state " + std::string(token));
}

std::string ControllerRecord::to_string() const {
  std::string text;
  detail::append_field(text, "controller", controller_.view());
  detail::append_field(text, "incarnation", incarnation_number_.to_string());
  detail::append_field(text, "incarnation_id", incarnation_id_.to_hex());
  detail::append_field(text, "incarnation_state", incarnation_state_token(incarnation_state_));
  detail::append_field(text, "registrations", std::to_string(registration_count_));
  detail::append_field(text, "first_epoch", first_registered_epoch_.to_string());
  detail::append_field(text, "latest_epoch", latest_registered_epoch_.to_string());
  detail::append_field(text, "revoked_through", revocation_through_incarnation_.has_value()
                                                  ? revocation_through_incarnation_->to_string()
                                                  : std::string("-"));
  return text;
}

std::string ControllerRegistration::to_string() const {
  std::string text;
  detail::append_field(text, "controller", controller_.view());
  detail::append_field(text, "incarnation", incarnation_number_.to_string());
  detail::append_field(text, "incarnation_id", incarnation_id_.to_hex());
  detail::append_field(text, "epoch", epoch_.to_string());
  detail::append_field(text, "registration_sequence", sequence_.to_string());
  detail::append_field(text, "replayed", detail::yes_no(replayed_));
  return text;
}

}  // namespace dccp::epoch
