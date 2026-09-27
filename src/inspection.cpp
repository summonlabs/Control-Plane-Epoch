// Control Plane Epoch 1.0.0 - Summon Software Labs
// Rendering of status, accounting, and store inspection views.
#include "control_plane_epoch/inspection.hpp"

#include <string>

#include "format.hpp"

namespace dccp::epoch {

std::string AuthorityStatus::to_string() const {
  std::string text;
  detail::append_field(text, "initialized", detail::yes_no(initialized_));
  detail::append_field(text, "domain", domain_.empty() ? std::string("-") : domain_.to_string());
  detail::append_field(text, "domain_instance", domain_instance_.to_string());
  detail::append_field(text, "epoch", epoch_.to_string());
  detail::append_field(text, "durable_generation", durable_generation_.to_string());
  detail::append_field(text, "authority_root", authority_root_.empty() ? std::string("-") : authority_root_.to_string());
  detail::append_field(text, "controllers", std::to_string(controller_count_));
  detail::append_field(text, "live_grants", std::to_string(live_grant_count_));
  detail::append_field(text, "mutation_grants", std::to_string(mutation_grant_count_));
  detail::append_field(text, "observation_grants", std::to_string(observation_grant_count_));
  std::string scopes;
  for (const ScopeName& scope : declared_scopes_) {
    if (!scopes.empty()) {
      scopes.push_back(',');
    }
    scopes.append(scope.view());
  }
  detail::append_field(text, "declared_scopes", detail::or_dash(scopes));
  detail::append_field(text, "transitions", std::to_string(transition_count_));
  detail::append_field(text, "revocations", std::to_string(revocation_count_));
  detail::append_field(text, "idempotency_records", std::to_string(idempotency_record_count_));
  detail::append_field(text, "snapshot_digest", snapshot_digest_.to_hex());
  detail::append_field(text, "transition_chain_head", transition_chain_head_.to_hex());
  detail::append_field(text, "recovery_outcome", recovery_outcome_token(recovery_outcome_));
  detail::append_field(text, "open_mode", store_open_mode_token(open_mode_));
  return text;
}

std::string AuthorityAccounting::to_string() const {
  std::string text;
  detail::append_field(text, "controller_records", std::to_string(controller_records_));
  detail::append_field(text, "grant_records", std::to_string(grant_records_));
  detail::append_field(text, "live_grant_records", std::to_string(live_grant_records_));
  detail::append_field(text, "transition_records_retained", std::to_string(transition_records_retained_));
  detail::append_field(text, "transition_records_trimmed", std::to_string(transition_records_trimmed_));
  detail::append_field(text, "revocation_records_retained", std::to_string(revocation_records_retained_));
  detail::append_field(text, "revocation_records_trimmed", std::to_string(revocation_records_trimmed_));
  detail::append_field(text, "idempotency_records", std::to_string(idempotency_records_));
  detail::append_field(text, "idempotency_records_evicted", std::to_string(idempotency_records_evicted_));
  detail::append_field(text, "snapshot_bytes", std::to_string(snapshot_bytes_));
  detail::append_field(text, "retained_previous_generation", detail::yes_no(retained_previous_generation_));
  return text;
}

}  // namespace dccp::epoch
