// Control Plane Epoch 1.0.0 - Summon Software Labs
// Rendering and parsing of durable-store vocabulary and reports.
#include <array>
#include <string>

#include "control_plane_epoch/store.hpp"
#include "format.hpp"

namespace dccp::epoch {
namespace {

struct ModeToken {
  StoreOpenMode mode;
  std::string_view token;
};

constexpr std::array<ModeToken, 2> kModeTokens{{
    {StoreOpenMode::ReadWrite, "read-write"},
    {StoreOpenMode::ReadOnly, "read-only"},
}};

struct PolicyToken {
  RecoveryPolicy policy;
  std::string_view token;
};

constexpr std::array<PolicyToken, 3> kPolicyTokens{{
    {RecoveryPolicy::RefuseOnDamage, "refuse-on-damage"},
    {RecoveryPolicy::AdoptPreviousGeneration, "adopt-previous-generation"},
    {RecoveryPolicy::ReinitializeDomain, "reinitialize-domain"},
}};

struct OutcomeToken {
  RecoveryOutcome outcome;
  std::string_view token;
};

constexpr std::array<OutcomeToken, 4> kOutcomeTokens{{
    {RecoveryOutcome::OpenedClean, "opened-clean"},
    {RecoveryOutcome::AdoptedPreviousGeneration, "adopted-previous-generation"},
    {RecoveryOutcome::ReinitializedDamagedStore, "reinitialized-damaged-store"},
    {RecoveryOutcome::ReadOnlyInspection, "read-only-inspection"},
}};

[[nodiscard]] std::string join_list(const std::vector<std::string>& values) {
  std::string text;
  for (const std::string& value : values) {
    if (!text.empty()) {
      text.push_back(',');
    }
    text.append(value);
  }
  return detail::or_dash(text);
}

}  // namespace

std::string_view store_open_mode_token(StoreOpenMode mode) noexcept {
  for (const ModeToken& entry : kModeTokens) {
    if (entry.mode == mode) {
      return entry.token;
    }
  }
  return "unknown";
}

std::string_view recovery_policy_token(RecoveryPolicy policy) noexcept {
  for (const PolicyToken& entry : kPolicyTokens) {
    if (entry.policy == policy) {
      return entry.token;
    }
  }
  return "unknown";
}

Result<StoreOpenMode> parse_store_open_mode(std::string_view token) {
  for (const ModeToken& entry : kModeTokens) {
    if (entry.token == token) {
      return entry.mode;
    }
  }
  return Explanation(ErrorCode::InvalidOption, "unknown store open mode " + std::string(token));
}

Result<RecoveryPolicy> parse_recovery_policy(std::string_view token) {
  for (const PolicyToken& entry : kPolicyTokens) {
    if (entry.token == token) {
      return entry.policy;
    }
  }
  return Explanation(ErrorCode::InvalidOption, "unknown recovery policy " + std::string(token));
}

std::string_view recovery_outcome_token(RecoveryOutcome outcome) noexcept {
  for (const OutcomeToken& entry : kOutcomeTokens) {
    if (entry.outcome == outcome) {
      return entry.token;
    }
  }
  return "unknown";
}

std::string RecoveryReport::to_string() const {
  std::string text;
  detail::append_field(text, "outcome", recovery_outcome_token(outcome_));
  detail::append_field(text, "domain", has_domain_ ? domain_.to_string() : std::string("-"));
  detail::append_field(text, "domain_instance",
                       domain_instance_.has_value() ? domain_instance_->to_string() : std::string("-"));
  detail::append_field(text, "epoch", epoch_.has_value() ? epoch_->to_string() : std::string("-"));
  detail::append_field(text, "durable_generation",
                       durable_generation_.has_value() ? durable_generation_->to_string() : std::string("-"));
  detail::append_field(text, "snapshot_digest", snapshot_digest_.is_zero() ? std::string("-")
                                                                          : snapshot_digest_.to_hex());
  detail::append_field(text, "floor_digest",
                       floor_digest_.has_value() ? floor_digest_->to_hex() : std::string("-"));
  detail::append_field(text, "damaged_files", join_list(damaged_files_));
  detail::append_field(text, "quarantined_files", join_list(quarantined_files_));
  detail::append_field(text, "detail", detail_);
  return text;
}

std::string DurableCommitReport::to_string() const {
  std::string text;
  detail::append_field(text, "durable_generation", generation_.to_string());
  detail::append_field(text, "epoch", epoch_.to_string());
  detail::append_field(text, "snapshot_digest", snapshot_digest_.to_hex());
  detail::append_field(text, "bytes_written", std::to_string(bytes_written_));
  detail::append_field(text, "retained_previous_generation", detail::yes_no(retained_previous_generation_));
  return text;
}

std::string StoreInspection::to_string() const {
  std::string text;
  detail::append_field(text, "verified", detail::yes_no(verified_));
  detail::append_field(text, "read_only_safe", detail::yes_no(read_only_safe_));
  detail::append_field(text, "store_initialized", detail::yes_no(store_initialized_));
  detail::append_field(text, "domain", store_initialized_ ? domain_.to_string() : std::string("-"));
  detail::append_field(text, "domain_instance",
                       domain_instance_.has_value() ? domain_instance_->to_string() : std::string("-"));
  detail::append_field(text, "epoch", epoch_.has_value() ? epoch_->to_string() : std::string("-"));
  detail::append_field(text, "durable_generation",
                       durable_generation_.has_value() ? durable_generation_->to_string() : std::string("-"));
  detail::append_field(text, "controllers", std::to_string(controller_count_));
  detail::append_field(text, "live_grants", std::to_string(live_grant_count_));
  detail::append_field(text, "transitions", std::to_string(transition_count_));
  detail::append_field(text, "revocations", std::to_string(revocation_count_));
  detail::append_field(text, "idempotency_records", std::to_string(idempotency_record_count_));
  detail::append_field(text, "snapshot_bytes", std::to_string(snapshot_bytes_));
  detail::append_field(text, "snapshot_digest",
                       snapshot_digest_.is_zero() ? std::string("-") : snapshot_digest_.to_hex());
  detail::append_field(text, "floor_epoch", floor_epoch_.has_value() ? floor_epoch_->to_string() : std::string("-"));
  detail::append_field(text, "floor_generation",
                       floor_generation_.has_value() ? floor_generation_->to_string() : std::string("-"));
  detail::append_field(text, "transition_chain_verified", detail::yes_no(transition_chain_verified_));
  detail::append_field(text, "problems", join_list(problems_));
  return text;
}

}  // namespace dccp::epoch
