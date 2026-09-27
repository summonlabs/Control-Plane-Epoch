// Control Plane Epoch 1.0.0 - Summon Software Labs
// Recovered-state claim validation and qualification rendering.
#include "control_plane_epoch/recovery.hpp"

#include <array>

#include "format.hpp"

namespace dccp::epoch {
namespace {

struct VerdictToken {
  RecoveredStateVerdict verdict;
  std::string_view token;
};

constexpr std::array<VerdictToken, 5> kVerdictTokens{{
    {RecoveredStateVerdict::Current, "current"},
    {RecoveredStateVerdict::Stale, "stale"},
    {RecoveredStateVerdict::Superseded, "superseded"},
    {RecoveredStateVerdict::NeedsReconciliation, "needs_reconciliation"},
    {RecoveredStateVerdict::Rejected, "rejected"},
}};

}  // namespace

std::string_view recovered_state_verdict_token(RecoveredStateVerdict verdict) noexcept {
  for (const VerdictToken& entry : kVerdictTokens) {
    if (entry.verdict == verdict) {
      return entry.token;
    }
  }
  return "unknown";
}

Result<RecoveredStateVerdict> parse_recovered_state_verdict(std::string_view token) {
  for (const VerdictToken& entry : kVerdictTokens) {
    if (entry.token == token) {
      return entry.verdict;
    }
  }
  return Explanation(ErrorCode::EnumOutOfDomain, "unknown recovered state verdict " + std::string(token));
}

Result<RecoveredStateClaim> RecoveredStateClaim::create(FacilityAuthorityDomainId domain, Epoch producing_epoch,
                                                        ControllerId producer,
                                                        ControllerIncarnationId producer_incarnation,
                                                        ScopeName scope, Sha256Digest content_digest) {
  if (domain.empty()) {
    return Explanation(ErrorCode::IdentifierEmpty, "recovered state claim has an empty domain");
  }
  if (producing_epoch.value() == 0) {
    return Explanation(ErrorCode::EpochZero, "recovered state claim has an unset producing epoch");
  }
  if (producer.empty()) {
    return Explanation(ErrorCode::IdentifierEmpty, "recovered state claim has an empty producer");
  }
  if (producer_incarnation.is_zero()) {
    return Explanation(ErrorCode::InvalidArgument, "recovered state claim has an unset producer incarnation");
  }
  if (scope.empty()) {
    return Explanation(ErrorCode::ScopeUnknown, "recovered state claim has an empty scope");
  }
  if (content_digest.is_zero()) {
    return Explanation(ErrorCode::InvalidArgument, "recovered state claim has a zero content digest");
  }

  RecoveredStateClaim claim;
  claim.domain_ = std::move(domain);
  claim.producing_epoch_ = producing_epoch;
  claim.producer_ = std::move(producer);
  claim.producer_incarnation_ = producer_incarnation;
  claim.scope_ = std::move(scope);
  claim.content_digest_ = content_digest;
  return claim;
}

std::string RecoveredStateClaim::to_string() const {
  std::string text;
  detail::append_field(text, "domain", domain_.view());
  detail::append_field(text, "producing_epoch", producing_epoch_.to_string());
  detail::append_field(text, "producer", producer_.view());
  detail::append_field(text, "producer_incarnation", producer_incarnation_.to_hex());
  detail::append_field(text, "scope", scope_.view());
  detail::append_field(text, "content_digest", content_digest_.to_hex());
  return text;
}

std::string RecoveryQualification::to_string() const {
  std::string text;
  detail::append_field(text, "verdict", recovered_state_verdict_token(verdict_));
  detail::append_field(text, "code", explanation_.token());
  detail::append_field(text, "matching_grant",
                       matching_grant_.has_value() ? matching_grant_->to_string() : std::string("-"));
  detail::append_field(text, "requires_revalidation", detail::yes_no(requires_revalidation_));
  if (!explanation_.detail().empty()) {
    detail::append_field(text, "detail", explanation_.detail());
  }
  return text;
}

}  // namespace dccp::epoch
