// Control Plane Epoch 1.0.0 - Summon Software Labs
// Suite: recovery_qualification.
//
// Invariant under test: recovering state never upgrades it. A verdict is a
// function of durable state alone (current epoch, controller current
// incarnation, live grants covering the claimed scope) and every claim that
// cannot be tied to all three is reported as something other than "current".

#include <optional>
#include <string>
#include <string_view>

#include "test_support.hpp"

namespace {

using namespace cpe_test;
using namespace dccp::epoch;

/// Builds a claim and qualifies it. Qualification itself must always produce a
/// verdict: a Result rejection here would mean the authority could not decide,
/// which is a defect rather than a domain outcome.
[[nodiscard]] RecoveryQualification qualify(cpe_test::TestAuthority& fixture, std::string_view domain,
                                            std::uint64_t producing_epoch, const std::string& producer,
                                            const ControllerIncarnationId& incarnation, const std::string& scope,
                                            std::string_view content) {
  auto claim = RecoveredStateClaim::create(domain_id(std::string(domain)), Epoch::from_trusted(producing_epoch),
                                           controller_id(producer), incarnation, scope_name(scope),
                                           digest_of(content));
  if (!claim.has_value()) {
    throw cpe_test::Failure("could not build the claim: " + claim.rejection().to_string());
  }
  auto qualification = fixture.authority().qualify_recovered_state(claim.value());
  if (!qualification.has_value()) {
    throw cpe_test::Failure("qualification was rejected instead of decided: " +
                            qualification.rejection().to_string());
  }
  return qualification.move_value();
}

/// Current incarnation identity of a registered controller.
[[nodiscard]] ControllerIncarnationId incarnation_of(cpe_test::TestAuthority& fixture,
                                                     const std::string& controller) {
  auto record = fixture.authority().controller_record(controller_id(controller));
  if (!record.has_value()) {
    throw cpe_test::Failure("controller '" + controller + "' is not registered");
  }
  return record.value().incarnation_id();
}

[[nodiscard]] std::string verdict_and_code(const RecoveryQualification& qualification) {
  return std::string(recovered_state_verdict_token(qualification.verdict())) + "/" +
         std::string(error_token(qualification.code()));
}

}  // namespace

// ---------------------------------------------------------------------------
// Current: the only verdict that is usable as current authority.
// ---------------------------------------------------------------------------

CPE_TEST(recovery_qualification, current_requires_current_epoch_incarnation_and_live_grant) {
  cpe_test::TestAuthority fixture;
  const ControllerRegistration registered = fixture.register_controller("ctrl-a");
  const ControllerIncarnationId incarnation = registered.incarnation_id();
  CPE_REQUIRE_EQ(registered.incarnation_number().value(), 1u);
  CPE_REQUIRE_EQ(incarnation_of(fixture, "ctrl-a"), incarnation);

  // Same epoch and same incarnation, but the producer holds nothing yet: the
  // claim must not be promoted to current merely because identity matches.
  const RecoveryQualification ungranted =
      qualify(fixture, "facility-alpha", 1, "ctrl-a", incarnation, "facility.inventory", "content-a");
  CPE_REQUIRE(ungranted.verdict() == RecoveredStateVerdict::Rejected);
  CPE_REQUIRE(ungranted.code() == ErrorCode::RecoveredRejectedNoAuthority);
  CPE_REQUIRE(!ungranted.matching_grant().has_value());
  CPE_REQUIRE(!ungranted.requires_revalidation());
  CPE_REQUIRE(!ungranted.usable_as_current());
  CPE_REQUIRE_EQ(ungranted.to_string(),
                 std::string("verdict=rejected code=recovery.rejected_no_authority matching_grant=- "
                             "requires_revalidation=no detail=the producer holds no live authority over scope "
                             "'facility.inventory' in epoch 1"));

  const MutationAuthority root = fixture.root_authority();
  const AuthorityGrantView grant = fixture.acquire("ctrl-a", incarnation, {"facility.inventory"}, root);
  const GrantId grant_id = grant.record().id();

  const RecoveryQualification current =
      qualify(fixture, "facility-alpha", 1, "ctrl-a", incarnation, "facility.inventory", "content-a");
  CPE_REQUIRE(current.verdict() == RecoveredStateVerdict::Current);
  CPE_REQUIRE(current.code() == ErrorCode::RecoveredCurrent);
  CPE_REQUIRE(current.matching_grant().has_value());
  CPE_REQUIRE_EQ(*current.matching_grant(), grant_id);
  CPE_REQUIRE(!current.requires_revalidation());
  CPE_REQUIRE(current.usable_as_current());
  CPE_REQUIRE_EQ(current.to_string(),
                 "verdict=current code=recovery.current matching_grant=" + grant_id.to_string() +
                     " requires_revalidation=no detail=produced under the current epoch by the current incarnation");

  // A scope the live grant does not cover is exactly as unauthoritative as no
  // grant at all, even for the same controller, epoch, and incarnation.
  const RecoveryQualification uncovered =
      qualify(fixture, "facility-alpha", 1, "ctrl-a", incarnation, "facility.topology", "content-a");
  CPE_REQUIRE(uncovered.verdict() == RecoveredStateVerdict::Rejected);
  CPE_REQUIRE(uncovered.code() == ErrorCode::RecoveredRejectedNoAuthority);
  CPE_REQUIRE(!uncovered.matching_grant().has_value());

  // Another incarnation of the same controller is not the claim's incarnation.
  const ControllerIncarnationId other =
      ControllerIncarnationId::derive(domain_id(fixture.domain()), controller_id("ctrl-a"),
                                      IncarnationNumber::from_trusted(2));
  const RecoveryQualification wrong_incarnation =
      qualify(fixture, "facility-alpha", 1, "ctrl-a", other, "facility.inventory", "content-a");
  CPE_REQUIRE(wrong_incarnation.verdict() == RecoveredStateVerdict::Rejected);
  CPE_REQUIRE(wrong_incarnation.code() == ErrorCode::RecoveredRejectedUnknownIncarnation);
}

// ---------------------------------------------------------------------------
// Stale and NeedsReconciliation: the same incarnation surviving an epoch change.
// ---------------------------------------------------------------------------

CPE_TEST(recovery_qualification, epoch_change_splits_stale_from_needs_reconciliation) {
  cpe_test::TestAuthority fixture;
  const ControllerIncarnationId incarnation = fixture.register_controller("ctrl-a").incarnation_id();

  const MutationAuthority root = fixture.root_authority();
  const AuthorityGrantView epoch_one = fixture.acquire("ctrl-a", incarnation, {"facility.inventory"}, root);
  CPE_REQUIRE_EQ(epoch_one.record().epoch().value(), 1u);

  const EpochTransitionRecord transition = fixture.advance(Epoch::initial(), root);
  CPE_REQUIRE_EQ(transition.new_epoch().value(), 2u);
  CPE_REQUIRE_EQ(fixture.authority().current_epoch().value(), 2u);

  // The incarnation is still current, but no live grant covers the scope in the
  // new epoch: the state is old, not fenced, and must be revalidated.
  const RecoveryQualification stale =
      qualify(fixture, "facility-alpha", 1, "ctrl-a", incarnation, "facility.inventory", "content-a");
  CPE_REQUIRE(stale.verdict() == RecoveredStateVerdict::Stale);
  CPE_REQUIRE(stale.code() == ErrorCode::RecoveredStale);
  CPE_REQUIRE(!stale.matching_grant().has_value());
  CPE_REQUIRE(stale.requires_revalidation());
  CPE_REQUIRE(!stale.usable_as_current());
  CPE_REQUIRE_EQ(stale.to_string(),
                 std::string("verdict=stale code=recovery.stale matching_grant=- requires_revalidation=yes "
                             "detail=produced in epoch 1 which is no longer current; the producer holds no authority "
                             "over scope 'facility.inventory' now"));

  // Re-acquiring the same scope in the new epoch makes the same old data
  // reconcilable -- and still never current.
  const MutationAuthority root_again = fixture.root_authority();
  const AuthorityGrantView epoch_two = fixture.acquire("ctrl-a", incarnation, {"facility.inventory"}, root_again);
  const GrantId grant_id = epoch_two.record().id();
  CPE_REQUIRE_EQ(epoch_two.record().epoch().value(), 2u);

  const RecoveryQualification reconcilable =
      qualify(fixture, "facility-alpha", 1, "ctrl-a", incarnation, "facility.inventory", "content-a");
  CPE_REQUIRE(reconcilable.verdict() == RecoveredStateVerdict::NeedsReconciliation);
  CPE_REQUIRE(reconcilable.code() == ErrorCode::RecoveredNeedsReconciliation);
  CPE_REQUIRE(reconcilable.matching_grant().has_value());
  CPE_REQUIRE_EQ(*reconcilable.matching_grant(), grant_id);
  CPE_REQUIRE(reconcilable.requires_revalidation());
  CPE_REQUIRE(!reconcilable.usable_as_current());
  CPE_REQUIRE_EQ(reconcilable.to_string(),
                 "verdict=needs_reconciliation code=recovery.needs_reconciliation matching_grant=" +
                     grant_id.to_string() +
                     " requires_revalidation=yes detail=produced in epoch 1; the producer is still the current "
                     "incarnation and still holds scope 'facility.inventory' in epoch 2");

  // Under the current epoch the identical claim is current, which proves the
  // only difference between the two verdicts is the producing epoch.
  const RecoveryQualification current =
      qualify(fixture, "facility-alpha", 2, "ctrl-a", incarnation, "facility.inventory", "content-a");
  CPE_REQUIRE(current.verdict() == RecoveredStateVerdict::Current);
  CPE_REQUIRE_EQ(*current.matching_grant(), grant_id);
}

// ---------------------------------------------------------------------------
// Superseded: the producing incarnation was fenced for good.
// ---------------------------------------------------------------------------

CPE_TEST(recovery_qualification, reregistration_supersedes_the_producing_incarnation) {
  cpe_test::TestAuthority fixture;
  const ControllerRegistration first = fixture.register_controller("ctrl-a");
  const ControllerIncarnationId superseded = first.incarnation_id();

  const MutationAuthority root = fixture.root_authority();
  const AuthorityGrantView grant = fixture.acquire("ctrl-a", superseded, {"facility.inventory"}, root);

  const ControllerRegistration second = fixture.register_controller("ctrl-a");
  CPE_REQUIRE_EQ(second.incarnation_number().value(), 2u);
  CPE_REQUIRE(second.incarnation_id() != superseded);

  // The grant is fenced the moment the incarnation is superseded.
  const auto fenced_grant = fixture.authority().grant_record(grant.record().id());
  CPE_REQUIRE(fenced_grant.has_value());

  const RecoveryQualification verdict =
      qualify(fixture, "facility-alpha", 1, "ctrl-a", superseded, "facility.inventory", "content-a");
  CPE_REQUIRE(verdict.verdict() == RecoveredStateVerdict::Superseded);
  CPE_REQUIRE(verdict.code() == ErrorCode::RecoveredSuperseded);
  CPE_REQUIRE(!verdict.matching_grant().has_value());
  CPE_REQUIRE(!verdict.requires_revalidation());
  CPE_REQUIRE(!verdict.usable_as_current());
  CPE_REQUIRE_EQ(verdict.to_string(),
                 std::string("verdict=superseded code=recovery.superseded matching_grant=- "
                             "requires_revalidation=no detail=the producing incarnation is permanently fenced: a "
                             "newer incarnation is current"));

  // The new incarnation is a different claim entirely and is judged on its own
  // (absent) authority.
  const RecoveryQualification replacement =
      qualify(fixture, "facility-alpha", 1, "ctrl-a", second.incarnation_id(), "facility.inventory", "content-a");
  CPE_REQUIRE(replacement.verdict() == RecoveredStateVerdict::Rejected);
  CPE_REQUIRE(replacement.code() == ErrorCode::RecoveredRejectedNoAuthority);
}

CPE_TEST(recovery_qualification, controller_revocation_supersedes_the_current_incarnation) {
  cpe_test::TestAuthority fixture;
  const ControllerRegistration registered = fixture.register_controller("ctrl-a");
  const ControllerIncarnationId incarnation = registered.incarnation_id();

  const MutationAuthority root = fixture.root_authority();
  const AuthorityGrantView grant = fixture.acquire("ctrl-a", incarnation, {"facility.inventory"}, root);

  RevokeAuthorityRequest revoke;
  revoke.target = RevocationTarget::controller_all(controller_id("ctrl-a"));
  revoke.reason = RevocationReason::OperatorRequest;
  revoke.authority = root;
  revoke.provenance = provenance_input("operator");
  auto revocation = fixture.authority().revoke_authority(std::move(revoke));
  CPE_REQUIRE(revocation.has_value());
  CPE_REQUIRE_EQ(revocation.value().fenced_grant_count(), 1u);
  CPE_REQUIRE(revocation.value().through_incarnation().has_value());
  CPE_REQUIRE_EQ(revocation.value().through_incarnation()->value(), 1u);

  const auto fenced = fixture.authority().grant_record(grant.record().id());
  CPE_REQUIRE(fenced.has_value());
  CPE_REQUIRE(fenced.value().revoked());

  // A revoked incarnation is current but permanently fenced: superseded, not
  // stale, and never current.
  const RecoveryQualification verdict =
      qualify(fixture, "facility-alpha", 1, "ctrl-a", incarnation, "facility.inventory", "content-a");
  CPE_REQUIRE(verdict.verdict() == RecoveredStateVerdict::Superseded);
  CPE_REQUIRE(verdict.code() == ErrorCode::RecoveredSuperseded);
  CPE_REQUIRE(!verdict.matching_grant().has_value());
  CPE_REQUIRE(!verdict.requires_revalidation());
  CPE_REQUIRE_EQ(verdict.to_string(),
                 std::string("verdict=superseded code=recovery.superseded matching_grant=- "
                             "requires_revalidation=no detail=the producing incarnation is permanently fenced: the "
                             "controller is revoked"));
}

// ---------------------------------------------------------------------------
// Rejections: claims that cannot be tied to this authority at all.
// ---------------------------------------------------------------------------

CPE_TEST(recovery_qualification, future_epoch_is_rejected_and_never_current) {
  cpe_test::TestAuthority fixture;
  const ControllerIncarnationId incarnation = fixture.register_controller("ctrl-a").incarnation_id();
  const MutationAuthority root = fixture.root_authority();
  (void)fixture.acquire("ctrl-a", incarnation, {"facility.inventory"}, root);

  const RecoveryQualification verdict =
      qualify(fixture, "facility-alpha", 2, "ctrl-a", incarnation, "facility.inventory", "content-a");
  CPE_REQUIRE(verdict.verdict() == RecoveredStateVerdict::Rejected);
  CPE_REQUIRE(verdict.code() == ErrorCode::RecoveredRejectedFutureEpoch);
  CPE_REQUIRE(!verdict.matching_grant().has_value());
  CPE_REQUIRE(!verdict.requires_revalidation());
  CPE_REQUIRE_EQ(verdict.to_string(),
                 std::string("verdict=rejected code=recovery.rejected_future_epoch matching_grant=- "
                             "requires_revalidation=no detail=the claim names producing epoch 2 which this domain "
                             "never committed; the current epoch is 1"));

  // The same claim one epoch earlier, with the same live grant, is current:
  // epoch comparison is the discriminator and nothing else changed.
  const RecoveryQualification current =
      qualify(fixture, "facility-alpha", 1, "ctrl-a", incarnation, "facility.inventory", "content-a");
  CPE_REQUIRE(current.verdict() == RecoveredStateVerdict::Current);
}

CPE_TEST(recovery_qualification, foreign_domain_is_rejected_before_anything_else) {
  cpe_test::TestAuthority fixture;
  const ControllerIncarnationId incarnation = fixture.register_controller("ctrl-a").incarnation_id();

  // A claim from another domain must be rejected even though every other field
  // would qualify against this authority's state.
  const RecoveryQualification verdict =
      qualify(fixture, "facility-beta", 1, "ctrl-a", incarnation, "facility.inventory", "content-a");
  CPE_REQUIRE(verdict.verdict() == RecoveredStateVerdict::Rejected);
  CPE_REQUIRE(verdict.code() == ErrorCode::RecoveredRejectedDomainMismatch);
  CPE_REQUIRE(!verdict.matching_grant().has_value());
  CPE_REQUIRE(!verdict.requires_revalidation());
  CPE_REQUIRE(!verdict.usable_as_current());
  CPE_REQUIRE_EQ(verdict.to_string(),
                 std::string("verdict=rejected code=recovery.rejected_domain_mismatch matching_grant=- "
                             "requires_revalidation=no detail=the claim names domain 'facility-beta' but this "
                             "authority serves 'facility-alpha'"));
}

CPE_TEST(recovery_qualification, unknown_or_never_issued_incarnation_is_rejected) {
  cpe_test::TestAuthority fixture;
  const ControllerIncarnationId incarnation = fixture.register_controller("ctrl-a").incarnation_id();

  // (a) A controller this domain never registered.
  const RecoveryQualification ghost_controller =
      qualify(fixture, "facility-alpha", 1, "ctrl-ghost",
              ControllerIncarnationId::derive(domain_id(fixture.domain()), controller_id("ctrl-ghost"),
                                              IncarnationNumber::from_trusted(1)),
              "facility.inventory", "content-a");
  CPE_REQUIRE(ghost_controller.verdict() == RecoveredStateVerdict::Rejected);
  CPE_REQUIRE(ghost_controller.code() == ErrorCode::RecoveredRejectedUnknownIncarnation);
  CPE_REQUIRE(!ghost_controller.matching_grant().has_value());
  CPE_REQUIRE_EQ(ghost_controller.to_string(),
                 std::string("verdict=rejected code=recovery.rejected_unknown_incarnation matching_grant=- "
                             "requires_revalidation=no detail=controller 'ctrl-ghost' is not registered in this "
                             "domain"));

  // (b) A registered controller with an incarnation identity that was never
  // issued: not current, not in the superseded set, therefore unknown.
  const ControllerIncarnationId never_issued = ControllerIncarnationId::from_digest(digest_of("never-issued"));
  const RecoveryQualification ghost_incarnation =
      qualify(fixture, "facility-alpha", 1, "ctrl-a", never_issued, "facility.inventory", "content-a");
  CPE_REQUIRE(ghost_incarnation.verdict() == RecoveredStateVerdict::Rejected);
  CPE_REQUIRE(ghost_incarnation.code() == ErrorCode::RecoveredRejectedUnknownIncarnation);
  CPE_REQUIRE_EQ(ghost_incarnation.to_string(),
                 "verdict=rejected code=recovery.rejected_unknown_incarnation matching_grant=- "
                 "requires_revalidation=no detail=incarnation " +
                     never_issued.to_hex() + " is not the current incarnation 1 of controller 'ctrl-a'");

  // The registered incarnation itself is still recognised, so (b) is a property
  // of the claim and not of the controller.
  const RecoveryQualification known =
      qualify(fixture, "facility-alpha", 1, "ctrl-a", incarnation, "facility.inventory", "content-a");
  CPE_REQUIRE(known.code() == ErrorCode::RecoveredRejectedNoAuthority);
}

CPE_TEST(recovery_qualification, no_authority_is_reported_for_every_unauthorised_shape) {
  cpe_test::TestAuthority fixture;
  const ControllerRegistration registered = fixture.register_controller("ctrl-a");
  const ControllerIncarnationId incarnation = registered.incarnation_id();

  const MutationAuthority root = fixture.root_authority();

  // Recovery qualification asks only whether a live grant covers the scope; the
  // grant class does not enter the verdict.
  const AuthorityGrantView observation =
      fixture.acquire("ctrl-a", incarnation, {"facility.inventory"}, root, AuthorityClass::Observation);
  const RecoveryQualification covered =
      qualify(fixture, "facility-alpha", 1, "ctrl-a", incarnation, "facility.inventory", "content-a");
  CPE_REQUIRE(covered.verdict() == RecoveredStateVerdict::Current);
  CPE_REQUIRE_EQ(covered.matching_grant().value(), observation.record().id());

  // Revoking exactly that grant removes the only coverage, so the same claim
  // becomes an outright rejection while the epoch and incarnation stay current.
  RevokeAuthorityRequest revoke;
  revoke.target = RevocationTarget::grant(observation.record().id(), controller_id("ctrl-a"));
  revoke.reason = RevocationReason::SuspectedStaleAuthority;
  revoke.authority = root;
  revoke.provenance = provenance_input("operator");
  auto revocation = fixture.authority().revoke_authority(std::move(revoke));
  CPE_REQUIRE(revocation.has_value());

  const RecoveryQualification revoked =
      qualify(fixture, "facility-alpha", 1, "ctrl-a", incarnation, "facility.inventory", "content-a");
  CPE_REQUIRE(revoked.verdict() == RecoveredStateVerdict::Rejected);
  CPE_REQUIRE(revoked.code() == ErrorCode::RecoveredRejectedNoAuthority);
  CPE_REQUIRE(!revoked.matching_grant().has_value());
  CPE_REQUIRE(!revoked.requires_revalidation());
}

CPE_TEST(recovery_qualification, verdicts_survive_a_store_reopen_unchanged) {
  cpe_test::TestAuthority fixture;
  const ControllerRegistration registered = fixture.register_controller("ctrl-a");
  const ControllerIncarnationId incarnation = registered.incarnation_id();
  const MutationAuthority root = fixture.root_authority();
  const AuthorityGrantView grant = fixture.acquire("ctrl-a", incarnation, {"facility.inventory"}, root);
  const RecoveryQualification before =
      qualify(fixture, "facility-alpha", 1, "ctrl-a", incarnation, "facility.inventory", "content-a");
  CPE_REQUIRE(before.verdict() == RecoveredStateVerdict::Current);

  fixture.reopen();

  const RecoveryQualification after =
      qualify(fixture, "facility-alpha", 1, "ctrl-a", incarnation, "facility.inventory", "content-a");
  // Verdicts are a pure function of durable state, so a restart cannot change
  // one; equality compares the verdict, the explanation, and the grant.
  CPE_REQUIRE(after == before);
  CPE_REQUIRE_EQ(after.to_string(), before.to_string());
  CPE_REQUIRE(after.matching_grant().has_value());
  CPE_REQUIRE_EQ(after.matching_grant().value(), grant.record().id());
  CPE_REQUIRE_EQ(verdict_and_code(after), std::string("current/recovery.current"));
}
