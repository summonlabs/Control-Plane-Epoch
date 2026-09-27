// Control Plane Epoch 1.0.0 - Summon Software Labs
// Authority validation suite.
//
// The validation ladder is a contract, not an implementation detail: the
// documented order is domain, token integrity, epoch above, epoch below, grant
// existence, authority class, claim agreement, revocation, controller
// existence, supersession, incarnation currency, scope coverage. The *first*
// failing rung owns the reported code, and that is what makes a rejection
// explainable ("your token is stale", not "something was wrong with it").
//
// Failing tokens are built two ways: directly from claims
// (MutationAuthority::from_claims), which produces a token whose claims are
// deliberately wrong while its integrity is intact, and by editing token text,
// which is where tampering is observable.
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "test_support.hpp"

namespace {

using dccp::epoch::AcquireAuthorityRequest;
using dccp::epoch::AuthorityClass;
using dccp::epoch::AuthorityClaims;
using dccp::epoch::AuthorityGrantView;
using dccp::epoch::ControllerIncarnationId;
using dccp::epoch::ControllerRegistration;
using dccp::epoch::ErrorCode;
using dccp::epoch::Epoch;
using dccp::epoch::EpochTransitionReason;
using dccp::epoch::FacilityAuthorityDomainId;
using dccp::epoch::GrantId;
using dccp::epoch::IncarnationNumber;
using dccp::epoch::MutationAuthority;
using dccp::epoch::ObservationAuthority;
using dccp::epoch::ProvenanceSourceKind;
using dccp::epoch::Result;
using dccp::epoch::ScopeName;
using dccp::epoch::ValidationOutcome;

template <class T>
[[nodiscard]] ErrorCode rejection_code(const Result<T>& result) {
  return result.has_value() ? ErrorCode::Ok : result.rejection().code();
}

[[nodiscard]] ErrorCode validation_code(const ValidationOutcome& outcome) {
  return outcome.accepted() ? ErrorCode::Ok : outcome.rejection()->code();
}

[[nodiscard]] AuthorityClaims claims_with(const FacilityAuthorityDomainId& domain, std::uint64_t epoch,
                                          const std::string& controller,
                                          const ControllerIncarnationId& incarnation, std::uint64_t grant,
                                          const std::vector<std::string>& scopes) {
  auto created = AuthorityClaims::create(domain, Epoch::from_trusted(epoch), cpe_test::controller_id(controller),
                                         incarnation, GrantId::from_trusted(grant), cpe_test::scope_set(scopes));
  if (!created.has_value()) {
    throw cpe_test::Failure("could not build claims: " + created.rejection().to_string());
  }
  return created.move_value();
}

[[nodiscard]] AcquireAuthorityRequest acquire_request(
    const std::string& controller, const ControllerIncarnationId& incarnation, const std::vector<std::string>& scopes,
    const std::optional<MutationAuthority>& sponsor,
    AuthorityClass authority_class = AuthorityClass::Mutation) {
  AcquireAuthorityRequest request;
  request.authority_class = authority_class;
  request.controller = cpe_test::controller_id(controller);
  request.incarnation = incarnation;
  request.scopes = cpe_test::scope_set(scopes);
  request.sponsor = sponsor;
  request.provenance = cpe_test::provenance_input(controller, ProvenanceSourceKind::Controller);
  return request;
}

[[nodiscard]] ControllerIncarnationId derived(const std::string& controller, std::uint64_t number) {
  return ControllerIncarnationId::derive(cpe_test::domain_id("facility-alpha"), cpe_test::controller_id(controller),
                                         IncarnationNumber::from_trusted(number));
}

/// Token text whose trailing fencing digest was replaced by a different,
/// well-formed digest: the claims no longer agree with the digest, which is
/// exactly the tampering signature.
[[nodiscard]] std::string with_tampered_digest(std::string_view text) {
  const std::size_t separator = text.rfind(':');
  if (separator == std::string_view::npos) {
    return std::string(text);
  }
  return std::string(text.substr(0, separator + 1)) + std::string(std::size_t{64}, 'f');
}

}  // namespace

CPE_TEST(authority_validation, ladder_rejects_domain_epoch_grant_class_and_claim_mismatches) {
  cpe_test::TestAuthority test_authority;
  auto& authority = test_authority.authority();
  const FacilityAuthorityDomainId domain = cpe_test::domain_id(test_authority.domain());
  const MutationAuthority root = test_authority.root_authority();
  const ControllerRegistration worker = test_authority.register_controller("worker-a");
  const ScopeName inventory = cpe_test::scope_name("facility.inventory");
  const ScopeName topology = cpe_test::scope_name("facility.topology");
  const AuthorityGrantView view =
      test_authority.acquire("worker-a", worker.incarnation_id(), {"facility.inventory"}, root);
  const MutationAuthority live = test_authority.mutation_authority_of(view);
  const std::uint64_t grant_id = view.record().id().value();
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(live, inventory)), ErrorCode::Ok);

  // Rung 1: domain. Checked before anything else, because a token from another
  // authority domain is not evidence about this one no matter how well formed
  // it is. The second case would also fail rung 3 (epoch 99) and rung 5 (grant
  // 9999); the domain rung is still the one reported.
  const MutationAuthority foreign = MutationAuthority::from_claims(
      claims_with(cpe_test::domain_id("facility-beta"), 1, "worker-a", worker.incarnation_id(), grant_id,
                  {"facility.inventory"}));
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(foreign, inventory)), ErrorCode::DomainMismatch);
  const MutationAuthority foreign_and_wrong = MutationAuthority::from_claims(
      claims_with(cpe_test::domain_id("facility-beta"), 99, "worker-a", worker.incarnation_id(), 9999,
                  {"facility.inventory"}));
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(foreign_and_wrong, inventory)),
                 ErrorCode::DomainMismatch);

  // Rung 2 is token integrity. A default-constructed token fails both rung 1 and
  // rung 2, and the earlier rung owns the code; the integrity rung itself is
  // exercised in the dedicated case below.
  const MutationAuthority blank;
  CPE_REQUIRE_EQ(blank.verify_integrity().code(), ErrorCode::TokenTampered);
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(blank, inventory)), ErrorCode::DomainMismatch);

  // Rung 3: an epoch this domain never committed. Rung 5 would also fail for
  // grant 9999, so this proves the epoch rung is decided first.
  const MutationAuthority future = MutationAuthority::from_claims(
      claims_with(domain, 2, "worker-a", worker.incarnation_id(), 9999, {"facility.inventory"}));
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(future, inventory)), ErrorCode::EpochUnknown);
  const MutationAuthority future_with_real_grant = MutationAuthority::from_claims(
      claims_with(domain, 2, "worker-a", worker.incarnation_id(), grant_id, {"facility.inventory"}));
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(future_with_real_grant, inventory)),
                 ErrorCode::EpochUnknown);

  // Rung 5: no grant with that identifier exists in the current epoch. Every
  // earlier rung passes here, which is what isolates the code.
  const MutationAuthority unknown_grant = MutationAuthority::from_claims(
      claims_with(domain, 1, "worker-a", worker.incarnation_id(), 9999, {"facility.inventory"}));
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(unknown_grant, inventory)), ErrorCode::UnknownGrant);

  // Rung 6: the grant exists but authorizes a different class. The mutation
  // token below names a real observation grant with claims that match it
  // exactly, so rung 7 agrees and rung 6 owns the rejection.
  const AuthorityGrantView observed = test_authority.acquire("worker-a", worker.incarnation_id(),
                                                             {"facility.inventory"}, root, AuthorityClass::Observation);
  CPE_REQUIRE(observed.observation_authority().has_value());
  const MutationAuthority cross_class = MutationAuthority::from_claims(
      claims_with(domain, 1, "worker-a", worker.incarnation_id(), observed.record().id().value(),
                  {"facility.inventory"}));
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(cross_class, inventory)),
                 ErrorCode::AuthorityClassMismatch);

  // Rung 7: claims must agree with the stored grant byte for byte. Each case
  // below would also fail rung 12 for the requested scope, so the claim rung is
  // demonstrably decided first.
  const MutationAuthority wrong_scopes = MutationAuthority::from_claims(
      claims_with(domain, 1, "worker-a", worker.incarnation_id(), grant_id, {"facility.topology"}));
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(wrong_scopes, topology)), ErrorCode::ClaimsMismatch);
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(wrong_scopes, inventory)), ErrorCode::ClaimsMismatch);

  const ControllerRegistration other = test_authority.register_controller("worker-b");
  const MutationAuthority wrong_controller = MutationAuthority::from_claims(
      claims_with(domain, 1, "worker-b", other.incarnation_id(), grant_id, {"facility.inventory"}));
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(wrong_controller, inventory)),
                 ErrorCode::ClaimsMismatch);

  const MutationAuthority wrong_incarnation = MutationAuthority::from_claims(
      claims_with(domain, 1, "worker-a", derived("worker-a", 2), grant_id, {"facility.inventory"}));
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(wrong_incarnation, inventory)),
                 ErrorCode::ClaimsMismatch);

  // The genuine token still validates after all of those rejections: validation
  // is a read, and a rejected probe changes nothing.
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(live, inventory)), ErrorCode::Ok);
}

CPE_TEST(authority_validation, ladder_fenced_epoch_outranks_grant_existence) {
  cpe_test::TestAuthority test_authority;
  auto& authority = test_authority.authority();
  const FacilityAuthorityDomainId domain = cpe_test::domain_id(test_authority.domain());
  const MutationAuthority root = test_authority.root_authority();
  const ControllerRegistration worker = test_authority.register_controller("worker-a");
  const ScopeName inventory = cpe_test::scope_name("facility.inventory");
  const AuthorityGrantView view =
      test_authority.acquire("worker-a", worker.incarnation_id(), {"facility.inventory"}, root);
  const MutationAuthority epoch_one = test_authority.mutation_authority_of(view);
  CPE_REQUIRE(epoch_one.verify_integrity().accepted());

  (void)test_authority.advance(Epoch::initial(), root, EpochTransitionReason::OperatorRequest);
  CPE_REQUIRE_EQ(authority.current_epoch().value(), std::uint64_t{2});

  // The token is intact; only its epoch is stale. Advancing clears every grant
  // of the base epoch, so rung 5 would fail too, and rung 4 is what is reported.
  CPE_REQUIRE(epoch_one.verify_integrity().accepted());
  CPE_REQUIRE_EQ(rejection_code(authority.grant_record(view.record().id())), ErrorCode::UnknownGrant);
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(epoch_one, inventory)), ErrorCode::EpochFenced);
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(epoch_one, cpe_test::scope_name("facility.topology"))),
                 ErrorCode::EpochFenced);

  // A token naming the *current* epoch with a grant that was never issued lands
  // on rung 5: the two epochs produce two different, actionable codes.
  const MutationAuthority current_epoch_unknown_grant = MutationAuthority::from_claims(
      claims_with(domain, 2, "worker-a", worker.incarnation_id(), 9999, {"facility.inventory"}));
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(current_epoch_unknown_grant, inventory)),
                 ErrorCode::UnknownGrant);

  // Fencing is permanent and accumulates: after a second advancement the epoch-1
  // token is still fenced, and the epoch-2 grant it named is gone as well.
  const MutationAuthority epoch_two_root = test_authority.root_authority();
  (void)test_authority.advance(Epoch::from_trusted(2), epoch_two_root, EpochTransitionReason::Fencing);
  CPE_REQUIRE_EQ(authority.current_epoch().value(), std::uint64_t{3});
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(epoch_one, inventory)), ErrorCode::EpochFenced);
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(epoch_two_root, inventory)), ErrorCode::EpochFenced);
}

CPE_TEST(authority_validation, ladder_revocation_and_supersession_outrank_scope_coverage) {
  // Rung 8 and rung 10 both concern authority that was valid once and has been
  // fenced since. They are checked before scope coverage, so an operator is told
  // "this authority was revoked", not "you asked for the wrong scope".
  {
    cpe_test::TestAuthority test_authority;
    auto& authority = test_authority.authority();
    const MutationAuthority root = test_authority.root_authority();
    const ControllerRegistration worker = test_authority.register_controller("worker-a");
    const AuthorityGrantView view =
        test_authority.acquire("worker-a", worker.incarnation_id(), {"facility.inventory"}, root);
    const MutationAuthority revoked_token = test_authority.mutation_authority_of(view);
    CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(revoked_token,
                                                              cpe_test::scope_name("facility.inventory"))),
                   ErrorCode::Ok);

    dccp::epoch::RevokeAuthorityRequest request;
    request.target = dccp::epoch::RevocationTarget::grant(view.record().id(),
                                                          cpe_test::controller_id("worker-a"));
    request.reason = dccp::epoch::RevocationReason::OperatorRequest;
    request.authority = root;
    request.provenance = cpe_test::provenance_input("operator");
    const auto revocation = authority.revoke_authority(std::move(request));
    CPE_REQUIRE(revocation.has_value());
    CPE_REQUIRE_EQ(revocation.value().fenced_grant_count(), std::uint64_t{1});

    CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(revoked_token,
                                                              cpe_test::scope_name("facility.inventory"))),
                   ErrorCode::AuthorityRevoked);
    // A scope the grant never covered would fail rung 12; rung 8 is reported.
    CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(revoked_token,
                                                              cpe_test::scope_name("facility.topology"))),
                   ErrorCode::AuthorityRevoked);
    CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(revoked_token,
                                                              dccp::epoch::epoch_advance_scope())),
                   ErrorCode::AuthorityRevoked);
  }

  // Rung 10: the grant belonged to an incarnation that is no longer current.
  // The grant is not revoked, so rung 8 passes and rung 10 owns the rejection.
  {
    cpe_test::TestAuthority test_authority;
    auto& authority = test_authority.authority();
    const MutationAuthority root = test_authority.root_authority();
    const ControllerRegistration worker = test_authority.register_controller("worker-a");
    const AuthorityGrantView view =
        test_authority.acquire("worker-a", worker.incarnation_id(), {"facility.inventory"}, root);
    const MutationAuthority superseded_token = test_authority.mutation_authority_of(view);
    CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(superseded_token,
                                                              cpe_test::scope_name("facility.inventory"))),
                   ErrorCode::Ok);
    CPE_REQUIRE(!authority.grant_record(view.record().id()).value().revoked());

    (void)test_authority.register_controller("worker-a");
    CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(superseded_token,
                                                              cpe_test::scope_name("facility.inventory"))),
                   ErrorCode::IncarnationSuperseded);
    // Again with a scope the grant never covered: supersession outranks it.
    CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(superseded_token,
                                                              cpe_test::scope_name("facility.topology"))),
                   ErrorCode::IncarnationSuperseded);
    const auto controller_after_supersession =
        authority.controller_record(cpe_test::controller_id("worker-a"));
    CPE_REQUIRE(controller_after_supersession.has_value());
    CPE_REQUIRE_EQ(controller_after_supersession.value().incarnation_state(),
                   dccp::epoch::IncarnationState::Current);
  }
}

CPE_TEST(authority_validation, ladder_integrity_controller_and_incarnation_rungs) {
  cpe_test::TestAuthority test_authority;
  auto& authority = test_authority.authority();
  const MutationAuthority root = test_authority.root_authority();
  const ControllerRegistration worker = test_authority.register_controller("worker-a");
  const ScopeName inventory = cpe_test::scope_name("facility.inventory");
  const AuthorityGrantView view =
      test_authority.acquire("worker-a", worker.incarnation_id(), {"facility.inventory"}, root);
  const MutationAuthority live = test_authority.mutation_authority_of(view);

  // Rung 2, token integrity. Both construction paths derive the fencing digest
  // from the claims, so a *token object* cannot carry claims that disagree with
  // its digest; tampering is therefore observable when text is decoded, and it
  // is rejected before any authoritative state is consulted.
  CPE_REQUIRE(live.verify_integrity().accepted());
  const std::string tampered = with_tampered_digest(live.to_string());
  CPE_REQUIRE(tampered != live.to_string());
  CPE_REQUIRE_EQ(rejection_code(MutationAuthority::parse(tampered)), ErrorCode::TokenTampered);
  // The same check applied to a token that was never derived from real claims.
  const MutationAuthority blank;
  CPE_REQUIRE(!blank.verify_integrity().accepted());
  CPE_REQUIRE_EQ(blank.verify_integrity().code(), ErrorCode::TokenTampered);
  CPE_REQUIRE_EQ(blank.verify_integrity().rejection()->token(), std::string_view("authority.token_tampered"));

  // Rung 9, controller existence. Inside the token ladder rung 7 has already
  // pinned the token to the grant's controller, and that controller is the one
  // rung 9 examines, so a token whose grant exists can never reach rung 9. The
  // code is reachable where the ladder is entered earlier: an acquisition for a
  // controller that was never registered.
  AcquireAuthorityRequest ghost = acquire_request("ghost", derived("ghost", 1), {"facility.inventory"}, root);
  CPE_REQUIRE_EQ(rejection_code(authority.acquire_authority(std::move(ghost))), ErrorCode::ControllerUnknown);

  // Rung 11, incarnation currency, is likewise owned by rung 10 for tokens whose
  // incarnation was remembered as superseded (see the previous case). What
  // remains for rung 11 is an incarnation identity that was never issued: it is
  // unknown, not superseded, and the distinction is what stops an operator from
  // chasing a fencing event that never happened.
  AcquireAuthorityRequest stranger =
      acquire_request("worker-a", derived("worker-a", 9), {"facility.inventory"}, root);
  CPE_REQUIRE_EQ(rejection_code(authority.acquire_authority(std::move(stranger))), ErrorCode::IncarnationUnknown);
  AcquireAuthorityRequest reissued =
      acquire_request("worker-a", worker.incarnation_id(), {"facility.inventory"}, root);
  CPE_REQUIRE(rejection_code(authority.acquire_authority(std::move(reissued))) == ErrorCode::Ok);
}

CPE_TEST(authority_validation, observation_authority_follows_the_same_ladder) {
  cpe_test::TestAuthority test_authority;
  auto& authority = test_authority.authority();
  const FacilityAuthorityDomainId domain = cpe_test::domain_id(test_authority.domain());
  const MutationAuthority root = test_authority.root_authority();
  const ControllerRegistration worker = test_authority.register_controller("worker-a");
  const ScopeName inventory = cpe_test::scope_name("facility.inventory");
  const ScopeName topology = cpe_test::scope_name("facility.topology");

  const AuthorityGrantView mutation_view =
      test_authority.acquire("worker-a", worker.incarnation_id(), {"facility.inventory"}, root);
  const AuthorityGrantView observation_view = test_authority.acquire(
      "worker-a", worker.incarnation_id(), {"facility.inventory"}, root, AuthorityClass::Observation);
  CPE_REQUIRE(observation_view.observation_authority().has_value());
  const ObservationAuthority token = *observation_view.observation_authority();

  // Acceptance, then coverage: the ladder ends at scope coverage, so a live
  // observation grant authorizes exactly the scopes it covers.
  CPE_REQUIRE_EQ(validation_code(authority.validate_observation(token, inventory)), ErrorCode::Ok);
  CPE_REQUIRE_EQ(validation_code(authority.validate_observation(token, topology)), ErrorCode::ScopeNotGranted);

  // Rung 6 from the observation side: a token of the observation class naming a
  // mutation grant.
  const ObservationAuthority cross_class = ObservationAuthority::from_claims(
      claims_with(domain, 1, "worker-a", worker.incarnation_id(), mutation_view.record().id().value(),
                  {"facility.inventory"}));
  CPE_REQUIRE_EQ(validation_code(authority.validate_observation(cross_class, inventory)),
                 ErrorCode::AuthorityClassMismatch);

  // Rungs 1 and 3 apply unchanged, and in the same order.
  const ObservationAuthority foreign = ObservationAuthority::from_claims(
      claims_with(cpe_test::domain_id("facility-beta"), 1, "worker-a", worker.incarnation_id(),
                  observation_view.record().id().value(), {"facility.inventory"}));
  CPE_REQUIRE_EQ(validation_code(authority.validate_observation(foreign, inventory)), ErrorCode::DomainMismatch);
  const ObservationAuthority future = ObservationAuthority::from_claims(
      claims_with(domain, 4, "worker-a", worker.incarnation_id(), observation_view.record().id().value(),
                  {"facility.inventory"}));
  CPE_REQUIRE_EQ(validation_code(authority.validate_observation(future, inventory)), ErrorCode::EpochUnknown);

  // Rung 8 applies unchanged: a revoked observation grant is revoked.
  dccp::epoch::RevokeAuthorityRequest request;
  request.target = dccp::epoch::RevocationTarget::grant(observation_view.record().id(),
                                                        cpe_test::controller_id("worker-a"));
  request.reason = dccp::epoch::RevocationReason::SuspectedStaleAuthority;
  request.authority = root;
  request.provenance = cpe_test::provenance_input("operator");
  const auto revocation = authority.revoke_authority(std::move(request));
  CPE_REQUIRE(revocation.has_value());
  CPE_REQUIRE_EQ(validation_code(authority.validate_observation(token, inventory)), ErrorCode::AuthorityRevoked);

  // Rung 4 for observation authority: advancing fences observation grants just
  // as it fences mutation grants.
  const AuthorityGrantView second_observation = test_authority.acquire(
      "worker-a", worker.incarnation_id(), {"facility.inventory"}, root, AuthorityClass::Observation);
  CPE_REQUIRE(second_observation.observation_authority().has_value());
  const ObservationAuthority live_observation = *second_observation.observation_authority();
  CPE_REQUIRE_EQ(validation_code(authority.validate_observation(live_observation, inventory)), ErrorCode::Ok);
  (void)test_authority.advance(Epoch::initial(), root, EpochTransitionReason::OperatorRequest);
  CPE_REQUIRE_EQ(validation_code(authority.validate_observation(live_observation, inventory)), ErrorCode::EpochFenced);
}

CPE_TEST(authority_validation, acceptance_is_the_last_rung_and_is_scope_exact) {
  cpe_test::TestAuthority test_authority;
  auto& authority = test_authority.authority();
  const MutationAuthority root = test_authority.root_authority();
  const ControllerRegistration worker = test_authority.register_controller("worker-a");
  const ScopeName inventory = cpe_test::scope_name("facility.inventory");
  const ScopeName topology = cpe_test::scope_name("facility.topology");

  const AuthorityGrantView narrow =
      test_authority.acquire("worker-a", worker.incarnation_id(), {"facility.inventory"}, root);
  const MutationAuthority narrow_token = test_authority.mutation_authority_of(narrow);
  const ValidationOutcome accepted = authority.validate_mutation(narrow_token, inventory);
  CPE_REQUIRE(accepted.accepted());
  CPE_REQUIRE(static_cast<bool>(accepted));
  CPE_REQUIRE_EQ(accepted.code(), ErrorCode::Ok);
  CPE_REQUIRE(!accepted.rejection().has_value());
  CPE_REQUIRE_EQ(accepted.to_string(), std::string("accepted"));
  // Validation is a pure read: repeating it produces the identical outcome.
  CPE_REQUIRE_EQ(authority.validate_mutation(narrow_token, inventory).to_string(), accepted.to_string());

  // Coverage is exact, not approximate: one scope granted is one scope usable.
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(narrow_token, topology)), ErrorCode::ScopeNotGranted);
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(narrow_token, dccp::epoch::authority_grant_scope())),
                 ErrorCode::ScopeNotGranted);
  const ValidationOutcome denied = authority.validate_mutation(narrow_token, topology);
  CPE_REQUIRE_EQ(denied.rejection()->token(), std::string_view("authority.scope_not_granted"));

  const AuthorityGrantView wide = test_authority.acquire(
      "worker-a", worker.incarnation_id(), {"facility.topology", "facility.inventory"}, root);
  const MutationAuthority wide_token = test_authority.mutation_authority_of(wide);
  CPE_REQUIRE(authority.validate_mutation(wide_token, inventory).accepted());
  CPE_REQUIRE(authority.validate_mutation(wide_token, topology).accepted());
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(wide_token, dccp::epoch::authority_revoke_scope())),
                 ErrorCode::ScopeNotGranted);
  // The scope order the caller used does not matter: the grant is canonical.
  CPE_REQUIRE_EQ(wide.record().scopes().to_string(), std::string("facility.inventory+facility.topology"));
}
