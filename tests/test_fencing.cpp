// Control Plane Epoch 1.0.0 - Summon Software Labs
// Fencing suite.
//
// Advancing the epoch is the facility-wide fence: it is the one operation that
// invalidates every grant of the base epoch at once, permanently and
// unconditionally. This suite proves that the fence is total (no grant of the
// base epoch survives), permanent (a later epoch never revives it), and
// singular (exactly one successor exists per base epoch, no matter how many
// callers race for it).
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "test_support.hpp"

namespace {

using dccp::epoch::AcquireAuthorityRequest;
using dccp::epoch::AuthorityClass;
using dccp::epoch::AuthorityGrantView;
using dccp::epoch::ControllerIncarnationId;
using dccp::epoch::ControllerRegistration;
using dccp::epoch::Epoch;
using dccp::epoch::EpochTransitionReason;
using dccp::epoch::EpochTransitionRecord;
using dccp::epoch::ErrorCode;
using dccp::epoch::MutationAuthority;
using dccp::epoch::ProvenanceSourceKind;
using dccp::epoch::Result;
using dccp::epoch::ValidationOutcome;

template <class T>
[[nodiscard]] ErrorCode rejection_code(const Result<T>& result) {
  return result.has_value() ? ErrorCode::Ok : result.rejection().code();
}

[[nodiscard]] ErrorCode validation_code(const ValidationOutcome& outcome) {
  return outcome.accepted() ? ErrorCode::Ok : outcome.rejection()->code();
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

/// One advancement attempt, returned unexamined so that both the rejection and
/// the committed record can be inspected.
[[nodiscard]] Result<EpochTransitionRecord> advance_attempt(cpe_test::TestAuthority& test_authority,
                                                           const MutationAuthority& authority,
                                                           std::uint64_t expected_current,
                                                           EpochTransitionReason reason =
                                                               EpochTransitionReason::OperatorRequest) {
  dccp::epoch::AdvanceEpochRequest request;
  request.expected_current = Epoch::from_trusted(expected_current);
  request.authority = authority;
  request.reason = reason;
  request.provenance = cpe_test::provenance_input("operator");
  return test_authority.authority().advance_epoch(std::move(request));
}

}  // namespace

CPE_TEST(fencing, advancement_fences_every_grant_of_the_base_epoch) {
  cpe_test::TestAuthority test_authority;
  auto& authority = test_authority.authority();
  const MutationAuthority root = test_authority.root_authority();
  const ControllerRegistration worker = test_authority.register_controller("worker-a");
  const dccp::epoch::ScopeName inventory = cpe_test::scope_name("facility.inventory");
  const AuthorityGrantView view =
      test_authority.acquire("worker-a", worker.incarnation_id(), {"facility.inventory"}, root);
  const MutationAuthority base_token = test_authority.mutation_authority_of(view);
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(base_token, inventory)), ErrorCode::Ok);

  const dccp::epoch::AuthorityStatus before = authority.status();
  CPE_REQUIRE_EQ(before.epoch().value(), std::uint64_t{1});
  // The root's bootstrap grant and the worker's grant are both live now.
  CPE_REQUIRE(before.live_grant_count() >= 2);

  const EpochTransitionRecord committed =
      test_authority.advance(Epoch::initial(), root, EpochTransitionReason::OperatorRequest);
  CPE_REQUIRE(!committed.is_origin());
  CPE_REQUIRE_EQ(committed.base_epoch().value(), std::uint64_t{1});
  CPE_REQUIRE_EQ(committed.new_epoch().value(), std::uint64_t{2});
  CPE_REQUIRE_EQ(committed.reason(), EpochTransitionReason::OperatorRequest);
  // The transition records how much authority it fenced, which is the whole
  // point of advancing: the count is the number of live grants of the base epoch.
  CPE_REQUIRE_EQ(committed.fenced_grant_count(), before.live_grant_count());

  const dccp::epoch::AuthorityStatus after = authority.status();
  CPE_REQUIRE_EQ(after.epoch().value(), std::uint64_t{2});
  CPE_REQUIRE_EQ(after.live_grant_count(), std::uint64_t{0});
  CPE_REQUIRE_EQ(after.mutation_grant_count(), std::uint64_t{0});
  CPE_REQUIRE_EQ(after.observation_grant_count(), std::uint64_t{0});
  // Identities survive the transition; only authority is fenced. A controller
  // does not have to re-register to exist, it has to re-acquire to act.
  CPE_REQUIRE_EQ(after.controller_count(), before.controller_count());

  // Every path back to the old authority is closed: the token is fenced, its
  // grant record no longer exists, and the root's bootstrap token is fenced too.
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(base_token, inventory)), ErrorCode::EpochFenced);
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(base_token, dccp::epoch::authority_grant_scope())),
                 ErrorCode::EpochFenced);
  CPE_REQUIRE_EQ(rejection_code(authority.grant_record(view.record().id())), ErrorCode::UnknownGrant);
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(root, dccp::epoch::epoch_advance_scope())),
                 ErrorCode::EpochFenced);
  // The controller itself is still authoritative for the *new* epoch.
  const auto worker_record = authority.controller_record(cpe_test::controller_id("worker-a"));
  CPE_REQUIRE(worker_record.has_value());
  CPE_REQUIRE_EQ(worker_record.value().incarnation_state(), dccp::epoch::IncarnationState::Current);
  CPE_REQUIRE_EQ(worker_record.value().incarnation_id(), worker.incarnation_id());
}

CPE_TEST(fencing, a_fenced_token_cannot_sponsor_a_real_command) {
  cpe_test::TestAuthority test_authority;
  auto& authority = test_authority.authority();
  const MutationAuthority root = test_authority.root_authority();
  const ControllerRegistration worker = test_authority.register_controller("worker-a");
  const dccp::epoch::ScopeName inventory = cpe_test::scope_name("facility.inventory");
  const AuthorityGrantView view =
      test_authority.acquire("worker-a", worker.incarnation_id(), {"facility.inventory"}, root);
  const MutationAuthority stale = test_authority.mutation_authority_of(view);

  (void)test_authority.advance(Epoch::initial(), root, EpochTransitionReason::OperatorRequest);

  // Acquiring observation authority is a real command: it commits durable state
  // and it needs a currently valid sponsor. The stale token is rejected as
  // fenced, not as "missing the authority.grant scope", because the epoch rung
  // is decided first.
  AcquireAuthorityRequest observation_request = acquire_request(
      "worker-a", worker.incarnation_id(), {"facility.inventory"}, stale, AuthorityClass::Observation);
  CPE_REQUIRE_EQ(rejection_code(authority.acquire_authority(std::move(observation_request))),
                 ErrorCode::EpochFenced);

  // The identical shape with a sponsor from the current epoch succeeds, so the
  // rejection was about the token's epoch and nothing else.
  const MutationAuthority current_root = test_authority.root_authority();
  const AuthorityGrantView observation = test_authority.acquire(
      "worker-a", worker.incarnation_id(), {"facility.inventory"}, current_root, AuthorityClass::Observation);
  CPE_REQUIRE(observation.observation_authority().has_value());
  CPE_REQUIRE_EQ(validation_code(authority.validate_observation(*observation.observation_authority(), inventory)),
                 ErrorCode::Ok);
  CPE_REQUIRE_EQ(observation.record().epoch().value(), std::uint64_t{2});

  // A mutation acquisition sponsored by the same stale token is fenced as well.
  AcquireAuthorityRequest mutation_request =
      acquire_request("worker-a", worker.incarnation_id(), {"facility.topology"}, stale);
  CPE_REQUIRE_EQ(rejection_code(authority.acquire_authority(std::move(mutation_request))),
                 ErrorCode::EpochFenced);

  // Nothing the stale token names works anywhere: validation, sponsorship, and
  // revocation all consult the same ladder.
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(stale, inventory)), ErrorCode::EpochFenced);
  dccp::epoch::RevokeAuthorityRequest revoke_with_stale;
  revoke_with_stale.target =
      dccp::epoch::RevocationTarget::grant(view.record().id(), cpe_test::controller_id("worker-a"));
  revoke_with_stale.reason = dccp::epoch::RevocationReason::OperatorRequest;
  revoke_with_stale.authority = stale;
  revoke_with_stale.provenance = cpe_test::provenance_input("operator");
  const auto revoked = authority.revoke_authority(std::move(revoke_with_stale));
  CPE_REQUIRE(!revoked.has_value());
  CPE_REQUIRE_EQ(revoked.rejection().code(), ErrorCode::EpochFenced);
}

CPE_TEST(fencing, re_registration_cannot_revive_authority_from_a_superseded_incarnation) {
  cpe_test::TestAuthority test_authority;
  auto& authority = test_authority.authority();
  const MutationAuthority root = test_authority.root_authority();
  const dccp::epoch::ScopeName inventory = cpe_test::scope_name("facility.inventory");

  const ControllerRegistration first = test_authority.register_controller("worker-b");
  const AuthorityGrantView view =
      test_authority.acquire("worker-b", first.incarnation_id(), {"facility.inventory"}, root);
  const MutationAuthority old_token = test_authority.mutation_authority_of(view);
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(old_token, inventory)), ErrorCode::Ok);

  // A restart re-registers the controller. The new incarnation fences the
  // authority the previous boot persisted locally.
  const ControllerRegistration second = test_authority.register_controller("worker-b");
  CPE_REQUIRE_EQ(second.incarnation_number().value(), std::uint64_t{2});
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(old_token, inventory)), ErrorCode::IncarnationSuperseded);

  // The old token is unusable as a sponsor: a restarted controller cannot
  // bootstrap itself back into authority with the token it saved.
  AcquireAuthorityRequest sponsored_by_old =
      acquire_request("worker-b", second.incarnation_id(), {"facility.inventory"}, old_token);
  CPE_REQUIRE_EQ(rejection_code(authority.acquire_authority(std::move(sponsored_by_old))),
                 ErrorCode::IncarnationSuperseded);

  // Nor can the old incarnation present itself directly.
  AcquireAuthorityRequest old_incarnation =
      acquire_request("worker-b", first.incarnation_id(), {"facility.inventory"}, root);
  CPE_REQUIRE_EQ(rejection_code(authority.acquire_authority(std::move(old_incarnation))),
                 ErrorCode::IncarnationSuperseded);

  // With a sponsor, the new incarnation acquires normally: re-registration
  // restored the ability to be sponsored, not authority itself.
  const AuthorityGrantView fresh =
      test_authority.acquire("worker-b", second.incarnation_id(), {"facility.inventory"}, root);
  const MutationAuthority fresh_token = test_authority.mutation_authority_of(fresh);
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(fresh_token, inventory)), ErrorCode::Ok);
  CPE_REQUIRE(fresh.record().incarnation_number().value() == std::uint64_t{2});
  // The superseded token stays dead even though its controller is authoritative
  // again.
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(old_token, inventory)), ErrorCode::IncarnationSuperseded);
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(old_token, dccp::epoch::authority_grant_scope())),
                 ErrorCode::IncarnationSuperseded);
}

CPE_TEST(fencing, advancement_requires_the_epoch_advance_scope) {
  cpe_test::TestAuthority test_authority;
  auto& authority = test_authority.authority();
  const MutationAuthority root = test_authority.root_authority();
  const ControllerRegistration worker = test_authority.register_controller("worker-d");

  // A grant that is valid in every other respect still cannot advance the epoch
  // unless it covers the reserved administrative scope.
  const AuthorityGrantView ordinary =
      test_authority.acquire("worker-d", worker.incarnation_id(), {"facility.inventory"}, root);
  const AuthorityGrantView granting =
      test_authority.acquire("worker-d", worker.incarnation_id(), {"authority.grant"}, root);
  const MutationAuthority ordinary_token = test_authority.mutation_authority_of(ordinary);
  const MutationAuthority granting_token = test_authority.mutation_authority_of(granting);
  CPE_REQUIRE_EQ(rejection_code(advance_attempt(test_authority, ordinary_token, 1)), ErrorCode::ScopeNotGranted);
  CPE_REQUIRE_EQ(rejection_code(advance_attempt(test_authority, granting_token, 1)), ErrorCode::ScopeNotGranted);
  // Rejected advancement committed nothing.
  CPE_REQUIRE_EQ(authority.current_epoch().value(), std::uint64_t{1});
  CPE_REQUIRE_EQ(authority.status().transition_count(), std::uint64_t{1});

  // The scope is necessary and sufficient: a sponsored grant covering it, held
  // by a non-root controller, advances the epoch.
  const AuthorityGrantView advancing =
      test_authority.acquire("worker-d", worker.incarnation_id(), {"epoch.advance"}, root);
  const MutationAuthority advancing_token = test_authority.mutation_authority_of(advancing);
  const Result<EpochTransitionRecord> committed =
      advance_attempt(test_authority, advancing_token, 1, EpochTransitionReason::FacilityReconfiguration);
  CPE_REQUIRE(committed.has_value());
  CPE_REQUIRE_EQ(committed.value().base_epoch().value(), std::uint64_t{1});
  CPE_REQUIRE_EQ(committed.value().new_epoch().value(), std::uint64_t{2});
  CPE_REQUIRE_EQ(committed.value().committed_by().to_string(), std::string("worker-d"));
  CPE_REQUIRE_EQ(committed.value().committed_by_grant(), advancing.record().id());
  CPE_REQUIRE_EQ(committed.value().committed_by_incarnation(), worker.incarnation_id());
  CPE_REQUIRE_EQ(committed.value().reason(), EpochTransitionReason::FacilityReconfiguration);
  CPE_REQUIRE_EQ(authority.current_epoch().value(), std::uint64_t{2});
  // The authorizing grant was itself a grant of the base epoch, so it is fenced
  // by the transition it authorized.
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(advancing_token, dccp::epoch::epoch_advance_scope())),
                 ErrorCode::EpochFenced);
}

CPE_TEST(fencing, stale_expectations_conflict_and_exactly_one_successor_exists) {
  cpe_test::TestAuthority test_authority;
  auto& authority = test_authority.authority();
  const MutationAuthority root = test_authority.root_authority();

  const Result<EpochTransitionRecord> committed = advance_attempt(test_authority, root, 1);
  CPE_REQUIRE(committed.has_value());
  CPE_REQUIRE_EQ(committed.value().new_epoch().value(), std::uint64_t{2});
  CPE_REQUIRE_EQ(committed.value().sequence().value(), std::uint64_t{2});

  // The second advancement from the same base epoch loses the race. The
  // expected epoch is a precondition, so the loser is told it conflicted rather
  // than that its authority is bad, and the code is retryable: the same request
  // against the new authoritative epoch is a legitimate retry.
  const Result<EpochTransitionRecord> conflict = advance_attempt(test_authority, root, 1);
  CPE_REQUIRE(!conflict.has_value());
  CPE_REQUIRE_EQ(conflict.rejection().code(), ErrorCode::EpochConflict);
  CPE_REQUIRE(conflict.rejection().retryable());
  CPE_REQUIRE_EQ(conflict.rejection().token(), std::string_view("epoch.conflict"));
  CPE_REQUIRE_EQ(conflict.rejection().detail(),
                 std::string("expected epoch 1 but the authoritative epoch is 2"));
  // The conflict is reported before the authority is even examined: the token
  // used above is now stale, and a fenced token would have produced EpochFenced
  // had the authority rung been reached first.
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(root, dccp::epoch::epoch_advance_scope())),
                 ErrorCode::EpochFenced);
  CPE_REQUIRE_EQ(authority.current_epoch().value(), std::uint64_t{2});

  // An unset expectation is rejected before the conflict is considered.
  CPE_REQUIRE_EQ(rejection_code(advance_attempt(test_authority, root, 0)), ErrorCode::EpochZero);

  // Exactly one successor exists per base epoch: the ledger holds one record
  // whose base epoch is 1, and after the retry one whose base epoch is 2.
  const auto first_ledger = authority.history(dccp::epoch::HistoryQuery{});
  CPE_REQUIRE(first_ledger.has_value());
  std::uint64_t successors_of_one = 0;
  for (const EpochTransitionRecord& record : first_ledger.value().records()) {
    if (!record.is_origin() && record.base_epoch().value() == 1) {
      ++successors_of_one;
      CPE_REQUIRE_EQ(record.new_epoch().value(), std::uint64_t{2});
    }
  }
  CPE_REQUIRE_EQ(successors_of_one, std::uint64_t{1});
  CPE_REQUIRE_EQ(first_ledger.value().total_count(), std::uint64_t{2});

  const MutationAuthority epoch_two_root = test_authority.root_authority();
  const Result<EpochTransitionRecord> retried = advance_attempt(test_authority, epoch_two_root, 2);
  CPE_REQUIRE(retried.has_value());
  CPE_REQUIRE_EQ(retried.value().base_epoch().value(), std::uint64_t{2});
  CPE_REQUIRE_EQ(retried.value().new_epoch().value(), std::uint64_t{3});

  const auto second_ledger = authority.history(dccp::epoch::HistoryQuery{});
  CPE_REQUIRE(second_ledger.has_value());
  std::uint64_t successors_of_two = 0;
  std::uint64_t successors_of_one_again = 0;
  for (const EpochTransitionRecord& record : second_ledger.value().records()) {
    if (record.is_origin()) {
      continue;
    }
    if (record.base_epoch().value() == 1) {
      ++successors_of_one_again;
    }
    if (record.base_epoch().value() == 2) {
      ++successors_of_two;
    }
  }
  CPE_REQUIRE_EQ(successors_of_one_again, std::uint64_t{1});
  CPE_REQUIRE_EQ(successors_of_two, std::uint64_t{1});
  CPE_REQUIRE_EQ(second_ledger.value().total_count(), std::uint64_t{3});
  CPE_REQUIRE_EQ(authority.current_epoch().value(), std::uint64_t{3});
  // Both records chain, so the two-successor claim is verifiable from the ledger
  // alone: a fork would break the chain at the second record.
  const std::vector<EpochTransitionRecord>& records = second_ledger.value().records();
  for (std::size_t index = 1; index < records.size(); ++index) {
    CPE_REQUIRE_EQ(records[index].previous_record_digest(), records[index - 1].record_digest());
  }
}
