// Control Plane Epoch 1.0.0 - Summon Software Labs
// Revocation suite.
//
// Revocation is the operator's fencing tool, so its contract is precision and
// monotonicity: a grant revocation fences exactly the named grant, a controller
// revocation fences every grant of the incarnations it names, and no later
// command can reduce a fence that is already in force. Repeating a revocation is
// safe: it is accepted, recorded, and marked as a replay that fenced nothing.
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "test_support.hpp"

namespace {

using dccp::epoch::AcquireAuthorityRequest;
using dccp::epoch::AuthorityClass;
using dccp::epoch::ControllerIncarnationId;
using dccp::epoch::ControllerRegistration;
using dccp::epoch::ErrorCode;
using dccp::epoch::IncarnationNumber;
using dccp::epoch::IncarnationState;
using dccp::epoch::MutationAuthority;
using dccp::epoch::ProvenanceSourceKind;
using dccp::epoch::Result;
using dccp::epoch::RevocationQuery;
using dccp::epoch::RevocationReason;
using dccp::epoch::RevocationRecord;
using dccp::epoch::RevocationSequence;
using dccp::epoch::RevocationTarget;
using dccp::epoch::RevocationTargetKind;
using dccp::epoch::RevokeAuthorityRequest;
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

[[nodiscard]] RevokeAuthorityRequest revoke_request(const RevocationTarget& target,
                                                    const MutationAuthority& authority,
                                                    RevocationReason reason) {
  RevokeAuthorityRequest request;
  request.target = target;
  request.reason = reason;
  request.authority = authority;
  request.provenance = cpe_test::provenance_input("operator", ProvenanceSourceKind::Operator);
  return request;
}

/// Revocation is expected to succeed in this suite; a rejection is a test
/// failure that reports the authority's own explanation.
[[nodiscard]] RevocationRecord revoke(cpe_test::TestAuthority& test_authority, const RevocationTarget& target,
                                      const MutationAuthority& authority,
                                      RevocationReason reason = RevocationReason::OperatorRequest) {
  auto result = test_authority.authority().revoke_authority(revoke_request(target, authority, reason));
  if (!result.has_value()) {
    throw cpe_test::Failure("revocation was rejected: " + result.rejection().to_string());
  }
  return result.move_value();
}

/// A controller registered three times, holding two live grants issued to its
/// third incarnation: the shape most revocation cases need.
struct ThreeIncarnationController {
  ControllerRegistration first;
  ControllerRegistration third;
  dccp::epoch::AuthorityGrantView inventory_grant;
  dccp::epoch::AuthorityGrantView topology_grant;
  MutationAuthority inventory_token;
  MutationAuthority topology_token;
};

[[nodiscard]] ThreeIncarnationController prepare_controller(cpe_test::TestAuthority& test_authority,
                                                            const MutationAuthority& sponsor,
                                                            const std::string& controller) {
  ThreeIncarnationController prepared;
  prepared.first = test_authority.register_controller(controller);
  (void)test_authority.register_controller(controller);
  prepared.third = test_authority.register_controller(controller);
  prepared.inventory_grant =
      test_authority.acquire(controller, prepared.third.incarnation_id(), {"facility.inventory"}, sponsor);
  prepared.topology_grant =
      test_authority.acquire(controller, prepared.third.incarnation_id(), {"facility.topology"}, sponsor);
  prepared.inventory_token = test_authority.mutation_authority_of(prepared.inventory_grant);
  prepared.topology_token = test_authority.mutation_authority_of(prepared.topology_grant);
  return prepared;
}

}  // namespace

CPE_TEST(revocation, grant_revocation_fences_exactly_one_grant) {
  cpe_test::TestAuthority test_authority;
  auto& authority = test_authority.authority();
  const MutationAuthority root = test_authority.root_authority();
  const ControllerRegistration worker = test_authority.register_controller("worker-a");
  const ControllerRegistration bystander = test_authority.register_controller("worker-b");
  const dccp::epoch::ScopeName inventory = cpe_test::scope_name("facility.inventory");
  const dccp::epoch::ScopeName topology = cpe_test::scope_name("facility.topology");

  const dccp::epoch::AuthorityGrantView inventory_grant =
      test_authority.acquire("worker-a", worker.incarnation_id(), {"facility.inventory"}, root);
  const dccp::epoch::AuthorityGrantView topology_grant =
      test_authority.acquire("worker-a", worker.incarnation_id(), {"facility.topology"}, root);
  const dccp::epoch::AuthorityGrantView bystander_grant =
      test_authority.acquire("worker-b", bystander.incarnation_id(), {"facility.topology"}, root);
  const MutationAuthority inventory_token = test_authority.mutation_authority_of(inventory_grant);
  const MutationAuthority topology_token = test_authority.mutation_authority_of(topology_grant);
  const MutationAuthority bystander_token = test_authority.mutation_authority_of(bystander_grant);
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(inventory_token, inventory)), ErrorCode::Ok);
  const std::uint64_t live_before = authority.status().live_grant_count();

  const RevocationRecord record =
      revoke(test_authority, RevocationTarget::grant(inventory_grant.record().id(),
                                                     cpe_test::controller_id("worker-a")),
             root);
  CPE_REQUIRE_EQ(record.target_kind(), RevocationTargetKind::Grant);
  CPE_REQUIRE(record.grant().has_value());
  CPE_REQUIRE_EQ(*record.grant(), inventory_grant.record().id());
  CPE_REQUIRE(!record.through_incarnation().has_value());
  CPE_REQUIRE_EQ(record.fenced_grant_count(), std::uint64_t{1});
  CPE_REQUIRE(!record.replayed());
  CPE_REQUIRE_EQ(record.sequence().value(), std::uint64_t{1});
  CPE_REQUIRE_EQ(record.epoch().value(), std::uint64_t{1});
  CPE_REQUIRE_EQ(record.reason(), RevocationReason::OperatorRequest);
  CPE_REQUIRE_EQ(record.issued_by().to_string(), test_authority.root());
  CPE_REQUIRE_EQ(record.issued_by_incarnation(), root.incarnation());
  CPE_REQUIRE_EQ(record.issued_by_grant(), root.grant());
  CPE_REQUIRE_EQ(record.provenance().kind(), ProvenanceSourceKind::Operator);
  CPE_REQUIRE_EQ(record.provenance().source().to_string(), std::string("operator"));
  // The first record in the ledger chains to the (absent) anchor, which is the
  // zero digest rather than an invented predecessor.
  CPE_REQUIRE(record.previous_record_digest().is_zero());
  CPE_REQUIRE(!record.record_digest().is_zero());
  CPE_REQUIRE_EQ(record.to_string(), record.to_string());
  CPE_REQUIRE(record.to_string().find("target=grant") != std::string::npos);
  CPE_REQUIRE(record.to_string().find("fenced_grants=1") != std::string::npos);
  CPE_REQUIRE(record.to_string().find("replayed=no") != std::string::npos);

  // Exactly one grant is fenced: the named one. The same controller's other
  // grant and another controller's grant are untouched.
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(inventory_token, inventory)), ErrorCode::AuthorityRevoked);
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(inventory_token, topology)), ErrorCode::AuthorityRevoked);
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(topology_token, topology)), ErrorCode::Ok);
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(bystander_token, topology)), ErrorCode::Ok);
  CPE_REQUIRE_EQ(authority.status().live_grant_count(), live_before - 1);

  // The durable grant record names the revocation that fenced it, so the fence
  // is auditable from either direction.
  const auto fenced = authority.grant_record(inventory_grant.record().id());
  CPE_REQUIRE(fenced.has_value());
  CPE_REQUIRE(fenced.value().revoked());
  CPE_REQUIRE(fenced.value().revoked_by_sequence().has_value());
  CPE_REQUIRE_EQ(*fenced.value().revoked_by_sequence(), record.sequence());
  CPE_REQUIRE(!authority.grant_record(topology_grant.record().id()).value().revoked());
  CPE_REQUIRE(!authority.grant_record(bystander_grant.record().id()).value().revoked());
  CPE_REQUIRE_EQ(authority.status().revocation_count(), std::uint64_t{1});
}

CPE_TEST(revocation, controller_revocation_fences_incarnations_through_and_marks_revoked) {
  cpe_test::TestAuthority test_authority;
  auto& authority = test_authority.authority();
  const MutationAuthority root = test_authority.root_authority();
  const dccp::epoch::ScopeName inventory = cpe_test::scope_name("facility.inventory");
  const dccp::epoch::ScopeName topology = cpe_test::scope_name("facility.topology");
  const ThreeIncarnationController worker = prepare_controller(test_authority, root, "worker-c");
  CPE_REQUIRE_EQ(worker.third.incarnation_number().value(), std::uint64_t{3});

  const RevocationRecord record =
      revoke(test_authority,
             RevocationTarget::controller_through(cpe_test::controller_id("worker-c"),
                                                  IncarnationNumber::from_trusted(3)),
             root);
  CPE_REQUIRE_EQ(record.target_kind(), RevocationTargetKind::ControllerIncarnations);
  CPE_REQUIRE(!record.grant().has_value());
  CPE_REQUIRE(record.through_incarnation().has_value());
  CPE_REQUIRE_EQ(record.through_incarnation()->value(), std::uint64_t{3});
  // Both live grants of the controller belong to incarnation 3 and are fenced.
  CPE_REQUIRE_EQ(record.fenced_grant_count(), std::uint64_t{2});
  CPE_REQUIRE(!record.replayed());

  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(worker.inventory_token, inventory)),
                 ErrorCode::AuthorityRevoked);
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(worker.topology_token, topology)),
                 ErrorCode::AuthorityRevoked);
  CPE_REQUIRE(authority.grant_record(worker.inventory_grant.record().id()).value().revoked());
  CPE_REQUIRE(authority.grant_record(worker.topology_grant.record().id()).value().revoked());
  // Held in a named result: a reference into a destroyed temporary would make
  // this assertion read freed memory.
  const auto fenced_inventory = authority.grant_record(worker.inventory_grant.record().id());
  CPE_REQUIRE(fenced_inventory.has_value());
  CPE_REQUIRE(fenced_inventory.value().revoked_by_sequence().has_value());
  CPE_REQUIRE_EQ(*fenced_inventory.value().revoked_by_sequence(), record.sequence());

  // The controller record carries the fence: the incarnation is Revoked, so no
  // reader can mistake it for the authoritative incarnation.
  const auto controller = authority.controller_record(cpe_test::controller_id("worker-c"));
  CPE_REQUIRE(controller.has_value());
  CPE_REQUIRE_EQ(controller.value().incarnation_state(), IncarnationState::Revoked);
  CPE_REQUIRE(!controller.value().is_authoritative_incarnation());
  CPE_REQUIRE(controller.value().revocation_through_incarnation().has_value());
  CPE_REQUIRE_EQ(controller.value().revocation_through_incarnation()->value(), std::uint64_t{3});

  // A revoked controller cannot re-acquire with the revoked incarnation, even
  // with a sponsor: the fence is checked before authority is issued.
  AcquireAuthorityRequest blocked =
      acquire_request("worker-c", worker.third.incarnation_id(), {"facility.inventory"}, root);
  CPE_REQUIRE_EQ(rejection_code(authority.acquire_authority(std::move(blocked))), ErrorCode::AuthorityRevoked);
}

CPE_TEST(revocation, revocation_is_monotonic_and_replays_without_new_fencing) {
  cpe_test::TestAuthority test_authority;
  auto& authority = test_authority.authority();
  const MutationAuthority root = test_authority.root_authority();
  const dccp::epoch::ScopeName topology = cpe_test::scope_name("facility.topology");
  const ThreeIncarnationController worker = prepare_controller(test_authority, root, "worker-c");

  // A first-time grant revocation fences exactly that grant.
  const RevocationRecord grant_first =
      revoke(test_authority,
             RevocationTarget::grant(worker.inventory_grant.record().id(), cpe_test::controller_id("worker-c")),
             root);
  CPE_REQUIRE(!grant_first.replayed());
  CPE_REQUIRE_EQ(grant_first.fenced_grant_count(), std::uint64_t{1});

  // Repeating it is accepted, recorded, and fences nothing: a retry after a lost
  // response must not look like new fencing.
  const RevocationRecord grant_replay =
      revoke(test_authority,
             RevocationTarget::grant(worker.inventory_grant.record().id(), cpe_test::controller_id("worker-c")),
             root);
  CPE_REQUIRE(grant_replay.replayed());
  CPE_REQUIRE_EQ(grant_replay.fenced_grant_count(), std::uint64_t{0});
  CPE_REQUIRE(grant_replay.sequence().value() > grant_first.sequence().value());
  CPE_REQUIRE(grant_replay.to_string().find("replayed=yes") != std::string::npos);
  CPE_REQUIRE(grant_first.to_string().find("replayed=no") != std::string::npos);

  // A controller revocation through incarnation 3 fences the remaining live
  // grant of that incarnation, and only that one.
  const RevocationRecord high =
      revoke(test_authority,
             RevocationTarget::controller_through(cpe_test::controller_id("worker-c"),
                                                  IncarnationNumber::from_trusted(3)),
             root);
  CPE_REQUIRE(!high.replayed());
  CPE_REQUIRE_EQ(high.fenced_grant_count(), std::uint64_t{1});

  // Revoking through a *lower* number is accepted for retry safety but must not
  // reduce the fence that is already in force.
  const RevocationRecord lower =
      revoke(test_authority,
             RevocationTarget::controller_through(cpe_test::controller_id("worker-c"),
                                                  IncarnationNumber::from_trusted(1)),
             root);
  CPE_REQUIRE(lower.replayed());
  CPE_REQUIRE_EQ(lower.fenced_grant_count(), std::uint64_t{0});
  CPE_REQUIRE(lower.through_incarnation().has_value());
  CPE_REQUIRE_EQ(lower.through_incarnation()->value(), std::uint64_t{1});
  CPE_REQUIRE(lower.sequence().value() > high.sequence().value());
  const auto after_lower = authority.controller_record(cpe_test::controller_id("worker-c"));
  CPE_REQUIRE(after_lower.value().revocation_through_incarnation().has_value());
  CPE_REQUIRE_EQ(after_lower.value().revocation_through_incarnation()->value(), std::uint64_t{3});
  CPE_REQUIRE_EQ(after_lower.value().incarnation_state(), IncarnationState::Revoked);

  // Repeating the highest revocation is likewise a replay that fences nothing.
  const RevocationRecord repeat =
      revoke(test_authority,
             RevocationTarget::controller_through(cpe_test::controller_id("worker-c"),
                                                  IncarnationNumber::from_trusted(3)),
             root);
  CPE_REQUIRE(repeat.replayed());
  CPE_REQUIRE_EQ(repeat.fenced_grant_count(), std::uint64_t{0});
  CPE_REQUIRE_EQ(repeat.through_incarnation()->value(), std::uint64_t{3});
  const auto after_repeat = authority.controller_record(cpe_test::controller_id("worker-c"));
  CPE_REQUIRE(after_repeat.has_value());
  CPE_REQUIRE(after_repeat.value().revocation_through_incarnation().has_value());
  CPE_REQUIRE_EQ(after_repeat.value().revocation_through_incarnation()->value(), std::uint64_t{3});

  // Every accepted revocation, including a replay, is one durable record.
  CPE_REQUIRE_EQ(authority.status().revocation_count(), std::uint64_t{5});
  CPE_REQUIRE_EQ(authority.accounting().revocation_records_retained(), std::uint64_t{5});
  // And the fenced set did not grow after the first two fencing operations.
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(worker.topology_token, topology)),
                 ErrorCode::AuthorityRevoked);
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(worker.inventory_token,
                                                            cpe_test::scope_name("facility.inventory"))),
                 ErrorCode::AuthorityRevoked);
}

CPE_TEST(revocation, revoking_an_already_superseded_grant_fences_nothing) {
  // A re-registration already fenced every grant of the earlier incarnation, so
  // that grant is not live any more. Revoking it documents the operator's
  // request but fences nothing new: reporting fresh fencing here would overstate
  // what just happened, and it would contradict the controller-wide path, which
  // skips every non-live grant.
  cpe_test::TestAuthority test_authority;
  auto& authority = test_authority.authority();
  const MutationAuthority root = test_authority.root_authority();
  const dccp::epoch::ScopeName inventory = cpe_test::scope_name("facility.inventory");
  const ControllerRegistration first = test_authority.register_controller("worker-e");
  const dccp::epoch::AuthorityGrantView grant =
      test_authority.acquire("worker-e", first.incarnation_id(), {"facility.inventory"}, root);
  const MutationAuthority token = test_authority.mutation_authority_of(grant);
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(token, inventory)), ErrorCode::Ok);

  // Supersession fences the grant without recording a revocation sequence: from
  // the ledger the grant is simply no longer live.
  (void)test_authority.register_controller("worker-e");
  const auto superseded = authority.grant_record(grant.record().id());
  CPE_REQUIRE(superseded.has_value());
  CPE_REQUIRE(!superseded.value().revoked());
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(token, inventory)), ErrorCode::IncarnationSuperseded);
  const std::uint64_t live_before = authority.status().live_grant_count();

  const RevocationRecord record =
      revoke(test_authority,
             RevocationTarget::grant(grant.record().id(), cpe_test::controller_id("worker-e")), root);
  CPE_REQUIRE(record.replayed());
  CPE_REQUIRE_EQ(record.fenced_grant_count(), std::uint64_t{0});
  CPE_REQUIRE(record.to_string().find("replayed=yes") != std::string::npos);
  // The replay changed no grant state, so no grant gained a revocation sequence
  // and no live authority was lost.
  const auto after = authority.grant_record(grant.record().id());
  CPE_REQUIRE(after.has_value());
  CPE_REQUIRE(!after.value().revoked());
  CPE_REQUIRE_EQ(authority.status().live_grant_count(), live_before);
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(token, inventory)), ErrorCode::IncarnationSuperseded);
  // The request itself is still durable and chained, so the replay is auditable.
  CPE_REQUIRE_EQ(record.sequence().value(), std::uint64_t{1});
  CPE_REQUIRE(record.previous_record_digest().is_zero());
  CPE_REQUIRE(!record.record_digest().is_zero());
  CPE_REQUIRE_EQ(authority.status().revocation_count(), std::uint64_t{1});
}

CPE_TEST(revocation, re_registration_above_the_fence_restores_sponsorable_authority) {
  cpe_test::TestAuthority test_authority;
  auto& authority = test_authority.authority();
  const MutationAuthority root = test_authority.root_authority();
  const dccp::epoch::ScopeName inventory = cpe_test::scope_name("facility.inventory");
  const ThreeIncarnationController worker = prepare_controller(test_authority, root, "worker-c");

  (void)revoke(test_authority,
               RevocationTarget::controller_through(cpe_test::controller_id("worker-c"),
                                                    IncarnationNumber::from_trusted(3)),
               root);

  // Re-registering above the fence produces a fresh incarnation that is not
  // covered by it: revocation is monotonic without being permanent.
  const ControllerRegistration fourth = test_authority.register_controller("worker-c");
  CPE_REQUIRE_EQ(fourth.incarnation_number().value(), std::uint64_t{4});
  CPE_REQUIRE(fourth.incarnation_id() != worker.third.incarnation_id());
  const auto controller = authority.controller_record(cpe_test::controller_id("worker-c"));
  CPE_REQUIRE(controller.has_value());
  CPE_REQUIRE_EQ(controller.value().incarnation_state(), IncarnationState::Current);
  CPE_REQUIRE_EQ(controller.value().registration_count(), std::uint64_t{4});
  // The fence itself is durable state and is not cleared by re-registration.
  CPE_REQUIRE(controller.value().revocation_through_incarnation().has_value());
  CPE_REQUIRE_EQ(controller.value().revocation_through_incarnation()->value(), std::uint64_t{3});

  // The revoked incarnation is remembered as superseded, so an old presentation
  // is attributed precisely: supersession first, revocation second.
  AcquireAuthorityRequest stale =
      acquire_request("worker-c", worker.third.incarnation_id(), {"facility.inventory"}, root);
  CPE_REQUIRE_EQ(rejection_code(authority.acquire_authority(std::move(stale))), ErrorCode::IncarnationSuperseded);

  // Re-registration restores the ability to *be sponsored*; it does not confer
  // authority by itself.
  AcquireAuthorityRequest unsponsored =
      acquire_request("worker-c", fourth.incarnation_id(), {"facility.inventory"}, std::nullopt);
  CPE_REQUIRE_EQ(rejection_code(authority.acquire_authority(std::move(unsponsored))), ErrorCode::SponsorRequired);

  const dccp::epoch::AuthorityGrantView restored =
      test_authority.acquire("worker-c", fourth.incarnation_id(), {"facility.inventory"}, root);
  const MutationAuthority restored_token = test_authority.mutation_authority_of(restored);
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(restored_token, inventory)), ErrorCode::Ok);
  // The pre-fence tokens stay dead.
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(worker.inventory_token, inventory)),
                 ErrorCode::AuthorityRevoked);
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(worker.topology_token,
                                                            cpe_test::scope_name("facility.topology"))),
                 ErrorCode::AuthorityRevoked);

  // controller_all fences through the controller's *current* incarnation, so the
  // restored authority is fenced by it.
  const RevocationRecord all =
      revoke(test_authority, RevocationTarget::controller_all(cpe_test::controller_id("worker-c")), root);
  CPE_REQUIRE(all.through_incarnation().has_value());
  CPE_REQUIRE_EQ(all.through_incarnation()->value(), std::uint64_t{4});
  CPE_REQUIRE_EQ(all.fenced_grant_count(), std::uint64_t{1});
  CPE_REQUIRE(!all.replayed());
  CPE_REQUIRE_EQ(validation_code(authority.validate_mutation(restored_token, inventory)), ErrorCode::AuthorityRevoked);
  const auto fenced_again = authority.controller_record(cpe_test::controller_id("worker-c"));
  CPE_REQUIRE(fenced_again.has_value());
  CPE_REQUIRE_EQ(fenced_again.value().incarnation_state(), IncarnationState::Revoked);
  CPE_REQUIRE_EQ(fenced_again.value().revocation_through_incarnation()->value(), std::uint64_t{4});
}

CPE_TEST(revocation, ledger_is_ordered_chained_and_unknown_targets_are_rejected) {
  cpe_test::TestAuthority test_authority;
  auto& authority = test_authority.authority();
  const MutationAuthority root = test_authority.root_authority();
  const ControllerRegistration worker = test_authority.register_controller("worker-a");
  const ControllerRegistration bystander = test_authority.register_controller("worker-b");

  const dccp::epoch::AuthorityGrantView inventory_grant =
      test_authority.acquire("worker-a", worker.incarnation_id(), {"facility.inventory"}, root);
  const dccp::epoch::AuthorityGrantView topology_grant =
      test_authority.acquire("worker-a", worker.incarnation_id(), {"facility.topology"}, root);
  const dccp::epoch::AuthorityGrantView bystander_grant =
      test_authority.acquire("worker-b", bystander.incarnation_id(), {"facility.topology"}, root);

  const RevocationRecord first =
      revoke(test_authority,
             RevocationTarget::grant(inventory_grant.record().id(), cpe_test::controller_id("worker-a")), root,
             RevocationReason::SuspectedStaleAuthority);
  const RevocationRecord second =
      revoke(test_authority,
             RevocationTarget::controller_through(cpe_test::controller_id("worker-a"),
                                                  IncarnationNumber::from_trusted(1)),
             root, RevocationReason::Decommission);
  const RevocationRecord third =
      revoke(test_authority,
             RevocationTarget::grant(inventory_grant.record().id(), cpe_test::controller_id("worker-a")), root);
  CPE_REQUIRE_EQ(first.reason(), RevocationReason::SuspectedStaleAuthority);
  CPE_REQUIRE_EQ(second.reason(), RevocationReason::Decommission);
  CPE_REQUIRE(third.replayed());
  CPE_REQUIRE_EQ(second.fenced_grant_count(), std::uint64_t{1});

  // The ledger is ascending by sequence and each record chains to its
  // predecessor, so a truncation, reorder, or substitution is detectable.
  const auto page = authority.revocations(RevocationQuery{});
  CPE_REQUIRE(page.has_value());
  const std::vector<RevocationRecord>& records = page.value().records();
  CPE_REQUIRE_EQ(records.size(), std::size_t{3});
  CPE_REQUIRE_EQ(page.value().total_count(), std::uint64_t{3});
  CPE_REQUIRE_EQ(page.value().trimmed_count(), std::uint64_t{0});
  CPE_REQUIRE_EQ(page.value().first_retained_sequence(), std::uint64_t{1});
  CPE_REQUIRE(records.front().previous_record_digest().is_zero());
  for (std::size_t index = 0; index < records.size(); ++index) {
    CPE_REQUIRE_EQ(records[index].sequence().value(), static_cast<std::uint64_t>(index + 1));
    CPE_REQUIRE(!records[index].record_digest().is_zero());
    if (index > 0) {
      CPE_REQUIRE_EQ(records[index].previous_record_digest(), records[index - 1].record_digest());
    }
  }
  CPE_REQUIRE_EQ(page.value().chain_head(), records.back().record_digest());
  CPE_REQUIRE(records[0] == first);
  CPE_REQUIRE(records[1] == second);
  CPE_REQUIRE(records[2] == third);
  CPE_REQUIRE_EQ(records[1].to_string(), second.to_string());
  CPE_REQUIRE_EQ(records[2].to_string(), third.to_string());
  CPE_REQUIRE(records[1].to_string().find("replayed=no") != std::string::npos);
  CPE_REQUIRE(records[2].to_string().find("replayed=yes") != std::string::npos);

  // A paged query returns the requested window without changing the totals.
  RevocationQuery tail_query;
  tail_query.from_sequence = RevocationSequence::from_trusted(2);
  const auto tail = authority.revocations(tail_query);
  CPE_REQUIRE(tail.has_value());
  CPE_REQUIRE_EQ(tail.value().records().size(), std::size_t{2});
  CPE_REQUIRE_EQ(tail.value().records().front().sequence().value(), std::uint64_t{2});
  CPE_REQUIRE_EQ(tail.value().total_count(), std::uint64_t{3});
  CPE_REQUIRE_EQ(tail.value().chain_head(), page.value().chain_head());

  // Unknown targets are rejected, and a rejected revocation changes nothing.
  const auto unknown_grant = authority.revoke_authority(revoke_request(
      RevocationTarget::grant(dccp::epoch::GrantId::from_trusted(99999), cpe_test::controller_id("worker-a")), root,
      RevocationReason::OperatorRequest));
  CPE_REQUIRE(!unknown_grant.has_value());
  CPE_REQUIRE_EQ(unknown_grant.rejection().code(), ErrorCode::RevocationUnknownTarget);
  // A grant that exists but belongs to a different controller is unknown for the
  // stated target: the target names both the grant and its owner.
  const auto wrong_owner = authority.revoke_authority(revoke_request(
      RevocationTarget::grant(bystander_grant.record().id(), cpe_test::controller_id("worker-a")), root,
      RevocationReason::OperatorRequest));
  CPE_REQUIRE(!wrong_owner.has_value());
  CPE_REQUIRE_EQ(wrong_owner.rejection().code(), ErrorCode::RevocationUnknownTarget);
  const auto unknown_controller = authority.revoke_authority(revoke_request(
      RevocationTarget::controller_all(cpe_test::controller_id("nobody")), root, RevocationReason::OperatorRequest));
  CPE_REQUIRE(!unknown_controller.has_value());
  CPE_REQUIRE_EQ(unknown_controller.rejection().code(), ErrorCode::RevocationUnknownTarget);
  // A target with an empty controller identifier is a malformed request, not an
  // unknown controller.
  const auto empty_target = authority.revoke_authority(revoke_request(
      RevocationTarget::controller_all(dccp::epoch::ControllerId{}), root, RevocationReason::OperatorRequest));
  CPE_REQUIRE(!empty_target.has_value());
  CPE_REQUIRE_EQ(empty_target.rejection().code(), ErrorCode::IdentifierEmpty);

  CPE_REQUIRE_EQ(authority.status().revocation_count(), std::uint64_t{3});
  CPE_REQUIRE_EQ(authority.accounting().revocation_records_retained(), std::uint64_t{3});
  // The controller revocation fenced worker-a's remaining live grant as well
  // (it belongs to incarnation 1, which is <= the fence), while the bystander
  // controller's grant was never a target of any revocation here.
  CPE_REQUIRE(authority.grant_record(topology_grant.record().id()).value().revoked());
  CPE_REQUIRE(!authority.grant_record(bystander_grant.record().id()).value().revoked());
}
