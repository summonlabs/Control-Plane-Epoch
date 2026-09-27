// Control Plane Epoch 1.0.0 - Summon Software Labs
// Registration suite.
//
// Registration is the discovery step every controller performs after boot. It
// confers identity and nothing else: a registered controller still holds no
// authority, and re-registering supersedes the previous incarnation so that
// authority persisted by an earlier boot can never be reused.
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
using dccp::epoch::IdempotencyKey;
using dccp::epoch::IncarnationNumber;
using dccp::epoch::IncarnationState;
using dccp::epoch::MutationAuthority;
using dccp::epoch::OperationSequence;
using dccp::epoch::ProvenanceSourceKind;
using dccp::epoch::Result;

template <class T>
[[nodiscard]] ErrorCode rejection_code(const Result<T>& result) {
  return result.has_value() ? ErrorCode::Ok : result.rejection().code();
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

/// Reproducible incarnation identity: derived from (domain, controller, number)
/// and therefore reconstructible from durable state alone.
[[nodiscard]] ControllerIncarnationId derived(const cpe_test::TestAuthority& test_authority,
                                              const std::string& controller, std::uint64_t number) {
  return ControllerIncarnationId::derive(cpe_test::domain_id(test_authority.domain()),
                                         cpe_test::controller_id(controller),
                                         IncarnationNumber::from_trusted(number));
}

}  // namespace

CPE_TEST(registration, fresh_registration_allocates_incarnation_one) {
  cpe_test::TestAuthority test_authority;
  CPE_REQUIRE_EQ(test_authority.authority().status().controller_count(), std::uint64_t{1});

  const ControllerRegistration registration = test_authority.register_controller("worker-a");
  CPE_REQUIRE_EQ(registration.controller().to_string(), std::string("worker-a"));
  CPE_REQUIRE_EQ(registration.incarnation_number().value(), std::uint64_t{1});
  CPE_REQUIRE(!registration.replayed());
  CPE_REQUIRE_EQ(registration.epoch().value(), std::uint64_t{1});
  CPE_REQUIRE(registration.sequence().is_set());
  CPE_REQUIRE(!registration.incarnation_id().is_zero());
  CPE_REQUIRE_EQ(registration.incarnation_id(), derived(test_authority, "worker-a", 1));
  // Determinism: the same derivation asked twice gives the same identity, so a
  // registration can be checked against durable state without trusting a
  // random value.
  CPE_REQUIRE_EQ(registration.incarnation_id(), derived(test_authority, "worker-a", 1));

  const auto record = test_authority.authority().controller_record(cpe_test::controller_id("worker-a"));
  CPE_REQUIRE(record.has_value());
  CPE_REQUIRE_EQ(record.value().incarnation_number().value(), std::uint64_t{1});
  CPE_REQUIRE_EQ(record.value().incarnation_id(), registration.incarnation_id());
  CPE_REQUIRE_EQ(record.value().incarnation_state(), IncarnationState::Current);
  CPE_REQUIRE(record.value().is_authoritative_incarnation());
  CPE_REQUIRE_EQ(record.value().registration_count(), std::uint64_t{1});
  CPE_REQUIRE_EQ(record.value().first_registered_epoch().value(), std::uint64_t{1});
  CPE_REQUIRE_EQ(record.value().latest_registered_epoch().value(), std::uint64_t{1});
  CPE_REQUIRE(!record.value().revocation_through_incarnation().has_value());
  CPE_REQUIRE(!record.value().record_digest().is_zero());
  CPE_REQUIRE_EQ(record.value().latest_registration_provenance().kind(), ProvenanceSourceKind::Controller);
  CPE_REQUIRE_EQ(record.value().latest_registration_provenance().source().to_string(), std::string("worker-a"));
  CPE_REQUIRE_EQ(record.value().latest_registration_provenance().recorded_epoch().value(), std::uint64_t{1});
  CPE_REQUIRE_EQ(record.value().latest_registration_provenance().recorded_sequence(),
                 registration.sequence().value());

  CPE_REQUIRE_EQ(test_authority.authority().status().controller_count(), std::uint64_t{2});
  CPE_REQUIRE_EQ(test_authority.authority().accounting().controller_records(), std::uint64_t{2});

  // Rendering is deterministic and carries the recorded state, so a log line
  // can be compared between runs.
  const std::string rendered = registration.to_string();
  CPE_REQUIRE(rendered.find("controller=worker-a") != std::string::npos);
  CPE_REQUIRE(rendered.find("incarnation=1") != std::string::npos);
  CPE_REQUIRE(rendered.find("epoch=1") != std::string::npos);
  CPE_REQUIRE(rendered.find("replayed=no") != std::string::npos);
  CPE_REQUIRE(rendered.find(registration.incarnation_id().to_hex()) != std::string::npos);
  CPE_REQUIRE_EQ(registration.to_string(), rendered);

  // An unregistered controller is reported as unknown, never as an empty record.
  const auto missing = test_authority.authority().controller_record(cpe_test::controller_id("nobody"));
  CPE_REQUIRE(!missing.has_value());
  CPE_REQUIRE_EQ(missing.rejection().code(), ErrorCode::ControllerUnknown);
}

CPE_TEST(registration, re_registration_supersedes_the_previous_incarnation) {
  cpe_test::TestAuthority test_authority;
  const MutationAuthority root = test_authority.root_authority();
  const std::string controller = "worker-a";
  const dccp::epoch::ScopeName inventory = cpe_test::scope_name("facility.inventory");

  const ControllerRegistration first = test_authority.register_controller(controller);
  const dccp::epoch::AuthorityGrantView view =
      test_authority.acquire(controller, first.incarnation_id(), {"facility.inventory"}, root);
  const MutationAuthority old_token = test_authority.mutation_authority_of(view);
  CPE_REQUIRE(test_authority.authority().validate_mutation(old_token, inventory).accepted());

  const ControllerRegistration second = test_authority.register_controller(controller);
  CPE_REQUIRE_EQ(second.incarnation_number().value(), std::uint64_t{2});
  CPE_REQUIRE(second.incarnation_id() != first.incarnation_id());
  CPE_REQUIRE_EQ(second.incarnation_id(), derived(test_authority, controller, 2));
  CPE_REQUIRE_EQ(second.epoch().value(), std::uint64_t{1});
  CPE_REQUIRE(second.sequence().value() > first.sequence().value());
  CPE_REQUIRE(!second.replayed());

  const auto record = test_authority.authority().controller_record(cpe_test::controller_id(controller));
  CPE_REQUIRE(record.has_value());
  CPE_REQUIRE_EQ(record.value().incarnation_number().value(), std::uint64_t{2});
  CPE_REQUIRE_EQ(record.value().registration_count(), std::uint64_t{2});
  CPE_REQUIRE_EQ(record.value().incarnation_state(), IncarnationState::Current);
  CPE_REQUIRE_EQ(record.value().incarnation_id(), second.incarnation_id());
  CPE_REQUIRE_EQ(record.value().first_registered_epoch().value(), std::uint64_t{1});
  CPE_REQUIRE_EQ(record.value().latest_registered_epoch().value(), std::uint64_t{1});

  // The authority bound to the earlier boot is rejected because that incarnation
  // is *remembered* as superseded, not because it is unrecognized: the two
  // codes mean different things to an operator.
  const dccp::epoch::ValidationOutcome superseded = test_authority.authority().validate_mutation(old_token, inventory);
  CPE_REQUIRE(!superseded.accepted());
  CPE_REQUIRE_EQ(superseded.rejection()->code(), ErrorCode::IncarnationSuperseded);
  CPE_REQUIRE_EQ(superseded.rejection()->token(), std::string_view("incarnation.superseded"));

  // Presenting the old incarnation directly is rejected the same way, even with
  // a valid sponsor.
  AcquireAuthorityRequest stale =
      acquire_request(controller, first.incarnation_id(), {"facility.inventory"}, root);
  CPE_REQUIRE_EQ(rejection_code(test_authority.authority().acquire_authority(std::move(stale))),
                 ErrorCode::IncarnationSuperseded);

  // An incarnation that was never issued is a different failure.
  AcquireAuthorityRequest stranger = acquire_request(controller, derived(test_authority, controller, 9),
                                                     {"facility.inventory"}, root);
  CPE_REQUIRE_EQ(rejection_code(test_authority.authority().acquire_authority(std::move(stranger))),
                 ErrorCode::IncarnationUnknown);

  // A third registration keeps moving the incarnation forward and is reproduced
  // by the same derivation.
  const ControllerRegistration third = test_authority.register_controller(controller);
  CPE_REQUIRE_EQ(third.incarnation_number().value(), std::uint64_t{3});
  CPE_REQUIRE_EQ(third.incarnation_id(), derived(test_authority, controller, 3));
  const auto thrice_registered =
      test_authority.authority().controller_record(cpe_test::controller_id(controller));
  CPE_REQUIRE(thrice_registered.has_value());
  CPE_REQUIRE_EQ(thrice_registered.value().registration_count(), std::uint64_t{3});
  // The newest incarnation can acquire again; the superseded ones cannot.
  const dccp::epoch::AuthorityGrantView current =
      test_authority.acquire(controller, third.incarnation_id(), {"facility.inventory"}, root);
  CPE_REQUIRE(test_authority.authority()
                  .validate_mutation(test_authority.mutation_authority_of(current), inventory)
                  .accepted());
}

CPE_TEST(registration, registration_confers_identity_only) {
  cpe_test::TestAuthority test_authority;
  const std::string controller = "worker-a";
  const ControllerRegistration registration = test_authority.register_controller(controller);
  const dccp::epoch::ControllerId controller_id = cpe_test::controller_id(controller);

  // No sponsor: registration produced an identity, not authority. Even the
  // reserved administrative scopes are not available to an ordinary controller
  // without a sponsor.
  for (const std::vector<std::string>& scopes :
       std::vector<std::vector<std::string>>{{"facility.inventory"}, {"authority.grant"}, {"epoch.advance"},
                                             {"authority.grant", "authority.revoke"}}) {
    AcquireAuthorityRequest unsponsored = acquire_request(controller, registration.incarnation_id(), scopes, std::nullopt);
    CPE_REQUIRE_MSG(rejection_code(test_authority.authority().acquire_authority(std::move(unsponsored))) ==
                        ErrorCode::SponsorRequired,
                    "an unsponsored grant was issued");
  }

  // The root is the documented bootstrap exception, and only for the reserved
  // administrative scopes: it cannot silently take over an ordinary facility
  // scope without a sponsor either.
  const MutationAuthority root = test_authority.root_authority();
  const auto root_record = test_authority.authority().controller_record(cpe_test::controller_id(test_authority.root()));
  CPE_REQUIRE(root_record.has_value());
  AcquireAuthorityRequest root_ordinary =
      acquire_request(test_authority.root(), root_record.value().incarnation_id(), {"facility.inventory"},
                      std::nullopt);
  CPE_REQUIRE_EQ(rejection_code(test_authority.authority().acquire_authority(std::move(root_ordinary))),
                 ErrorCode::SponsorRequired);

  // An unregistered controller cannot acquire even with a valid sponsor: the
  // grant would be bound to an incarnation that does not exist.
  AcquireAuthorityRequest ghost = acquire_request(
      "ghost", derived(test_authority, "ghost", 1), {"facility.inventory"}, root);
  CPE_REQUIRE_EQ(rejection_code(test_authority.authority().acquire_authority(std::move(ghost))),
                 ErrorCode::ControllerUnknown);

  // With a sponsor the identical request succeeds: the rejection above was
  // about missing authority, not about the request shape.
  const dccp::epoch::AuthorityGrantView granted =
      test_authority.acquire(controller, registration.incarnation_id(), {"facility.inventory"}, root);
  CPE_REQUIRE_EQ(granted.record().controller(), controller_id);
  CPE_REQUIRE_EQ(granted.record().incarnation(), registration.incarnation_id());
  CPE_REQUIRE(granted.record().epoch().value() == registration.epoch().value());
  CPE_REQUIRE(test_authority.authority()
                  .validate_mutation(test_authority.mutation_authority_of(granted),
                                     cpe_test::scope_name("facility.inventory"))
                  .accepted());

  // A registration with no provenance at all is rejected: provenance is
  // recorded, never inferred.
  dccp::epoch::RegisterControllerRequest unprovenanced;
  unprovenanced.controller = cpe_test::controller_id("worker-b");
  CPE_REQUIRE_EQ(rejection_code(test_authority.authority().register_controller(std::move(unprovenanced))),
                 ErrorCode::InvalidArgument);

  // An empty identity is rejected before anything else is examined.
  dccp::epoch::RegisterControllerRequest anonymous;
  anonymous.provenance = cpe_test::provenance_input("operator", ProvenanceSourceKind::Operator);
  CPE_REQUIRE_EQ(rejection_code(test_authority.authority().register_controller(std::move(anonymous))),
                 ErrorCode::IdentifierEmpty);
}

CPE_TEST(registration, controller_accounting_is_identity_keyed_and_bounded) {
  cpe_test::TestAuthority test_authority;
  const std::vector<std::string> names = {"worker-a", "worker-b", "worker-c", "worker-d", "worker-e"};

  // The initializer registered exactly one controller: the authority root.
  CPE_REQUIRE_EQ(test_authority.authority().status().controller_count(), std::uint64_t{1});
  for (const std::string& name : names) {
    (void)test_authority.register_controller(name);
  }
  CPE_REQUIRE_EQ(test_authority.authority().status().controller_count(), std::uint64_t{1 + names.size()});
  CPE_REQUIRE_EQ(test_authority.authority().accounting().controller_records(), std::uint64_t{1 + names.size()});

  // Re-registration supersedes an incarnation; it never adds a controller
  // identity. The domain's controller bound therefore counts distinct
  // identities, so a controller that reboots forever cannot exhaust it.
  for (const std::string& name : names) {
    (void)test_authority.register_controller(name);
    (void)test_authority.register_controller(name);
  }
  CPE_REQUIRE_EQ(test_authority.authority().status().controller_count(), std::uint64_t{1 + names.size()});
  CPE_REQUIRE_EQ(test_authority.authority().accounting().controller_records(), std::uint64_t{1 + names.size()});
  for (const std::string& name : names) {
    const auto record = test_authority.authority().controller_record(cpe_test::controller_id(name));
    CPE_REQUIRE(record.has_value());
    CPE_REQUIRE_EQ(record.value().incarnation_number().value(), std::uint64_t{3});
    CPE_REQUIRE_EQ(record.value().registration_count(), std::uint64_t{3});
  }

  // The bound itself is checked against exactly this accounting. Reaching
  // max_controllers == 65536 requires 65536 accepted registrations, each one an
  // fsync-bound, verified durable commit, which is far outside a unit suite's
  // budget; the scale choice is therefore to prove the accounting the bound is
  // applied to, and to pin the rejection contract that fires at the boundary.
  CPE_REQUIRE_EQ(dccp::epoch::max_controllers, std::size_t{65536});
  CPE_REQUIRE(test_authority.authority().status().controller_count() < dccp::epoch::max_controllers);
  CPE_REQUIRE_EQ(dccp::epoch::error_token(ErrorCode::ControllerLimitReached),
                 std::string_view("limit.controller_count"));
  CPE_REQUIRE(dccp::epoch::error_retryable(ErrorCode::ControllerLimitReached));

  // The controller ledger lists identities in ascending order with the total
  // count the bound is compared against.
  const auto page = test_authority.authority().controllers(dccp::epoch::ControllerQuery{});
  CPE_REQUIRE(page.has_value());
  CPE_REQUIRE_EQ(page.value().total_count(), std::uint64_t{1 + names.size()});
  CPE_REQUIRE_EQ(page.value().records().size(), std::size_t{1 + names.size()});
  for (std::size_t index = 1; index < page.value().records().size(); ++index) {
    CPE_REQUIRE(page.value().records()[index - 1].controller() < page.value().records()[index].controller());
  }
}

CPE_TEST(registration, provenance_and_sequences_are_recorded_in_order) {
  cpe_test::TestAuthority test_authority;
  std::vector<std::uint64_t> sequences;

  const ControllerRegistration first = test_authority.register_controller("worker-a");
  sequences.push_back(first.sequence().value());
  const ControllerRegistration second = test_authority.register_controller("worker-b");
  sequences.push_back(second.sequence().value());
  // Re-registration is a state change too, so it consumes a sequence as well.
  const ControllerRegistration third = test_authority.register_controller("worker-a");
  sequences.push_back(third.sequence().value());
  const ControllerRegistration fourth = test_authority.register_controller("worker-c");
  sequences.push_back(fourth.sequence().value());

  for (std::size_t index = 1; index < sequences.size(); ++index) {
    CPE_REQUIRE_MSG(sequences[index] > sequences[index - 1], "registration sequences must strictly increase");
  }
  CPE_REQUIRE(sequences.front() >= std::uint64_t{1});

  // Provenance is attached to the accepted change, and the recorded sequence is
  // the position of that change in the domain's mutation ledger.
  CPE_REQUIRE_EQ(fourth.provenance().kind(), ProvenanceSourceKind::Controller);
  CPE_REQUIRE_EQ(fourth.provenance().source().to_string(), std::string("worker-c"));
  CPE_REQUIRE_EQ(fourth.provenance().recorded_epoch().value(), std::uint64_t{1});
  CPE_REQUIRE_EQ(fourth.provenance().recorded_sequence(), fourth.sequence().value());
  CPE_REQUIRE(!fourth.provenance().record_digest().is_zero());
  CPE_REQUIRE(!fourth.provenance().external().has_value());
  CPE_REQUIRE_EQ(fourth.provenance().to_string(), fourth.provenance().to_string());
  CPE_REQUIRE_EQ(test_authority.authority()
                     .controller_record(cpe_test::controller_id("worker-c"))
                     .value()
                     .latest_registration_provenance()
                     .to_string(),
                 fourth.provenance().to_string());

  // A caller-supplied provenance is recorded as supplied, including its source
  // kind: the authority never substitutes its own.
  dccp::epoch::RegisterControllerRequest request;
  request.controller = cpe_test::controller_id("worker-d");
  request.provenance = cpe_test::provenance_input("operator-console", ProvenanceSourceKind::Operator);
  const auto operator_registration = test_authority.authority().register_controller(std::move(request));
  CPE_REQUIRE(operator_registration.has_value());
  CPE_REQUIRE_EQ(operator_registration.value().provenance().kind(), ProvenanceSourceKind::Operator);
  CPE_REQUIRE_EQ(operator_registration.value().provenance().source().to_string(), std::string("operator-console"));
  CPE_REQUIRE(operator_registration.value().sequence().value() > fourth.sequence().value());
  CPE_REQUIRE_EQ(operator_registration.value().provenance().recorded_epoch(), operator_registration.value().epoch());
}

CPE_TEST(registration, identical_requests_replay_the_recorded_registration) {
  cpe_test::TestAuthority test_authority;
  const dccp::epoch::ControllerId controller = cpe_test::controller_id("worker-a");
  const ControllerRegistration initial = test_authority.register_controller("worker-a");

  const Result<IdempotencyKey> key = IdempotencyKey::create(controller, initial.incarnation_id(),
                                                            OperationSequence::from_trusted(1));
  CPE_REQUIRE(key.has_value());

  // Two byte-identical requests: same controller, same provenance, same key.
  const auto make_request = [&key]() {
    dccp::epoch::RegisterControllerRequest request;
    request.controller = cpe_test::controller_id("worker-a");
    request.provenance = cpe_test::provenance_input("worker-a", ProvenanceSourceKind::Controller);
    request.idempotency = key.value();
    return request;
  };

  const auto accepted = test_authority.authority().register_controller(make_request());
  CPE_REQUIRE(accepted.has_value());
  CPE_REQUIRE(!accepted.value().replayed());
  CPE_REQUIRE_EQ(accepted.value().incarnation_number().value(), std::uint64_t{2});

  // The retry returns the recorded outcome instead of registering again: same
  // incarnation, same identity, same sequence. Only the replay flag differs,
  // because the caller is being told that nothing new happened.
  const auto replayed = test_authority.authority().register_controller(make_request());
  CPE_REQUIRE(replayed.has_value());
  CPE_REQUIRE(replayed.value().replayed());
  CPE_REQUIRE_EQ(replayed.value().incarnation_number().value(), std::uint64_t{2});
  CPE_REQUIRE_EQ(replayed.value().incarnation_id(), accepted.value().incarnation_id());
  CPE_REQUIRE_EQ(replayed.value().epoch(), accepted.value().epoch());
  CPE_REQUIRE_EQ(replayed.value().sequence().value(), accepted.value().sequence().value());
  CPE_REQUIRE_EQ(replayed.value().controller(), accepted.value().controller());
  CPE_REQUIRE_EQ(replayed.value().provenance().to_string(), accepted.value().provenance().to_string());
  CPE_REQUIRE(replayed.value().to_string().find("replayed=yes") != std::string::npos);
  CPE_REQUIRE(accepted.value().to_string().find("replayed=no") != std::string::npos);
  CPE_REQUIRE_EQ(replayed.value().incarnation_id(), derived(test_authority, "worker-a", 2));

  // The replay committed nothing: the incarnation counter and the registration
  // count are where the first, accepted command left them.
  const auto record = test_authority.authority().controller_record(controller);
  CPE_REQUIRE(record.has_value());
  CPE_REQUIRE_EQ(record.value().incarnation_number().value(), std::uint64_t{2});
  CPE_REQUIRE_EQ(record.value().registration_count(), std::uint64_t{2});

  // The same key with a different command is a conflict, not a silent
  // overwrite and not a second registration.
  dccp::epoch::RegisterControllerRequest conflicting = make_request();
  conflicting.provenance = cpe_test::provenance_input("someone-else", ProvenanceSourceKind::Operator);
  CPE_REQUIRE_EQ(rejection_code(test_authority.authority().register_controller(std::move(conflicting))),
                 ErrorCode::IdempotencyConflict);

  // An unset key is rejected where a key is constructed: absence is never
  // treated as "sequence zero".
  CPE_REQUIRE_EQ(rejection_code(IdempotencyKey::create(controller, initial.incarnation_id(),
                                                       OperationSequence::from_trusted(0))),
                 ErrorCode::InvalidArgument);
  CPE_REQUIRE_EQ(rejection_code(IdempotencyKey::create(dccp::epoch::ControllerId{}, initial.incarnation_id(),
                                                       OperationSequence::from_trusted(1))),
                 ErrorCode::IdentifierEmpty);
}
