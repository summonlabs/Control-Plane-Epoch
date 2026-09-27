// Control Plane Epoch 1.0.0 - Summon Software Labs
// Suite: idempotency.
//
// Invariant under test: a retryable command carries a key scoped to one
// controller incarnation. Replaying an identical command under the same key
// returns the recorded outcome and changes nothing; reusing the key for
// different content is an explicit conflict, never a silent overwrite; and the
// guarantee is bounded by max_idempotency_records, with eviction counted rather
// than hidden.

#include <cstddef>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "test_support.hpp"

#include "control_plane_epoch/version.hpp"

#include "durable.hpp"
#include "image.hpp"
#include "records.hpp"

namespace {

using namespace cpe_test;
using namespace dccp::epoch;

[[nodiscard]] OperationSequence operation_sequence(std::uint64_t value) {
  return OperationSequence::from_trusted(value);
}

[[nodiscard]] IdempotencyKey idempotency_key(const ControllerId& controller,
                                             const ControllerIncarnationId& incarnation, std::uint64_t sequence) {
  auto key = IdempotencyKey::create(controller, incarnation, operation_sequence(sequence));
  if (!key.has_value()) {
    throw Failure("could not build an idempotency key: " + key.rejection().to_string());
  }
  return key.move_value();
}

[[nodiscard]] RegisterControllerRequest register_request(const std::string& controller,
                                                         const std::optional<IdempotencyKey>& key) {
  RegisterControllerRequest request;
  request.controller = controller_id(controller);
  request.provenance = provenance_input(controller);
  request.idempotency = key;
  return request;
}

/// A registration result is the recorded outcome byte for byte when everything
/// except the replay marker agrees.
void require_same_registration(const ControllerRegistration& actual, const ControllerRegistration& expected) {
  CPE_REQUIRE_EQ(actual.controller(), expected.controller());
  CPE_REQUIRE_EQ(actual.incarnation_number().value(), expected.incarnation_number().value());
  CPE_REQUIRE_EQ(actual.incarnation_id(), expected.incarnation_id());
  CPE_REQUIRE_EQ(actual.epoch().value(), expected.epoch().value());
  CPE_REQUIRE_EQ(actual.sequence().value(), expected.sequence().value());
  CPE_REQUIRE_EQ(actual.provenance(), expected.provenance());
}

// ---------------------------------------------------------------------------
// Crafted durable state.
//
// The retained idempotency window is bounded at max_idempotency_records, so
// proving that eviction is counted would otherwise need more than four thousand
// durable commits -- quadratic work that would dominate this suite. Instead one
// verified generation holding a full window is written through the internal
// codec, and a single keyed command is then driven through the public API to
// cross the bound.
// ---------------------------------------------------------------------------

[[nodiscard]] detail::ProvenanceData seed_provenance(std::uint64_t epoch, std::uint64_t sequence) {
  detail::ProvenanceData data;
  data.kind = ProvenanceSourceKind::Initialization;
  data.source = "test-seed";
  data.recorded_epoch = epoch;
  data.recorded_sequence = sequence;
  data.record_digest = detail::compute_provenance_digest(data);
  return data;
}

void write_envelope_file(const std::filesystem::path& path, std::uint64_t generation, std::uint64_t epoch,
                         const std::vector<std::byte>& payload, std::size_t bound) {
  detail::FileEnvelope envelope;
  envelope.generation = generation;
  envelope.epoch = epoch;
  envelope.payload = payload;
  const std::vector<std::byte> bytes = detail::encode_envelope(envelope, bound);
  detail::write_file_exclusive(path, std::span<const std::byte>(bytes));
}

[[nodiscard]] ControllerIncarnationId root_incarnation(const FacilityAuthorityDomainId& domain,
                                                       const ControllerId& root) {
  return ControllerIncarnationId::derive(domain, root, IncarnationNumber::from_trusted(1));
}

void seed_store_with_full_idempotency_window(const std::filesystem::path& directory, std::uint64_t retained) {
  const FacilityAuthorityDomainId domain = domain_id("facility-alpha");
  const ControllerId root = controller_id("authority-root");

  detail::AuthorityImage image;
  image.schema_version = static_cast<std::uint32_t>(durable_schema_version);
  image.domain = domain.str();
  image.domain_instance = 1;
  image.epoch = 1;
  image.durable_generation = 1;
  image.authority_root = root.str();
  image.declared_scopes = default_scopes();

  detail::ControllerData controller;
  controller.controller = root.str();
  controller.incarnation_number = 1;
  controller.incarnation_id = root_incarnation(domain, root).digest();
  controller.incarnation_state = IncarnationState::Current;
  controller.registration_count = 1;
  controller.first_registered_epoch = 1;
  controller.latest_registered_epoch = 1;
  controller.latest_registration_provenance = seed_provenance(1, 1);
  controller.record_digest = detail::compute_controller_digest(controller);
  image.controllers.push_back(controller);

  detail::GrantData grant;
  grant.id = 1;
  grant.authority_class = AuthorityClass::Mutation;
  grant.epoch = 1;
  grant.controller = root.str();
  grant.incarnation_number = 1;
  grant.incarnation_id = controller.incarnation_id;
  grant.scopes = image.declared_scopes;
  grant.sequence = 2;
  grant.state = detail::GrantState::Live;
  grant.provenance = seed_provenance(1, 2);
  grant.record_digest = detail::compute_grant_digest(grant);
  image.grants.push_back(grant);

  detail::TransitionData transition;
  transition.sequence = 1;
  transition.origin = true;
  transition.base_epoch = 0;
  transition.new_epoch = 1;
  transition.reason = EpochTransitionReason::Genesis;
  transition.committed_by = root.str();
  transition.committed_by_incarnation = controller.incarnation_id;
  transition.committed_by_grant = grant.id;
  transition.fenced_grant_count = 0;
  transition.controller_count = 1;
  transition.provenance = seed_provenance(1, 3);
  transition.previous_record_digest = Sha256Digest::zero();
  transition.record_digest = detail::compute_transition_digest(transition);
  image.transitions.push_back(transition);
  image.transition_count = 1;

  for (std::uint64_t sequence = 1; sequence <= retained; ++sequence) {
    detail::IdempotencyData entry;
    entry.controller = root.str();
    entry.incarnation_id = controller.incarnation_id;
    entry.sequence = sequence;
    entry.command_digest = digest_of("seed-command-" + std::to_string(sequence));
    const std::string blob = "seed-outcome-" + std::to_string(sequence);
    entry.result_blob.assign(reinterpret_cast<const std::byte*>(blob.data()),
                             reinterpret_cast<const std::byte*>(blob.data()) + blob.size());
    image.idempotency.push_back(std::move(entry));
  }
  image.idempotency_count = retained;
  image.idempotency_evicted = 0;
  image.next_grant_id = 2;
  image.next_mutation_sequence = 4;

  const std::vector<std::byte> payload = detail::encode_image(image, detail::default_image_limits());
  write_envelope_file(directory / std::string(StoreLayout::snapshot_file), 1, 1, payload,
                      max_snapshot_bytes + detail::envelope_header_bytes);

  detail::FloorData floor;
  floor.domain = image.domain;
  floor.domain_instance = image.domain_instance;
  floor.epoch = 1;
  floor.generation = 1;
  floor.snapshot_digest = sha256(std::span<const std::byte>(payload));
  write_envelope_file(directory / std::string(StoreLayout::floor_file), 1, 1, detail::encode_floor(floor),
                      max_floor_bytes + detail::envelope_header_bytes);
}

}  // namespace

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

CPE_TEST(idempotency, registration_replay_returns_the_recorded_outcome_and_applies_nothing) {
  TestAuthority fixture;
  const ControllerId controller = controller_id("ctrl-a");
  const ControllerIncarnationId first_incarnation =
      ControllerIncarnationId::derive(domain_id(fixture.domain()), controller, IncarnationNumber::from_trusted(1));
  const RegisterControllerRequest request =
      register_request("ctrl-a", idempotency_key(controller, first_incarnation, 1));

  auto applied = fixture.authority().register_controller(request);
  CPE_REQUIRE(applied.has_value());
  CPE_REQUIRE(!applied.value().replayed());
  CPE_REQUIRE_EQ(applied.value().incarnation_number().value(), 1u);

  const AuthorityStatus status_before = fixture.authority().status();
  const AuthorityAccounting accounting_before = fixture.authority().accounting();

  auto replayed = fixture.authority().register_controller(request);
  CPE_REQUIRE(replayed.has_value());
  CPE_REQUIRE(replayed.value().replayed());
  require_same_registration(replayed.value(), applied.value());

  // Nothing was applied twice: a second application would have produced
  // incarnation 2 and a second registration sequence.
  const ControllerRecord record = fixture.authority().controller_record(controller).value();
  CPE_REQUIRE_EQ(record.incarnation_number().value(), 1u);
  CPE_REQUIRE_EQ(record.registration_count(), 1u);
  CPE_REQUIRE_EQ(record.incarnation_id(), first_incarnation);

  const AuthorityStatus status_after = fixture.authority().status();
  const AuthorityAccounting accounting_after = fixture.authority().accounting();
  CPE_REQUIRE_EQ(status_after.controller_count(), status_before.controller_count());
  CPE_REQUIRE_EQ(status_after.durable_generation().value(), status_before.durable_generation().value());
  CPE_REQUIRE_EQ(status_after.transition_count(), status_before.transition_count());
  // The replay reads the recorded outcome: it neither applies the command again
  // nor records a second idempotency entry.
  CPE_REQUIRE_EQ(status_after.idempotency_record_count(), status_before.idempotency_record_count());
  CPE_REQUIRE_EQ(status_after.idempotency_record_count(), 1u);
  CPE_REQUIRE(accounting_after == accounting_before);
  CPE_REQUIRE_EQ(accounting_after.controller_records(), accounting_before.controller_records());
  CPE_REQUIRE_EQ(accounting_after.grant_records(), accounting_before.grant_records());
  CPE_REQUIRE_EQ(accounting_after.snapshot_bytes(), accounting_before.snapshot_bytes());
}

CPE_TEST(idempotency, same_key_with_different_content_is_a_conflict) {
  TestAuthority fixture;
  const ControllerId controller = controller_id("ctrl-a");
  const ControllerIncarnationId incarnation =
      ControllerIncarnationId::derive(domain_id(fixture.domain()), controller, IncarnationNumber::from_trusted(1));
  const IdempotencyKey key = idempotency_key(controller, incarnation, 1);

  RegisterControllerRequest original = register_request("ctrl-a", key);
  auto applied = fixture.authority().register_controller(original);
  CPE_REQUIRE(applied.has_value());

  // Identical key, different content: the command digest differs, so the key is
  // a conflict rather than a replay.
  RegisterControllerRequest different = original;
  different.provenance = provenance_input("operator", ProvenanceSourceKind::Operator);
  auto conflicted = fixture.authority().register_controller(different);
  CPE_REQUIRE(!conflicted.has_value());
  CPE_REQUIRE(conflicted.rejection().code() == ErrorCode::IdempotencyConflict);
  CPE_REQUIRE(conflicted.rejection().token() == std::string_view("idempotency.conflict"));

  // The conflict changed nothing: the controller is still on its first
  // incarnation and the recorded outcome is untouched.
  const ControllerRecord record = fixture.authority().controller_record(controller).value();
  CPE_REQUIRE_EQ(record.incarnation_number().value(), 1u);
  CPE_REQUIRE_EQ(record.registration_count(), 1u);
  auto replayed = fixture.authority().register_controller(original);
  CPE_REQUIRE(replayed.has_value());
  CPE_REQUIRE(replayed.value().replayed());

  // A conflicting acquisition is reported the same way.
  const MutationAuthority root = fixture.root_authority();
  AcquireAuthorityRequest acquisition;
  acquisition.controller = controller;
  acquisition.incarnation = incarnation;
  acquisition.scopes = scope_set({"facility.inventory"});
  acquisition.sponsor = root;
  acquisition.provenance = provenance_input("ctrl-a");
  acquisition.idempotency = idempotency_key(controller, incarnation, 2);
  auto granted = fixture.authority().acquire_authority(acquisition);
  CPE_REQUIRE(granted.has_value());

  AcquireAuthorityRequest wider = acquisition;
  wider.scopes = scope_set({"facility.inventory", "facility.topology"});
  auto wider_result = fixture.authority().acquire_authority(wider);
  CPE_REQUIRE(!wider_result.has_value());
  CPE_REQUIRE(wider_result.rejection().code() == ErrorCode::IdempotencyConflict);
}

CPE_TEST(idempotency, keys_are_scoped_to_one_controller_incarnation) {
  TestAuthority fixture;
  const ControllerId controller = controller_id("ctrl-a");
  const ControllerId other = controller_id("ctrl-b");

  const ControllerIncarnationId a1 =
      ControllerIncarnationId::derive(domain_id(fixture.domain()), controller, IncarnationNumber::from_trusted(1));
  const ControllerIncarnationId a2 =
      ControllerIncarnationId::derive(domain_id(fixture.domain()), controller, IncarnationNumber::from_trusted(2));
  const ControllerIncarnationId b1 =
      ControllerIncarnationId::derive(domain_id(fixture.domain()), other, IncarnationNumber::from_trusted(1));

  auto first = fixture.authority().register_controller(register_request("ctrl-a", idempotency_key(controller, a1, 1)));
  CPE_REQUIRE(first.has_value());
  CPE_REQUIRE(!first.value().replayed());

  // Sequence 1 for a different controller is a different key entirely.
  auto second =
      fixture.authority().register_controller(register_request("ctrl-b", idempotency_key(other, b1, 1)));
  CPE_REQUIRE(second.has_value());
  CPE_REQUIRE(!second.value().replayed());
  CPE_REQUIRE_EQ(second.value().incarnation_number().value(), 1u);

  // Sequence 1 for the next incarnation of the same controller is also a
  // different key: a restarted controller cannot collide with its own past.
  auto restart = fixture.authority().register_controller(register_request("ctrl-a", idempotency_key(controller, a2, 1)));
  CPE_REQUIRE(restart.has_value());
  CPE_REQUIRE(!restart.value().replayed());
  CPE_REQUIRE_EQ(restart.value().incarnation_number().value(), 2u);
  CPE_REQUIRE_EQ(restart.value().incarnation_id(), a2);

  // Only now does the same (controller, incarnation, sequence) triple replay.
  auto replay = fixture.authority().register_controller(register_request("ctrl-a", idempotency_key(controller, a2, 1)));
  CPE_REQUIRE(replay.has_value());
  CPE_REQUIRE(replay.value().replayed());
  CPE_REQUIRE_EQ(replay.value().incarnation_number().value(), 2u);
  require_same_registration(replay.value(), restart.value());

  // ... and the older incarnation's key still replays the older outcome, which
  // proves the keys are three separate records rather than one overwritten one.
  auto old_replay =
      fixture.authority().register_controller(register_request("ctrl-a", idempotency_key(controller, a1, 1)));
  CPE_REQUIRE(old_replay.has_value());
  CPE_REQUIRE(old_replay.value().replayed());
  CPE_REQUIRE_EQ(old_replay.value().incarnation_number().value(), 1u);
  CPE_REQUIRE_EQ(fixture.authority().status().idempotency_record_count(), 3u);
}

// ---------------------------------------------------------------------------
// Acquisition, advancement, revocation
// ---------------------------------------------------------------------------

CPE_TEST(idempotency, acquisition_replay_returns_the_same_grant_and_adds_none) {
  TestAuthority fixture;
  const ControllerId controller = controller_id("ctrl-a");
  const ControllerIncarnationId incarnation = fixture.register_controller("ctrl-a").incarnation_id();
  const MutationAuthority root = fixture.root_authority();

  AcquireAuthorityRequest request;
  request.controller = controller;
  request.incarnation = incarnation;
  request.scopes = scope_set({"facility.inventory"});
  request.sponsor = root;
  request.provenance = provenance_input("ctrl-a");
  request.idempotency = idempotency_key(controller, incarnation, 9);

  auto applied = fixture.authority().acquire_authority(request);
  CPE_REQUIRE(applied.has_value());
  CPE_REQUIRE(!applied.value().replayed());
  const GrantId grant_id = applied.value().record().id();
  CPE_REQUIRE(applied.value().mutation_authority().has_value());

  const AuthorityAccounting before = fixture.authority().accounting();
  auto replayed = fixture.authority().acquire_authority(request);
  CPE_REQUIRE(replayed.has_value());
  CPE_REQUIRE(replayed.value().replayed());
  CPE_REQUIRE_EQ(replayed.value().record().id(), grant_id);
  CPE_REQUIRE_EQ(replayed.value().record(), applied.value().record());
  CPE_REQUIRE(replayed.value().mutation_authority() == applied.value().mutation_authority());

  const AuthorityAccounting after = fixture.authority().accounting();
  CPE_REQUIRE(after == before);
  CPE_REQUIRE_EQ(after.grant_records(), before.grant_records());
  CPE_REQUIRE_EQ(after.live_grant_records(), before.live_grant_records());
  CPE_REQUIRE_EQ(fixture.authority().status().live_grant_count(), before.live_grant_records());
}

CPE_TEST(idempotency, advancement_replay_returns_the_recorded_transition) {
  TestAuthority fixture;
  const MutationAuthority root = fixture.root_authority();
  const IdempotencyKey key = idempotency_key(root.controller(), root.incarnation(), 4);

  AdvanceEpochRequest request;
  request.expected_current = Epoch::initial();
  request.authority = root;
  request.reason = EpochTransitionReason::OperatorRequest;
  request.provenance = provenance_input("operator");
  request.idempotency = key;

  auto applied = fixture.authority().advance_epoch(request);
  CPE_REQUIRE(applied.has_value());
  CPE_REQUIRE_EQ(applied.value().new_epoch().value(), 2u);
  CPE_REQUIRE_EQ(applied.value().sequence().value(), 2u);

  const AuthorityAccounting before = fixture.authority().accounting();

  // The retry presents the *stale* expected epoch, which is exactly what a lost
  // response looks like. The recorded outcome must win over the precondition
  // check: a retry may not be reported as a conflict.
  AdvanceEpochRequest stale_retry = request;
  stale_retry.expected_current = Epoch::initial();
  auto replayed = fixture.authority().advance_epoch(stale_retry);
  CPE_REQUIRE(replayed.has_value());
  CPE_REQUIRE(replayed.value() == applied.value());
  CPE_REQUIRE_EQ(fixture.authority().current_epoch().value(), 2u);

  const AuthorityAccounting after = fixture.authority().accounting();
  CPE_REQUIRE(after == before);
  CPE_REQUIRE_EQ(after.transition_records_retained(), before.transition_records_retained());
  CPE_REQUIRE_EQ(after.transition_records_trimmed(), 0u);
  CPE_REQUIRE_EQ(fixture.authority().status().transition_count(), before.transition_records_retained());

  // A different command under the same key is a conflict, not a replay.
  AdvanceEpochRequest different = request;
  different.reason = EpochTransitionReason::Fencing;
  auto conflicted = fixture.authority().advance_epoch(different);
  CPE_REQUIRE(!conflicted.has_value());
  CPE_REQUIRE(conflicted.rejection().code() == ErrorCode::IdempotencyConflict);
  CPE_REQUIRE_EQ(fixture.authority().current_epoch().value(), 2u);

  // A key that does not belong to the presenting incarnation is rejected before
  // anything else, so a caller cannot claim another controller's key.
  AdvanceEpochRequest foreign_key = request;
  foreign_key.idempotency = idempotency_key(controller_id("someone-else"), root.incarnation(), 1);
  auto foreign = fixture.authority().advance_epoch(foreign_key);
  CPE_REQUIRE(!foreign.has_value());
  CPE_REQUIRE(foreign.rejection().code() == ErrorCode::IdempotencyConflict);
}

CPE_TEST(idempotency, revocation_replay_returns_the_same_record_and_fences_nothing_again) {
  TestAuthority fixture;
  const ControllerIncarnationId incarnation = fixture.register_controller("ctrl-a").incarnation_id();
  const MutationAuthority root = fixture.root_authority();
  const AuthorityGrantView grant =
      fixture.acquire("ctrl-a", incarnation, {"facility.inventory"}, root);

  RevokeAuthorityRequest request;
  request.target = RevocationTarget::grant(grant.record().id(), controller_id("ctrl-a"));
  request.reason = RevocationReason::OperatorRequest;
  request.authority = root;
  request.provenance = provenance_input("operator");
  request.idempotency = idempotency_key(root.controller(), root.incarnation(), 11);

  auto applied = fixture.authority().revoke_authority(request);
  CPE_REQUIRE(applied.has_value());
  CPE_REQUIRE(!applied.value().replayed());
  CPE_REQUIRE_EQ(applied.value().fenced_grant_count(), 1u);

  const AuthorityAccounting before = fixture.authority().accounting();
  auto replayed = fixture.authority().revoke_authority(request);
  CPE_REQUIRE(replayed.has_value());
  CPE_REQUIRE(replayed.value().replayed());
  CPE_REQUIRE_EQ(replayed.value().sequence().value(), applied.value().sequence().value());
  CPE_REQUIRE_EQ(replayed.value().fenced_grant_count(), applied.value().fenced_grant_count());
  CPE_REQUIRE_EQ(replayed.value().through_incarnation(), applied.value().through_incarnation());
  CPE_REQUIRE_EQ(replayed.value().grant(), applied.value().grant());

  const AuthorityAccounting after = fixture.authority().accounting();
  CPE_REQUIRE(after == before);
  CPE_REQUIRE_EQ(after.revocation_records_retained(), before.revocation_records_retained());
  CPE_REQUIRE_EQ(fixture.authority().status().revocation_count(), before.revocation_records_retained());

  const auto fenced = fixture.authority().grant_record(grant.record().id());
  CPE_REQUIRE(fenced.has_value());
  CPE_REQUIRE(fenced.value().revoked());
}

CPE_TEST(idempotency, replay_after_reopen_returns_the_recorded_outcome) {
  TestAuthority fixture;
  const ControllerId controller = controller_id("ctrl-a");
  const ControllerIncarnationId incarnation =
      ControllerIncarnationId::derive(domain_id(fixture.domain()), controller, IncarnationNumber::from_trusted(1));
  const RegisterControllerRequest registration =
      register_request("ctrl-a", idempotency_key(controller, incarnation, 1));
  auto applied_registration = fixture.authority().register_controller(registration);
  CPE_REQUIRE(applied_registration.has_value());

  const MutationAuthority root = fixture.root_authority();
  AcquireAuthorityRequest acquisition;
  acquisition.controller = controller;
  acquisition.incarnation = incarnation;
  acquisition.scopes = scope_set({"facility.inventory"});
  acquisition.sponsor = root;
  acquisition.provenance = provenance_input("ctrl-a");
  acquisition.idempotency = idempotency_key(controller, incarnation, 5);
  auto applied_grant = fixture.authority().acquire_authority(acquisition);
  CPE_REQUIRE(applied_grant.has_value());
  const GrantId grant_id = applied_grant.value().record().id();

  fixture.reopen();

  // Idempotency is durable: the recorded outcomes survive the restart and a
  // retry still replays rather than re-applying.
  auto replayed_registration = fixture.authority().register_controller(registration);
  CPE_REQUIRE(replayed_registration.has_value());
  CPE_REQUIRE(replayed_registration.value().replayed());
  require_same_registration(replayed_registration.value(), applied_registration.value());

  const AuthorityAccounting before = fixture.authority().accounting();
  auto replayed_grant = fixture.authority().acquire_authority(acquisition);
  CPE_REQUIRE(replayed_grant.has_value());
  CPE_REQUIRE(replayed_grant.value().replayed());
  CPE_REQUIRE_EQ(replayed_grant.value().record().id(), grant_id);
  CPE_REQUIRE(fixture.authority().accounting() == before);

  const ControllerRecord record = fixture.authority().controller_record(controller).value();
  CPE_REQUIRE_EQ(record.incarnation_number().value(), 1u);
  CPE_REQUIRE_EQ(record.registration_count(), 1u);
  CPE_REQUIRE_EQ(fixture.authority().status().idempotency_record_count(), 2u);
}

// ---------------------------------------------------------------------------
// The retained window
// ---------------------------------------------------------------------------

CPE_TEST(idempotency, retained_window_is_bounded_and_eviction_is_counted) {
  // The documented configuration this test depends on.
  CPE_REQUIRE_EQ(max_idempotency_records, 4096u);
  CPE_REQUIRE_EQ(max_idempotency_blob_bytes, 4096u);

  TempDirectory directory;
  seed_store_with_full_idempotency_window(directory.path(), max_idempotency_records);

  StoreOpenOptions options;
  options.directory = directory.path();

  {
    ControlPlaneEpochAuthority authority(options);
    CPE_REQUIRE(authority.initialized());
    CPE_REQUIRE(authority.accounting().idempotency_records() == max_idempotency_records);
    CPE_REQUIRE(authority.accounting().idempotency_records_evicted() == 0);
    CPE_REQUIRE(authority.status().idempotency_record_count() == max_idempotency_records);

    // One further keyed command pushes the retained window one record past its
    // bound, so exactly one recorded outcome must be evicted.
    RegisterControllerRequest request;
    request.controller = controller_id("authority-root");
    request.provenance = provenance_input("operator");
    request.idempotency = idempotency_key(controller_id("authority-root"),
                                          root_incarnation(domain_id("facility-alpha"),
                                                           controller_id("authority-root")),
                                          max_idempotency_records + 1);
    auto applied = authority.register_controller(std::move(request));
    CPE_REQUIRE(applied.has_value());
    CPE_REQUIRE(!applied.value().replayed());

    const AuthorityAccounting accounting = authority.accounting();
    CPE_REQUIRE_EQ(accounting.idempotency_records(), max_idempotency_records);
    CPE_REQUIRE_EQ(accounting.idempotency_records_evicted(), 1u);
    CPE_REQUIRE_EQ(authority.status().idempotency_record_count(), max_idempotency_records + 1);

    authority.close();
  }

  // The trimmed generation is still a valid durable image: reopening proves the
  // window was reduced rather than grown past what the reader accepts.
  ControlPlaneEpochAuthority reopened(options);
  CPE_REQUIRE(reopened.initialized());
  CPE_REQUIRE_EQ(reopened.accounting().idempotency_records(), max_idempotency_records);
  CPE_REQUIRE_EQ(reopened.accounting().idempotency_records_evicted(), 1u);
  CPE_REQUIRE_EQ(reopened.status().idempotency_record_count(), max_idempotency_records + 1);

  const StoreInspection inspection = inspect_store(directory.path());
  CPE_REQUIRE(inspection.verified());
  CPE_REQUIRE(inspection.problems().empty());
  CPE_REQUIRE_EQ(inspection.idempotency_record_count(), max_idempotency_records + 1);
}
