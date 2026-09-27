// Control Plane Epoch 1.0.0 - Summon Software Labs
// Suite: persistence.
//
// Invariant under test: durable state is exactly reproducible. Identical
// operations produce identical bytes, every accepted command advances the
// durable generation by exactly one step, the superseded generation is kept as
// a fallback, the writer lock is the only thing that makes a directory
// single-writer, and a store that is closed or opened read-only cannot be
// mutated or silently rewritten.

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include "test_support.hpp"

#include "control_plane_epoch/version.hpp"

#include "authority_store.hpp"
#include "durable.hpp"
#include "image.hpp"

namespace {

using namespace cpe_test;
using namespace dccp::epoch;

[[nodiscard]] StoreOpenOptions options_for(const std::filesystem::path& directory,
                                           StoreOpenMode mode = StoreOpenMode::ReadWrite) {
  StoreOpenOptions options;
  options.directory = directory;
  options.mode = mode;
  return options;
}

void initialize_facility(ControlPlaneEpochAuthority& authority) {
  InitializeDomainRequest request;
  request.domain = domain_id("facility-alpha");
  request.authority_root = controller_id("authority-root");
  request.provenance = provenance_input("test-initialization", ProvenanceSourceKind::Initialization);
  for (const std::string& scope : default_scopes()) {
    request.scopes.push_back(scope_name(scope));
  }
  auto initialized = authority.initialize(std::move(request));
  if (!initialized.has_value()) {
    throw Failure("initialization failed: " + initialized.rejection().to_string());
  }
}

[[nodiscard]] std::vector<std::byte> store_bytes(const std::filesystem::path& path) {
  auto bytes = detail::read_file_optional(path, max_snapshot_bytes + detail::envelope_header_bytes);
  if (!bytes.has_value()) {
    throw Failure("expected the durable file " + path.string() + " to exist");
  }
  return std::move(*bytes);
}

[[nodiscard]] std::uint64_t file_bytes(const std::filesystem::path& path) {
  std::error_code error;
  const std::uintmax_t size = std::filesystem::file_size(path, error);
  if (error) {
    throw Failure("could not size " + path.string() + ": " + error.message());
  }
  return static_cast<std::uint64_t>(size);
}

/// Overwrites an existing durable file in place. Used only to simulate damage
/// that recovery must refuse; the library's own writer never does this.
void overwrite_bytes(const std::filesystem::path& path, const std::vector<std::byte>& bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!stream) {
    throw Failure("could not open " + path.string() + " for writing");
  }
  stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  if (!stream) {
    throw Failure("could not write " + path.string());
  }
}

/// Content digest of every regular file in a directory, keyed by file name. Used
/// to prove that a read-only operation rewrote nothing at all.
[[nodiscard]] std::map<std::string, Sha256Digest> digest_directory(const std::filesystem::path& directory) {
  std::map<std::string, Sha256Digest> digests;
  std::error_code error;
  std::filesystem::directory_iterator iterator(directory, error);
  if (error) {
    throw Failure("could not enumerate " + directory.string() + ": " + error.message());
  }
  for (const std::filesystem::directory_entry& entry : iterator) {
    if (!entry.is_regular_file(error) || error) {
      continue;
    }
    auto bytes = detail::read_file_optional(entry.path(), max_snapshot_bytes + detail::envelope_header_bytes);
    const std::vector<std::byte> content = bytes.has_value() ? std::move(*bytes) : std::vector<std::byte>{};
    digests.emplace(entry.path().filename().string(), sha256(std::span<const std::byte>(content)));
  }
  return digests;
}

/// One MutationAuthority value built from claims alone. Constructing a token
/// grants nothing, which is what makes it usable for "the authority is closed,
/// so even a well-formed token is refused" assertions.
[[nodiscard]] MutationAuthority synthetic_root_authority() {
  auto claims = AuthorityClaims::create(domain_id("facility-alpha"), Epoch::initial(), controller_id("authority-root"),
                                        ControllerIncarnationId::derive(domain_id("facility-alpha"),
                                                                        controller_id("authority-root"),
                                                                        IncarnationNumber::from_trusted(1)),
                                        GrantId::from_trusted(1), scope_set(default_scopes()));
  if (!claims.has_value()) {
    throw Failure("could not build synthetic claims: " + claims.rejection().to_string());
  }
  return MutationAuthority::from_claims(claims.move_value());
}

/// Replays one fixed sequence of commands against a freshly initialized store so
/// that two stores can be compared byte for byte.
void run_fixed_script(ControlPlaneEpochAuthority& authority) {
  initialize_facility(authority);

  RegisterControllerRequest registration;
  registration.controller = controller_id("ctrl-a");
  registration.provenance = provenance_input("ctrl-a");
  auto registered = authority.register_controller(std::move(registration));
  if (!registered.has_value()) {
    throw Failure("registration failed: " + registered.rejection().to_string());
  }
  const ControllerIncarnationId incarnation = registered.value().incarnation_id();

  AcquireAuthorityRequest bootstrap;
  bootstrap.controller = controller_id("authority-root");
  bootstrap.incarnation = authority.controller_record(controller_id("authority-root")).value().incarnation_id();
  bootstrap.scopes = scope_set({"authority.grant", "authority.revoke", "epoch.advance"});
  bootstrap.provenance = provenance_input("authority-root");
  auto root = authority.acquire_authority(std::move(bootstrap));
  if (!root.has_value()) {
    throw Failure("bootstrap acquisition failed: " + root.rejection().to_string());
  }

  AcquireAuthorityRequest scoped;
  scoped.controller = controller_id("ctrl-a");
  scoped.incarnation = incarnation;
  scoped.scopes = scope_set({"facility.inventory"});
  scoped.sponsor = *root.value().mutation_authority();
  scoped.provenance = provenance_input("ctrl-a");
  auto grant = authority.acquire_authority(std::move(scoped));
  if (!grant.has_value()) {
    throw Failure("scoped acquisition failed: " + grant.rejection().to_string());
  }

  AdvanceEpochRequest advance;
  advance.expected_current = Epoch::initial();
  advance.authority = *root.value().mutation_authority();
  advance.reason = EpochTransitionReason::OperatorRequest;
  advance.provenance = provenance_input("operator");
  auto transition = authority.advance_epoch(std::move(advance));
  if (!transition.has_value()) {
    throw Failure("advancement failed: " + transition.rejection().to_string());
  }
}

}  // namespace

// ---------------------------------------------------------------------------
// Identity of durable state across a restart
// ---------------------------------------------------------------------------

CPE_TEST(persistence, reopen_preserves_every_durable_fact) {
  TestAuthority fixture;
  const ControllerRegistration registered = fixture.register_controller("ctrl-a");
  const MutationAuthority root = fixture.root_authority();
  const AuthorityGrantView grant = fixture.acquire("ctrl-a", registered.incarnation_id(), {"facility.inventory"}, root);

  const AuthorityStatus status_before = fixture.authority().status();
  const AuthorityAccounting accounting_before = fixture.authority().accounting();
  const auto history_before = fixture.authority().history(HistoryQuery{}).value();
  const auto controllers_before = fixture.authority().controllers(ControllerQuery{}).value();
  const auto grants_before = fixture.authority().grants(GrantQuery{}).value();

  // This open happened before the domain existed, so the report says "no
  // authority here yet" rather than epoch 0. A recovered store must instead
  // report the domain it recovered.
  CPE_REQUIRE(!fixture.authority().recovery().has_domain());

  fixture.reopen();

  const RecoveryReport recovered = fixture.authority().recovery();
  CPE_REQUIRE(recovered.has_domain());
  CPE_REQUIRE(recovered.outcome() == RecoveryOutcome::OpenedClean);
  CPE_REQUIRE_EQ(recovered.domain(), status_before.domain());
  CPE_REQUIRE_EQ(recovered.epoch()->value(), status_before.epoch().value());
  CPE_REQUIRE_EQ(recovered.durable_generation()->value(), status_before.durable_generation().value());
  CPE_REQUIRE_EQ(recovered.snapshot_digest(), status_before.snapshot_digest());
  CPE_REQUIRE_EQ(recovered.damaged_files().size(), 0u);
  CPE_REQUIRE_EQ(recovered.quarantined_files().size(), 0u);

  const AuthorityStatus status_after = fixture.authority().status();
  CPE_REQUIRE(status_after == status_before);
  CPE_REQUIRE_EQ(status_after.domain(), status_before.domain());
  CPE_REQUIRE_EQ(status_after.domain_instance().value(), status_before.domain_instance().value());
  CPE_REQUIRE_EQ(status_after.epoch().value(), status_before.epoch().value());
  CPE_REQUIRE_EQ(status_after.durable_generation().value(), status_before.durable_generation().value());
  CPE_REQUIRE_EQ(status_after.controller_count(), status_before.controller_count());
  CPE_REQUIRE_EQ(status_after.live_grant_count(), status_before.live_grant_count());
  CPE_REQUIRE_EQ(status_after.transition_count(), status_before.transition_count());
  CPE_REQUIRE_EQ(status_after.snapshot_digest(), status_before.snapshot_digest());
  CPE_REQUIRE_EQ(status_after.transition_chain_head(), status_before.transition_chain_head());
  CPE_REQUIRE_EQ(status_after.idempotency_record_count(), status_before.idempotency_record_count());
  CPE_REQUIRE(status_after.declared_scopes() == status_before.declared_scopes());
  CPE_REQUIRE(status_after.recovery_outcome() == RecoveryOutcome::OpenedClean);

  CPE_REQUIRE(fixture.authority().accounting() == accounting_before);

  CPE_REQUIRE(fixture.authority().history(HistoryQuery{}).value() == history_before);
  CPE_REQUIRE(fixture.authority().controllers(ControllerQuery{}).value() == controllers_before);
  CPE_REQUIRE(fixture.authority().grants(GrantQuery{}).value() == grants_before);

  const auto grant_after = fixture.authority().grant_record(grant.record().id());
  CPE_REQUIRE(grant_after.has_value());
  CPE_REQUIRE_EQ(grant_after.value(), grant.record());
  CPE_REQUIRE_EQ(grant_after.value().record_digest(), grant.record().record_digest());

  const auto controller_after = fixture.authority().controller_record(controller_id("ctrl-a"));
  CPE_REQUIRE(controller_after.has_value());
  CPE_REQUIRE_EQ(controller_after.value().incarnation_id(), registered.incarnation_id());
  CPE_REQUIRE_EQ(controller_after.value().incarnation_number().value(), 1u);
}

// ---------------------------------------------------------------------------
// Generation arithmetic and the commit report
// ---------------------------------------------------------------------------

CPE_TEST(persistence, every_commit_advances_the_generation_by_exactly_one) {
  TestAuthority fixture;

  const std::optional<DurableCommitReport> initialization = fixture.authority().last_commit();
  CPE_REQUIRE(initialization.has_value());
  CPE_REQUIRE_EQ(initialization->generation().value(), 1u);
  CPE_REQUIRE_EQ(initialization->epoch().value(), 1u);
  CPE_REQUIRE(!initialization->retained_previous_generation());
  CPE_REQUIRE_EQ(initialization->snapshot_digest(), fixture.authority().status().snapshot_digest());
  CPE_REQUIRE_EQ(initialization->bytes_written(), file_bytes(fixture.file("authority.state")));

  std::uint64_t previous_generation = initialization->generation().value();
  const auto require_one_step = [&](const char* what) {
    const std::optional<DurableCommitReport> report = fixture.authority().last_commit();
    if (!report.has_value()) {
      throw Failure(std::string("no commit report after ") + what);
    }
    CPE_REQUIRE_MSG(report->generation().value() == previous_generation + 1,
                    std::string(what) + ": generation moved from " + std::to_string(previous_generation) + " to " +
                        std::to_string(report->generation().value()));
    // The report is the published generation, not a projection of it.
    CPE_REQUIRE_EQ(report->generation().value(), fixture.authority().status().durable_generation().value());
    CPE_REQUIRE_EQ(report->epoch().value(), fixture.authority().status().epoch().value());
    CPE_REQUIRE_EQ(report->snapshot_digest(), fixture.authority().status().snapshot_digest());
    CPE_REQUIRE_EQ(report->bytes_written(), file_bytes(fixture.file("authority.state")));
    previous_generation = report->generation().value();
  };

  const ControllerRegistration registered = fixture.register_controller("ctrl-a");
  require_one_step("registration");
  CPE_REQUIRE(fixture.authority().last_commit()->retained_previous_generation());

  const MutationAuthority root = fixture.root_authority();
  require_one_step("grant acquisition");

  (void)fixture.acquire("ctrl-a", registered.incarnation_id(), {"facility.inventory"}, root);
  require_one_step("scoped acquisition");

  (void)fixture.advance(Epoch::initial(), root);
  require_one_step("epoch advancement");
  CPE_REQUIRE_EQ(fixture.authority().last_commit()->epoch().value(), 2u);
}

CPE_TEST(persistence, identical_operations_produce_identical_snapshot_bytes) {
  TempDirectory first_directory;
  TempDirectory second_directory;

  std::vector<std::byte> first_bytes;
  std::vector<std::byte> second_bytes;
  Sha256Digest first_digest;
  Sha256Digest second_digest;
  {
    ControlPlaneEpochAuthority first(options_for(first_directory.path()));
    run_fixed_script(first);
    first_bytes = store_bytes(first_directory.file(std::string(StoreLayout::snapshot_file)));
    first_digest = first.last_commit()->snapshot_digest();
  }
  {
    ControlPlaneEpochAuthority second(options_for(second_directory.path()));
    run_fixed_script(second);
    second_bytes = store_bytes(second_directory.file(std::string(StoreLayout::snapshot_file)));
    second_digest = second.last_commit()->snapshot_digest();
  }

  // Canonical serialization: the same operations on the same domain produce the
  // same generation, byte for byte, in two independent store directories.
  CPE_REQUIRE(first_bytes == second_bytes);
  CPE_REQUIRE_EQ(first_digest, second_digest);
  CPE_REQUIRE_EQ(first_bytes.size(), second_bytes.size());

  // The floor of an identical store is identical too.
  const std::vector<std::byte> first_floor =
      store_bytes(first_directory.file(std::string(StoreLayout::floor_file)));
  const std::vector<std::byte> second_floor =
      store_bytes(second_directory.file(std::string(StoreLayout::floor_file)));
  CPE_REQUIRE(first_floor == second_floor);
}

CPE_TEST(persistence, the_superseded_generation_is_retained_as_the_fallback) {
  TestAuthority fixture;
  const std::filesystem::path previous = fixture.file(std::string(StoreLayout::previous_snapshot_file));
  CPE_REQUIRE(!std::filesystem::exists(previous));

  const std::vector<std::byte> generation_one = store_bytes(fixture.file("authority.state"));
  (void)fixture.register_controller("ctrl-a");
  CPE_REQUIRE(std::filesystem::exists(previous));
  CPE_REQUIRE(store_bytes(previous) == generation_one);
  CPE_REQUIRE(store_bytes(fixture.file("authority.state")) != generation_one);
  CPE_REQUIRE(fixture.authority().accounting().retained_previous_generation());

  const std::vector<std::byte> generation_two = store_bytes(fixture.file("authority.state"));
  (void)fixture.register_controller("ctrl-b");
  CPE_REQUIRE(store_bytes(previous) == generation_two);

  // The retained fallback is one generation behind the live file, never equal to
  // it, and it is itself a fully verified generation.
  const std::vector<std::byte> live = store_bytes(fixture.file("authority.state"));
  CPE_REQUIRE(live != generation_two);
  const detail::FileEnvelope fallback =
      detail::decode_envelope(store_bytes(previous), max_snapshot_bytes + detail::envelope_header_bytes);
  CPE_REQUIRE_EQ(fallback.generation,
                 fixture.authority().status().durable_generation().value() - 1);
  const detail::AuthorityImage image = detail::decode_image(fallback.payload, detail::default_image_limits());
  CPE_REQUIRE_EQ(image.domain, std::string("facility-alpha"));
  CPE_REQUIRE_EQ(image.epoch, fixture.authority().status().epoch().value());
}

// ---------------------------------------------------------------------------
// Exclusive writer lock and read-only opening
// ---------------------------------------------------------------------------

CPE_TEST(persistence, read_only_opens_take_no_writer_lock) {
  TestAuthority fixture;
  (void)fixture.register_controller("ctrl-a");

  const StoreOpenOptions read_only = options_for(fixture.store(), StoreOpenMode::ReadOnly);
  ControlPlaneEpochAuthority reader_one(read_only);
  CPE_REQUIRE(reader_one.initialized());
  CPE_REQUIRE(reader_one.status().open_mode() == StoreOpenMode::ReadOnly);
  CPE_REQUIRE(reader_one.recovery().outcome() == RecoveryOutcome::ReadOnlyInspection);

  // A second read-only instance at the same time is allowed: no writer lock is
  // taken, so read-only opening never contends.
  ControlPlaneEpochAuthority reader_two(read_only);
  CPE_REQUIRE(reader_two.initialized());
  CPE_REQUIRE(reader_two.status() == reader_one.status());
  CPE_REQUIRE_EQ(reader_two.status().durable_generation().value(),
                 fixture.authority().status().durable_generation().value());

  // Read-only means read-only: every mutation is refused, and no file changes.
  const std::map<std::string, Sha256Digest> before = digest_directory(fixture.store());
  CPE_REQUIRE_THROWS_CODE(reader_one.initialize(InitializeDomainRequest{}), ErrorCode::UnsupportedOperation);
  RegisterControllerRequest registration;
  registration.controller = controller_id("ctrl-b");
  registration.provenance = provenance_input("ctrl-b");
  CPE_REQUIRE_THROWS_CODE(reader_one.register_controller(registration), ErrorCode::UnsupportedOperation);
  CPE_REQUIRE(digest_directory(fixture.store()) == before);

  // The same directory cannot be opened for writing while the writer holds it.
  CPE_REQUIRE_THROWS_CODE(ControlPlaneEpochAuthority{options_for(fixture.store())}, ErrorCode::StoreLocked);

  // Close the writer; the exclusive lock is released and a new writer is allowed.
  fixture.reopen();
  CPE_REQUIRE(fixture.authority().status().open_mode() == StoreOpenMode::ReadWrite);
  CPE_REQUIRE(fixture.authority().recovery().outcome() == RecoveryOutcome::OpenedClean);
}

CPE_TEST(persistence, every_stateful_operation_is_rejected_after_close) {
  TempDirectory directory;
  const StoreOpenOptions options = options_for(directory.path());
  std::unique_ptr<ControlPlaneEpochAuthority> authority = std::make_unique<ControlPlaneEpochAuthority>(options);
  initialize_facility(*authority);

  RegisterControllerRequest registration;
  registration.controller = controller_id("ctrl-a");
  registration.provenance = provenance_input("ctrl-a");
  auto registered = authority->register_controller(std::move(registration));
  CPE_REQUIRE(registered.has_value());

  const std::map<std::string, Sha256Digest> before = digest_directory(directory.path());
  authority->close();
  CPE_REQUIRE(authority->closed());

  // Nothing may silently succeed against released state -- including the
  // recovery report, which is the one accessor that used to escape the rule.
  CPE_REQUIRE_THROWS_CODE(authority->initialize(InitializeDomainRequest{}), ErrorCode::StoreNotFound);
  CPE_REQUIRE_THROWS_CODE(authority->recovery(), ErrorCode::StoreNotFound);
  CPE_REQUIRE_THROWS_CODE(authority->status(), ErrorCode::StoreNotFound);
  CPE_REQUIRE_THROWS_CODE(authority->accounting(), ErrorCode::StoreNotFound);
  CPE_REQUIRE_THROWS_CODE(authority->current_epoch(), ErrorCode::StoreNotFound);
  CPE_REQUIRE_THROWS_CODE(authority->history(HistoryQuery{}), ErrorCode::StoreNotFound);
  CPE_REQUIRE_THROWS_CODE(authority->revocations(RevocationQuery{}), ErrorCode::StoreNotFound);
  CPE_REQUIRE_THROWS_CODE(authority->controllers(ControllerQuery{}), ErrorCode::StoreNotFound);
  CPE_REQUIRE_THROWS_CODE(authority->grants(GrantQuery{}), ErrorCode::StoreNotFound);
  CPE_REQUIRE_THROWS_CODE(authority->controller_record(controller_id("ctrl-a")), ErrorCode::StoreNotFound);
  CPE_REQUIRE_THROWS_CODE(authority->grant_record(GrantId::from_trusted(1)), ErrorCode::StoreNotFound);
  CPE_REQUIRE_THROWS_CODE(authority->write_snapshot_artifact(directory.file("closed.cpesnap")),
                          ErrorCode::StoreNotFound);

  RegisterControllerRequest another;
  another.controller = controller_id("ctrl-b");
  another.provenance = provenance_input("ctrl-b");
  CPE_REQUIRE_THROWS_CODE(authority->register_controller(another), ErrorCode::StoreNotFound);

  AcquireAuthorityRequest acquisition;
  acquisition.controller = controller_id("ctrl-b");
  acquisition.incarnation = ControllerIncarnationId::derive(domain_id("facility-alpha"), controller_id("ctrl-b"),
                                                            IncarnationNumber::from_trusted(1));
  acquisition.scopes = scope_set({"facility.inventory"});
  acquisition.provenance = provenance_input("ctrl-b");
  CPE_REQUIRE_THROWS_CODE(authority->acquire_authority(acquisition), ErrorCode::StoreNotFound);

  AdvanceEpochRequest advance;
  advance.expected_current = Epoch::initial();
  advance.authority = synthetic_root_authority();
  advance.provenance = provenance_input("operator");
  CPE_REQUIRE_THROWS_CODE(authority->advance_epoch(advance), ErrorCode::StoreNotFound);

  RevokeAuthorityRequest revocation;
  revocation.target = RevocationTarget::controller_all(controller_id("ctrl-a"));
  revocation.authority = synthetic_root_authority();
  revocation.provenance = provenance_input("operator");
  CPE_REQUIRE_THROWS_CODE(authority->revoke_authority(revocation), ErrorCode::StoreNotFound);

  CPE_REQUIRE_THROWS_CODE(authority->validate_mutation(synthetic_root_authority(), scope_name("authority.grant")),
                          ErrorCode::StoreNotFound);
  CPE_REQUIRE_THROWS_CODE(
      authority->validate_observation(ObservationAuthority::from_claims(synthetic_root_authority().claims()),
                                      scope_name("authority.grant")),
      ErrorCode::StoreNotFound);

  auto claim = RecoveredStateClaim::create(domain_id("facility-alpha"), Epoch::initial(), controller_id("ctrl-a"),
                                           registered.value().incarnation_id(), scope_name("facility.inventory"),
                                           digest_of("content"));
  CPE_REQUIRE(claim.has_value());
  CPE_REQUIRE_THROWS_CODE(authority->qualify_recovered_state(claim.value()), ErrorCode::StoreNotFound);

  // Every refusal was a refusal: the durable files are untouched.
  CPE_REQUIRE(digest_directory(directory.path()) == before);
}

// ---------------------------------------------------------------------------
// Read-only verification and snapshot artifacts
// ---------------------------------------------------------------------------

CPE_TEST(persistence, inspect_store_verifies_a_healthy_store_without_modifying_it) {
  TestAuthority fixture;
  const ControllerRegistration registered = fixture.register_controller("ctrl-a");
  const MutationAuthority root = fixture.root_authority();
  const AuthorityGrantView grant = fixture.acquire("ctrl-a", registered.incarnation_id(), {"facility.inventory"}, root);

  RevokeAuthorityRequest revocation;
  revocation.target = RevocationTarget::grant(grant.record().id(), controller_id("ctrl-a"));
  revocation.reason = RevocationReason::OperatorRequest;
  revocation.authority = root;
  revocation.provenance = provenance_input("operator");
  auto revoked = fixture.authority().revoke_authority(std::move(revocation));
  CPE_REQUIRE(revoked.has_value());

  const AuthorityStatus status = fixture.authority().status();
  const std::map<std::string, Sha256Digest> before = digest_directory(fixture.store());

  const StoreInspection inspection = inspect_store(fixture.store());

  CPE_REQUIRE(inspection.verified());
  CPE_REQUIRE(inspection.read_only_safe());
  CPE_REQUIRE(inspection.store_initialized());
  CPE_REQUIRE(inspection.problems().empty());
  CPE_REQUIRE(inspection.transition_chain_verified());
  CPE_REQUIRE_EQ(inspection.domain(), status.domain());
  CPE_REQUIRE_EQ(inspection.domain_instance()->value(), status.domain_instance().value());
  CPE_REQUIRE_EQ(inspection.epoch()->value(), status.epoch().value());
  CPE_REQUIRE_EQ(inspection.durable_generation()->value(), status.durable_generation().value());
  CPE_REQUIRE_EQ(inspection.controller_count(), status.controller_count());
  CPE_REQUIRE_EQ(inspection.live_grant_count(), status.live_grant_count());
  CPE_REQUIRE_EQ(inspection.transition_count(), status.transition_count());
  CPE_REQUIRE_EQ(inspection.revocation_count(), status.revocation_count());
  CPE_REQUIRE_EQ(inspection.idempotency_record_count(), status.idempotency_record_count());
  CPE_REQUIRE_EQ(inspection.snapshot_digest(), status.snapshot_digest());
  CPE_REQUIRE_EQ(inspection.snapshot_bytes(), file_bytes(fixture.file("authority.state")));
  CPE_REQUIRE_EQ(inspection.floor_epoch()->value(), status.epoch().value());
  CPE_REQUIRE_EQ(inspection.floor_generation()->value(), status.durable_generation().value());

  // Verification is read-only: not one byte of the store changed.
  CPE_REQUIRE(digest_directory(fixture.store()) == before);

  // A store whose live generation is damaged no longer verifies, which is what
  // makes verified()==true meaningful rather than vacuous.
  fixture.close();
  std::vector<std::byte> damaged = store_bytes(fixture.file("authority.state"));
  damaged.back() ^= std::byte{0xFF};
  overwrite_bytes(fixture.file("authority.state"), damaged);

  const StoreInspection broken = inspect_store(fixture.store());
  CPE_REQUIRE(!broken.verified());
  CPE_REQUIRE(!broken.read_only_safe());
  CPE_REQUIRE(!broken.problems().empty());
}

CPE_TEST(persistence, snapshot_artifact_bytes_equal_the_live_generation) {
  TestAuthority fixture;
  (void)fixture.register_controller("ctrl-a");

  TempDirectory export_directory;
  const std::filesystem::path artifact = export_directory.file("facility-alpha.cpesnap");
  CPE_REQUIRE(!std::filesystem::exists(artifact));

  fixture.authority().write_snapshot_artifact(artifact);
  CPE_REQUIRE(std::filesystem::exists(artifact));

  // The artifact is the live generation, not a re-serialization of it.
  const std::vector<std::byte> live = store_bytes(fixture.file("authority.state"));
  const std::vector<std::byte> exported = store_bytes(artifact);
  CPE_REQUIRE(exported == live);

  const detail::FileEnvelope envelope =
      detail::decode_envelope(exported, max_snapshot_artifact_bytes);
  CPE_REQUIRE_EQ(envelope.generation, fixture.authority().status().durable_generation().value());
  CPE_REQUIRE_EQ(envelope.epoch, fixture.authority().status().epoch().value());
  CPE_REQUIRE_EQ(envelope.payload_digest, fixture.authority().status().snapshot_digest());
  CPE_REQUIRE_EQ(envelope.payload_digest, fixture.authority().last_commit()->snapshot_digest());

  // Overwriting an existing artifact is an atomic replace, not an append.
  fixture.authority().write_snapshot_artifact(artifact);
  CPE_REQUIRE(store_bytes(artifact) == live);
}
