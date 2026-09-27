// Control Plane Epoch 1.0.0 - Summon Software Labs
// Suite: limits.
//
// Invariant under test: every documented bound is enforced with its exact code,
// and enforcing it costs nothing. A request that exceeds a bound is refused
// before it changes any state, and a structure that reaches its retention bound
// is trimmed and anchored rather than grown.
//
// The server-side connection bounds (max_server_connections,
// max_requests_per_connection) are covered by the process suite, which owns a
// real runtime; this suite covers the bounds that are observable from a single
// authority instance.

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include "test_support.hpp"

#include "control_plane_epoch/version.hpp"

#include "durable.hpp"
#include "image.hpp"
#include "records.hpp"

namespace {

using namespace cpe_test;
using namespace dccp::epoch;

[[nodiscard]] StoreOpenOptions options_for(const std::filesystem::path& directory) {
  StoreOpenOptions options;
  options.directory = directory;
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

/// `count` distinct, syntactically valid scope names. Distinctness matters: the
/// bound being tested is a count bound, not a duplicate check.
[[nodiscard]] std::vector<std::string> many_scopes(std::size_t count) {
  std::vector<std::string> scopes;
  scopes.reserve(count);
  for (std::size_t index = 0; index < count; ++index) {
    std::string name = "scope." + std::to_string(index);
    scopes.push_back(name);
  }
  // The three reserved administrative scopes must be present for a domain to be
  // administrable, so they replace the first three generated names.
  scopes[0] = "authority.grant";
  scopes[1] = "authority.revoke";
  scopes[2] = "epoch.advance";
  return scopes;
}

[[nodiscard]] std::vector<std::byte> read_bytes(const std::filesystem::path& path) {
  auto bytes = detail::read_file_optional(path, max_snapshot_bytes + detail::envelope_header_bytes);
  if (!bytes.has_value()) {
    throw Failure("expected " + path.string() + " to exist");
  }
  return std::move(*bytes);
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

[[nodiscard]] detail::ProvenanceData seed_provenance(std::uint64_t epoch, std::uint64_t sequence) {
  detail::ProvenanceData data;
  data.kind = ProvenanceSourceKind::Initialization;
  data.source = "test-seed";
  data.recorded_epoch = epoch;
  data.recorded_sequence = sequence;
  data.record_digest = detail::compute_provenance_digest(data);
  return data;
}

/// A verified generation that already retains `transition_count` epoch
/// transitions. Proving that trimming is counted would otherwise need more than
/// four thousand durable commits -- quadratic work that would dominate the
/// suite -- so the saturated ledger is written through the internal codec and a
/// single advancement is then driven through the public API to cross the bound.
struct SaturatedStore {
  std::uint64_t epoch = 0;
  Sha256Digest first_transition_digest;
  Sha256Digest newest_transition_digest;
};

[[nodiscard]] SaturatedStore seed_transition_saturated_store(const std::filesystem::path& directory,
                                                             std::uint64_t transition_count) {
  const FacilityAuthorityDomainId domain = domain_id("facility-alpha");
  const ControllerId root = controller_id("authority-root");
  const ControllerIncarnationId incarnation =
      ControllerIncarnationId::derive(domain, root, IncarnationNumber::from_trusted(1));

  detail::AuthorityImage image;
  image.schema_version = static_cast<std::uint32_t>(durable_schema_version);
  image.domain = domain.str();
  image.domain_instance = 1;
  image.epoch = transition_count;
  image.durable_generation = 1;
  image.authority_root = root.str();
  image.declared_scopes = default_scopes();

  detail::ControllerData controller;
  controller.controller = root.str();
  controller.incarnation_number = 1;
  controller.incarnation_id = incarnation.digest();
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
  grant.epoch = image.epoch;
  grant.controller = root.str();
  grant.incarnation_number = 1;
  grant.incarnation_id = controller.incarnation_id;
  grant.scopes = image.declared_scopes;
  grant.sequence = 2;
  grant.state = detail::GrantState::Live;
  grant.provenance = seed_provenance(image.epoch, 2);
  grant.record_digest = detail::compute_grant_digest(grant);
  image.grants.push_back(grant);

  SaturatedStore result;
  result.epoch = image.epoch;
  Sha256Digest previous = Sha256Digest::zero();
  for (std::uint64_t sequence = 1; sequence <= transition_count; ++sequence) {
    detail::TransitionData transition;
    transition.sequence = sequence;
    transition.origin = sequence == 1;
    transition.base_epoch = sequence == 1 ? 0 : sequence - 1;
    transition.new_epoch = sequence;
    transition.reason = sequence == 1 ? EpochTransitionReason::Genesis : EpochTransitionReason::OperatorRequest;
    transition.committed_by = root.str();
    transition.committed_by_incarnation = controller.incarnation_id;
    transition.committed_by_grant = grant.id;
    transition.fenced_grant_count = 0;
    transition.controller_count = 1;
    transition.provenance = seed_provenance(sequence, sequence);
    transition.previous_record_digest = previous;
    transition.record_digest = detail::compute_transition_digest(transition);
    previous = transition.record_digest;
    if (sequence == 1) {
      result.first_transition_digest = transition.record_digest;
    }
    image.transitions.push_back(std::move(transition));
  }
  result.newest_transition_digest = image.transitions.back().record_digest;
  image.transition_count = transition_count;
  image.transition_trimmed = 0;
  image.next_grant_id = 2;
  image.next_mutation_sequence = transition_count + 1;

  const std::vector<std::byte> payload = detail::encode_image(image, detail::default_image_limits());
  write_envelope_file(directory / std::string(StoreLayout::snapshot_file), 1, image.epoch, payload,
                      max_snapshot_bytes + detail::envelope_header_bytes);

  detail::FloorData floor;
  floor.domain = image.domain;
  floor.domain_instance = image.domain_instance;
  floor.epoch = image.epoch;
  floor.generation = 1;
  floor.snapshot_digest = sha256(std::span<const std::byte>(payload));
  write_envelope_file(directory / std::string(StoreLayout::floor_file), 1, image.epoch, detail::encode_floor(floor),
                      max_floor_bytes + detail::envelope_header_bytes);
  return result;
}

/// Standing-root bootstrap used by the crafted-store tests, which cannot use the
/// TestAuthority fixture because they start from a pre-existing directory.
[[nodiscard]] MutationAuthority bootstrap_root(ControlPlaneEpochAuthority& authority) {
  AcquireAuthorityRequest request;
  request.controller = controller_id("authority-root");
  request.incarnation = authority.controller_record(controller_id("authority-root")).value().incarnation_id();
  request.scopes = scope_set({"authority.grant", "authority.revoke", "epoch.advance"});
  request.provenance = provenance_input("authority-root");
  auto view = authority.acquire_authority(std::move(request));
  if (!view.has_value()) {
    throw Failure("bootstrap acquisition failed: " + view.rejection().to_string());
  }
  if (!view.value().mutation_authority().has_value()) {
    throw Failure("the bootstrap grant carried no mutation authority");
  }
  return *view.value().mutation_authority();
}

}  // namespace

// ---------------------------------------------------------------------------
// Paged query bounds
// ---------------------------------------------------------------------------

CPE_TEST(limits, every_paged_query_enforces_the_page_bound) {
  TestAuthority fixture;
  const ControllerRegistration registered = fixture.register_controller("ctrl-a");
  const MutationAuthority root = fixture.root_authority();
  (void)fixture.acquire("ctrl-a", registered.incarnation_id(), {"facility.inventory"}, root);
  (void)fixture.advance(Epoch::initial(), root);

  CPE_REQUIRE_EQ(max_page_size, 256u);

  const AuthorityStatus status_before = fixture.authority().status();
  const AuthorityAccounting accounting_before = fixture.authority().accounting();

  const auto require_page_limit = [&](const char* what, const Explanation& rejection) {
    CPE_REQUIRE_MSG(rejection.code() == ErrorCode::PageLimitExceeded,
                    std::string(what) + ": expected limit.page_size but observed " +
                        std::string(error_token(rejection.code())));
    CPE_REQUIRE_MSG(rejection.token() == std::string_view("limit.page_size"), std::string(what));
  };

  // Zero is out of range, not "unbounded": an unbounded page would let one call
  // size its own result.
  for (const std::size_t limit : {std::size_t{0}, max_page_size + 1, max_page_size * 4}) {
    HistoryQuery history;
    history.limit = limit;
    auto history_page = fixture.authority().history(history);
    CPE_REQUIRE(!history_page.has_value());
    require_page_limit("history", history_page.rejection());

    RevocationQuery revocations;
    revocations.limit = limit;
    auto revocation_page = fixture.authority().revocations(revocations);
    CPE_REQUIRE(!revocation_page.has_value());
    require_page_limit("revocations", revocation_page.rejection());

    ControllerQuery controllers;
    controllers.limit = limit;
    auto controller_page = fixture.authority().controllers(controllers);
    CPE_REQUIRE(!controller_page.has_value());
    require_page_limit("controllers", controller_page.rejection());

    GrantQuery grants;
    grants.limit = limit;
    auto grant_page = fixture.authority().grants(grants);
    CPE_REQUIRE(!grant_page.has_value());
    require_page_limit("grants", grant_page.rejection());
  }

  // The bound itself is usable, and one page cannot exceed its own limit.
  HistoryQuery history;
  history.limit = max_page_size;
  const auto full_page = fixture.authority().history(history);
  CPE_REQUIRE(full_page.has_value());
  CPE_REQUIRE(full_page.value().records().size() <= max_page_size);
  CPE_REQUIRE_EQ(full_page.value().total_count(), status_before.transition_count());

  HistoryQuery single;
  single.limit = 1;
  const auto single_page = fixture.authority().history(single);
  CPE_REQUIRE(single_page.has_value());
  CPE_REQUIRE_EQ(single_page.value().records().size(), 1u);
  CPE_REQUIRE_EQ(single_page.value().records().front().sequence().value(), 1u);

  ControllerQuery controller_query;
  controller_query.limit = 1;
  const auto controller_page = fixture.authority().controllers(controller_query);
  CPE_REQUIRE(controller_page.has_value());
  CPE_REQUIRE_EQ(controller_page.value().records().size(), 1u);
  CPE_REQUIRE_EQ(controller_page.value().total_count(), status_before.controller_count());

  // A refused request is a pure rejection: not one durable value moved.
  CPE_REQUIRE(fixture.authority().status() == status_before);
  CPE_REQUIRE(fixture.authority().accounting() == accounting_before);
  CPE_REQUIRE_EQ(fixture.authority().status().snapshot_digest(), status_before.snapshot_digest());
}

// ---------------------------------------------------------------------------
// Scope and count bounds
// ---------------------------------------------------------------------------

CPE_TEST(limits, scope_list_and_declaration_bounds_are_enforced) {
  CPE_REQUIRE_EQ(max_scopes_per_authority, 64u);
  CPE_REQUIRE_EQ(max_declared_scopes, 256u);

  // A grant may cover at most max_scopes_per_authority scopes.
  const std::vector<std::string> oversized = many_scopes(max_scopes_per_authority + 1);
  auto too_many = AuthorityScopeSet::create(scope_list(oversized));
  CPE_REQUIRE(!too_many.has_value());
  CPE_REQUIRE_EQ(too_many.rejection().code(), ErrorCode::SizeLimitExceeded);
  CPE_REQUIRE(too_many.rejection().token() == std::string_view("limit.size_exceeded"));

  const std::vector<std::string> at_bound = many_scopes(max_scopes_per_authority);
  auto exact = AuthorityScopeSet::create(scope_list(at_bound));
  CPE_REQUIRE(exact.has_value());
  CPE_REQUIRE_EQ(exact.value().size(), max_scopes_per_authority);

  // A domain may declare at most max_declared_scopes scopes, and a rejected
  // declaration leaves the store exactly as uninitialized as it was.
  TempDirectory directory;
  ControlPlaneEpochAuthority authority(options_for(directory.path()));
  CPE_REQUIRE(!authority.initialized());

  InitializeDomainRequest oversized_domain;
  oversized_domain.domain = domain_id("facility-alpha");
  oversized_domain.authority_root = controller_id("authority-root");
  oversized_domain.provenance = provenance_input("operator");
  for (const std::string& scope : many_scopes(max_declared_scopes + 1)) {
    oversized_domain.scopes.push_back(scope_name(scope));
  }
  auto rejected = authority.initialize(std::move(oversized_domain));
  CPE_REQUIRE(!rejected.has_value());
  CPE_REQUIRE_EQ(rejected.rejection().code(), ErrorCode::SizeLimitExceeded);
  CPE_REQUIRE(!authority.initialized());
  CPE_REQUIRE(authority.accounting().controller_records() == 0);
  CPE_REQUIRE(authority.accounting().grant_records() == 0);
  CPE_REQUIRE(!authority.last_commit().has_value());
  CPE_REQUIRE(!std::filesystem::exists(directory.file(std::string(StoreLayout::snapshot_file))));

  // A duplicate inside the list is a different failure with its own code, so
  // the count bound above is demonstrably a count bound.
  InitializeDomainRequest duplicated;
  duplicated.domain = domain_id("facility-alpha");
  duplicated.authority_root = controller_id("authority-root");
  duplicated.provenance = provenance_input("operator");
  const std::vector<std::string> with_duplicate{"authority.grant", "authority.grant", "authority.revoke",
                                                "epoch.advance"};
  for (const std::string& scope : with_duplicate) {
    duplicated.scopes.push_back(scope_name(scope));
  }
  auto duplicate_result = authority.initialize(std::move(duplicated));
  CPE_REQUIRE(!duplicate_result.has_value());
  CPE_REQUIRE_EQ(duplicate_result.rejection().code(), ErrorCode::ScopeDuplicate);

  // The domain is still unused, so the valid declaration succeeds at epoch 1.
  initialize_facility(authority);
  CPE_REQUIRE_EQ(authority.status().epoch().value(), 1u);
  CPE_REQUIRE_EQ(authority.status().declared_scopes().size(), default_scopes().size());
}

CPE_TEST(limits, the_usable_declaration_bound_is_the_grant_bound) {
  // The genesis grant must cover the entire declared vocabulary, and one grant
  // covers at most max_scopes_per_authority scopes. So the largest declaration a
  // domain can round-trip is the grant bound, not the larger declaration bound,
  // and a domain may not publish a vocabulary its own reader would refuse.
  CPE_REQUIRE_EQ(max_declared_scopes, 256u);
  CPE_REQUIRE_EQ(max_scopes_per_authority, 64u);

  TempDirectory directory;

  // One scope above the usable bound is refused and commits nothing: no
  // generation, no floor, no controller, no grant.
  {
    ControlPlaneEpochAuthority authority(options_for(directory.path()));
    CPE_REQUIRE(!authority.initialized());

    InitializeDomainRequest request;
    request.domain = domain_id("facility-alpha");
    request.authority_root = controller_id("authority-root");
    request.provenance = provenance_input("operator");
    for (const std::string& scope : many_scopes(max_scopes_per_authority + 1)) {
      request.scopes.push_back(scope_name(scope));
    }
    auto rejected = authority.initialize(std::move(request));
    CPE_REQUIRE(!rejected.has_value());
    CPE_REQUIRE_EQ(rejected.rejection().code(), ErrorCode::SizeLimitExceeded);
    CPE_REQUIRE(rejected.rejection().token() == std::string_view("limit.size_exceeded"));

    CPE_REQUIRE(!authority.initialized());
    CPE_REQUIRE(!authority.last_commit().has_value());
    const AuthorityAccounting accounting = authority.accounting();
    CPE_REQUIRE_EQ(accounting.controller_records(), 0u);
    CPE_REQUIRE_EQ(accounting.grant_records(), 0u);
    CPE_REQUIRE_EQ(accounting.transition_records_retained(), 0u);
    CPE_REQUIRE_EQ(accounting.idempotency_records(), 0u);
    CPE_REQUIRE(!std::filesystem::exists(directory.file(std::string(StoreLayout::snapshot_file))));
    CPE_REQUIRE(!std::filesystem::exists(directory.file(std::string(StoreLayout::floor_file))));
    CPE_REQUIRE_THROWS_CODE(authority.status(), ErrorCode::StoreNotInitialized);
  }

  // Exactly the usable bound initializes, with the full vocabulary intact.
  const std::vector<std::string> scopes = many_scopes(max_scopes_per_authority);
  {
    ControlPlaneEpochAuthority authority(options_for(directory.path()));
    InitializeDomainRequest request;
    request.domain = domain_id("facility-alpha");
    request.authority_root = controller_id("authority-root");
    request.provenance = provenance_input("operator");
    for (const std::string& scope : scopes) {
      request.scopes.push_back(scope_name(scope));
    }
    auto initialized = authority.initialize(std::move(request));
    CPE_REQUIRE(initialized.has_value());
    CPE_REQUIRE_EQ(authority.status().declared_scopes().size(), max_scopes_per_authority);
    CPE_REQUIRE_EQ(authority.status().epoch().value(), 1u);
    CPE_REQUIRE_EQ(authority.status().domain_instance().value(), 1u);
    CPE_REQUIRE_EQ(authority.status().live_grant_count(), 1u);
    // The genesis grant covers the whole vocabulary, which is exactly why the
    // declaration bound cannot exceed the grant bound.
    const auto grants = authority.grants(GrantQuery{}).value();
    CPE_REQUIRE_EQ(grants.records().size(), 1u);
    CPE_REQUIRE_EQ(grants.records().front().scopes().size(), max_scopes_per_authority);
  }

  // ... and the store it published reopens clean and verifies.
  ControlPlaneEpochAuthority reopened(options_for(directory.path()));
  CPE_REQUIRE(reopened.initialized());
  CPE_REQUIRE_EQ(reopened.status().declared_scopes().size(), max_scopes_per_authority);
  CPE_REQUIRE_EQ(reopened.recovery().outcome(), RecoveryOutcome::OpenedClean);
  const StoreInspection inspection = inspect_store(directory.path());
  CPE_REQUIRE(inspection.verified());
  CPE_REQUIRE(inspection.problems().empty());
  CPE_REQUIRE_EQ(inspection.controller_count(), 1u);
  CPE_REQUIRE_EQ(inspection.live_grant_count(), 1u);

  // A declaration above the documented declaration bound is still refused, and
  // it is refused by the same code, so the reported bound is the tighter one.
  TempDirectory oversized_directory;
  {
    ControlPlaneEpochAuthority authority(options_for(oversized_directory.path()));
    InitializeDomainRequest request;
    request.domain = domain_id("facility-alpha");
    request.authority_root = controller_id("authority-root");
    request.provenance = provenance_input("operator");
    for (const std::string& scope : many_scopes(max_declared_scopes + 1)) {
      request.scopes.push_back(scope_name(scope));
    }
    auto rejected = authority.initialize(std::move(request));
    CPE_REQUIRE(!rejected.has_value());
    CPE_REQUIRE_EQ(rejected.rejection().code(), ErrorCode::SizeLimitExceeded);
    CPE_REQUIRE(!authority.initialized());
    CPE_REQUIRE(!authority.last_commit().has_value());
  }
}

// ---------------------------------------------------------------------------
// Store open option bounds
// ---------------------------------------------------------------------------

CPE_TEST(limits, snapshot_byte_option_is_validated_before_anything_is_created) {
  TempDirectory directory;
  const std::filesystem::path fresh = directory.file("not-created-yet");

  for (const std::size_t bound : {std::size_t{0}, max_snapshot_bytes + 1, max_snapshot_bytes * 2}) {
    StoreOpenOptions options;
    options.directory = fresh;
    options.max_snapshot_bytes = bound;
    CPE_REQUIRE_THROWS_CODE(ControlPlaneEpochAuthority{options}, ErrorCode::InvalidOption);
    // Validation happens before the store directory is touched.
    CPE_REQUIRE(!std::filesystem::exists(fresh));
  }

  // An empty directory path is refused, also before anything is created.
  StoreOpenOptions empty_path;
  CPE_REQUIRE_THROWS_CODE(ControlPlaneEpochAuthority{empty_path}, ErrorCode::PathInvalid);

  // The maximum itself is accepted and the store it opens is usable.
  StoreOpenOptions at_max;
  at_max.directory = fresh;
  at_max.max_snapshot_bytes = max_snapshot_bytes;
  {
    ControlPlaneEpochAuthority authority(at_max);
    CPE_REQUIRE(!authority.initialized());
    initialize_facility(authority);
    CPE_REQUIRE_EQ(authority.status().epoch().value(), 1u);
    CPE_REQUIRE_EQ(authority.status().domain_instance().value(), 1u);
  }

  // A lowered bound is accepted for reading the same store: the option may only
  // ever tighten, never widen.
  StoreOpenOptions lowered_options = options_for(fresh);
  lowered_options.max_snapshot_bytes = max_snapshot_bytes / 2;
  {
    ControlPlaneEpochAuthority lowered(lowered_options);
    CPE_REQUIRE(lowered.initialized());
    CPE_REQUIRE_EQ(lowered.status().epoch().value(), 1u);
  }
  CPE_REQUIRE(inspect_store(fresh).verified());
}

// ---------------------------------------------------------------------------
// Idempotency blob bound
// ---------------------------------------------------------------------------

CPE_TEST(limits, idempotency_result_blobs_cannot_exceed_their_encoding_bound) {
  CPE_REQUIRE_EQ(max_idempotency_blob_bytes, 4096u);

  TestAuthority fixture;
  const ControllerId controller = controller_id("ctrl-a");
  const ControllerIncarnationId incarnation =
      ControllerIncarnationId::derive(domain_id(fixture.domain()), controller, IncarnationNumber::from_trusted(1));

  // Every blob the API can produce is bounded by construction: the longest
  // inputs the API accepts (an identifier of at most 96 bytes and a note of at
  // most 256 bytes) cannot push a recorded outcome past the bound.
  RegisterControllerRequest registration;
  registration.controller = controller;
  registration.provenance = provenance_input("ctrl-a");
  registration.idempotency = IdempotencyKey::create(controller, incarnation, OperationSequence::from_trusted(1)).value();
  CPE_REQUIRE(fixture.authority().register_controller(std::move(registration)).has_value());

  const MutationAuthority root = fixture.root_authority();
  AcquireAuthorityRequest acquisition;
  acquisition.controller = controller;
  acquisition.incarnation = incarnation;
  acquisition.scopes = scope_set(default_scopes());
  acquisition.sponsor = root;
  acquisition.provenance = provenance_input("ctrl-a");
  acquisition.idempotency = IdempotencyKey::create(controller, incarnation, OperationSequence::from_trusted(2)).value();
  CPE_REQUIRE(fixture.authority().acquire_authority(std::move(acquisition)).has_value());

  const detail::FileEnvelope envelope =
      detail::decode_envelope(read_bytes(fixture.file(std::string(StoreLayout::snapshot_file))),
                              max_snapshot_bytes + detail::envelope_header_bytes);
  const detail::AuthorityImage image = detail::decode_image(envelope.payload, detail::default_image_limits());
  CPE_REQUIRE_EQ(image.idempotency.size(), 2u);
  for (const detail::IdempotencyData& entry : image.idempotency) {
    CPE_REQUIRE(!entry.result_blob.empty());
    CPE_REQUIRE(entry.result_blob.size() <= max_idempotency_blob_bytes);
  }

  // The reader is the enforcement point that matters: a blob one byte past the
  // bound is refused by the decoder, and the largest legal blob is accepted.
  const auto with_blob = [&](std::size_t size) {
    detail::AuthorityImage probe = image;
    detail::IdempotencyData entry;
    entry.controller = "zz-limit-probe";
    entry.incarnation_id = digest_of("probe-incarnation");
    entry.sequence = 1;
    entry.command_digest = digest_of("probe-command");
    entry.result_blob.assign(size, std::byte{0x41});
    probe.idempotency.push_back(std::move(entry));
    probe.idempotency_count += 1;
    return detail::encode_image(probe, detail::default_image_limits());
  };

  CPE_REQUIRE_NO_THROW(detail::decode_image(with_blob(max_idempotency_blob_bytes), detail::default_image_limits()));
  CPE_REQUIRE_THROWS_CODE(detail::decode_image(with_blob(max_idempotency_blob_bytes + 1),
                                               detail::default_image_limits()),
                          ErrorCode::IntegrityLimitExceeded);
  CPE_REQUIRE_THROWS_CODE(detail::decode_image(with_blob(1u << 20), detail::default_image_limits()),
                          ErrorCode::IntegrityLimitExceeded);

  // The bound also holds across a restart, so it is a durable property.
  fixture.reopen();
  CPE_REQUIRE_EQ(fixture.authority().status().idempotency_record_count(), 2u);
}

// ---------------------------------------------------------------------------
// Ledger retention bounds
// ---------------------------------------------------------------------------

CPE_TEST(limits, transition_retention_is_bounded_trimmed_and_anchored) {
  CPE_REQUIRE_EQ(max_transition_records, 4096u);

  TempDirectory directory;
  const SaturatedStore saturated = seed_transition_saturated_store(directory.path(), max_transition_records);
  CPE_REQUIRE_EQ(saturated.epoch, max_transition_records);

  ControlPlaneEpochAuthority authority(options_for(directory.path()));
  CPE_REQUIRE(authority.initialized());
  CPE_REQUIRE_EQ(authority.status().transition_count(), max_transition_records);
  const AuthorityAccounting saturated_accounting = authority.accounting();
  CPE_REQUIRE_EQ(saturated_accounting.transition_records_retained(), max_transition_records);
  CPE_REQUIRE_EQ(saturated_accounting.transition_records_trimmed(), 0u);

  const auto saturated_history = authority.history(HistoryQuery{}).value();
  CPE_REQUIRE_EQ(saturated_history.records().size(), max_page_size);
  CPE_REQUIRE_EQ(saturated_history.trimmed_count(), 0u);
  CPE_REQUIRE(saturated_history.history_anchor().is_zero());
  CPE_REQUIRE_EQ(saturated_history.chain_head(), saturated.newest_transition_digest);

  // One further advancement crosses the retention bound: exactly one record is
  // trimmed, and the trimmed record's digest becomes the durable anchor that the
  // oldest retained record still links to.
  const MutationAuthority root = bootstrap_root(authority);
  AdvanceEpochRequest advance;
  advance.expected_current = Epoch::from_trusted(saturated.epoch);
  advance.authority = root;
  advance.reason = EpochTransitionReason::OperatorRequest;
  advance.provenance = provenance_input("operator");
  auto transition = authority.advance_epoch(std::move(advance));
  CPE_REQUIRE(transition.has_value());
  CPE_REQUIRE_EQ(transition.value().new_epoch().value(), saturated.epoch + 1);
  CPE_REQUIRE_EQ(transition.value().sequence().value(), max_transition_records + 1);

  const AuthorityAccounting trimmed_accounting = authority.accounting();
  CPE_REQUIRE_EQ(trimmed_accounting.transition_records_retained(), max_transition_records);
  CPE_REQUIRE_EQ(trimmed_accounting.transition_records_trimmed(), 1u);
  CPE_REQUIRE_EQ(authority.status().transition_count(), max_transition_records + 1);

  const auto trimmed_history = authority.history(HistoryQuery{}).value();
  CPE_REQUIRE_EQ(trimmed_history.trimmed_count(), 1u);
  CPE_REQUIRE_EQ(trimmed_history.total_count(), max_transition_records + 1);
  CPE_REQUIRE_EQ(trimmed_history.first_retained_sequence(), 2u);
  CPE_REQUIRE(trimmed_history.history_anchor() == saturated.first_transition_digest);
  CPE_REQUIRE(trimmed_history.chain_head() == transition.value().record_digest());
  CPE_REQUIRE_EQ(trimmed_history.records().front().previous_record_digest(), trimmed_history.history_anchor());

  // The trimmed ledger is still a verifiable chain, so the anchor is durable
  // rather than a rendering of something that was simply dropped.
  authority.close();
  ControlPlaneEpochAuthority reopened(options_for(directory.path()));
  CPE_REQUIRE(reopened.initialized());
  CPE_REQUIRE_EQ(reopened.accounting().transition_records_trimmed(), 1u);
  CPE_REQUIRE_EQ(reopened.history(HistoryQuery{}).value().history_anchor(), saturated.first_transition_digest);
  const StoreInspection inspection = inspect_store(directory.path());
  CPE_REQUIRE(inspection.verified());
  CPE_REQUIRE(inspection.problems().empty());
  CPE_REQUIRE(inspection.transition_chain_verified());
  CPE_REQUIRE_EQ(inspection.transition_count(), max_transition_records + 1);
  CPE_REQUIRE_EQ(inspection.durable_generation()->value(), 3u);
}

CPE_TEST(limits, a_retained_window_above_the_bound_is_refused_by_the_reader) {
  // The retention bound is enforced on the way in as well as on the way out: an
  // image that retains more transition records than the bound allows cannot be
  // read at all, so a hostile or hand-edited file cannot make the reader
  // allocate for a ledger it would never keep.
  TempDirectory directory;
  const SaturatedStore saturated = seed_transition_saturated_store(directory.path(), max_transition_records + 1);
  CPE_REQUIRE_EQ(saturated.epoch, max_transition_records + 1);

  CPE_REQUIRE_THROWS_CODE(ControlPlaneEpochAuthority{options_for(directory.path())},
                          ErrorCode::IntegrityLimitExceeded);
  const StoreInspection inspection = inspect_store(directory.path());
  CPE_REQUIRE(!inspection.verified());
  CPE_REQUIRE(!inspection.problems().empty());
}
