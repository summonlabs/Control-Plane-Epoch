// Control Plane Epoch 1.0.0 - Summon Software Labs
// Suite: corruption.
//
// Invariant under test: damage is never repaired silently and never
// half-repaired. Every refusal is a thrown EpochError carrying the exact
// integrity or persistence code, and a refused open leaves the damaged bytes on
// disk exactly as it found them. Repair happens only under an explicit operator
// policy, only within the durable floor, and only by moving state aside.

#include <algorithm>
#include <array>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include "test_support.hpp"

#include "control_plane_epoch/version.hpp"

#include "durable.hpp"
#include "fault.hpp"
#include "image.hpp"

namespace {

using namespace cpe_test;
using namespace dccp::epoch;

[[nodiscard]] StoreOpenOptions options_for(const std::filesystem::path& directory,
                                           RecoveryPolicy policy = RecoveryPolicy::RefuseOnDamage,
                                           std::optional<std::uint64_t> asserted = std::nullopt) {
  StoreOpenOptions options;
  options.directory = directory;
  options.recovery_policy = policy;
  options.asserted_epoch_floor = asserted;
  return options;
}

[[nodiscard]] std::vector<std::byte> read_bytes(const std::filesystem::path& path) {
  auto bytes = detail::read_file_optional(path, max_snapshot_bytes + detail::envelope_header_bytes);
  if (!bytes.has_value()) {
    throw Failure("expected " + path.string() + " to exist");
  }
  return std::move(*bytes);
}

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

[[nodiscard]] std::map<std::string, Sha256Digest> digest_directory(const std::filesystem::path& directory) {
  std::map<std::string, Sha256Digest> digests;
  std::error_code error;
  std::filesystem::recursive_directory_iterator iterator(directory, error);
  if (error) {
    throw Failure("could not enumerate " + directory.string() + ": " + error.message());
  }
  for (const std::filesystem::directory_entry& entry : iterator) {
    if (!entry.is_regular_file(error) || error) {
      continue;
    }
    const std::vector<std::byte> content =
        read_bytes(entry.path());
    std::error_code relative_error;
    const std::filesystem::path relative = std::filesystem::relative(entry.path(), directory, relative_error);
    digests.emplace(relative_error ? entry.path().filename().string() : relative.generic_string(),
                    sha256(std::span<const std::byte>(content)));
  }
  return digests;
}

[[nodiscard]] std::array<std::byte, 2> little_u16(std::uint16_t value) {
  return {static_cast<std::byte>(value & 0xFFu), static_cast<std::byte>((value >> 8u) & 0xFFu)};
}

[[nodiscard]] std::array<std::byte, 4> little_u32(std::uint32_t value) {
  return {static_cast<std::byte>(value & 0xFFu), static_cast<std::byte>((value >> 8u) & 0xFFu),
          static_cast<std::byte>((value >> 16u) & 0xFFu), static_cast<std::byte>((value >> 24u) & 0xFFu)};
}

void patch(std::vector<std::byte>& file, std::size_t offset, std::span<const std::byte> replacement) {
  if (offset + replacement.size() > file.size()) {
    throw Failure("patch is outside the file");
  }
  std::copy(replacement.begin(), replacement.end(), file.begin() + static_cast<std::ptrdiff_t>(offset));
}

/// Patches bytes inside the envelope payload and repairs the envelope digest, so
/// that the *payload* is what the reader rejects rather than the envelope
/// checksum. This is how a semantically unsupported generation is crafted
/// without producing a file the format layer would refuse first.
void patch_payload(std::vector<std::byte>& file, std::size_t payload_offset, std::span<const std::byte> replacement) {
  const std::size_t base = detail::envelope_header_bytes;
  patch(file, base + payload_offset, replacement);
  const std::span<const std::byte> payload(file.data() + base, file.size() - base);
  const Sha256Digest digest = sha256(payload);
  patch(file, 32, digest.bytes());
}

[[nodiscard]] detail::FileEnvelope generation_envelope(const std::filesystem::path& snapshot) {
  return detail::decode_envelope(read_bytes(snapshot), max_snapshot_bytes + detail::envelope_header_bytes);
}

[[nodiscard]] detail::FloorData floor_of(const std::filesystem::path& floor_file) {
  const detail::FileEnvelope envelope =
      detail::decode_envelope(read_bytes(floor_file), max_floor_bytes + detail::envelope_header_bytes);
  return detail::decode_floor(envelope.payload);
}

/// Opens the directory and reports why it refused, or Ok when it opened.
[[nodiscard]] Explanation open_failure(const std::filesystem::path& directory, RecoveryPolicy policy,
                                       std::optional<std::uint64_t> asserted = std::nullopt) {
  try {
    ControlPlaneEpochAuthority authority(options_for(directory, policy, asserted));
    (void)authority;
  } catch (const EpochError& error) {
    return error.explanation();
  }
  return Explanation();
}

/// The core conservation property of this suite: the refusal carries exactly the
/// expected code and not one byte of the store changed.
void require_refusal(const std::filesystem::path& directory, ErrorCode expected, RecoveryPolicy policy,
                     std::optional<std::uint64_t> asserted = std::nullopt) {
  const std::map<std::string, Sha256Digest> before = digest_directory(directory);
  const Explanation failure = open_failure(directory, policy, asserted);
  CPE_REQUIRE_MSG(failure.code() == expected, std::string("expected ") + std::string(error_token(expected)) +
                                                  " but observed " + std::string(error_token(failure.code())) + ": " +
                                                  failure.detail());
  CPE_REQUIRE_MSG(digest_directory(directory) == before,
                  std::string("refusing ") + std::string(error_token(expected)) + " rewrote the damaged store");
}

/// A store with three committed generations: the live file, a retained previous
/// file, and a floor that matches the live generation.
void build_three_generation_store(TestAuthority& fixture) {
  (void)fixture.register_controller("ctrl-a");
  (void)fixture.register_controller("ctrl-b");
  CPE_REQUIRE_EQ(fixture.authority().status().durable_generation().value(), 3u);
  CPE_REQUIRE(std::filesystem::exists(fixture.file(std::string(StoreLayout::previous_snapshot_file))));
  fixture.close();
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

}  // namespace

// ---------------------------------------------------------------------------
// Damage kinds
// ---------------------------------------------------------------------------

CPE_TEST(corruption, every_damage_kind_is_refused_with_its_exact_integrity_code) {
  enum class Damage { TruncateBelowHeader, TruncatePayload, FlipPayloadByte, WrongMagic, BadFormatVersion, BadSchemaVersion, AppendedBytes };

  struct Case {
    Damage damage;
    ErrorCode expected;
    const char* what;
  };
  const std::vector<Case> cases{
      {Damage::TruncateBelowHeader, ErrorCode::Truncated, "a file shorter than its header"},
      {Damage::TruncatePayload, ErrorCode::SizeMismatch, "a payload cut short"},
      {Damage::FlipPayloadByte, ErrorCode::DigestMismatch, "a flipped payload byte"},
      {Damage::WrongMagic, ErrorCode::MagicMismatch, "a wrong magic"},
      {Damage::BadFormatVersion, ErrorCode::FormatVersionUnsupported, "an unsupported format version"},
      {Damage::BadSchemaVersion, ErrorCode::SchemaUnsupported, "an unsupported schema version"},
      {Damage::AppendedBytes, ErrorCode::SizeMismatch, "bytes appended after the payload"},
  };

  for (const Case& item : cases) {
    TestAuthority fixture;
    (void)fixture.register_controller("ctrl-a");
    fixture.close();

    const std::filesystem::path live = fixture.file(std::string(StoreLayout::snapshot_file));
    std::vector<std::byte> bytes = read_bytes(live);
    switch (item.damage) {
      case Damage::TruncateBelowHeader:
        bytes.resize(detail::envelope_header_bytes - 8);
        break;
      case Damage::TruncatePayload:
        bytes.resize(bytes.size() - 8);
        break;
      case Damage::FlipPayloadByte:
        bytes.back() ^= std::byte{0x5A};
        break;
      case Damage::WrongMagic:
        bytes[0] = std::byte{'X'};
        break;
      case Damage::BadFormatVersion: {
        const std::array<std::byte, 2> version = little_u16(99);
        patch(bytes, 4, version);
        break;
      }
      case Damage::BadSchemaVersion: {
        // The durable schema version lives inside the payload, so the payload
        // digest must be repaired for the schema check to be what refuses.
        const std::array<std::byte, 4> schema = little_u32(99);
        patch_payload(bytes, 0, schema);
        break;
      }
      case Damage::AppendedBytes:
        bytes.insert(bytes.end(), 4, std::byte{0x00});
        break;
    }
    overwrite_bytes(live, bytes);

    require_refusal(fixture.store(), item.expected, RecoveryPolicy::RefuseOnDamage);
    CPE_REQUIRE_MSG(error_category(item.expected) == ErrorCategory::Integrity,
                    std::string("the expected code for ") + item.what + " is not an integrity code");
  }
}

CPE_TEST(corruption, no_payload_byte_can_be_corrupted_without_being_detected) {
  // Property: the durable envelope digest covers every payload byte, so no
  // single-bit corruption of the authoritative payload can be tolerated. The
  // loop is exhaustive over the payload rather than sampled, which is what makes
  // it a proof of coverage instead of a spot check.
  //
  // The same holds for every envelope header byte except one range, reported
  // rather than encoded here: the envelope's own schema_version field (file
  // offsets 6 and 7) is neither validated on read nor covered by the payload
  // digest, so a flipped bit there is silently tolerated. It is low impact --
  // the authoritative schema version lives inside the digested payload and is
  // validated there -- but it is the one byte range of a durable file that is
  // neither validated nor authenticated.
  TestAuthority fixture;
  (void)fixture.register_controller("ctrl-a");
  fixture.close();

  const std::filesystem::path live = fixture.file(std::string(StoreLayout::snapshot_file));
  const std::vector<std::byte> good = read_bytes(live);
  const std::size_t payload_offset = detail::envelope_header_bytes;
  CPE_REQUIRE(good.size() > payload_offset);

  const std::uint64_t seed = 0xC0FFEE01ull;
  DeterministicRandom random(seed);
  const std::size_t sample_count = good.size() - payload_offset;

  std::size_t checked = 0;
  for (std::size_t offset = payload_offset; offset < good.size(); ++offset) {
    std::vector<std::byte> damaged = good;
    damaged[offset] ^= static_cast<std::byte>(1u << random.next_below(8));
    overwrite_bytes(live, damaged);
    require_refusal(fixture.store(), ErrorCode::DigestMismatch, RecoveryPolicy::RefuseOnDamage);
    ++checked;
  }
  overwrite_bytes(live, good);
  CPE_REQUIRE_EQ(checked, sample_count);

  // A deterministic sample of offsets additionally proves the refusal repaired
  // nothing: the byte that was flipped is still the byte on disk afterwards.
  const std::map<std::string, Sha256Digest> before = digest_directory(fixture.store());
  for (int iteration = 0; iteration < 32; ++iteration) {
    const std::size_t offset =
        payload_offset + static_cast<std::size_t>(random.next_below(sample_count));
    std::vector<std::byte> damaged = good;
    damaged[offset] ^= std::byte{0x80};
    overwrite_bytes(live, damaged);
    const Explanation failure = open_failure(fixture.store(), RecoveryPolicy::RefuseOnDamage);
    CPE_REQUIRE_MSG(failure.code() == ErrorCode::DigestMismatch,
                    "seed=" + std::to_string(random.seed()) + " offset=" + std::to_string(offset));
    CPE_REQUIRE_MSG(read_bytes(live) == damaged,
                    "seed=" + std::to_string(random.seed()) + " offset=" + std::to_string(offset));
  }
  overwrite_bytes(live, good);
  CPE_REQUIRE(digest_directory(fixture.store()) == before);

  // The negative control: the undamaged generation still opens, so the loop
  // above refused damage and not merely everything.
  fixture.reopen();
  CPE_REQUIRE(fixture.authority().initialized());
  CPE_REQUIRE_EQ(fixture.authority().status().durable_generation().value(), 2u);
}

CPE_TEST(corruption, a_damaged_previous_generation_alone_does_not_hide_the_live_one) {
  TestAuthority fixture;
  build_three_generation_store(fixture);

  // Only the fallback copy is damaged. The live generation is intact, so the
  // store must still open on it -- and recovery must not have touched anything.
  const std::filesystem::path previous = fixture.file(std::string(StoreLayout::previous_snapshot_file));
  std::vector<std::byte> bytes = read_bytes(previous);
  bytes[0] = std::byte{'X'};
  overwrite_bytes(previous, bytes);

  const std::map<std::string, Sha256Digest> before = digest_directory(fixture.store());
  fixture.reopen();
  CPE_REQUIRE(fixture.authority().initialized());
  CPE_REQUIRE(fixture.authority().recovery().outcome() == RecoveryOutcome::OpenedClean);
  CPE_REQUIRE_EQ(fixture.authority().status().durable_generation().value(), 3u);
  CPE_REQUIRE(!fixture.authority().accounting().retained_previous_generation());
  CPE_REQUIRE(digest_directory(fixture.store()) == before);
}

// ---------------------------------------------------------------------------
// Floor discipline
// ---------------------------------------------------------------------------

CPE_TEST(corruption, a_generation_below_the_durable_floor_is_refused) {
  TestAuthority fixture;
  build_three_generation_store(fixture);

  // Rewriting the live file with the retained previous generation produces a
  // perfectly valid image that is one generation behind the floor: rollback
  // must be impossible even for valid data.
  const std::vector<std::byte> previous_bytes =
      read_bytes(fixture.file(std::string(StoreLayout::previous_snapshot_file)));
  const std::filesystem::path live = fixture.file(std::string(StoreLayout::snapshot_file));
  const std::vector<std::byte> live_bytes = read_bytes(live);
  overwrite_bytes(live, previous_bytes);
  CPE_REQUIRE_EQ(generation_envelope(live).generation, 2u);

  require_refusal(fixture.store(), ErrorCode::GenerationBelowFloor, RecoveryPolicy::RefuseOnDamage);
  require_refusal(fixture.store(), ErrorCode::GenerationBelowFloor, RecoveryPolicy::AdoptPreviousGeneration);

  // The rollback attempt is still on disk: nothing was repaired implicitly.
  CPE_REQUIRE(read_bytes(live) == previous_bytes);
  CPE_REQUIRE(!std::filesystem::exists(fixture.store() / std::string(StoreLayout::quarantine_directory)));

  // Restoring the live generation restores the store, which shows the refusal
  // was about the floor and not about the bytes.
  overwrite_bytes(live, live_bytes);
  fixture.reopen();
  CPE_REQUIRE_EQ(fixture.authority().status().durable_generation().value(), 3u);
  CPE_REQUIRE(fixture.authority().recovery().outcome() == RecoveryOutcome::OpenedClean);
}

CPE_TEST(corruption, a_missing_or_unreadable_floor_is_refused) {
  // A readable generation with no floor cannot exclude rollback, so it must be
  // refused rather than assumed safe.
  {
    TestAuthority fixture;
    (void)fixture.register_controller("ctrl-a");
    fixture.close();
    std::error_code error;
    CPE_REQUIRE(std::filesystem::remove(fixture.file(std::string(StoreLayout::floor_file)), error));
    CPE_REQUIRE(!error);
    require_refusal(fixture.store(), ErrorCode::FloorMissing, RecoveryPolicy::RefuseOnDamage);
    require_refusal(fixture.store(), ErrorCode::FloorMissing, RecoveryPolicy::AdoptPreviousGeneration);
  }

  // An unreadable floor is exactly as absent as a missing one.
  {
    TestAuthority fixture;
    (void)fixture.register_controller("ctrl-a");
    fixture.close();
    const std::filesystem::path floor_file = fixture.file(std::string(StoreLayout::floor_file));
    std::vector<std::byte> bytes = read_bytes(floor_file);
    bytes.resize(bytes.size() / 2);
    overwrite_bytes(floor_file, bytes);
    require_refusal(fixture.store(), ErrorCode::FloorMissing, RecoveryPolicy::RefuseOnDamage);
  }
}

// ---------------------------------------------------------------------------
// Adopting the retained previous generation
// ---------------------------------------------------------------------------

CPE_TEST(corruption, adopting_the_previous_generation_is_bounded_by_the_floor) {
  TestAuthority fixture;
  build_three_generation_store(fixture);

  const std::filesystem::path live = fixture.file(std::string(StoreLayout::snapshot_file));
  const std::filesystem::path previous = fixture.file(std::string(StoreLayout::previous_snapshot_file));
  std::vector<std::byte> damaged = read_bytes(live);
  damaged.back() ^= std::byte{0x5A};
  overwrite_bytes(live, damaged);

  // The live generation is damaged and the fallback sits one generation below
  // the floor that the failed commit already published: adopting it would roll
  // the epoch back, so even the repair policy must refuse.
  CPE_REQUIRE_EQ(floor_of(fixture.file(std::string(StoreLayout::floor_file))).generation, 3u);
  CPE_REQUIRE_EQ(generation_envelope(previous).generation, 2u);
  require_refusal(fixture.store(), ErrorCode::DigestMismatch, RecoveryPolicy::RefuseOnDamage);
  require_refusal(fixture.store(), ErrorCode::GenerationBelowFloor, RecoveryPolicy::AdoptPreviousGeneration);
  CPE_REQUIRE(!std::filesystem::exists(fixture.store() / std::string(StoreLayout::quarantine_directory)));
}

CPE_TEST(corruption, adopting_the_previous_generation_repairs_within_the_floor) {
  TestAuthority fixture;
  (void)fixture.register_controller("ctrl-a");

  // Interrupt the third commit after it published the new generation but before
  // it published the floor. This is the one durable state in which the retained
  // fallback is at the floor: exactly the state an operator-driven repair is
  // allowed to adopt.
  detail::arm_durable_fault(detail::DurableFaultPoint::AfterPublish);
  RegisterControllerRequest third;
  third.controller = controller_id("ctrl-b");
  third.provenance = provenance_input("ctrl-b");
  CPE_REQUIRE_THROWS_CODE(fixture.authority().register_controller(third), ErrorCode::CommitFailed);
  detail::clear_durable_fault();
  fixture.close();

  const std::filesystem::path live = fixture.file(std::string(StoreLayout::snapshot_file));
  const std::filesystem::path previous = fixture.file(std::string(StoreLayout::previous_snapshot_file));
  const std::filesystem::path floor_file = fixture.file(std::string(StoreLayout::floor_file));
  CPE_REQUIRE_EQ(generation_envelope(live).generation, 3u);
  CPE_REQUIRE_EQ(floor_of(floor_file).generation, 2u);
  const std::vector<std::byte> fallback_bytes = read_bytes(previous);
  CPE_REQUIRE_EQ(generation_envelope(previous).generation, 2u);

  std::vector<std::byte> damaged = read_bytes(live);
  damaged.back() ^= std::byte{0x5A};
  overwrite_bytes(live, damaged);
  const Sha256Digest damaged_digest = sha256(std::span<const std::byte>(damaged));

  // Conservative opening refuses.
  require_refusal(fixture.store(), ErrorCode::DigestMismatch, RecoveryPolicy::RefuseOnDamage);

  // Explicit repair adopts.
  fixture.reopen(StoreOpenMode::ReadWrite, RecoveryPolicy::AdoptPreviousGeneration);
  const RecoveryReport report = fixture.authority().recovery();
  CPE_REQUIRE(report.outcome() == RecoveryOutcome::AdoptedPreviousGeneration);
  CPE_REQUIRE_EQ(report.quarantined_files().size(), 1u);
  CPE_REQUIRE_EQ(report.damaged_files().size(), 1u);
  CPE_REQUIRE_EQ(report.damaged_files().front(), std::string(StoreLayout::snapshot_file));

  // The damaged file was moved aside, addressed by its content.
  CPE_REQUIRE_EQ(report.quarantined_files().front().rfind(
                     std::string(StoreLayout::quarantine_directory) + "/" + std::string(StoreLayout::snapshot_file),
                     0),
                 0u);
  const std::filesystem::path quarantined =
      fixture.store() / std::filesystem::path(report.quarantined_files().front());
  CPE_REQUIRE(std::filesystem::exists(quarantined));
  CPE_REQUIRE_EQ(sha256(std::span<const std::byte>(read_bytes(quarantined))), damaged_digest);
  CPE_REQUIRE(std::filesystem::exists(live));

  // The fallback was republished as the live generation, and the floor now
  // describes it: the store satisfies its own floor after the repair.
  CPE_REQUIRE(read_bytes(live) == fallback_bytes);
  CPE_REQUIRE_EQ(floor_of(floor_file).generation, 2u);
  CPE_REQUIRE_EQ(floor_of(floor_file).snapshot_digest, generation_envelope(live).payload_digest);
  CPE_REQUIRE_EQ(fixture.authority().status().durable_generation().value(), 2u);
  CPE_REQUIRE_EQ(fixture.authority().last_commit(), std::nullopt);

  const StoreInspection inspection = inspect_store(fixture.store());
  CPE_REQUIRE(inspection.verified());
  CPE_REQUIRE(inspection.problems().empty());
  CPE_REQUIRE_EQ(inspection.durable_generation()->value(), 2u);
  CPE_REQUIRE_EQ(inspection.floor_generation()->value(), 2u);

  // The repaired store keeps working: the adopted generation is authoritative.
  fixture.reopen();
  CPE_REQUIRE(fixture.authority().recovery().outcome() == RecoveryOutcome::OpenedClean);
  CPE_REQUIRE_EQ(fixture.authority().status().durable_generation().value(), 2u);
  CPE_REQUIRE(fixture.authority().controller_record(controller_id("ctrl-a")).has_value());
  CPE_REQUIRE(!fixture.authority().controller_record(controller_id("ctrl-b")).has_value());
}

// ---------------------------------------------------------------------------
// Reinitializing a damaged store
// ---------------------------------------------------------------------------

CPE_TEST(corruption, reinitialization_quarantines_everything_and_restarts_above_the_recoverable_epoch) {
  TempDirectory directory;
  const StoreOpenOptions options = options_for(directory.path());
  {
    ControlPlaneEpochAuthority authority(options);
    initialize_facility(authority);
    RegisterControllerRequest registration;
    registration.controller = controller_id("ctrl-a");
    registration.provenance = provenance_input("ctrl-a");
    CPE_REQUIRE(authority.register_controller(std::move(registration)).has_value());

    AcquireAuthorityRequest bootstrap;
    bootstrap.controller = controller_id("authority-root");
    bootstrap.incarnation = authority.controller_record(controller_id("authority-root")).value().incarnation_id();
    bootstrap.scopes = scope_set({"authority.grant", "authority.revoke", "epoch.advance"});
    bootstrap.provenance = provenance_input("authority-root");
    auto root = authority.acquire_authority(std::move(bootstrap));
    CPE_REQUIRE(root.has_value());
    AdvanceEpochRequest advance;
    advance.expected_current = Epoch::initial();
    advance.authority = *root.value().mutation_authority();
    advance.provenance = provenance_input("operator");
    CPE_REQUIRE(authority.advance_epoch(std::move(advance)).has_value());
    CPE_REQUIRE_EQ(authority.status().epoch().value(), 2u);
    CPE_REQUIRE_EQ(authority.status().durable_generation().value(), 4u);
  }

  const std::filesystem::path live = directory.file(std::string(StoreLayout::snapshot_file));
  const std::filesystem::path floor_file = directory.file(std::string(StoreLayout::floor_file));
  CPE_REQUIRE_EQ(floor_of(floor_file).epoch, 2u);
  std::vector<std::byte> damaged = read_bytes(live);
  damaged.back() ^= std::byte{0x5A};
  overwrite_bytes(live, damaged);

  // Conservative opening refuses, so reinitialization is an operator decision
  // and never a fallback.
  require_refusal(directory.path(), ErrorCode::DigestMismatch, RecoveryPolicy::RefuseOnDamage);

  ControlPlaneEpochAuthority repaired(options_for(directory.path(), RecoveryPolicy::ReinitializeDomain));
  const RecoveryReport report = repaired.recovery();
  CPE_REQUIRE(report.outcome() == RecoveryOutcome::ReinitializedDamagedStore);
  CPE_REQUIRE(!repaired.initialized());
  CPE_REQUIRE_EQ(report.quarantined_files().size(), 3u);
  for (const std::string& name : report.quarantined_files()) {
    CPE_REQUIRE(name.rfind(std::string(StoreLayout::quarantine_directory) + "/", 0) == 0);
    CPE_REQUIRE(std::filesystem::exists(directory.path() / std::filesystem::path(name)));
  }
  CPE_REQUIRE(!std::filesystem::exists(live));
  CPE_REQUIRE(!std::filesystem::exists(directory.file(std::string(StoreLayout::previous_snapshot_file))));

  // The repair is only complete once the recoverable epoch is durable. The
  // floor that was quarantined is replaced by one that records the highest
  // recoverable epoch and generation, so a later open can never start lower.
  CPE_REQUIRE(std::filesystem::exists(floor_file));
  const detail::FloorData repair_floor = floor_of(floor_file);
  CPE_REQUIRE_EQ(repair_floor.epoch, 2u);
  CPE_REQUIRE_EQ(repair_floor.generation, 4u);
  CPE_REQUIRE_EQ(repair_floor.domain_instance, 1u);

  initialize_facility(repaired);
  // A fresh durable instance strictly above every recoverable value: the
  // damaged instance reached epoch 2 and generation 4, so the new one starts at
  // epoch 3, instance 2, generation 5 and can never re-issue authority that the
  // old instance already issued.
  CPE_REQUIRE_EQ(repaired.status().epoch().value(), repair_floor.epoch + 1);
  CPE_REQUIRE_EQ(repaired.status().domain_instance().value(), repair_floor.domain_instance + 1);
  CPE_REQUIRE(repaired.status().durable_generation().value() > repair_floor.generation);
  CPE_REQUIRE_EQ(repaired.status().epoch().value(), 3u);
  CPE_REQUIRE_EQ(repaired.status().domain_instance().value(), 2u);
  CPE_REQUIRE_EQ(repaired.status().durable_generation().value(), 5u);

  // The reinitialized instance publishes a well-formed generation whose floor
  // describes it, so the durable artifacts themselves are consistent.
  const detail::FileEnvelope live_envelope = generation_envelope(live);
  CPE_REQUIRE_EQ(live_envelope.epoch, 3u);
  CPE_REQUIRE_EQ(live_envelope.generation, 5u);
  const detail::FloorData reinitialized_floor = floor_of(floor_file);
  CPE_REQUIRE_EQ(reinitialized_floor.epoch, 3u);
  CPE_REQUIRE_EQ(reinitialized_floor.generation, 5u);
  CPE_REQUIRE_EQ(reinitialized_floor.snapshot_digest, live_envelope.payload_digest);
  CPE_REQUIRE_EQ(repaired.status().snapshot_digest(), live_envelope.payload_digest);

  // A reinitialized store is durable: the reader accepts the generation that
  // the reinitialized writer published, so the repair survives a restart.
  repaired.close();
  ControlPlaneEpochAuthority reopened(options);
  CPE_REQUIRE(reopened.initialized());
  CPE_REQUIRE(reopened.recovery().outcome() == RecoveryOutcome::OpenedClean);
  CPE_REQUIRE_EQ(reopened.status().epoch().value(), 3u);
  CPE_REQUIRE_EQ(reopened.status().durable_generation().value(), 5u);
  const StoreInspection inspection = inspect_store(directory.path());
  CPE_REQUIRE(inspection.verified());
  CPE_REQUIRE(inspection.problems().empty());
  CPE_REQUIRE_EQ(inspection.epoch()->value(), 3u);
  CPE_REQUIRE_EQ(inspection.floor_epoch()->value(), 3u);
  CPE_REQUIRE_EQ(inspection.floor_generation()->value(), 5u);
}

CPE_TEST(corruption, reinitialization_requires_an_assertion_when_nothing_is_readable) {
  TempDirectory directory;
  const StoreOpenOptions options = options_for(directory.path());
  {
    ControlPlaneEpochAuthority authority(options);
    initialize_facility(authority);
    RegisterControllerRequest registration;
    registration.controller = controller_id("ctrl-a");
    registration.provenance = provenance_input("ctrl-a");
    CPE_REQUIRE(authority.register_controller(std::move(registration)).has_value());
  }

  // Nothing readable remains: the live file is damaged and the floor and the
  // fallback are gone. The library cannot know which epoch was issued, so it
  // must demand an explicit operator assertion rather than guess.
  std::error_code error;
  CPE_REQUIRE(std::filesystem::remove(directory.file(std::string(StoreLayout::floor_file)), error));
  CPE_REQUIRE(std::filesystem::remove(directory.file(std::string(StoreLayout::previous_snapshot_file)), error));
  std::vector<std::byte> damaged = read_bytes(directory.file(std::string(StoreLayout::snapshot_file)));
  damaged[0] = std::byte{'X'};
  overwrite_bytes(directory.file(std::string(StoreLayout::snapshot_file)), damaged);

  require_refusal(directory.path(), ErrorCode::MagicMismatch, RecoveryPolicy::RefuseOnDamage);
  require_refusal(directory.path(), ErrorCode::AssertedEpochFloorRequired, RecoveryPolicy::ReinitializeDomain);

  // With an assertion the repair proceeds, and the fresh instance starts above
  // the asserted floor rather than at it.
  ControlPlaneEpochAuthority repaired(
      options_for(directory.path(), RecoveryPolicy::ReinitializeDomain, 7));
  CPE_REQUIRE(repaired.recovery().outcome() == RecoveryOutcome::ReinitializedDamagedStore);
  initialize_facility(repaired);
  CPE_REQUIRE_EQ(repaired.status().epoch().value(), 8u);
}

CPE_TEST(corruption, reinitialization_rejects_an_assertion_below_a_readable_floor) {
  TempDirectory directory;
  const StoreOpenOptions options = options_for(directory.path());
  {
    ControlPlaneEpochAuthority authority(options);
    initialize_facility(authority);
    RegisterControllerRequest registration;
    registration.controller = controller_id("ctrl-a");
    registration.provenance = provenance_input("ctrl-a");
    CPE_REQUIRE(authority.register_controller(std::move(registration)).has_value());

    AcquireAuthorityRequest bootstrap;
    bootstrap.controller = controller_id("authority-root");
    bootstrap.incarnation = authority.controller_record(controller_id("authority-root")).value().incarnation_id();
    bootstrap.scopes = scope_set({"authority.grant", "authority.revoke", "epoch.advance"});
    bootstrap.provenance = provenance_input("authority-root");
    auto root = authority.acquire_authority(std::move(bootstrap));
    CPE_REQUIRE(root.has_value());
    AdvanceEpochRequest advance;
    advance.expected_current = Epoch::initial();
    advance.authority = *root.value().mutation_authority();
    advance.provenance = provenance_input("operator");
    CPE_REQUIRE(authority.advance_epoch(std::move(advance)).has_value());
  }

  // The floor is still readable at epoch 2, so asserting anything lower is
  // rejected outright and never clamped: a clamp would silently roll the epoch
  // back to whatever the operator mistyped.
  const std::filesystem::path live = directory.file(std::string(StoreLayout::snapshot_file));
  std::vector<std::byte> damaged = read_bytes(live);
  damaged.back() ^= std::byte{0x5A};
  overwrite_bytes(live, damaged);

  require_refusal(directory.path(), ErrorCode::AssertedEpochFloorTooLow, RecoveryPolicy::ReinitializeDomain, 1);
  require_refusal(directory.path(), ErrorCode::AssertedEpochFloorTooLow, RecoveryPolicy::ReinitializeDomain, 0);

  // Asserting the readable floor itself is accepted and is not clamped upward.
  ControlPlaneEpochAuthority repaired(options_for(directory.path(), RecoveryPolicy::ReinitializeDomain, 2));
  CPE_REQUIRE(repaired.recovery().outcome() == RecoveryOutcome::ReinitializedDamagedStore);
  initialize_facility(repaired);
  CPE_REQUIRE_EQ(repaired.status().epoch().value(), 3u);
}

CPE_TEST(corruption, an_empty_or_uninitialized_directory_is_not_damage) {
  // The negative control for this suite: absence of durable state is not
  // corruption. A fresh directory opens, is simply not initialized, and offers
  // epoch 1 of instance 1 rather than a recovered epoch.
  TempDirectory directory;
  ControlPlaneEpochAuthority authority(options_for(directory.path()));
  CPE_REQUIRE(!authority.initialized());
  CPE_REQUIRE(authority.recovery().outcome() == RecoveryOutcome::OpenedClean);
  CPE_REQUIRE(!authority.recovery().has_domain());
  CPE_REQUIRE(authority.recovery().damaged_files().empty());
  CPE_REQUIRE_THROWS_CODE(authority.status(), ErrorCode::StoreNotInitialized);

  initialize_facility(authority);
  CPE_REQUIRE_EQ(authority.status().epoch().value(), 1u);
  CPE_REQUIRE_EQ(authority.status().domain_instance().value(), 1u);

  // A valid floor with no generation is the state a reinitialized store is in
  // before it is initialized again. That is a legitimate, floor-bounded state,
  // not damage: the floor still decides where the fresh instance may start.
  TempDirectory floored;
  {
    ControlPlaneEpochAuthority seeded(options_for(floored.path()));
    initialize_facility(seeded);
    RegisterControllerRequest registration;
    registration.controller = controller_id("ctrl-a");
    registration.provenance = provenance_input("ctrl-a");
    CPE_REQUIRE(seeded.register_controller(std::move(registration)).has_value());
  }
  std::error_code error;
  CPE_REQUIRE(std::filesystem::exists(floored.file(std::string(StoreLayout::floor_file))));
  CPE_REQUIRE(std::filesystem::remove(floored.file(std::string(StoreLayout::snapshot_file)), error));
  CPE_REQUIRE(std::filesystem::remove(floored.file(std::string(StoreLayout::previous_snapshot_file)), error));

  const detail::FloorData surviving_floor = floor_of(floored.file(std::string(StoreLayout::floor_file)));
  CPE_REQUIRE_EQ(surviving_floor.epoch, 1u);
  CPE_REQUIRE_EQ(surviving_floor.generation, 2u);

  ControlPlaneEpochAuthority floored_authority(options_for(floored.path()));
  CPE_REQUIRE(!floored_authority.initialized());
  CPE_REQUIRE(floored_authority.recovery().outcome() == RecoveryOutcome::OpenedClean);
  CPE_REQUIRE(floored_authority.recovery().damaged_files().empty());

  initialize_facility(floored_authority);
  CPE_REQUIRE_EQ(floored_authority.status().epoch().value(), surviving_floor.epoch + 1);
  CPE_REQUIRE_EQ(floored_authority.status().domain_instance().value(), surviving_floor.domain_instance + 1);
  CPE_REQUIRE(floored_authority.status().durable_generation().value() > surviving_floor.generation);
  CPE_REQUIRE_EQ(floored_authority.status().epoch().value(), 2u);
  CPE_REQUIRE_EQ(floored_authority.status().domain_instance().value(), 2u);

  // A floor that exists but cannot be read is damage, and it is still refused
  // when no generation is present either: the epoch bound was lost.
  TempDirectory broken;
  {
    ControlPlaneEpochAuthority seeded(options_for(broken.path()));
    initialize_facility(seeded);
    RegisterControllerRequest registration;
    registration.controller = controller_id("ctrl-a");
    registration.provenance = provenance_input("ctrl-a");
    CPE_REQUIRE(seeded.register_controller(std::move(registration)).has_value());
  }
  CPE_REQUIRE(std::filesystem::remove(broken.file(std::string(StoreLayout::snapshot_file)), error));
  CPE_REQUIRE(std::filesystem::remove(broken.file(std::string(StoreLayout::previous_snapshot_file)), error));
  const std::filesystem::path broken_floor = broken.file(std::string(StoreLayout::floor_file));
  std::vector<std::byte> floor_bytes = read_bytes(broken_floor);
  floor_bytes[0] = std::byte{'X'};
  overwrite_bytes(broken_floor, floor_bytes);
  require_refusal(broken.path(), ErrorCode::MagicMismatch, RecoveryPolicy::RefuseOnDamage);
}
