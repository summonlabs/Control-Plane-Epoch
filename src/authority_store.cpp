// Control Plane Epoch 1.0.0 - Summon Software Labs
// Durable authority store: conservative recovery and transactional publication.
//
// Publication protocol for one commit:
//   write exclusive temporary -> flush to device -> verify by reading back ->
//   retain the superseded generation as the fallback -> atomic replace of the
//   live generation -> publish the floor -> flush the directory.
// A commit is reported successful only after the new generation *and* the floor
// are durable. The in-memory authoritative state is updated last, so a failed
// or interrupted commit leaves the previous generation authoritative.
#include "authority_store.hpp"

#include <algorithm>
#include <array>
#include <utility>

#include "durable.hpp"
#include "fault.hpp"

namespace dccp::epoch {

/// Builder for the immutable store reports. RecoveryReport and StoreInspection
/// declare it as a friend, so producing a report never requires exposing a raw
/// persistence structure to consumers.
struct StoreReportFactory {
  static RecoveryReport make_recovery(RecoveryOutcome outcome, std::string detail) {
    RecoveryReport report;
    report.outcome_ = outcome;
    report.detail_ = std::move(detail);
    return report;
  }
};

}  // namespace dccp::epoch

namespace dccp::epoch::detail {
namespace {

constexpr std::size_t kMaxStoreFileBytes = max_snapshot_bytes + envelope_header_bytes;
constexpr std::size_t kMaxFloorFileBytes = max_floor_bytes + envelope_header_bytes;

/// One durable file that was read and decoded, with damage captured rather than
/// thrown so that the recovery policy can decide what to do about it.
struct LoadedFile {
  bool present = false;
  bool valid = false;
  std::vector<std::byte> bytes;
  FileEnvelope envelope;
  ErrorCode damage_code = ErrorCode::Ok;
  std::string damage_detail;
};

/// One durable generation: a loaded file plus its decoded image.
struct LoadedGeneration {
  bool present = false;
  bool valid = false;
  std::vector<std::byte> bytes;
  FileEnvelope envelope;
  AuthorityImage image;
  ErrorCode damage_code = ErrorCode::Ok;
  std::string damage_detail;
};

[[nodiscard]] LoadedFile load_envelope_file(const std::filesystem::path& path, std::size_t max_bytes) {
  LoadedFile loaded;
  std::optional<std::vector<std::byte>> bytes;
  try {
    bytes = read_file_optional(path, max_bytes);
  } catch (const EpochError& error) {
    loaded.present = path_exists(path);
    loaded.damage_code = error.code();
    loaded.damage_detail = error.explanation().detail();
    return loaded;
  }
  if (!bytes.has_value()) {
    return loaded;
  }
  loaded.present = true;
  loaded.bytes = std::move(*bytes);
  try {
    loaded.envelope = decode_envelope(loaded.bytes, max_bytes);
    loaded.valid = true;
  } catch (const EpochError& error) {
    loaded.damage_code = error.code();
    loaded.damage_detail = error.explanation().detail();
  }
  return loaded;
}

/// Loads and fully verifies one durable generation: envelope header, encoded
/// payload, record digests, and ledger chains must all agree.
[[nodiscard]] LoadedGeneration load_generation(const std::filesystem::path& path, const ImageLimits& limits) {
  LoadedGeneration loaded;
  std::optional<std::vector<std::byte>> bytes;
  try {
    bytes = read_file_optional(path, kMaxStoreFileBytes);
  } catch (const EpochError& error) {
    loaded.present = path_exists(path);
    loaded.damage_code = error.code();
    loaded.damage_detail = error.explanation().detail();
    return loaded;
  }
  if (!bytes.has_value()) {
    return loaded;
  }
  loaded.present = true;
  loaded.bytes = std::move(*bytes);

  try {
    loaded.envelope = decode_envelope(loaded.bytes, kMaxStoreFileBytes);
    loaded.image = decode_image(loaded.envelope.payload, limits);
    if (loaded.image.durable_generation != loaded.envelope.generation) {
      throw EpochError(ErrorCode::CountMismatch,
                       "the file header generation " + std::to_string(loaded.envelope.generation) +
                           " does not match the encoded generation " +
                           std::to_string(loaded.image.durable_generation));
    }
    if (loaded.image.epoch != loaded.envelope.epoch) {
      throw EpochError(ErrorCode::CountMismatch, "the file header epoch " + std::to_string(loaded.envelope.epoch) +
                                                     " does not match the encoded epoch " +
                                                     std::to_string(loaded.image.epoch));
    }
    loaded.valid = true;
  } catch (const EpochError& error) {
    loaded.valid = false;
    loaded.damage_code = error.code();
    loaded.damage_detail = error.explanation().detail();
  }
  return loaded;
}

[[nodiscard]] std::string file_label(const StorePaths& paths, const std::filesystem::path& path) {
  std::error_code error;
  const std::filesystem::path relative = std::filesystem::relative(path, paths.directory, error);
  if (error || relative.empty()) {
    return path.filename().string();
  }
  return relative.generic_string();
}

[[nodiscard]] bool satisfies_floor(const AuthorityImage& image, const FloorData& floor) {
  return image.durable_generation >= floor.generation && image.epoch >= floor.epoch;
}

[[nodiscard]] std::string floor_violation_detail(const AuthorityImage& image, const FloorData& floor) {
  return "generation " + std::to_string(image.durable_generation) + " epoch " + std::to_string(image.epoch) +
         " is below the durable floor generation " + std::to_string(floor.generation) + " epoch " +
         std::to_string(floor.epoch);
}

/// Moves one damaged file into the quarantine directory under a content
/// addressed name, then removes the original. The name depends only on the
/// store-relative name and the file bytes, never on a clock.
[[nodiscard]] std::string quarantine_file(const StorePaths& paths, const std::filesystem::path& path) {
  const std::vector<std::byte> bytes = read_file_bounded(path, kMaxStoreFileBytes);
  const Sha256Digest digest = sha256(std::span<const std::byte>(bytes));
  const std::string name = sanitize_file_name_component(file_label(paths, path)) + "." +
                           digest.to_hex().substr(0, 16) + ".quarantined";
  const std::filesystem::path target = paths.quarantine / name;

  ensure_directories(paths.quarantine);
  const std::filesystem::path temporary = paths.quarantine / next_temp_name(name);
  write_file_exclusive(temporary, std::span<const std::byte>(bytes));
  try {
    atomic_replace(temporary, target);
  } catch (const EpochError& error) {
    remove_file_if_exists(temporary);
    throw EpochError(ErrorCode::QuarantineFailed,
                     "could not move damaged state to " + target.string() + ": " + error.explanation().detail());
  }
  remove_file_if_exists(path);
  return file_label(paths, target);
}

void publish_bytes(const std::filesystem::path& directory, const std::filesystem::path& target,
                   const std::vector<std::byte>& bytes, std::string_view base_name) {
  const std::filesystem::path temporary = directory / next_temp_name(base_name);
  try {
    write_file_exclusive(temporary, std::span<const std::byte>(bytes));
    atomic_replace(temporary, target);
  } catch (...) {
    remove_file_if_exists(temporary);
    throw;
  }
}

void publish_floor(const StorePaths& paths, const FloorData& floor) {
  FileEnvelope envelope;
  envelope.generation = floor.generation;
  envelope.epoch = floor.epoch;
  envelope.payload = encode_floor(floor);
  publish_bytes(paths.directory, paths.floor, encode_envelope(envelope, kMaxFloorFileBytes),
                StoreLayout::floor_file);
}

/// Removes temporary files left behind by an interrupted commit. Only names this
/// repository owns are considered, and only while the writer lock is held, so no
/// other writer's in-flight temporary can be removed.
void retire_stale_temporaries(const StorePaths& paths) {
  const std::array<std::string_view, 3> bases{StoreLayout::snapshot_file, StoreLayout::previous_snapshot_file,
                                              StoreLayout::floor_file};
  std::error_code error;
  std::filesystem::directory_iterator iterator(paths.directory, error);
  if (error) {
    return;
  }
  for (const std::filesystem::directory_entry& entry : iterator) {
    if (!entry.is_regular_file(error) || error) {
      continue;
    }
    const std::string name = entry.path().filename().string();
    for (const std::string_view base : bases) {
      const std::string prefix = std::string(base) + ".tmp.";
      if (name.rfind(prefix, 0) == 0) {
        remove_file_if_exists(entry.path());
        break;
      }
    }
  }
}

}  // namespace

StorePaths StorePaths::for_directory(const std::filesystem::path& directory) {
  StorePaths paths;
  paths.directory = directory;
  paths.lock = directory / std::string(StoreLayout::lock_file);
  paths.snapshot = directory / std::string(StoreLayout::snapshot_file);
  paths.previous = directory / std::string(StoreLayout::previous_snapshot_file);
  paths.floor = directory / std::string(StoreLayout::floor_file);
  paths.quarantine = directory / std::string(StoreLayout::quarantine_directory);
  return paths;
}

std::unique_ptr<AuthorityStore> AuthorityStore::open(const StoreOpenOptions& options) {
  if (options.directory.empty()) {
    throw EpochError(ErrorCode::PathInvalid, "the store directory is empty");
  }
  if (options.max_snapshot_bytes == 0 || options.max_snapshot_bytes > max_snapshot_bytes) {
    throw EpochError(ErrorCode::InvalidOption,
                     "max_snapshot_bytes must be between 1 and " + std::to_string(max_snapshot_bytes));
  }

  auto store = std::unique_ptr<AuthorityStore>(new AuthorityStore());
  store->paths_ = StorePaths::for_directory(options.directory);
  store->mode_ = options.mode;
  store->policy_ = options.recovery_policy;
  store->limits_.max_bytes = options.max_snapshot_bytes;

  if (!path_exists(store->paths_.directory)) {
    if (options.mode == StoreOpenMode::ReadOnly) {
      throw EpochError(ErrorCode::StoreNotFound,
                       "store directory " + store->paths_.directory.string() + " does not exist");
    }
    ensure_directories(store->paths_.directory);
  }
  if (!directory_exists(store->paths_.directory)) {
    throw EpochError(ErrorCode::PathInvalid,
                     "store path " + store->paths_.directory.string() + " is not a directory");
  }
  if (options.mode == StoreOpenMode::ReadWrite) {
    store->lock_ = WriterLock::acquire(store->paths_.lock);
    // The writer lock is held, so any temporary file still present belongs to a
    // commit that was interrupted. Retiring it here is what keeps the store
    // directory clean across real crashes.
    retire_stale_temporaries(store->paths_);
  }

  // Read every durable artifact before deciding anything.
  std::vector<std::string> damaged;
  LoadedFile floor_file = load_envelope_file(store->paths_.floor, kMaxFloorFileBytes);
  std::optional<FloorData> floor;
  std::optional<Sha256Digest> floor_digest;
  if (floor_file.present) {
    floor_digest = sha256(std::span<const std::byte>(floor_file.bytes));
    if (floor_file.valid) {
      try {
        floor = decode_floor(floor_file.envelope.payload);
      } catch (const EpochError& error) {
        floor_file.valid = false;
        floor_file.damage_code = error.code();
        floor_file.damage_detail = error.explanation().detail();
      }
    }
    if (!floor_file.valid) {
      damaged.push_back(file_label(store->paths_, store->paths_.floor));
    }
  }

  LoadedGeneration current = load_generation(store->paths_.snapshot, store->limits_);
  if (current.present && !current.valid) {
    damaged.push_back(file_label(store->paths_, store->paths_.snapshot));
  }
  LoadedGeneration previous = load_generation(store->paths_.previous, store->limits_);
  if (previous.present && !previous.valid) {
    damaged.push_back(file_label(store->paths_, store->paths_.previous));
  }

  const bool current_usable =
      current.present && current.valid && floor.has_value() && satisfies_floor(current.image, *floor);

  RecoveryReport report = StoreReportFactory::make_recovery(
      options.mode == StoreOpenMode::ReadOnly ? RecoveryOutcome::ReadOnlyInspection : RecoveryOutcome::OpenedClean,
      options.mode == StoreOpenMode::ReadOnly ? "verified the current durable generation read-only"
                                             : "opened the current durable generation");
  std::vector<std::string> quarantined;

  if (current_usable) {
    store->image_ = current.image;
    store->snapshot_bytes_cache_ = current.bytes;
    store->snapshot_digest_ = current.envelope.payload_digest;
    store->snapshot_bytes_ = current.bytes.size();
    store->retained_previous_ = previous.present && previous.valid;
    store->initialized_ = true;
  } else if (options.mode == StoreOpenMode::ReadWrite &&
             options.recovery_policy == RecoveryPolicy::ReinitializeDomain) {
    // Operator-driven repair. Everything recoverable is quarantined and a fresh
    // durable instance starts strictly above every readable epoch.
    std::uint64_t observed_epoch = floor.has_value() ? floor->epoch : 0;
    std::uint64_t observed_instance = floor.has_value() ? floor->domain_instance : 0;
    if (current.present && current.valid) {
      observed_epoch = std::max(observed_epoch, current.image.epoch);
      observed_instance = std::max(observed_instance, current.image.domain_instance);
    }
    if (previous.present && previous.valid) {
      observed_epoch = std::max(observed_epoch, previous.image.epoch);
      observed_instance = std::max(observed_instance, previous.image.domain_instance);
    }
    if (options.asserted_epoch_floor.has_value()) {
      if (*options.asserted_epoch_floor < observed_epoch) {
        throw EpochError(ErrorCode::AssertedEpochFloorTooLow,
                         "the asserted epoch floor " + std::to_string(*options.asserted_epoch_floor) +
                             " is below the recoverable epoch " + std::to_string(observed_epoch));
      }
      observed_epoch = *options.asserted_epoch_floor;
    } else if (observed_epoch == 0) {
      throw EpochError(ErrorCode::AssertedEpochFloorRequired,
                       "no durable epoch floor is readable in " + store->paths_.directory.string() +
                           "; reinitializing requires an explicit operator assertion of the highest epoch issued");
    }

    for (const std::filesystem::path& path :
         {store->paths_.snapshot, store->paths_.previous, store->paths_.floor}) {
      if (path_exists(path)) {
        quarantined.push_back(quarantine_file(store->paths_, path));
      }
    }

    FloorData seed;
    seed.domain = "reinitialized";
    seed.domain_instance = observed_instance;
    seed.epoch = observed_epoch;
    seed.generation = floor.has_value() ? floor->generation : 0;
    seed.snapshot_digest = Sha256Digest::zero();

    // The floor is published durably before the repair is reported as done. It is
    // the only thing that stops the epoch from ratcheting backwards if the
    // operator never initializes the fresh instance: a later open reads this
    // floor and must start strictly above it.
    if (seed.generation == 0) {
      seed.generation = 1;
    }
    publish_floor(store->paths_, seed);
    sync_directory(store->paths_.directory);

    store->floor_ = seed;
    store->floor_asserted_ = true;

    report = StoreReportFactory::make_recovery(
        RecoveryOutcome::ReinitializedDamagedStore,
        "damaged state was quarantined; a fresh durable instance starts above the recoverable epoch");
  } else if (options.mode == StoreOpenMode::ReadWrite &&
             options.recovery_policy == RecoveryPolicy::AdoptPreviousGeneration && previous.present &&
             previous.valid) {
    if (!floor.has_value()) {
      throw EpochError(ErrorCode::FloorMissing,
                       "store " + store->paths_.directory.string() +
                           " holds a durable generation but no readable epoch floor: rollback cannot be excluded");
    }
    if (!satisfies_floor(previous.image, *floor)) {
      throw EpochError(ErrorCode::GenerationBelowFloor,
                       "the retained previous generation is below the floor: " +
                           floor_violation_detail(previous.image, *floor));
    }
    // Repair: quarantine the unusable live file, then republish the retained
    // generation as the live one. Until both publishes succeed, nothing about
    // the authoritative state has changed.
    if (current.present) {
      quarantined.push_back(quarantine_file(store->paths_, store->paths_.snapshot));
    }
    publish_bytes(store->paths_.directory, store->paths_.snapshot, previous.bytes, StoreLayout::snapshot_file);

    FloorData repaired = *floor;
    repaired.domain = previous.image.domain;
    repaired.domain_instance = previous.image.domain_instance;
    repaired.epoch = previous.image.epoch;
    repaired.generation = previous.image.durable_generation;
    repaired.snapshot_digest = previous.envelope.payload_digest;
    publish_floor(store->paths_, repaired);
    sync_directory(store->paths_.directory);

    store->image_ = previous.image;
    store->snapshot_bytes_cache_ = previous.bytes;
    store->snapshot_digest_ = previous.envelope.payload_digest;
    store->snapshot_bytes_ = previous.bytes.size();
    store->retained_previous_ = false;
    store->initialized_ = true;
    store->floor_ = repaired;

    report = StoreReportFactory::make_recovery(
        RecoveryOutcome::AdoptedPreviousGeneration,
        "the current generation was unusable; the retained previous generation satisfied the durable floor and was "
        "republished as the live generation");
  } else if (current.present && current.valid) {
    // Undamaged, but the floor is missing, unreadable, or below the generation.
    if (!floor.has_value()) {
      throw EpochError(ErrorCode::FloorMissing,
                       "store " + store->paths_.directory.string() +
                           " holds a durable generation but no readable epoch floor: rollback cannot be excluded");
    }
    throw EpochError(ErrorCode::GenerationBelowFloor,
                     "the durable generation is below the floor: " + floor_violation_detail(current.image, *floor));
  } else if (current.present) {
    throw EpochError(current.damage_code,
                     "damaged durable state in " + store->paths_.directory.string() + ": " + current.damage_detail);
  } else if (previous.present) {
    throw EpochError(previous.damage_code,
                     "damaged durable state in " + store->paths_.directory.string() + ": " + previous.damage_detail);
  } else if (floor_file.present && !floor.has_value()) {
    throw EpochError(floor_file.damage_code,
                     "damaged durable state in " + store->paths_.directory.string() + ": " +
                         floor_file.damage_detail);
  } else if (floor.has_value()) {
    // A valid floor with no generation is the state a reinitialized store is in
    // until it is initialized again. The floor still bounds the epoch, so the
    // fresh instance can only start strictly above it.
    report = StoreReportFactory::make_recovery(
        RecoveryOutcome::OpenedClean,
        "no durable generation is present; the durable floor bounds the epoch this instance may start at");
  } else if (floor_file.present) {
    throw EpochError(ErrorCode::SnapshotMissing,
                     "store " + store->paths_.directory.string() + " holds an epoch floor but no durable generation");
  }

  if (!store->floor_asserted_) {
    store->floor_ = floor;
  }
  report.damaged_files_ = std::move(damaged);
  report.quarantined_files_ = std::move(quarantined);
  report.floor_digest_ = floor_digest;
  if (store->initialized_) {
    report.has_domain_ = true;
    report.domain_ = FacilityAuthorityDomainId::from_trusted(store->image_.domain);
    report.domain_instance_ = DomainInstanceNumber::from_trusted(store->image_.domain_instance);
    report.epoch_ = Epoch::from_trusted(store->image_.epoch);
    report.durable_generation_ = DurableGeneration::from_trusted(store->image_.durable_generation);
    report.snapshot_digest_ = store->snapshot_digest_;
  }
  store->report_ = std::move(report);
  store->open_ = true;
  return store;
}

InitializationSeed AuthorityStore::seed() const {
  if (initialized_) {
    throw EpochError(ErrorCode::StoreAlreadyInitialized, "the store already holds an authority domain");
  }
  InitializationSeed result{Epoch::initial(), DomainInstanceNumber::from_trusted(1)};
  if (floor_.has_value() && floor_->epoch != 0) {
    Result<Epoch> epoch = Epoch::from_value(floor_->epoch + 1);
    if (!epoch.has_value()) {
      throw EpochError(ErrorCode::EpochExhausted, "the recovered epoch floor is at its maximum value");
    }
    result.first_epoch = epoch.value();
    result.domain_instance = DomainInstanceNumber::from_trusted(floor_->domain_instance + 1);
  }
  return result;
}

DurableCommitReport AuthorityStore::commit(AuthorityImage& image) {
  if (mode_ != StoreOpenMode::ReadWrite) {
    throw EpochError(ErrorCode::UnsupportedOperation, "a read-only store cannot commit");
  }
  if (!open_) {
    throw EpochError(ErrorCode::StoreNotFound, "the store is closed");
  }

  const std::uint64_t previous_generation =
      initialized_ ? image_.durable_generation : (floor_.has_value() ? floor_->generation : 0);
  const std::uint64_t next_generation = previous_generation + 1;
  if (next_generation == 0) {
    throw EpochError(ErrorCode::CounterExhausted, "the durable generation counter is exhausted");
  }
  image.schema_version = static_cast<std::uint32_t>(durable_schema_version);
  image.durable_generation = next_generation;

  FileEnvelope envelope;
  envelope.generation = next_generation;
  envelope.epoch = image.epoch;
  envelope.payload = encode_image(image, limits_);
  const std::vector<std::byte> bytes = encode_envelope(envelope, limits_.max_bytes + envelope_header_bytes);

  const std::filesystem::path snapshot_temp =
      paths_.directory / next_temp_name(std::string(StoreLayout::snapshot_file));
  const std::filesystem::path previous_temp =
      paths_.directory / next_temp_name(std::string(StoreLayout::previous_snapshot_file));
  const std::filesystem::path floor_temp = paths_.directory / next_temp_name(std::string(StoreLayout::floor_file));

  bool published = false;
  try {
    // 1. Write and flush the new generation into an exclusively created file.
    write_file_exclusive(snapshot_temp, std::span<const std::byte>(bytes));
    reach_durable_fault_point(DurableFaultPoint::AfterTempWrite);

    // 2. Verify by reading the temporary file back and re-decoding it. A file
    //    that does not verify byte for byte is never published.
    const std::vector<std::byte> verification =
        read_file_bounded(snapshot_temp, limits_.max_bytes + envelope_header_bytes);
    if (verification != bytes) {
      throw EpochError(ErrorCode::CommitFailed, "the temporary generation did not verify byte for byte");
    }
    const FileEnvelope verified_envelope =
        decode_envelope(verification, limits_.max_bytes + envelope_header_bytes);
    if (verified_envelope.generation != next_generation || verified_envelope.epoch != image.epoch) {
      throw EpochError(ErrorCode::CommitFailed,
                       "the temporary generation header does not match the committed values");
    }
    reach_durable_fault_point(DurableFaultPoint::AfterTempVerify);

    // 3. Retain the superseded generation as the fallback copy. The bytes come
    //    from the verified in-memory cache of the live generation rather than
    //    from a second read of the live file, so no interleaving is possible.
    bool retained = false;
    if (initialized_ && !snapshot_bytes_cache_.empty()) {
      write_file_exclusive(previous_temp, std::span<const std::byte>(snapshot_bytes_cache_));
      atomic_replace(previous_temp, paths_.previous);
      retained = true;
    }
    reach_durable_fault_point(DurableFaultPoint::AfterRetainPrevious);

    // 4. Publish atomically: the live file is replaced in one step, so a crash
    //    can never leave the store without a readable generation.
    atomic_replace(snapshot_temp, paths_.snapshot);
    published = true;
    reach_durable_fault_point(DurableFaultPoint::AfterPublish);

    // 5. Publish the floor. This is the step that makes rollback below the
    //    acknowledged generation impossible.
    FloorData floor;
    floor.domain = image.domain;
    floor.domain_instance = image.domain_instance;
    floor.epoch = image.epoch;
    floor.generation = next_generation;
    floor.snapshot_digest = verified_envelope.payload_digest;
    FileEnvelope floor_envelope;
    floor_envelope.generation = next_generation;
    floor_envelope.epoch = image.epoch;
    floor_envelope.payload = encode_floor(floor);
    write_file_exclusive(floor_temp, std::span<const std::byte>(encode_envelope(floor_envelope, kMaxFloorFileBytes)));
    atomic_replace(floor_temp, paths_.floor);
    reach_durable_fault_point(DurableFaultPoint::AfterFloorWrite);
    sync_directory(paths_.directory);

    // 6. Only now is the commit reported successful, and only now does the
    //    in-memory authoritative state move forward.
    snapshot_bytes_cache_ = bytes;
    snapshot_bytes_ = bytes.size();
    snapshot_digest_ = verified_envelope.payload_digest;
    retained_previous_ = retained;
    floor_ = floor;
    initialized_ = true;
    image_ = image;

    DurableCommitReport report;
    report.generation_ = DurableGeneration::from_trusted(next_generation);
    report.epoch_ = Epoch::from_trusted(image.epoch);
    report.snapshot_digest_ = verified_envelope.payload_digest;
    report.bytes_written_ = bytes.size();
    report.retained_previous_generation_ = retained;
    return report;
  } catch (...) {
    remove_file_if_exists(floor_temp);
    remove_file_if_exists(previous_temp);
    if (!published) {
      remove_file_if_exists(snapshot_temp);
    }
    throw;
  }
}

StoreInspection AuthorityStore::inspect(const std::filesystem::path& directory) {
  if (directory.empty() || !path_exists(directory)) {
    throw EpochError(ErrorCode::StoreNotFound, "store directory " + directory.string() + " does not exist");
  }
  if (!directory_exists(directory)) {
    throw EpochError(ErrorCode::PathInvalid, "store path " + directory.string() + " is not a directory");
  }

  const StorePaths paths = StorePaths::for_directory(directory);
  const ImageLimits limits{};

  StoreInspection inspection;
  auto note_problem = [&inspection](std::string problem) { inspection.problems_.push_back(std::move(problem)); };

  std::optional<FloorData> floor;
  LoadedFile floor_file = load_envelope_file(paths.floor, kMaxFloorFileBytes);
  if (floor_file.present) {
    if (!floor_file.valid) {
      note_problem("floor: " + floor_file.damage_detail);
    } else {
      try {
        floor = decode_floor(floor_file.envelope.payload);
        inspection.floor_epoch_ = Epoch::from_trusted(floor->epoch);
        inspection.floor_generation_ = DurableGeneration::from_trusted(floor->generation);
      } catch (const EpochError& error) {
        note_problem("floor: " + error.explanation().detail());
      }
    }
  }

  LoadedGeneration current = load_generation(paths.snapshot, limits);
  if (current.present && !current.valid) {
    note_problem("current generation: " + current.damage_detail);
  }
  LoadedGeneration previous = load_generation(paths.previous, limits);
  if (previous.present && !previous.valid) {
    note_problem("previous generation: " + previous.damage_detail);
  }

  const LoadedGeneration* usable = nullptr;
  if (current.present && current.valid) {
    usable = &current;
  } else if (previous.present && previous.valid) {
    usable = &previous;
    note_problem("the current generation is unusable; the retained previous generation is intact");
  }

  if (usable != nullptr) {
    inspection.store_initialized_ = true;
    inspection.domain_ = FacilityAuthorityDomainId::from_trusted(usable->image.domain);
    inspection.domain_instance_ = DomainInstanceNumber::from_trusted(usable->image.domain_instance);
    inspection.epoch_ = Epoch::from_trusted(usable->image.epoch);
    inspection.durable_generation_ = DurableGeneration::from_trusted(usable->image.durable_generation);
    inspection.controller_count_ = usable->image.controllers.size();
    inspection.transition_count_ = usable->image.transition_count;
    inspection.revocation_count_ = usable->image.revocation_count;
    inspection.idempotency_record_count_ = usable->image.idempotency_count;
    inspection.snapshot_bytes_ = usable->bytes.size();
    inspection.snapshot_digest_ = usable->envelope.payload_digest;
    inspection.transition_chain_verified_ = true;
    for (const GrantData& grant : usable->image.grants) {
      if (grant.state == GrantState::Live) {
        ++inspection.live_grant_count_;
      }
    }
  }

  if (usable != nullptr && floor.has_value() && !satisfies_floor(usable->image, *floor)) {
    note_problem("the retained generation is below the durable floor: " +
                 floor_violation_detail(usable->image, *floor));
  }
  if (usable != nullptr && !floor.has_value()) {
    note_problem("no readable epoch floor: rollback below the retained generation cannot be excluded");
  }
  if (usable == nullptr && floor_file.present) {
    note_problem("an epoch floor exists but no usable durable generation is present");
  }

  inspection.verified_ = usable != nullptr && floor.has_value() && satisfies_floor(usable->image, *floor);
  inspection.read_only_safe_ = inspection.verified_ && inspection.problems_.empty();
  return inspection;
}

void AuthorityStore::close() noexcept {
  if (lock_.has_value()) {
    lock_->release();
    lock_.reset();
  }
  open_ = false;
}

AuthorityStore::~AuthorityStore() { close(); }

}  // namespace dccp::epoch::detail

namespace dccp::epoch {

StoreInspection inspect_store(const std::filesystem::path& directory) {
  return detail::AuthorityStore::inspect(directory);
}

}  // namespace dccp::epoch


