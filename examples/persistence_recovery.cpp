// Control Plane Epoch 1.0.0 - Summon Software Labs
// Example: durable persistence and recovery.
//
// Commits several changes, closes the authority, and reopens the same directory
// to show that epoch, durable generation, and the transition-ledger chain head
// continue exactly where they stopped. It then damages the live generation file
// on disk (garbage bytes) and walks the operator responses:
//
//   * refuse-on-damage: fails with the exact integrity code and writes nothing;
//   * adopt-previous-generation: the retained previous generation is intact, but
//     the durable floor names the damaged generation, so adopting the retained
//     one would roll back below the floor. The store refuses with the exact
//     code rather than silently rolling authority backwards. Both branches of
//     that outcome are handled and printed explicitly;
//   * reinitialize-domain with an operator epoch assertion: quarantines the
//     damaged state and creates a fresh durable instance whose epoch is strictly
//     above the recoverable floor.
#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "control_plane_epoch/control_plane_epoch.hpp"

namespace {

using namespace dccp::epoch;

[[nodiscard]] std::filesystem::path prepare_store_directory() {
  const std::filesystem::path directory =
      std::filesystem::temp_directory_path() / "control-plane-epoch-examples" / "persistence_recovery";
  std::error_code ignored;
  std::filesystem::remove_all(directory, ignored);
  std::filesystem::create_directories(directory, ignored);
  return directory;
}

template <class T>
[[nodiscard]] T unwrap(Result<T> result, std::string_view what) {
  if (!result.has_value()) {
    throw EpochError(Explanation(result.rejection().code(),
                                 std::string(what) + " was rejected: " + result.rejection().detail()));
  }
  return result.move_value();
}

[[nodiscard]] ScopeName scope(std::string_view name) {
  return unwrap(ScopeName::parse(name, "scope name"), name);
}

[[nodiscard]] AuthorityScopeSet scope_set(std::vector<std::string_view> names) {
  std::vector<ScopeName> scopes;
  scopes.reserve(names.size());
  for (const std::string_view name : names) {
    scopes.push_back(scope(name));
  }
  return unwrap(AuthorityScopeSet::create(std::move(scopes)), "scope set");
}

[[nodiscard]] ProvenanceInput provenance(ProvenanceSourceKind kind, std::string_view source) {
  return unwrap(ProvenanceInput::from_source(kind, source), "provenance");
}

[[nodiscard]] std::unique_ptr<ControlPlaneEpochAuthority> open_store(const std::filesystem::path& directory,
                                                                    RecoveryPolicy policy,
                                                                    std::optional<std::uint64_t> asserted_floor) {
  StoreOpenOptions options;
  options.directory = directory;
  options.mode = StoreOpenMode::ReadWrite;
  options.recovery_policy = policy;
  options.asserted_epoch_floor = asserted_floor;
  return std::make_unique<ControlPlaneEpochAuthority>(options);
}

[[nodiscard]] MutationAuthority standing_root_authority(ControlPlaneEpochAuthority& authority,
                                                        const ControllerRecord& root_record) {
  AcquireAuthorityRequest request;
  request.controller = ControllerId::from_trusted("authority-root");
  request.incarnation = root_record.incarnation_id();
  request.scopes = scope_set({authority_grant_scope().view(), epoch_advance_scope().view()});
  request.provenance = provenance(ProvenanceSourceKind::Operator, "facility-operator");
  const AuthorityGrantView view = unwrap(authority.acquire_authority(std::move(request)), "standing-root authority");
  if (!view.mutation_authority().has_value()) {
    throw EpochError(ErrorCode::InvariantViolation, "the authority root acquired no mutation authority");
  }
  return *view.mutation_authority();
}

/// Lists one store subdirectory in ascending name order, so the printed output
/// is stable across runs.
[[nodiscard]] std::vector<std::string> list_directory(const std::filesystem::path& directory) {
  std::vector<std::string> names;
  std::error_code error;
  std::filesystem::directory_iterator iterator(directory, error);
  if (error) {
    return names;
  }
  for (const std::filesystem::directory_entry& entry : iterator) {
    names.push_back(entry.path().filename().string());
  }
  std::sort(names.begin(), names.end());
  return names;
}

/// Overwrites one file with a fixed byte pattern, which is what a damaged or
/// partially overwritten durable file looks like to the opener.
void overwrite_with_garbage(const std::filesystem::path& path, std::size_t byte_count, unsigned char pattern) {
  std::vector<char> bytes(byte_count, static_cast<char>(pattern));
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  stream.flush();
  if (!stream.good()) {
    throw EpochError(ErrorCode::WriteFailed, "could not damage " + path.string());
  }
}

void initialize_domain(ControlPlaneEpochAuthority& authority) {
  InitializeDomainRequest request;
  request.domain = unwrap(FacilityAuthorityDomainId::parse("facility-alpha", "authority domain"), "domain");
  request.authority_root = unwrap(ControllerId::parse("authority-root", "authority root"), "authority root");
  for (const std::string_view name : {authority_grant_scope().view(), authority_revoke_scope().view(),
                                      epoch_advance_scope().view(), std::string_view("facility.inventory")}) {
    request.scopes.push_back(scope(name));
  }
  request.provenance = provenance(ProvenanceSourceKind::Initialization, "facility-operator");
  (void)unwrap(authority.initialize(std::move(request)), "domain initialization");
}

}  // namespace

int main() {
  using namespace dccp::epoch;

  try {
    const std::filesystem::path directory = prepare_store_directory();
    const std::filesystem::path snapshot_path = directory / std::string(StoreLayout::snapshot_file);
    std::cout << "example=persistence_recovery\n";
    std::cout << "store=" << directory.string() << '\n';

    // -- Phase 1: commit several changes, then close. ------------------------
    std::uint64_t committed_epoch = 0;
    std::uint64_t committed_generation = 0;
    std::string committed_snapshot_digest;
    std::string committed_chain_head;
    {
      const std::unique_ptr<ControlPlaneEpochAuthority> authority =
          open_store(directory, RecoveryPolicy::RefuseOnDamage, std::nullopt);

      initialize_domain(*authority);
      std::cout << "commit initialize " << authority->last_commit()->to_string() << '\n';

      const MutationAuthority root_epoch_one = standing_root_authority(
          *authority,
          unwrap(authority->controller_record(ControllerId::from_trusted("authority-root")), "root record"));
      std::cout << "commit standing-root " << authority->last_commit()->to_string() << '\n';

      RegisterControllerRequest register_request;
      register_request.controller = unwrap(ControllerId::parse("worker-1", "controller"), "controller");
      register_request.provenance = provenance(ProvenanceSourceKind::Controller, "worker-1");
      const ControllerRegistration worker =
          unwrap(authority->register_controller(std::move(register_request)), "worker registration");
      std::cout << "commit register " << authority->last_commit()->to_string() << '\n';

      AcquireAuthorityRequest worker_request;
      worker_request.controller = worker.controller();
      worker_request.incarnation = worker.incarnation_id();
      worker_request.scopes = scope_set({std::string_view("facility.inventory")});
      worker_request.sponsor = root_epoch_one;
      worker_request.provenance = provenance(ProvenanceSourceKind::Controller, "worker-1");
      (void)unwrap(authority->acquire_authority(std::move(worker_request)), "worker scoped authority");
      std::cout << "commit grant " << authority->last_commit()->to_string() << '\n';

      AdvanceEpochRequest advance;
      advance.expected_current = authority->current_epoch();
      advance.authority = root_epoch_one;
      advance.reason = EpochTransitionReason::Recovery;
      advance.provenance = provenance(ProvenanceSourceKind::Operator, "facility-operator");
      const EpochTransitionRecord transition = unwrap(authority->advance_epoch(std::move(advance)), "epoch advance");
      std::cout << "commit advance " << authority->last_commit()->to_string()
                << " fenced_grants=" << transition.fenced_grant_count() << '\n';

      (void)standing_root_authority(
          *authority,
          unwrap(authority->controller_record(ControllerId::from_trusted("authority-root")), "root record"));
      const DurableCommitReport last = *authority->last_commit();
      std::cout << "commit standing-root-again " << last.to_string() << '\n';

      const AuthorityStatus status = authority->status();
      const EpochHistoryPage history = unwrap(authority->history(HistoryQuery{}), "history");
      committed_epoch = status.epoch().value();
      committed_generation = status.durable_generation().value();
      committed_snapshot_digest = status.snapshot_digest().to_hex();
      committed_chain_head = history.chain_head().to_hex();
      std::cout << "committed epoch=" << committed_epoch << " generation=" << committed_generation
                << " controllers=" << status.controller_count() << " live_grants=" << status.live_grant_count()
                << " transitions=" << status.transition_count() << " snapshot_digest=" << committed_snapshot_digest
                << " chain_head=" << committed_chain_head << '\n';
      authority->close();
    }

    // -- Phase 2: reopen the same directory. --------------------------------
    {
      const std::unique_ptr<ControlPlaneEpochAuthority> reopened =
          open_store(directory, RecoveryPolicy::RefuseOnDamage, std::nullopt);
      std::cout << "reopen-recovery " << reopened->recovery().to_string() << '\n';
      const AuthorityStatus status = reopened->status();
      const EpochHistoryPage history = unwrap(reopened->history(HistoryQuery{}), "history");
      const bool epoch_continued = status.epoch().value() == committed_epoch;
      const bool generation_continued = status.durable_generation().value() == committed_generation;
      const bool digest_continued = status.snapshot_digest().to_hex() == committed_snapshot_digest;
      const bool chain_continued = history.chain_head().to_hex() == committed_chain_head;
      std::cout << "continuity epoch=" << (epoch_continued ? "match" : "mismatch")
                << " generation=" << (generation_continued ? "match" : "mismatch")
                << " snapshot_digest=" << (digest_continued ? "match" : "mismatch")
                << " chain_head=" << (chain_continued ? "match" : "mismatch")
                << " epoch=" << status.epoch().to_string()
                << " generation=" << status.durable_generation().to_string()
                << " chain_head=" << history.chain_head().to_hex() << '\n';
      if (!epoch_continued || !generation_continued || !digest_continued || !chain_continued) {
        std::cerr << "the reopened store did not continue the committed state\n";
        return 1;
      }
      std::cout << "inspection " << inspect_store(directory).to_string() << '\n';
      reopened->close();
    }

    // -- Phase 3: damage the live generation file. --------------------------
    overwrite_with_garbage(snapshot_path, 128, 0x5AU);
    std::cout << "damaged file=" << std::string(StoreLayout::snapshot_file) << " bytes=128 pattern=0x5a\n";

    // 3a. refuse-on-damage: nothing is written and nothing is repaired.
    try {
      const std::unique_ptr<ControlPlaneEpochAuthority> refused =
          open_store(directory, RecoveryPolicy::RefuseOnDamage, std::nullopt);
      std::cerr << "refuse-on-damage unexpectedly opened the damaged store\n";
      return 1;
    } catch (const EpochError& error) {
      std::cout << "refuse-on-damage opened=no code=" << error.explanation().token()
                << " category=" << error_category_token(error.explanation().category())
                << " detail=" << error.explanation().detail() << '\n';
      if (error.code() != ErrorCode::MagicMismatch) {
        std::cerr << "refuse-on-damage did not report the expected integrity code\n";
        return 1;
      }
    }

    // 3b. The retained previous generation is intact; the durable floor is not.
    const StoreInspection damaged = inspect_store(directory);
    std::cout << "inspection-damaged " << damaged.to_string() << '\n';
    const bool retained_intact = damaged.store_initialized() && damaged.durable_generation().has_value() &&
                                 damaged.durable_generation()->value() + 1 == committed_generation;
    const bool floor_above_retained = damaged.floor_generation().has_value() &&
                                      damaged.floor_generation()->value() == committed_generation;
    std::cout << "retained-generation-intact=" << (retained_intact ? "yes" : "no")
              << " retained-generation="
              << (damaged.durable_generation().has_value() ? damaged.durable_generation()->to_string()
                                                            : std::string("-"))
              << " floor-generation="
              << (damaged.floor_generation().has_value() ? damaged.floor_generation()->to_string() : std::string("-"))
              << " inspection-verified=" << (damaged.verified() ? "yes" : "no") << '\n';
    if (!retained_intact || !floor_above_retained || damaged.verified()) {
      std::cerr << "the damaged store did not report an intact retained generation below the floor\n";
      return 1;
    }

    // 3c. adopt-previous-generation. The policy adopts the retained generation
    //     only while it satisfies the durable floor. Here the floor names the
    //     damaged generation, so adopting the retained one would roll authority
    //     backwards and the store refuses instead. Both outcomes are handled.
    bool adopted = false;
    try {
      const std::unique_ptr<ControlPlaneEpochAuthority> adopting =
          open_store(directory, RecoveryPolicy::AdoptPreviousGeneration, std::nullopt);
      const RecoveryReport& report = adopting->recovery();
      adopted = report.outcome() == RecoveryOutcome::AdoptedPreviousGeneration;
      std::cout << "adopt-previous-generation opened=yes outcome=" << recovery_outcome_token(report.outcome())
                << " epoch=" << (report.epoch().has_value() ? report.epoch()->to_string() : std::string("-"))
                << " generation=" << (report.durable_generation().has_value()
                                          ? report.durable_generation()->to_string()
                                          : std::string("-"))
                << " quarantined=" << report.quarantined_files().size() << '\n';
      if (adopted) {
        std::cout << "adopt-previous-generation-recovery " << report.to_string() << '\n';
      }
    } catch (const EpochError& error) {
      std::cout << "adopt-previous-generation opened=no code=" << error.explanation().token()
                << " category=" << error_category_token(error.explanation().category())
                << " detail=" << error.explanation().detail() << '\n';
      std::cout << "adopt-previous-generation-note the retained generation " << (committed_generation - 1)
                << " is intact but below the durable floor " << committed_generation
                << "; rolling back to it is refused, so the durable floor keeps authority monotonic\n";
      if (error.code() != ErrorCode::GenerationBelowFloor) {
        std::cerr << "the adopt policy did not refuse with integrity.generation_below_floor\n";
        return 1;
      }
    }
    std::cout << "adopt-previous-generation-adopted=" << (adopted ? "yes" : "no") << '\n';

    if (adopted) {
      // The retained generation was republished as the live one and the damaged
      // file was moved into quarantine, so the reinitialization path is not
      // needed. The store must verify again from the adopted generation.
      const std::vector<std::string> quarantined =
          list_directory(directory / std::string(StoreLayout::quarantine_directory));
      std::cout << "reinitialize-domain-not-needed=adopted-previous-generation quarantine-entries="
                << quarantined.size() << '\n';
      const StoreInspection inspection = inspect_store(directory);
      std::cout << "inspection-after-adoption " << inspection.to_string() << '\n';
      if (!inspection.verified()) {
        std::cerr << "the adopted store did not verify\n";
        return 1;
      }
      std::cout << "done=persistence_recovery\n";
      return 0;
    }

    // 3d. reinitialize-domain: the documented repair. Damaged state is moved
    //     into quarantine and a fresh durable instance starts strictly above
    //     every recoverable epoch, so authority never moves backwards.
    {
      const std::unique_ptr<ControlPlaneEpochAuthority> repaired =
          open_store(directory, RecoveryPolicy::ReinitializeDomain, committed_epoch);
      const RecoveryReport& report = repaired->recovery();
      std::cout << "reinitialize-domain " << report.to_string() << '\n';
      if (report.outcome() != RecoveryOutcome::ReinitializedDamagedStore) {
        std::cerr << "the repair did not report reinitialized-damaged-store\n";
        return 1;
      }
      const std::vector<std::string> quarantined =
          list_directory(directory / std::string(StoreLayout::quarantine_directory));
      std::cout << "quarantine entries=" << quarantined.size();
      for (const std::string& name : quarantined) {
        std::cout << ' ' << name;
      }
      std::cout << '\n';
      if (quarantined.size() != 3) {
        std::cerr << "the repair did not quarantine every durable file of the damaged instance\n";
        return 1;
      }
      std::cout << "repaired-store-initialized=" << (repaired->initialized() ? "yes" : "no") << '\n';

      // The fresh instance holds no domain yet; the operator re-initializes it
      // and the seed places the epoch strictly above the recoverable floor,
      // bumps the durable instance, and publishes a generation above the
      // reinitialization floor.
      initialize_domain(*repaired);
      const AuthorityStatus status = repaired->status();
      const DurableCommitReport commit = *repaired->last_commit();
      std::cout << "reinitialize-domain-commit " << commit.to_string() << '\n';
      const bool epoch_above_floor = status.epoch().value() > committed_epoch;
      const bool instance_bumped = status.domain_instance().value() >= 2;
      const bool generation_above_floor = status.durable_generation().value() > committed_generation;
      std::cout << "reinitialized domain=" << status.domain().to_string()
                << " domain_instance=" << status.domain_instance().to_string()
                << " epoch=" << status.epoch().to_string()
                << " durable_generation=" << status.durable_generation().to_string()
                << " epoch-above-recoverable-floor=" << (epoch_above_floor ? "yes" : "no")
                << " instance-bumped=" << (instance_bumped ? "yes" : "no")
                << " generation-above-recoverable-floor=" << (generation_above_floor ? "yes" : "no") << '\n';
      if (!epoch_above_floor || !instance_bumped || !generation_above_floor) {
        std::cerr << "the repair did not start strictly above the recoverable floor\n";
        return 1;
      }
      const StoreInspection inspection = inspect_store(directory);
      std::cout << "inspection-after-repair " << inspection.to_string() << '\n';
      if (!inspection.verified()) {
        std::cerr << "the repaired store did not verify\n";
        return 1;
      }
      repaired->close();
    }

    std::cout << "done=persistence_recovery\n";
    return 0;
  } catch (const EpochError& error) {
    std::cerr << "failure: " << error.explanation().to_string() << '\n';
    return 1;
  } catch (const std::exception& error) {
    std::cerr << "failure: " << error.what() << '\n';
    return 1;
  }
}
