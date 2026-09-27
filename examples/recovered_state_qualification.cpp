// Control Plane Epoch 1.0.0 - Summon Software Labs
// Example: qualification of recovered state.
//
// Persisted evidence does not become fresh because a process restarted. A
// consumer that recovered facility state presents a claim about who produced
// it, under which epoch, for which scope, and the authority qualifies it
// against current durable state into exactly one verdict. This example walks a
// claim through every verdict reachable in one scenario and prints the exact
// code of each.
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "control_plane_epoch/control_plane_epoch.hpp"

namespace {

using namespace dccp::epoch;

[[nodiscard]] std::filesystem::path prepare_store_directory() {
  const std::filesystem::path directory =
      std::filesystem::temp_directory_path() / "control-plane-epoch-examples" / "recovered_state_qualification";
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

/// Verdict tally, indexed by the stable numeric value of the verdict, so the
/// closing summary is derived from the qualifications that actually ran.
class VerdictTally {
 public:
  void count(RecoveredStateVerdict verdict) {
    const std::size_t index = static_cast<std::size_t>(verdict);
    if (index < counts_.size()) {
      counts_[index] += 1;
    }
  }

  [[nodiscard]] std::uint64_t operator[](RecoveredStateVerdict verdict) const {
    const std::size_t index = static_cast<std::size_t>(verdict);
    return index < counts_.size() ? counts_[index] : 0;
  }

  [[nodiscard]] std::uint64_t total() const {
    std::uint64_t total = 0;
    for (const std::uint64_t count : counts_) {
      total += count;
    }
    return total;
  }

 private:
  std::array<std::uint64_t, 6> counts_{};
};

/// Qualifies one claim and prints it together with its verdict and exact code.
[[nodiscard]] RecoveryQualification qualify(ControlPlaneEpochAuthority& authority, std::string_view label,
                                            const FacilityAuthorityDomainId& domain, Epoch producing_epoch,
                                            const ControllerId& producer,
                                            const ControllerIncarnationId& incarnation, const ScopeName& produced_scope,
                                            const Sha256Digest& content_digest, VerdictTally& tally) {
  const RecoveredStateClaim claim = unwrap(RecoveredStateClaim::create(domain, producing_epoch, producer, incarnation,
                                                                      produced_scope, content_digest),
                                           "recovered state claim");
  const RecoveryQualification qualification =
      unwrap(authority.qualify_recovered_state(claim), "recovered state qualification");
  tally.count(qualification.verdict());
  std::cout << "qualification case=" << label << ' ' << qualification.to_string()
            << " usable_as_current=" << (qualification.usable_as_current() ? "yes" : "no") << '\n';
  return qualification;
}

[[nodiscard]] MutationAuthority standing_root_authority(ControlPlaneEpochAuthority& authority,
                                                        const ControllerRecord& root_record) {
  AcquireAuthorityRequest request;
  request.controller = ControllerId::from_trusted("authority-root");
  request.incarnation = root_record.incarnation_id();
  request.scopes =
      scope_set({authority_grant_scope().view(), authority_revoke_scope().view(), epoch_advance_scope().view()});
  request.provenance = provenance(ProvenanceSourceKind::Operator, "facility-operator");
  const AuthorityGrantView view = unwrap(authority.acquire_authority(std::move(request)), "standing-root authority");
  if (!view.mutation_authority().has_value()) {
    throw EpochError(ErrorCode::InvariantViolation, "the authority root acquired no mutation authority");
  }
  return *view.mutation_authority();
}

}  // namespace

int main() {
  using namespace dccp::epoch;

  try {
    const std::filesystem::path directory = prepare_store_directory();
    std::cout << "example=recovered_state_qualification\n";
    std::cout << "store=" << directory.string() << '\n';

    StoreOpenOptions options;
    options.directory = directory;
    ControlPlaneEpochAuthority authority(options);

    const FacilityAuthorityDomainId domain =
        unwrap(FacilityAuthorityDomainId::parse("facility-alpha", "authority domain"), "domain");
    const FacilityAuthorityDomainId other_domain =
        unwrap(FacilityAuthorityDomainId::parse("facility-beta", "authority domain"), "other domain");
    const ControllerId root = unwrap(ControllerId::parse("authority-root", "authority root"), "authority root");
    const ControllerId producer = unwrap(ControllerId::parse("producer-1", "producer"), "producer");

    InitializeDomainRequest domain_request;
    domain_request.domain = domain;
    domain_request.authority_root = root;
    for (const std::string_view name : {authority_grant_scope().view(), authority_revoke_scope().view(),
                                        epoch_advance_scope().view(), std::string_view("facility.inventory"),
                                        std::string_view("facility.topology")}) {
      domain_request.scopes.push_back(scope(name));
    }
    domain_request.provenance = provenance(ProvenanceSourceKind::Initialization, "facility-operator");
    (void)unwrap(authority.initialize(std::move(domain_request)), "domain initialization");

    const MutationAuthority root_epoch_one =
        standing_root_authority(authority, unwrap(authority.controller_record(root), "authority root record"));

    RegisterControllerRequest register_request;
    register_request.controller = producer;
    register_request.provenance = provenance(ProvenanceSourceKind::Controller, "producer-1");
    const ControllerRegistration first_boot =
        unwrap(authority.register_controller(std::move(register_request)), "producer registration");
    std::cout << "registration " << first_boot.to_string() << '\n';

    AcquireAuthorityRequest producer_request;
    producer_request.controller = first_boot.controller();
    producer_request.incarnation = first_boot.incarnation_id();
    producer_request.scopes = scope_set({std::string_view("facility.inventory")});
    producer_request.sponsor = root_epoch_one;
    producer_request.provenance = provenance(ProvenanceSourceKind::Controller, "producer-1");
    const AuthorityGrantView epoch_one_grant =
        unwrap(authority.acquire_authority(std::move(producer_request)), "producer authority in epoch 1");
    std::cout << "grant-epoch-1 " << epoch_one_grant.record().to_string() << '\n';

    const Sha256Digest inventory_digest = sha256("facility inventory observation, epoch 1");
    const Sha256Digest topology_digest = sha256("facility topology observation, epoch 1");
    const Sha256Digest unsupported_digest = sha256("state produced under an unknown incarnation");
    VerdictTally tally;

    // 1. Current: produced under the current epoch by the current incarnation
    //    while holding a live grant that covers the claimed scope.
    const RecoveryQualification current =
        qualify(authority, "current-epoch-1", domain, authority.current_epoch(), producer,
                first_boot.incarnation_id(), scope("facility.inventory"), inventory_digest, tally);
    if (current.verdict() != RecoveredStateVerdict::Current || current.code() != ErrorCode::RecoveredCurrent ||
        !current.matching_grant().has_value() || current.requires_revalidation()) {
      std::cerr << "the current claim was not qualified as recovery.current\n";
      return 1;
    }

    // The writer survived an epoch change...
    AdvanceEpochRequest advance;
    advance.expected_current = authority.current_epoch();
    advance.authority = root_epoch_one;
    advance.reason = EpochTransitionReason::Fencing;
    advance.provenance = provenance(ProvenanceSourceKind::Operator, "facility-operator");
    const EpochTransitionRecord transition = unwrap(authority.advance_epoch(std::move(advance)), "epoch advance");
    std::cout << "epoch-advanced base=" << transition.base_epoch().to_string()
              << " new=" << transition.new_epoch().to_string()
              << " fenced-grants=" << transition.fenced_grant_count() << '\n';

    const MutationAuthority root_epoch_two =
        standing_root_authority(authority, unwrap(authority.controller_record(root), "authority root record"));

    AcquireAuthorityRequest renewed_request;
    renewed_request.controller = producer;
    renewed_request.incarnation = first_boot.incarnation_id();
    renewed_request.scopes = scope_set({std::string_view("facility.inventory")});
    renewed_request.sponsor = root_epoch_two;
    renewed_request.provenance = provenance(ProvenanceSourceKind::Controller, "producer-1");
    const AuthorityGrantView epoch_two_grant =
        unwrap(authority.acquire_authority(std::move(renewed_request)), "producer authority in epoch 2");
    std::cout << "grant-epoch-2 " << epoch_two_grant.record().to_string() << '\n';

    // 2. NeedsReconciliation: produced under an earlier epoch by the still
    //    current incarnation, which still holds the claimed scope.
    const RecoveryQualification needs_reconciliation =
        qualify(authority, "earlier-epoch-still-authorized", domain, Epoch::initial(), producer,
                first_boot.incarnation_id(), scope("facility.inventory"), inventory_digest, tally);
    if (needs_reconciliation.verdict() != RecoveredStateVerdict::NeedsReconciliation ||
        needs_reconciliation.code() != ErrorCode::RecoveredNeedsReconciliation ||
        !needs_reconciliation.matching_grant().has_value() || !needs_reconciliation.requires_revalidation()) {
      std::cerr << "the surviving-writer claim was not qualified as recovery.needs_reconciliation\n";
      return 1;
    }

    // 3. Stale: produced under an earlier epoch, and the producer holds no
    //    authority over the claimed scope now.
    const RecoveryQualification stale =
        qualify(authority, "earlier-epoch-scope-lost", domain, Epoch::initial(), producer, first_boot.incarnation_id(),
                scope("facility.topology"), topology_digest, tally);
    if (stale.verdict() != RecoveredStateVerdict::Stale || stale.code() != ErrorCode::RecoveredStale ||
        stale.matching_grant().has_value() || !stale.requires_revalidation()) {
      std::cerr << "the earlier-epoch claim was not qualified as recovery.stale\n";
      return 1;
    }

    // ...but this writer did not: it restarts, which supersedes its incarnation.
    RegisterControllerRequest restart_request;
    restart_request.controller = producer;
    restart_request.provenance = provenance(ProvenanceSourceKind::Controller, "producer-1");
    const ControllerRegistration second_boot =
        unwrap(authority.register_controller(std::move(restart_request)), "producer restart");
    std::cout << "restart " << second_boot.to_string() << '\n';

    // 4. Superseded: produced by an incarnation that is no longer current.
    const RecoveryQualification superseded =
        qualify(authority, "superseded-incarnation", domain, authority.current_epoch(), producer,
                first_boot.incarnation_id(), scope("facility.inventory"), inventory_digest, tally);
    if (superseded.verdict() != RecoveredStateVerdict::Superseded ||
        superseded.code() != ErrorCode::RecoveredSuperseded || superseded.usable_as_current()) {
      std::cerr << "the superseded claim was not qualified as recovery.superseded\n";
      return 1;
    }

    // 5. Rejected: the current incarnation of the domain, in the current epoch,
    //    but holding no authority over the claimed scope.
    const RecoveryQualification no_authority =
        qualify(authority, "no-authority-for-scope", domain, authority.current_epoch(), producer,
                second_boot.incarnation_id(), scope("facility.topology"), topology_digest, tally);
    if (no_authority.verdict() != RecoveredStateVerdict::Rejected ||
        no_authority.code() != ErrorCode::RecoveredRejectedNoAuthority) {
      std::cerr << "the unauthorized claim was not rejected with recovery.rejected_no_authority\n";
      return 1;
    }

    // 6. Rejected: the claim names an epoch this domain never committed.
    const RecoveryQualification future_epoch =
        qualify(authority, "future-epoch", domain, Epoch::from_trusted(authority.current_epoch().value() + 7), producer,
                second_boot.incarnation_id(), scope("facility.inventory"), inventory_digest, tally);
    if (future_epoch.verdict() != RecoveredStateVerdict::Rejected ||
        future_epoch.code() != ErrorCode::RecoveredRejectedFutureEpoch) {
      std::cerr << "the future-epoch claim was not rejected with recovery.rejected_future_epoch\n";
      return 1;
    }

    // 7. Rejected: the claim belongs to a different authority domain.
    const RecoveryQualification domain_mismatch =
        qualify(authority, "domain-mismatch", other_domain, authority.current_epoch(), producer,
                second_boot.incarnation_id(), scope("facility.inventory"), inventory_digest, tally);
    if (domain_mismatch.verdict() != RecoveredStateVerdict::Rejected ||
        domain_mismatch.code() != ErrorCode::RecoveredRejectedDomainMismatch) {
      std::cerr << "the foreign-domain claim was not rejected with recovery.rejected_domain_mismatch\n";
      return 1;
    }

    // 8. Rejected: the claim names an incarnation this controller never had.
    const ControllerIncarnationId unknown_incarnation =
        ControllerIncarnationId::derive(domain, producer, IncarnationNumber::from_trusted(9));
    const RecoveryQualification unknown =
        qualify(authority, "unknown-incarnation", domain, authority.current_epoch(), producer, unknown_incarnation,
                scope("facility.inventory"), unsupported_digest, tally);
    if (unknown.verdict() != RecoveredStateVerdict::Rejected ||
        unknown.code() != ErrorCode::RecoveredRejectedUnknownIncarnation) {
      std::cerr << "the unknown-incarnation claim was not rejected with recovery.rejected_unknown_incarnation\n";
      return 1;
    }

    std::cout << "verdicts-observed total=" << tally.total()
              << " current=" << tally[RecoveredStateVerdict::Current]
              << " needs_reconciliation=" << tally[RecoveredStateVerdict::NeedsReconciliation]
              << " stale=" << tally[RecoveredStateVerdict::Stale]
              << " superseded=" << tally[RecoveredStateVerdict::Superseded]
              << " rejected=" << tally[RecoveredStateVerdict::Rejected] << '\n';
    if (tally.total() != 8 || tally[RecoveredStateVerdict::Rejected] != 4) {
      std::cerr << "the scenario did not exercise the expected verdicts\n";
      return 1;
    }
    authority.close();
    std::cout << "done=recovered_state_qualification\n";
    return 0;
  } catch (const EpochError& error) {
    std::cerr << "failure: " << error.explanation().to_string() << '\n';
    return 1;
  } catch (const std::exception& error) {
    std::cerr << "failure: " << error.what() << '\n';
    return 1;
  }
}
