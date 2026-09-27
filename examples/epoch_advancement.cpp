// Control Plane Epoch 1.0.0 - Summon Software Labs
// Example: epoch advancement with the expected-epoch precondition.
//
// The expected epoch is a precondition, not a hint. A first advancement from
// epoch N to N+1 commits exactly one successor and permanently fences every
// grant of epoch N; a second advancement that still expects epoch N is refused
// with the retryable epoch.conflict code, and succeeds once it expects the
// committed epoch and presents fresh authority.
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
      std::filesystem::temp_directory_path() / "control-plane-epoch-examples" / "epoch_advancement";
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

/// Acquires the reserved administrative scopes for the authority root through
/// the standing-root path and returns the mutation token.
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
  std::cout << "standing-root-grant grant=" << view.record().id().to_string()
            << " epoch=" << view.record().epoch().to_string() << '\n';
  return *view.mutation_authority();
}

}  // namespace

int main() {
  using namespace dccp::epoch;

  try {
    const std::filesystem::path directory = prepare_store_directory();
    std::cout << "example=epoch_advancement\n";
    std::cout << "store=" << directory.string() << '\n';

    StoreOpenOptions options;
    options.directory = directory;
    ControlPlaneEpochAuthority authority(options);

    InitializeDomainRequest domain_request;
    domain_request.domain = unwrap(FacilityAuthorityDomainId::parse("facility-alpha", "authority domain"), "domain");
    domain_request.authority_root = unwrap(ControllerId::parse("authority-root", "authority root"), "authority root");
    for (const std::string_view name : {authority_grant_scope().view(), authority_revoke_scope().view(),
                                        epoch_advance_scope().view(), std::string_view("facility.inventory")}) {
      domain_request.scopes.push_back(scope(name));
    }
    domain_request.provenance = provenance(ProvenanceSourceKind::Initialization, "facility-operator");
    (void)unwrap(authority.initialize(std::move(domain_request)), "domain initialization");

    const ControllerId root = ControllerId::from_trusted("authority-root");
    const MutationAuthority root_epoch_one =
        standing_root_authority(authority, unwrap(authority.controller_record(root), "authority root record"));

    // Two live grants are added on top of the initialization grant, so the
    // transition has something to fence.
    RegisterControllerRequest register_request;
    register_request.controller = unwrap(ControllerId::parse("worker-1", "controller"), "controller");
    register_request.provenance = provenance(ProvenanceSourceKind::Controller, "worker-1");
    const ControllerRegistration worker =
        unwrap(authority.register_controller(std::move(register_request)), "worker registration");

    AcquireAuthorityRequest worker_request;
    worker_request.controller = worker.controller();
    worker_request.incarnation = worker.incarnation_id();
    worker_request.scopes = scope_set({std::string_view("facility.inventory")});
    worker_request.sponsor = root_epoch_one;
    worker_request.provenance = provenance(ProvenanceSourceKind::Controller, "worker-1");
    (void)unwrap(authority.acquire_authority(std::move(worker_request)), "worker scoped authority");

    const AuthorityStatus before = authority.status();
    std::cout << "before-advance epoch=" << before.epoch().to_string()
              << " live_grants=" << before.live_grant_count()
              << " controllers=" << before.controller_count()
              << " transitions=" << before.transition_count() << '\n';

    const Epoch expected = authority.current_epoch();
    AdvanceEpochRequest first_advance;
    first_advance.expected_current = expected;
    first_advance.authority = root_epoch_one;
    first_advance.reason = EpochTransitionReason::OperatorRequest;
    first_advance.provenance = provenance(ProvenanceSourceKind::Operator, "facility-operator");
    const EpochTransitionRecord transition =
        unwrap(authority.advance_epoch(std::move(first_advance)), "first advancement");
    std::cout << "transition " << transition.to_string() << '\n';
    std::cout << "epoch-change base=" << transition.base_epoch().to_string()
              << " new=" << transition.new_epoch().to_string()
              << " fenced-grants=" << transition.fenced_grant_count()
              << " controllers=" << transition.controller_count() << '\n';
    if (transition.base_epoch() != expected || transition.new_epoch() != Epoch::from_trusted(expected.value() + 1)) {
      std::cerr << "the transition did not move to exactly one successor\n";
      return 1;
    }

    const AuthorityStatus after = authority.status();
    std::cout << "after-advance epoch=" << after.epoch().to_string() << " live_grants=" << after.live_grant_count()
              << " transitions=" << after.transition_count() << '\n';
    if (after.live_grant_count() != 0) {
      std::cerr << "advancing the epoch left live grants behind\n";
      return 1;
    }

    // The same precondition again: the committed epoch moved, so the expected
    // value no longer matches and the command is refused as a retryable
    // conflict.
    AdvanceEpochRequest repeated_advance;
    repeated_advance.expected_current = expected;
    repeated_advance.authority = root_epoch_one;
    repeated_advance.provenance = provenance(ProvenanceSourceKind::Operator, "facility-operator");
    const Result<EpochTransitionRecord> repeated = authority.advance_epoch(std::move(repeated_advance));
    std::cout << "second-advance-same-expected accepted=" << (repeated.has_value() ? "yes" : "no")
              << " code=" << repeated.rejection().token() << " retryable="
              << (repeated.rejection().retryable() ? "yes" : "no")
              << " detail=" << (repeated.rejection().detail().empty() ? "-" : repeated.rejection().detail()) << '\n';
    if (repeated.has_value() || repeated.rejection().code() != ErrorCode::EpochConflict ||
        !repeated.rejection().retryable()) {
      std::cerr << "the repeated advancement was not refused with a retryable epoch.conflict\n";
      return 1;
    }

    // A retry that expects the committed epoch and presents fresh authority for
    // it succeeds.
    const MutationAuthority root_epoch_two =
        standing_root_authority(authority, unwrap(authority.controller_record(root), "authority root record"));
    AdvanceEpochRequest retry_advance;
    retry_advance.expected_current = authority.current_epoch();
    retry_advance.authority = root_epoch_two;
    retry_advance.reason = EpochTransitionReason::FacilityReconfiguration;
    retry_advance.provenance = provenance(ProvenanceSourceKind::Operator, "facility-operator");
    const EpochTransitionRecord retried = unwrap(authority.advance_epoch(std::move(retry_advance)), "retried advance");
    std::cout << "retry-advance base=" << retried.base_epoch().to_string() << " new=" << retried.new_epoch().to_string()
              << " reason=" << epoch_transition_reason_token(retried.reason())
              << " fenced-grants=" << retried.fenced_grant_count() << '\n';

    const EpochHistoryPage history = unwrap(authority.history(HistoryQuery{}), "history");
    std::cout << "history total=" << history.total_count() << " retained=" << history.records().size()
              << " first_retained=" << history.first_retained_sequence() << " trimmed=" << history.trimmed_count()
              << " chain_head=" << history.chain_head().to_hex() << '\n';
    for (const EpochTransitionRecord& record : history.records()) {
      std::cout << "history-record sequence=" << record.sequence().to_string()
                << " base=" << (record.is_origin() ? std::string("-") : record.base_epoch().to_string())
                << " new=" << record.new_epoch().to_string()
                << " reason=" << epoch_transition_reason_token(record.reason())
                << " fenced_grants=" << record.fenced_grant_count()
                << " origin=" << (record.is_origin() ? "yes" : "no")
                << " previous_record_digest=" << record.previous_record_digest().to_hex()
                << " record_digest=" << record.record_digest().to_hex() << '\n';
    }
    if (history.total_count() != 3 || history.records().back().record_digest().is_zero()) {
      std::cerr << "the transition ledger did not retain the expected records\n";
      return 1;
    }

    authority.close();
    std::cout << "done=epoch_advancement\n";
    return 0;
  } catch (const EpochError& error) {
    std::cerr << "failure: " << error.explanation().to_string() << '\n';
    return 1;
  } catch (const std::exception& error) {
    std::cerr << "failure: " << error.what() << '\n';
    return 1;
  }
}
