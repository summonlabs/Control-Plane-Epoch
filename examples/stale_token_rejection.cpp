// Control Plane Epoch 1.0.0 - Summon Software Labs
// Example: stale token rejection after an epoch advance.
//
// A token is evidence of claims made in one epoch, and nothing else. This
// example issues a token at epoch N, advances the epoch to N+1, and shows that
// the token is then refused with epoch.fenced both by validate_mutation and by
// a real sponsored command (an acquire that presents the token as its sponsor).
// Authority for the new epoch is re-acquired explicitly; the fenced token is
// never rehabilitated.
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
      std::filesystem::temp_directory_path() / "control-plane-epoch-examples" / "stale_token_rejection";
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

/// Stable code of a validation outcome: "ok" when the outcome was accepted.
[[nodiscard]] std::string_view validation_code(const ValidationOutcome& outcome) {
  return outcome.accepted() ? std::string_view("ok") : outcome.rejection()->token();
}

/// Deterministic detail of a validation outcome, or "-" when there is none.
[[nodiscard]] std::string validation_detail(const ValidationOutcome& outcome) {
  if (outcome.accepted() || outcome.rejection()->detail().empty()) {
    return std::string("-");
  }
  return outcome.rejection()->detail();
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

}  // namespace

int main() {
  using namespace dccp::epoch;

  try {
    const std::filesystem::path directory = prepare_store_directory();
    std::cout << "example=stale_token_rejection\n";
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
    const ControllerRecord root_record = unwrap(authority.controller_record(root), "authority root record");

    AcquireAuthorityRequest root_request;
    root_request.controller = root;
    root_request.incarnation = root_record.incarnation_id();
    root_request.scopes =
        scope_set({authority_grant_scope().view(), authority_revoke_scope().view(), epoch_advance_scope().view()});
    root_request.provenance = provenance(ProvenanceSourceKind::Operator, "facility-operator");
    const AuthorityGrantView root_view =
        unwrap(authority.acquire_authority(std::move(root_request)), "standing-root authority");
    if (!root_view.mutation_authority().has_value()) {
      std::cerr << "the authority root acquired no mutation authority\n";
      return 1;
    }
    const MutationAuthority root_token = *root_view.mutation_authority();

    RegisterControllerRequest register_request;
    register_request.controller = unwrap(ControllerId::parse("worker-1", "controller"), "controller");
    register_request.provenance = provenance(ProvenanceSourceKind::Controller, "worker-1");
    const ControllerRegistration worker =
        unwrap(authority.register_controller(std::move(register_request)), "worker registration");

    AcquireAuthorityRequest worker_request;
    worker_request.controller = worker.controller();
    worker_request.incarnation = worker.incarnation_id();
    worker_request.scopes = scope_set({std::string_view("facility.inventory")});
    worker_request.sponsor = root_token;
    worker_request.provenance = provenance(ProvenanceSourceKind::Controller, "worker-1");
    const AuthorityGrantView worker_view =
        unwrap(authority.acquire_authority(std::move(worker_request)), "worker scoped authority");
    if (!worker_view.mutation_authority().has_value()) {
      std::cerr << "the worker acquired no mutation authority\n";
      return 1;
    }
    const MutationAuthority issued_at_n = *worker_view.mutation_authority();
    const Epoch epoch_n = issued_at_n.epoch();
    std::cout << "token-issued epoch=" << epoch_n.to_string() << " grant=" << issued_at_n.grant().to_string()
              << " controller=" << issued_at_n.controller().to_string()
              << " scopes=" << issued_at_n.scopes().to_string() << '\n';

    const ValidationOutcome at_n = authority.validate_mutation(issued_at_n, scope("facility.inventory"));
    std::cout << "validate-before-advance accepted=" << (at_n.accepted() ? "yes" : "no")
              << " code=" << validation_code(at_n) << '\n';
    if (!at_n.accepted()) {
      std::cerr << "the token was refused in the epoch that issued it\n";
      return 1;
    }

    // Advance to N+1. Every grant of epoch N is fenced by this commit.
    AdvanceEpochRequest advance;
    advance.expected_current = epoch_n;
    advance.authority = root_token;
    advance.reason = EpochTransitionReason::OperatorRequest;
    advance.provenance = provenance(ProvenanceSourceKind::Operator, "facility-operator");
    const EpochTransitionRecord transition = unwrap(authority.advance_epoch(std::move(advance)), "epoch advance");
    const Epoch epoch_n_plus_one = authority.current_epoch();
    std::cout << "epoch-advanced base=" << transition.base_epoch().to_string()
              << " new=" << transition.new_epoch().to_string()
              << " fenced-grants=" << transition.fenced_grant_count() << '\n';

    // 1. Plain validation of the stale token.
    const ValidationOutcome after_advance =
        authority.validate_mutation(issued_at_n, scope("facility.inventory"));
    std::cout << "validate-after-advance accepted=" << (after_advance.accepted() ? "yes" : "no")
              << " code=" << validation_code(after_advance) << " detail=" << validation_detail(after_advance) << '\n';
    if (after_advance.accepted() || after_advance.code() != ErrorCode::EpochFenced) {
      std::cerr << "the stale token was not refused with epoch.fenced\n";
      return 1;
    }

    // 2. A real sponsored command: the worker tries to acquire observation
    //    authority for the new epoch and presents the fenced token as sponsor.
    //    The command is refused before any state changes.
    const std::uint64_t generation_before = authority.status().durable_generation().value();
    AcquireAuthorityRequest sponsored_request;
    sponsored_request.authority_class = AuthorityClass::Observation;
    sponsored_request.controller = issued_at_n.controller();
    sponsored_request.incarnation = issued_at_n.incarnation();
    sponsored_request.scopes = scope_set({std::string_view("facility.inventory")});
    sponsored_request.sponsor = issued_at_n;
    sponsored_request.provenance = provenance(ProvenanceSourceKind::Controller, "worker-1");
    const Result<AuthorityGrantView> sponsored = authority.acquire_authority(std::move(sponsored_request));
    const std::uint64_t generation_after = authority.status().durable_generation().value();
    std::cout << "sponsored-command-with-stale-sponsor accepted=" << (sponsored.has_value() ? "yes" : "no")
              << " code=" << sponsored.rejection().token()
              << " committed=" << (generation_before == generation_after ? "no" : "yes")
              << " durable_generation=" << generation_after << '\n';
    if (sponsored.has_value() || sponsored.rejection().code() != ErrorCode::EpochFenced ||
        generation_before != generation_after) {
      std::cerr << "the sponsored command with a fenced sponsor was not refused without committing\n";
      return 1;
    }

    // The worker is still the current incarnation of its controller; it must
    // acquire authority again in the new epoch. The old token is not reused.
    if (const ControllerRecord worker_record = unwrap(authority.controller_record(issued_at_n.controller()),
                                                      "worker record");
        worker_record.incarnation_id() != issued_at_n.incarnation()) {
      std::cerr << "the worker incarnation changed unexpectedly\n";
      return 1;
    }

    AcquireAuthorityRequest root_request_n_plus_one;
    root_request_n_plus_one.controller = root;
    root_request_n_plus_one.incarnation = root_record.incarnation_id();
    root_request_n_plus_one.scopes = scope_set({authority_grant_scope().view()});
    root_request_n_plus_one.provenance = provenance(ProvenanceSourceKind::Operator, "facility-operator");
    const AuthorityGrantView root_view_n_plus_one =
        unwrap(authority.acquire_authority(std::move(root_request_n_plus_one)), "standing-root authority at N+1");
    if (!root_view_n_plus_one.mutation_authority().has_value()) {
      std::cerr << "the authority root acquired no mutation authority at N+1\n";
      return 1;
    }

    AcquireAuthorityRequest renewal_request;
    renewal_request.controller = issued_at_n.controller();
    renewal_request.incarnation = issued_at_n.incarnation();
    renewal_request.scopes = scope_set({std::string_view("facility.inventory")});
    renewal_request.sponsor = *root_view_n_plus_one.mutation_authority();
    renewal_request.provenance = provenance(ProvenanceSourceKind::Controller, "worker-1");
    const AuthorityGrantView renewal =
        unwrap(authority.acquire_authority(std::move(renewal_request)), "renewed worker authority");
    if (!renewal.mutation_authority().has_value()) {
      std::cerr << "the renewal carries no mutation authority\n";
      return 1;
    }
    const ValidationOutcome renewed =
        authority.validate_mutation(*renewal.mutation_authority(), scope("facility.inventory"));
    std::cout << "renewed-token epoch=" << renewal.record().epoch().to_string()
              << " grant=" << renewal.record().id().to_string()
              << " accepted=" << (renewed.accepted() ? "yes" : "no") << " code=" << validation_code(renewed)
              << '\n';
    std::cout << "renewed-grant-is-new=" << (renewal.record().id() == issued_at_n.grant() ? "no" : "yes")
              << " epoch=" << epoch_n_plus_one.to_string() << '\n';
    if (!renewed.accepted() || renewal.record().id() == issued_at_n.grant()) {
      std::cerr << "the renewed authority did not replace the fenced grant\n";
      return 1;
    }

    authority.close();
    std::cout << "done=stale_token_rejection\n";
    return 0;
  } catch (const EpochError& error) {
    std::cerr << "failure: " << error.explanation().to_string() << '\n';
    return 1;
  } catch (const std::exception& error) {
    std::cerr << "failure: " << error.what() << '\n';
    return 1;
  }
}
