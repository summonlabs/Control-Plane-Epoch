// Control Plane Epoch 1.0.0 - Summon Software Labs
// Example: scoped authority.
//
// Shows the two documented paths to authority: the authority root acquiring the
// reserved administrative scopes through the standing-root path (no sponsor),
// and a worker controller receiving a scoped mutation grant sponsored by the
// root. The worker's token is then validated against a scope it covers
// (accepted) and against a declared scope it does not cover (rejected with the
// exact code).
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
      std::filesystem::temp_directory_path() / "control-plane-epoch-examples" / "scoped_authority";
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
    std::cout << "example=scoped_authority\n";
    std::cout << "store=" << directory.string() << '\n';

    StoreOpenOptions options;
    options.directory = directory;
    ControlPlaneEpochAuthority authority(options);

    InitializeDomainRequest domain_request;
    domain_request.domain = unwrap(FacilityAuthorityDomainId::parse("facility-alpha", "authority domain"), "domain");
    domain_request.authority_root = unwrap(ControllerId::parse("authority-root", "authority root"), "authority root");
    for (const std::string_view name : {authority_grant_scope().view(), authority_revoke_scope().view(),
                                        epoch_advance_scope().view(), std::string_view("facility.inventory"),
                                        std::string_view("facility.topology")}) {
      domain_request.scopes.push_back(scope(name));
    }
    domain_request.provenance = provenance(ProvenanceSourceKind::Initialization, "facility-operator");
    (void)unwrap(authority.initialize(std::move(domain_request)), "domain initialization");

    const ControllerId root = ControllerId::from_trusted("authority-root");
    const ControllerRecord root_record = unwrap(authority.controller_record(root), "authority root record");

    // Path 1: the authority root acquires the reserved administrative scopes
    // with no sponsor. This is the documented bootstrap path.
    AcquireAuthorityRequest root_request;
    root_request.controller = root;
    root_request.incarnation = root_record.incarnation_id();
    root_request.scopes =
        scope_set({authority_grant_scope().view(), authority_revoke_scope().view(), epoch_advance_scope().view()});
    root_request.provenance = provenance(ProvenanceSourceKind::Operator, "facility-operator");
    const AuthorityGrantView root_view =
        unwrap(authority.acquire_authority(std::move(root_request)), "standing-root authority");
    if (!root_view.mutation_authority().has_value()) {
      std::cerr << "the root acquired no mutation authority\n";
      return 1;
    }
    const MutationAuthority root_token = *root_view.mutation_authority();
    std::cout << "standing-root grant=" << root_view.record().id().to_string()
              << " scopes=" << root_view.record().scopes().to_string()
              << " epoch=" << root_view.record().epoch().to_string()
              << " sponsored=no\n";

    // The standing-root path covers reserved administrative scopes only: an
    // ordinary facility scope still needs a sponsor.
    AcquireAuthorityRequest unsponsored_request;
    unsponsored_request.controller = root;
    unsponsored_request.incarnation = root_record.incarnation_id();
    unsponsored_request.scopes = scope_set({std::string_view("facility.inventory")});
    unsponsored_request.provenance = provenance(ProvenanceSourceKind::Operator, "facility-operator");
    const Result<AuthorityGrantView> unsponsored = authority.acquire_authority(std::move(unsponsored_request));
    std::cout << "root-without-sponsor-for-facility-scope accepted=" << (unsponsored.has_value() ? "yes" : "no")
              << " code=" << unsponsored.rejection().token() << '\n';
    if (unsponsored.has_value() || unsponsored.rejection().code() != ErrorCode::SponsorRequired) {
      std::cerr << "the standing-root path was not limited to reserved scopes\n";
      return 1;
    }

    // Path 2: a worker controller registers and is granted one facility scope,
    // sponsored by the root.
    RegisterControllerRequest register_request;
    register_request.controller = unwrap(ControllerId::parse("worker-1", "controller"), "controller");
    register_request.provenance = provenance(ProvenanceSourceKind::Controller, "worker-1");
    const ControllerRegistration worker =
        unwrap(authority.register_controller(std::move(register_request)), "worker registration");
    std::cout << "worker-registration " << worker.to_string() << '\n';

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
    const MutationAuthority worker_token = *worker_view.mutation_authority();
    std::cout << "worker-grant " << worker_view.record().to_string() << '\n';
    std::cout << "worker-token " << worker_token.to_string() << '\n';
    std::cout << "worker-token-digest=" << worker_token.digest().to_hex()
              << " fencing-token=" << worker_token.fencing_token().to_hex() << '\n';

    // Covered scope: accepted.
    const ValidationOutcome covered = authority.validate_mutation(worker_token, scope("facility.inventory"));
    std::cout << "validate-covered-scope scope=facility.inventory accepted=" << (covered.accepted() ? "yes" : "no")
              << " code=" << validation_code(covered) << '\n';
    if (!covered.accepted()) {
      std::cerr << "the covered scope was rejected\n";
      return 1;
    }

    // Declared but uncovered scope: rejected with the exact code.
    const ValidationOutcome uncovered = authority.validate_mutation(worker_token, scope("facility.topology"));
    std::cout << "validate-uncovered-scope scope=facility.topology accepted=" << (uncovered.accepted() ? "yes" : "no")
              << " code=" << validation_code(uncovered) << " detail=" << validation_detail(uncovered) << '\n';
    if (uncovered.accepted() || uncovered.code() != ErrorCode::ScopeNotGranted) {
      std::cerr << "the uncovered scope was not rejected with authority.scope_not_granted\n";
      return 1;
    }

    // A scope the domain never declared cannot be granted at all.
    AcquireAuthorityRequest undeclared_request;
    undeclared_request.controller = worker.controller();
    undeclared_request.incarnation = worker.incarnation_id();
    undeclared_request.scopes = scope_set({std::string_view("facility.unknown")});
    undeclared_request.sponsor = root_token;
    undeclared_request.provenance = provenance(ProvenanceSourceKind::Controller, "worker-1");
    const Result<AuthorityGrantView> undeclared = authority.acquire_authority(std::move(undeclared_request));
    std::cout << "acquire-undeclared-scope accepted=" << (undeclared.has_value() ? "yes" : "no")
              << " code=" << undeclared.rejection().token() << '\n';
    if (undeclared.has_value() || undeclared.rejection().code() != ErrorCode::ScopeUnknown) {
      std::cerr << "an undeclared scope was not refused with authority.scope_unknown\n";
      return 1;
    }

    // Observation authority is a distinct C++ type as well as a distinct class
    // in the durable state; it is never interchangeable with mutation
    // authority.
    AcquireAuthorityRequest observation_request;
    observation_request.authority_class = AuthorityClass::Observation;
    observation_request.controller = worker.controller();
    observation_request.incarnation = worker.incarnation_id();
    observation_request.scopes = scope_set({std::string_view("facility.topology")});
    observation_request.sponsor = root_token;
    observation_request.provenance = provenance(ProvenanceSourceKind::Controller, "worker-1");
    const AuthorityGrantView observation_view =
        unwrap(authority.acquire_authority(std::move(observation_request)), "worker observation authority");
    if (!observation_view.observation_authority().has_value()) {
      std::cerr << "the worker acquired no observation authority\n";
      return 1;
    }
    const ValidationOutcome observed =
        authority.validate_observation(*observation_view.observation_authority(), scope("facility.topology"));
    std::cout << "observation-grant " << observation_view.record().to_string() << '\n';
    std::cout << "validate-observation-scope scope=facility.topology accepted=" << (observed.accepted() ? "yes" : "no")
              << " code=" << validation_code(observed) << '\n';

    std::cout << "status " << authority.status().to_string() << '\n';
    authority.close();
    std::cout << "done=scoped_authority\n";
    return 0;
  } catch (const EpochError& error) {
    std::cerr << "failure: " << error.explanation().to_string() << '\n';
    return 1;
  } catch (const std::exception& error) {
    std::cerr << "failure: " << error.what() << '\n';
    return 1;
  }
}
