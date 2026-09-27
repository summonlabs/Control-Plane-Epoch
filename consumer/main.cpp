// Control Plane Epoch 1.0.0 - Summon Software Labs
// Standalone consumer of the installed Control Plane Epoch package.
//
// This program is built out of tree and links only the installed package: the
// headers, the imported target SummonSoftwareLabs::ControlPlaneEpoch, and the
// installed package config file produced by a real `cmake --install`. It walks
// the public API end to end against a store in a temporary directory:
// initialize, register, acquire, validate, advance.
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
      std::filesystem::temp_directory_path() / "control-plane-epoch-consumer";
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

/// Stable code of a validation outcome: "ok" when the outcome was accepted.
[[nodiscard]] std::string_view validation_code(const ValidationOutcome& outcome) {
  return outcome.accepted() ? std::string_view("ok") : outcome.rejection()->token();
}

}  // namespace

int main() {
  using namespace dccp::epoch;

  try {
    std::cout << "consumer=control_plane_epoch_consumer\n";
    std::cout << "library-version=" << version_string << " protocol=" << protocol_version
              << " durable_schema=" << durable_schema_version << '\n';

    const std::filesystem::path directory = prepare_store_directory();
    std::cout << "store=" << directory.string() << '\n';

    StoreOpenOptions options;
    options.directory = directory;
    ControlPlaneEpochAuthority authority(options);
    std::cout << "recovery " << authority.recovery().to_string() << '\n';

    // 1. Initialize the domain: the three reserved administrative scopes are
    //    mandatory, the facility scope is this domain's own vocabulary.
    InitializeDomainRequest domain_request;
    domain_request.domain =
        unwrap(FacilityAuthorityDomainId::parse("consumer-facility", "authority domain"), "domain");
    domain_request.authority_root =
        unwrap(ControllerId::parse("consumer-root", "authority root"), "authority root");
    for (const std::string_view name : {authority_grant_scope().view(), authority_revoke_scope().view(),
                                        epoch_advance_scope().view(), std::string_view("facility.inventory")}) {
      domain_request.scopes.push_back(scope(name));
    }
    domain_request.provenance = provenance(ProvenanceSourceKind::Initialization, "consumer");
    (void)unwrap(authority.initialize(std::move(domain_request)), "domain initialization");
    const AuthorityStatus initialized = authority.status();
    std::cout << "initialize accepted domain=" << initialized.domain().to_string()
              << " epoch=" << initialized.epoch().to_string()
              << " durable_generation=" << initialized.durable_generation().to_string()
              << " declared_scopes=" << initialized.declared_scopes().size() << '\n';

    // 2. Register the worker controller: identity only, never authority.
    RegisterControllerRequest register_request;
    register_request.controller = unwrap(ControllerId::parse("consumer-worker", "controller"), "controller");
    register_request.provenance = provenance(ProvenanceSourceKind::Controller, "consumer-worker");
    const ControllerRegistration worker =
        unwrap(authority.register_controller(std::move(register_request)), "worker registration");
    std::cout << "register " << worker.to_string() << '\n';

    // 3. Acquire authority: the root through the standing-root path, then the
    //    worker through a sponsored scoped grant.
    const ControllerRecord root_record =
        unwrap(authority.controller_record(unwrap(ControllerId::parse("consumer-root", "authority root"), "root")),
               "authority root record");
    AcquireAuthorityRequest root_request;
    root_request.controller = ControllerId::from_trusted("consumer-root");
    root_request.incarnation = root_record.incarnation_id();
    root_request.scopes =
        scope_set({authority_grant_scope().view(), epoch_advance_scope().view()});
    root_request.provenance = provenance(ProvenanceSourceKind::Operator, "consumer");
    const AuthorityGrantView root_view =
        unwrap(authority.acquire_authority(std::move(root_request)), "standing-root authority");
    if (!root_view.mutation_authority().has_value()) {
      std::cerr << "the authority root acquired no mutation authority\n";
      return 1;
    }
    std::cout << "acquire-root grant=" << root_view.record().id().to_string()
              << " scopes=" << root_view.record().scopes().to_string() << '\n';

    AcquireAuthorityRequest worker_request;
    worker_request.controller = worker.controller();
    worker_request.incarnation = worker.incarnation_id();
    worker_request.scopes = scope_set({std::string_view("facility.inventory")});
    worker_request.sponsor = *root_view.mutation_authority();
    worker_request.provenance = provenance(ProvenanceSourceKind::Controller, "consumer-worker");
    const AuthorityGrantView worker_view =
        unwrap(authority.acquire_authority(std::move(worker_request)), "worker scoped authority");
    if (!worker_view.mutation_authority().has_value()) {
      std::cerr << "the worker acquired no mutation authority\n";
      return 1;
    }
    std::cout << "acquire-worker " << worker_view.record().to_string() << '\n';

    // 4. Validate the worker's token against a covered and an uncovered scope.
    const ValidationOutcome covered =
        authority.validate_mutation(*worker_view.mutation_authority(), scope("facility.inventory"));
    const ValidationOutcome uncovered =
        authority.validate_mutation(*worker_view.mutation_authority(), scope("facility.topology"));
    std::cout << "validate scope=facility.inventory accepted=" << (covered.accepted() ? "yes" : "no")
              << " code=" << validation_code(covered) << '\n';
    std::cout << "validate scope=facility.topology accepted=" << (uncovered.accepted() ? "yes" : "no")
              << " code=" << validation_code(uncovered) << '\n';
    if (!covered.accepted() || uncovered.accepted() || uncovered.code() != ErrorCode::ScopeNotGranted) {
      std::cerr << "validation did not behave as documented\n";
      return 1;
    }

    // 5. Advance the epoch, then show that the epoch-scoped token is fenced.
    AdvanceEpochRequest advance;
    advance.expected_current = authority.current_epoch();
    advance.authority = *root_view.mutation_authority();
    advance.reason = EpochTransitionReason::OperatorRequest;
    advance.provenance = provenance(ProvenanceSourceKind::Operator, "consumer");
    const EpochTransitionRecord transition = unwrap(authority.advance_epoch(std::move(advance)), "epoch advance");
    const ValidationOutcome fenced =
        authority.validate_mutation(*worker_view.mutation_authority(), scope("facility.inventory"));
    std::cout << "advance base=" << transition.base_epoch().to_string() << " new=" << transition.new_epoch().to_string()
              << " fenced_grants=" << transition.fenced_grant_count() << '\n';
    std::cout << "validate-after-advance accepted=" << (fenced.accepted() ? "yes" : "no")
              << " code=" << validation_code(fenced) << '\n';
    if (fenced.accepted() || fenced.code() != ErrorCode::EpochFenced) {
      std::cerr << "the epoch-scoped token was not fenced by the transition\n";
      return 1;
    }

    const DurableCommitReport commit = *authority.last_commit();
    std::cout << "last-commit " << commit.to_string() << '\n';
    const StoreInspection inspection = inspect_store(directory);
    std::cout << "inspection verified=" << (inspection.verified() ? "yes" : "no")
              << " epoch=" << (inspection.epoch().has_value() ? inspection.epoch()->to_string() : std::string("-"))
              << " transition_chain_verified=" << (inspection.transition_chain_verified() ? "yes" : "no") << '\n';
    if (!inspection.verified()) {
      std::cerr << "the consumer's store did not verify\n";
      return 1;
    }

    authority.close();
    std::cout << "done=control_plane_epoch_consumer\n";
    return 0;
  } catch (const EpochError& error) {
    std::cerr << "failure: " << error.explanation().to_string() << '\n';
    return 1;
  } catch (const std::exception& error) {
    std::cerr << "failure: " << error.what() << '\n';
    return 1;
  }
}
