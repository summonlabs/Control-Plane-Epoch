// Control Plane Epoch 1.0.0 - Summon Software Labs
// Example: controller registration and restart semantics.
//
// A controller identity is stable across restarts; an incarnation is not. This
// example registers a controller, acquires authority for the incarnation it was
// given, re-registers the same controller (which is what a restart does), and
// shows that the earlier incarnation identity is no longer the current one and
// that authority bound to it is permanently fenced.
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
      std::filesystem::temp_directory_path() / "control-plane-epoch-examples" / "controller_registration";
  std::error_code ignored;
  std::filesystem::remove_all(directory, ignored);
  std::filesystem::create_directories(directory, ignored);
  return directory;
}

/// Unwraps a Result. A rejection that the example did not expect is an explicit
/// failure rather than silently ignored state.
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

[[nodiscard]] AuthorityScopeSet scope_set(std::vector<std::string_view> names) {
  std::vector<ScopeName> scopes;
  scopes.reserve(names.size());
  for (const std::string_view name : names) {
    scopes.push_back(unwrap(ScopeName::parse(name, "scope name"), name));
  }
  return unwrap(AuthorityScopeSet::create(std::move(scopes)), "scope set");
}

[[nodiscard]] ProvenanceInput provenance(ProvenanceSourceKind kind, std::string_view source) {
  return unwrap(ProvenanceInput::from_source(kind, source), "provenance");
}

[[nodiscard]] ScopeName scope(std::string_view name) {
  return unwrap(ScopeName::parse(name, "scope name"), name);
}

}  // namespace

int main() {
  using namespace dccp::epoch;

  try {
    const std::filesystem::path directory = prepare_store_directory();
    std::cout << "example=controller_registration\n";
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
    std::cout << "domain=" << authority.status().domain().to_string()
              << " epoch=" << authority.current_epoch().to_string() << '\n';

    // The authority root acquires administrative authority through the
    // documented standing-root path (no sponsor) and becomes the sponsor for
    // everything this example grants afterwards.
    const ControllerRecord root_record =
        unwrap(authority.controller_record(ControllerId::from_trusted("authority-root")), "authority root record");
    AcquireAuthorityRequest root_request;
    root_request.controller = ControllerId::from_trusted("authority-root");
    root_request.incarnation = root_record.incarnation_id();
    root_request.scopes = scope_set({authority_grant_scope().view()});
    root_request.provenance = provenance(ProvenanceSourceKind::Operator, "facility-operator");
    const AuthorityGrantView root_view =
        unwrap(authority.acquire_authority(std::move(root_request)), "root authority");
    if (!root_view.mutation_authority().has_value()) {
      std::cerr << "the root acquired no mutation authority\n";
      return 1;
    }
    const MutationAuthority sponsor = *root_view.mutation_authority();
    std::cout << "root-grant " << root_view.record().to_string() << '\n';

    // First boot of "controller-7".
    RegisterControllerRequest first_request;
    first_request.controller = unwrap(ControllerId::parse("controller-7", "controller"), "controller");
    first_request.provenance = provenance(ProvenanceSourceKind::Controller, "controller-7");
    const ControllerRegistration first =
        unwrap(authority.register_controller(std::move(first_request)), "first registration");
    std::cout << "registration-1 " << first.to_string() << '\n';
    if (first.incarnation_number().value() != 1) {
      std::cerr << "the first registration did not produce incarnation 1\n";
      return 1;
    }

    // Authority acquired by that first incarnation.
    AcquireAuthorityRequest grant_request;
    grant_request.controller = first.controller();
    grant_request.incarnation = first.incarnation_id();
    grant_request.scopes = scope_set({std::string_view("facility.inventory")});
    grant_request.sponsor = sponsor;
    grant_request.provenance = provenance(ProvenanceSourceKind::Controller, "controller-7");
    const AuthorityGrantView grant =
        unwrap(authority.acquire_authority(std::move(grant_request)), "grant to incarnation 1");
    if (!grant.mutation_authority().has_value()) {
      std::cerr << "the grant carries no mutation authority\n";
      return 1;
    }
    const MutationAuthority first_token = *grant.mutation_authority();
    const ValidationOutcome before_restart = authority.validate_mutation(first_token, scope("facility.inventory"));
    std::cout << "grant-to-incarnation-1 grant=" << grant.record().id().to_string()
              << " incarnation=" << grant.record().incarnation_number().to_string()
              << " validate-before-restart=" << (before_restart.accepted() ? "accepted" : "rejected")
              << " code=" << validation_code(before_restart) << '\n';

    // Restart: the controller identity is reused, the incarnation is not.
    RegisterControllerRequest second_request;
    second_request.controller = first.controller();
    second_request.provenance = provenance(ProvenanceSourceKind::Controller, "controller-7");
    const ControllerRegistration second =
        unwrap(authority.register_controller(std::move(second_request)), "second registration");
    std::cout << "registration-2 " << second.to_string() << '\n';

    const ControllerRecord current = unwrap(authority.controller_record(first.controller()), "controller record");
    std::cout << "controller-record " << current.to_string() << '\n';
    std::cout << "incarnation-1-id=" << first.incarnation_id().to_hex() << '\n';
    std::cout << "incarnation-2-id=" << second.incarnation_id().to_hex() << '\n';
    std::cout << "incarnation-identity-fresh=" << (first.incarnation_id() != second.incarnation_id() ? "yes" : "no")
              << " old-is-still-current=" << (current.incarnation_id() == first.incarnation_id() ? "yes" : "no")
              << '\n';
    if (first.incarnation_id() == second.incarnation_id() || current.incarnation_id() != second.incarnation_id()) {
      std::cerr << "re-registration did not produce a fresh current incarnation\n";
      return 1;
    }

    // The token held by the pre-restart incarnation is now fenced.
    const ValidationOutcome after_restart = authority.validate_mutation(first_token, scope("facility.inventory"));
    std::cout << "validate-old-incarnation accepted=" << (after_restart.accepted() ? "yes" : "no")
              << " code=" << validation_code(after_restart) << '\n';

    // A restarted controller cannot acquire authority by presenting the old
    // incarnation identity either.
    AcquireAuthorityRequest stale_request;
    stale_request.controller = first.controller();
    stale_request.incarnation = first.incarnation_id();
    stale_request.scopes = scope_set({std::string_view("facility.inventory")});
    stale_request.sponsor = sponsor;
    stale_request.provenance = provenance(ProvenanceSourceKind::Controller, "controller-7");
    const Result<AuthorityGrantView> stale = authority.acquire_authority(std::move(stale_request));
    std::cout << "acquire-with-old-incarnation accepted=" << (stale.has_value() ? "yes" : "no")
              << " code=" << stale.rejection().token() << '\n';
    if (stale.has_value() || stale.rejection().code() != ErrorCode::IncarnationSuperseded) {
      std::cerr << "the superseded incarnation was not refused with incarnation.superseded\n";
      return 1;
    }

    // The current incarnation can still be granted authority.
    AcquireAuthorityRequest fresh_request;
    fresh_request.controller = second.controller();
    fresh_request.incarnation = second.incarnation_id();
    fresh_request.scopes = scope_set({std::string_view("facility.inventory")});
    fresh_request.sponsor = sponsor;
    fresh_request.provenance = provenance(ProvenanceSourceKind::Controller, "controller-7");
    const AuthorityGrantView fresh =
        unwrap(authority.acquire_authority(std::move(fresh_request)), "grant to incarnation 2");
    std::cout << "grant-to-incarnation-2 grant=" << fresh.record().id().to_string()
              << " incarnation=" << fresh.record().incarnation_number().to_string() << '\n';

    authority.close();
    std::cout << "done=controller_registration\n";
    return 0;
  } catch (const EpochError& error) {
    std::cerr << "failure: " << error.explanation().to_string() << '\n';
    return 1;
  } catch (const std::exception& error) {
    std::cerr << "failure: " << error.what() << '\n';
    return 1;
  }
}
