// Control Plane Epoch 1.0.0 - Summon Software Labs
// Example: revocation.
//
// Revocation is durable, monotonic, and idempotent. This example revokes one
// grant and then one controller, prints the revocation records that were
// committed, and shows the exact code each revoked token produces when it is
// presented. A controller-level revocation is monotonic without being
// permanent: a later incarnation of the same controller can be granted
// authority again.
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
      std::filesystem::temp_directory_path() / "control-plane-epoch-examples" / "revocation";
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

/// Registers a controller and grants it one scope, sponsored by the caller.
[[nodiscard]] AuthorityGrantView register_and_grant(ControlPlaneEpochAuthority& authority,
                                                    std::string_view controller_text, std::string_view scope_text,
                                                    const MutationAuthority& sponsor) {
  RegisterControllerRequest register_request;
  register_request.controller =
      unwrap(ControllerId::parse(controller_text, "controller"), "controller identifier");
  register_request.provenance = provenance(ProvenanceSourceKind::Controller, controller_text);
  const ControllerRegistration registration =
      unwrap(authority.register_controller(std::move(register_request)), "registration");
  std::cout << "registration " << registration.to_string() << '\n';

  AcquireAuthorityRequest grant_request;
  grant_request.controller = registration.controller();
  grant_request.incarnation = registration.incarnation_id();
  grant_request.scopes = scope_set({scope_text});
  grant_request.sponsor = sponsor;
  grant_request.provenance = provenance(ProvenanceSourceKind::Controller, controller_text);
  return unwrap(authority.acquire_authority(std::move(grant_request)), "scoped authority");
}

}  // namespace

int main() {
  using namespace dccp::epoch;

  try {
    const std::filesystem::path directory = prepare_store_directory();
    std::cout << "example=revocation\n";
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
    AcquireAuthorityRequest admin_request;
    admin_request.controller = root;
    admin_request.incarnation = root_record.incarnation_id();
    admin_request.scopes = scope_set({authority_grant_scope().view(), authority_revoke_scope().view()});
    admin_request.provenance = provenance(ProvenanceSourceKind::Operator, "facility-operator");
    const AuthorityGrantView admin_view =
        unwrap(authority.acquire_authority(std::move(admin_request)), "administrative authority");
    if (!admin_view.mutation_authority().has_value()) {
      std::cerr << "the authority root acquired no administrative authority\n";
      return 1;
    }
    const MutationAuthority admin = *admin_view.mutation_authority();

    // Grant 1, then revoke exactly that grant.
    const AuthorityGrantView first = register_and_grant(authority, "worker-1", "facility.inventory", admin);
    if (!first.mutation_authority().has_value()) {
      std::cerr << "worker-1 acquired no mutation authority\n";
      return 1;
    }
    const MutationAuthority first_token = *first.mutation_authority();
    const GrantId first_grant = first.record().id();
    const ValidationOutcome first_before = authority.validate_mutation(first_token, scope("facility.inventory"));
    std::cout << "grant-1 " << first.record().to_string() << '\n';
    std::cout << "grant-1-validate-before-revocation accepted=" << (first_before.accepted() ? "yes" : "no")
              << " code=" << validation_code(first_before) << '\n';

    RevokeAuthorityRequest grant_revocation;
    grant_revocation.target =
        RevocationTarget::grant(first_grant, unwrap(ControllerId::parse("worker-1", "controller"), "controller"));
    grant_revocation.reason = RevocationReason::OperatorRequest;
    grant_revocation.authority = admin;
    grant_revocation.provenance = provenance(ProvenanceSourceKind::Operator, "facility-operator");
    const RevocationRecord revoked_grant =
        unwrap(authority.revoke_authority(std::move(grant_revocation)), "grant revocation");
    std::cout << "revocation-grant " << revoked_grant.to_string() << '\n';
    if (revoked_grant.fenced_grant_count() != 1 || revoked_grant.replayed()) {
      std::cerr << "the grant revocation did not fence exactly one live grant\n";
      return 1;
    }

    const ValidationOutcome first_after = authority.validate_mutation(first_token, scope("facility.inventory"));
    std::cout << "grant-1-validate-after-revocation accepted=" << (first_after.accepted() ? "yes" : "no")
              << " code=" << validation_code(first_after) << " detail=" << validation_detail(first_after) << '\n';
    if (first_after.accepted() || first_after.code() != ErrorCode::AuthorityRevoked) {
      std::cerr << "the revoked grant was not refused with authority.revoked\n";
      return 1;
    }
    std::cout << "grant-1-record " << unwrap(authority.grant_record(first_grant), "grant record").to_string() << '\n';

    // Grant 2, then revoke the whole controller through its current
    // incarnation.
    const AuthorityGrantView second = register_and_grant(authority, "controller-8", "facility.topology", admin);
    if (!second.mutation_authority().has_value()) {
      std::cerr << "controller-8 acquired no mutation authority\n";
      return 1;
    }
    const MutationAuthority second_token = *second.mutation_authority();
    std::cout << "grant-2 " << second.record().to_string() << '\n';

    const ControllerId controller_eight =
        unwrap(ControllerId::parse("controller-8", "controller"), "controller identifier");
    RevokeAuthorityRequest controller_revocation;
    controller_revocation.target = RevocationTarget::controller_all(controller_eight);
    controller_revocation.reason = RevocationReason::Decommission;
    controller_revocation.authority = admin;
    controller_revocation.provenance = provenance(ProvenanceSourceKind::Operator, "facility-operator");
    const RevocationRecord revoked_controller =
        unwrap(authority.revoke_authority(std::move(controller_revocation)), "controller revocation");
    std::cout << "revocation-controller " << revoked_controller.to_string() << '\n';
    if (revoked_controller.fenced_grant_count() != 1 || revoked_controller.target_kind() !=
                                                            RevocationTargetKind::ControllerIncarnations) {
      std::cerr << "the controller revocation did not fence the live grant of that controller\n";
      return 1;
    }

    const ValidationOutcome second_after = authority.validate_mutation(second_token, scope("facility.topology"));
    std::cout << "grant-2-validate-after-revocation accepted=" << (second_after.accepted() ? "yes" : "no")
              << " code=" << validation_code(second_after) << '\n';
    if (second_after.accepted() || second_after.code() != ErrorCode::AuthorityRevoked) {
      std::cerr << "the controller-revoked grant was not refused with authority.revoked\n";
      return 1;
    }
    std::cout << "controller-8-record " << unwrap(authority.controller_record(controller_eight), "controller record").to_string()
              << '\n';

    // Repeating a revocation that is already fully in force is accepted and
    // returns the existing record marked as a replay.
    RevokeAuthorityRequest repeated_revocation;
    repeated_revocation.target = RevocationTarget::controller_all(controller_eight);
    repeated_revocation.reason = RevocationReason::Decommission;
    repeated_revocation.authority = admin;
    repeated_revocation.provenance = provenance(ProvenanceSourceKind::Operator, "facility-operator");
    const RevocationRecord replayed =
        unwrap(authority.revoke_authority(std::move(repeated_revocation)), "repeated revocation");
    std::cout << "revocation-repeated accepted=yes replayed=" << (replayed.replayed() ? "yes" : "no")
              << " fenced-grants=" << replayed.fenced_grant_count() << " sequence=" << replayed.sequence().to_string()
              << '\n';
    if (!replayed.replayed() || replayed.fenced_grant_count() != 0) {
      std::cerr << "the repeated revocation did not report itself as a replay\n";
      return 1;
    }

    const RevocationPage page = unwrap(authority.revocations(RevocationQuery{}), "revocation ledger");
    std::cout << "revocation-page total=" << page.total_count() << " retained=" << page.records().size()
              << " first_retained=" << page.first_retained_sequence() << " trimmed=" << page.trimmed_count()
              << " chain_head=" << page.chain_head().to_hex() << '\n';
    for (const RevocationRecord& record : page.records()) {
      std::cout << "revocation-record sequence=" << record.sequence().to_string()
                << " target=" << revocation_target_kind_token(record.target_kind())
                << " controller=" << record.controller().to_string()
                << " reason=" << revocation_reason_token(record.reason())
                << " epoch=" << record.epoch().to_string()
                << " fenced_grants=" << record.fenced_grant_count()
                << " replayed=" << (record.replayed() ? "yes" : "no")
                << " previous=" << record.previous_record_digest().to_hex()
                << " digest=" << record.record_digest().to_hex() << '\n';
    }

    // Revocation is monotonic without being permanent for a controller: a later
    // incarnation re-registers above the fenced number and can be granted
    // authority again.
    RegisterControllerRequest restart_request;
    restart_request.controller = controller_eight;
    restart_request.provenance = provenance(ProvenanceSourceKind::Controller, "controller-8");
    const ControllerRegistration restarted =
        unwrap(authority.register_controller(std::move(restart_request)), "controller-8 restart");
    std::cout << "controller-8-restart " << restarted.to_string() << '\n';

    AcquireAuthorityRequest renewed_request;
    renewed_request.controller = restarted.controller();
    renewed_request.incarnation = restarted.incarnation_id();
    renewed_request.scopes = scope_set({std::string_view("facility.topology")});
    renewed_request.sponsor = admin;
    renewed_request.provenance = provenance(ProvenanceSourceKind::Controller, "controller-8");
    const AuthorityGrantView renewed =
        unwrap(authority.acquire_authority(std::move(renewed_request)), "renewed authority");
    if (!renewed.mutation_authority().has_value()) {
      std::cerr << "the restarted controller acquired no mutation authority\n";
      return 1;
    }
    const ValidationOutcome renewed_validation =
        authority.validate_mutation(*renewed.mutation_authority(), scope("facility.topology"));
    std::cout << "controller-8-renewed incarnation=" << restarted.incarnation_number().to_string()
              << " grant=" << renewed.record().id().to_string()
              << " accepted=" << (renewed_validation.accepted() ? "yes" : "no")
              << " code=" << validation_code(renewed_validation) << '\n';
    if (!renewed_validation.accepted()) {
      std::cerr << "the restarted controller could not be granted authority again\n";
      return 1;
    }

    std::cout << "status " << authority.status().to_string() << '\n';
    authority.close();
    std::cout << "done=revocation\n";
    return 0;
  } catch (const EpochError& error) {
    std::cerr << "failure: " << error.explanation().to_string() << '\n';
    return 1;
  } catch (const std::exception& error) {
    std::cerr << "failure: " << error.what() << '\n';
    return 1;
  }
}
