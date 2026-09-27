// Control Plane Epoch 1.0.0 - Summon Software Labs
// control-plane-epoch-controller: an independent controller process.
//
// This tool is a real client of the authority runtime. It registers a fresh
// incarnation, acquires scoped authority, validates and attempts mutations, and
// persists tokens locally so that a restarted process can demonstrate that
// reloaded local state is not authority. It never bypasses an authority check:
// every mutation it performs is sponsored by a token the authority issued.
#include <cstdlib>
#include <exception>
#include <iostream>
#include <optional>
#include <string>

#include "control_plane_epoch/control_plane_epoch.hpp"

#include "arguments.hpp"
#include "tool_support.hpp"

namespace {

constexpr const char* kUsage =
    "usage: control-plane-epoch-controller --endpoint HOST:PORT --controller ID --action ACTION [options]\n"
    "  --endpoint HOST:PORT      authority runtime to contact (required)\n"
    "  --controller ID           stable controller identity (required)\n"
    "  --action ACTION           register | acquire | validate | mutate | status | advance | revoke |\n"
    "                            qualify\n"
    "  --token-file FILE         read the authority token from FILE\n"
    "  --sponsor-file FILE       read the sponsoring token from FILE\n"
    "  --save-token FILE         persist the acquired token to FILE\n"
    "  --scopes a,b              scopes to acquire or validate against\n"
    "  --scope NAME              single scope for validate/mutate\n"
    "  --target controller|grant  revocation target kind (revoke)\n"
    "  --target-controller ID    controller being revoked (revoke)\n"
    "  --through N               highest incarnation fenced (revoke)\n"
    "  --grant N                 grant being revoked (revoke)\n"
    "  --class CLASS             mutation | observation (default mutation)\n"
    "  --epoch N                 expected epoch (advance) or producing epoch (qualify)\n"
    "  --incarnation HEX         incarnation identity (qualify)\n"
    "  --digest HEX              content digest (qualify)\n"
    "  --persist-local FILE      write the acquired token to FILE (restart replay test)\n"
    "  --await-stdin             wait for one line on stdin before acting\n"
    "  --source ID               provenance source (default controller)\n";

[[nodiscard]] dccp::epoch::Result<dccp::epoch::MutationAuthority> load_token(const std::string& path) {
  return dccp::epoch::MutationAuthority::parse(cpe_app::Arguments::read_argument_file(path));
}

[[nodiscard]] std::string require_scope(const cpe_app::Arguments& arguments) {
  const std::optional<std::string> scope = arguments.get("scope");
  if (scope.has_value()) {
    return *scope;
  }
  const std::vector<std::string> scopes = arguments.require_list("scopes");
  if (scopes.size() != 1) {
    throw cpe_app::UsageError("--scopes must name exactly one scope for this action");
  }
  return scopes.front();
}

}  // namespace

int main(int argc, char** argv) {
  using namespace dccp::epoch;

  try {
    const cpe_app::Arguments arguments = cpe_app::Arguments::parse(argc, argv);
    if (arguments.has("help")) {
      std::cout << kUsage;
      return cpe_app::exit_ok;
    }

    ClientOptions options;
    const cpe_app::Endpoint endpoint = cpe_app::parse_endpoint(arguments.require("endpoint"));
    options.host = endpoint.host;
    options.port = endpoint.port;

    const std::string controller_text = arguments.require("controller");
    Result<ControllerId> controller = ControllerId::parse(controller_text, "controller");
    if (!controller.has_value()) {
      return cpe_app::report_rejection(controller.rejection());
    }

    Result<ProvenanceInput> provenance = cpe_app::make_provenance(
        "controller", arguments.has("source") ? arguments.require("source") : controller_text, std::string{});
    if (!provenance.has_value()) {
      return cpe_app::report_rejection(provenance.rejection());
    }

    EpochAuthorityClient client(options);
    cpe_app::print_line("controller-endpoint " + client.endpoint().to_string());

    if (arguments.has("await-stdin")) {
      cpe_app::await_stdin_trigger();
    }

    const std::string action = arguments.require("action");

    if (action == "register") {
      RegisterControllerRequest request;
      request.controller = controller.move_value();
      request.provenance = provenance.move_value();
      Result<ControllerRegistration> registration = client.register_controller(std::move(request));
      if (!registration.has_value()) {
        return cpe_app::report_rejection(registration.rejection());
      }
      std::string line = "controller-registered controller=" + registration.value().controller().to_string();
      line += " incarnation=" + registration.value().incarnation_number().to_string();
      line += " incarnation-id=" + registration.value().incarnation_id().to_hex();
      line += " epoch=" + registration.value().epoch().to_string();
      line += " replayed=" + cpe_app::bool_token(registration.value().replayed());
      cpe_app::print_line(line);
      return cpe_app::exit_ok;
    }

    if (action == "acquire") {
      RegisterControllerRequest register_request;
      register_request.controller = controller.value();
      register_request.provenance = provenance.value();
      Result<ControllerRegistration> registration = client.register_controller(std::move(register_request));
      if (!registration.has_value()) {
        return cpe_app::report_rejection(registration.rejection());
      }

      AcquireAuthorityRequest request;
      request.controller = controller.value();
      request.incarnation = registration.value().incarnation_id();
      request.provenance = provenance.value();
      if (arguments.has("class")) {
        Result<AuthorityClass> parsed = parse_authority_class(arguments.require("class"));
        if (!parsed.has_value()) {
          return cpe_app::report_rejection(parsed.rejection());
        }
        request.authority_class = parsed.value();
      }
      std::vector<ScopeName> scopes;
      for (const std::string& scope : arguments.require_list("scopes")) {
        Result<ScopeName> parsed = ScopeName::parse(scope, "scope name");
        if (!parsed.has_value()) {
          return cpe_app::report_rejection(parsed.rejection());
        }
        scopes.push_back(parsed.move_value());
      }
      Result<AuthorityScopeSet> scope_set = AuthorityScopeSet::create(std::move(scopes));
      if (!scope_set.has_value()) {
        return cpe_app::report_rejection(scope_set.rejection());
      }
      request.scopes = scope_set.move_value();

      if (arguments.has("sponsor-file")) {
        Result<MutationAuthority> sponsor = load_token(arguments.require("sponsor-file"));
        if (!sponsor.has_value()) {
          return cpe_app::report_rejection(sponsor.rejection());
        }
        request.sponsor = sponsor.move_value();
      }

      Result<AuthorityGrantView> grant = client.acquire_authority(std::move(request));
      if (!grant.has_value()) {
        return cpe_app::report_rejection(grant.rejection());
      }

      std::string token_text;
      if (grant.value().mutation_authority().has_value()) {
        token_text = grant.value().mutation_authority()->to_string();
      } else if (grant.value().observation_authority().has_value()) {
        token_text = grant.value().observation_authority()->to_string();
      }

      std::string line = "authority-acquired grant=" + grant.value().record().id().to_string();
      line += " epoch=" + grant.value().record().epoch().to_string();
      line += " incarnation=" + registration.value().incarnation_number().to_string();
      line += " replayed=" + cpe_app::bool_token(grant.value().replayed());
      cpe_app::print_line(line);
      cpe_app::print_field("authority-token", token_text);

      for (const std::string& path : {"save-token", "persist-local"}) {
        if (arguments.has(path)) {
          cpe_app::Arguments::write_argument_file(arguments.require(path), token_text);
          cpe_app::print_field("authority-token-file", arguments.require(path));
        }
      }
      return cpe_app::exit_ok;
    }

    if (action == "validate") {
      Result<MutationAuthority> token = load_token(arguments.require("token-file"));
      if (!token.has_value()) {
        return cpe_app::report_rejection(token.rejection());
      }
      Result<ScopeName> scope = ScopeName::parse(require_scope(arguments), "scope name");
      if (!scope.has_value()) {
        return cpe_app::report_rejection(scope.rejection());
      }
      return cpe_app::report_rejection(client.validate_mutation(token.value(), scope.value()));
    }

    if (action == "mutate") {
      // A real mutation: acquire observation authority for one scope using the
      // presented token as sponsor. If the token has been fenced, the authority
      // refuses and no state changes.
      Result<MutationAuthority> token = load_token(arguments.require("token-file"));
      if (!token.has_value()) {
        return cpe_app::report_rejection(token.rejection());
      }
      Result<ScopeName> scope = ScopeName::parse(require_scope(arguments), "scope name");
      if (!scope.has_value()) {
        return cpe_app::report_rejection(scope.rejection());
      }
      Result<AuthorityScopeSet> scope_set = AuthorityScopeSet::create({scope.value()});
      if (!scope_set.has_value()) {
        return cpe_app::report_rejection(scope_set.rejection());
      }

      AcquireAuthorityRequest request;
      request.authority_class = AuthorityClass::Observation;
      request.controller = token.value().controller();
      request.incarnation = token.value().incarnation();
      request.scopes = scope_set.move_value();
      request.sponsor = token.value();
      request.provenance = provenance.value();

      Result<AuthorityGrantView> grant = client.acquire_authority(std::move(request));
      if (!grant.has_value()) {
        cpe_app::print_line("mutation accepted=false code=" + std::string(grant.rejection().token()) +
                            " detail=" + (grant.rejection().detail().empty() ? std::string("-")
                                                                            : grant.rejection().detail()));
        return cpe_app::exit_rejected;
      }
      cpe_app::print_line("mutation accepted=true grant=" + grant.value().record().id().to_string() +
                          " epoch=" + grant.value().record().epoch().to_string());
      return cpe_app::exit_ok;
    }

    if (action == "revoke") {
      Result<MutationAuthority> token = load_token(arguments.require("token-file"));
      if (!token.has_value()) {
        return cpe_app::report_rejection(token.rejection());
      }
      Result<ControllerId> target_controller =
          ControllerId::parse(arguments.require("target-controller"), "revocation target controller");
      if (!target_controller.has_value()) {
        return cpe_app::report_rejection(target_controller.rejection());
      }

      RevokeAuthorityRequest request;
      request.authority = token.value();
      request.provenance = provenance.value();
      const std::string target = arguments.has("target") ? arguments.require("target") : std::string("controller");
      if (target == "grant") {
        const std::optional<std::uint64_t> grant = arguments.get_unsigned("grant");
        if (!grant.has_value()) {
          throw cpe_app::UsageError("--grant is required for --target grant");
        }
        Result<GrantId> grant_id = GrantId::from_value(*grant, "grant");
        if (!grant_id.has_value()) {
          return cpe_app::report_rejection(grant_id.rejection());
        }
        request.target = RevocationTarget::grant(grant_id.value(), target_controller.move_value());
      } else if (target == "controller") {
        if (const auto through = arguments.get_unsigned("through"); through.has_value()) {
          request.target = RevocationTarget::controller_through(
              target_controller.move_value(), IncarnationNumber::from_trusted(*through));
        } else {
          request.target = RevocationTarget::controller_all(target_controller.move_value());
        }
      } else {
        throw cpe_app::UsageError("--target must be controller or grant");
      }
      if (arguments.has("reason")) {
        Result<RevocationReason> reason = parse_revocation_reason(arguments.require("reason"));
        if (!reason.has_value()) {
          return cpe_app::report_rejection(reason.rejection());
        }
        request.reason = reason.value();
      }

      Result<RevocationRecord> revocation = client.revoke_authority(std::move(request));
      if (!revocation.has_value()) {
        cpe_app::print_line("revocation accepted=false code=" + std::string(revocation.rejection().token()) +
                            " detail=" + (revocation.rejection().detail().empty() ? std::string("-")
                                                                                 : revocation.rejection().detail()));
        return cpe_app::exit_rejected;
      }
      cpe_app::print_line("revocation accepted=true " + revocation.value().to_string());
      return cpe_app::exit_ok;
    }

    if (action == "status") {
      Result<AuthorityStatus> status = client.status();
      if (!status.has_value()) {
        return cpe_app::report_rejection(status.rejection());
      }
      cpe_app::print_line("status " + status.value().to_string());
      return cpe_app::exit_ok;
    }

    if (action == "advance") {
      Result<MutationAuthority> token = load_token(arguments.require("token-file"));
      if (!token.has_value()) {
        return cpe_app::report_rejection(token.rejection());
      }
      const std::optional<std::uint64_t> expected = arguments.get_unsigned("epoch");
      if (!expected.has_value()) {
        throw cpe_app::UsageError("--epoch is required for --action advance");
      }
      Result<Epoch> expected_epoch = Epoch::from_value(*expected);
      if (!expected_epoch.has_value()) {
        return cpe_app::report_rejection(expected_epoch.rejection());
      }

      AdvanceEpochRequest request;
      request.expected_current = expected_epoch.value();
      request.authority = token.value();
      request.provenance = provenance.value();
      if (arguments.has("reason")) {
        Result<EpochTransitionReason> reason = parse_epoch_transition_reason(arguments.require("reason"));
        if (!reason.has_value()) {
          return cpe_app::report_rejection(reason.rejection());
        }
        request.reason = reason.value();
      }

      Result<EpochTransitionRecord> transition = client.advance_epoch(std::move(request));
      if (!transition.has_value()) {
        cpe_app::print_line("advance accepted=false code=" +
                            std::string(transition.rejection().token()) + " retryable=" +
                            cpe_app::bool_token(transition.rejection().retryable()) + " detail=" +
                            (transition.rejection().detail().empty() ? std::string("-")
                                                                    : transition.rejection().detail()));
        return cpe_app::exit_rejected;
      }
      std::string line = "advance accepted=true base=" + transition.value().base_epoch().to_string();
      line += " new=" + transition.value().new_epoch().to_string();
      line += " transition=" + transition.value().sequence().to_string();
      line += " fenced-grants=" + std::to_string(transition.value().fenced_grant_count());
      cpe_app::print_line(line);
      return cpe_app::exit_ok;
    }

    if (action == "qualify") {
      const std::optional<std::uint64_t> epoch = arguments.get_unsigned("epoch");
      if (!epoch.has_value()) {
        throw cpe_app::UsageError("--epoch is required for --action qualify");
      }
      Result<Epoch> producing_epoch = Epoch::from_value(*epoch);
      if (!producing_epoch.has_value()) {
        return cpe_app::report_rejection(producing_epoch.rejection());
      }
      Result<ControllerIncarnationId> incarnation = cpe_app::parse_incarnation(arguments.require("incarnation"));
      if (!incarnation.has_value()) {
        return cpe_app::report_rejection(incarnation.rejection());
      }
      Result<ScopeName> scope = ScopeName::parse(require_scope(arguments), "scope name");
      if (!scope.has_value()) {
        return cpe_app::report_rejection(scope.rejection());
      }
      Result<Sha256Digest> digest = Sha256Digest::from_hex(arguments.require("digest"));
      if (!digest.has_value()) {
        return cpe_app::report_rejection(digest.rejection());
      }
      Result<FacilityAuthorityDomainId> domain =
          FacilityAuthorityDomainId::parse(client.endpoint().domain().str(), "authority domain");
      if (!domain.has_value()) {
        return cpe_app::report_rejection(domain.rejection());
      }

      Result<RecoveredStateClaim> claim =
          RecoveredStateClaim::create(domain.move_value(), producing_epoch.value(), controller.move_value(),
                                      incarnation.value(), scope.move_value(), digest.value());
      if (!claim.has_value()) {
        return cpe_app::report_rejection(claim.rejection());
      }
      Result<RecoveryQualification> qualification = client.qualify_recovered_state(claim.value());
      if (!qualification.has_value()) {
        return cpe_app::report_rejection(qualification.rejection());
      }
      cpe_app::print_line("qualification " + qualification.value().to_string());
      return cpe_app::exit_ok;
    }

    throw cpe_app::UsageError("unknown --action '" + action + "'");
  } catch (const cpe_app::UsageError& error) {
    std::cerr << "usage error: " << error.what() << '\n' << kUsage;
    return cpe_app::exit_usage;
  } catch (const dccp::epoch::EpochError& error) {
    return cpe_app::report_failure(error);
  } catch (const std::exception& error) {
    std::cerr << "failure: " << error.what() << '\n';
    return cpe_app::exit_infrastructure;
  }
}

