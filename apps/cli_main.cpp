// Control Plane Epoch 1.0.0 - Summon Software Labs
// control-plane-epoch-cli: read-only inspection plus narrowly scoped operator
// commands.
//
// Read-only commands open the store without the writer lock, so they are safe to
// run against a live authority runtime. Mutating commands take the exclusive
// writer lock and are therefore refused while a runtime holds it, and they face
// exactly the same authority checks as any other consumer: every mutation needs
// a sponsoring token that the authority issued.
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
    "usage: control-plane-epoch-cli COMMAND [options]\n"
    "read-only commands (no writer lock):\n"
    "  status     --store DIR\n"
    "  verify     --store DIR\n"
    "  controllers --store DIR [--from ID] [--limit N]\n"
    "  grants     --store DIR [--from N] [--limit N]\n"
    "  history    --store DIR [--from N] [--limit N]\n"
    "  revocations --store DIR [--from N] [--limit N]\n"
    "  recovery   --store DIR [--recovery-policy P] [--asserted-epoch-floor N]\n"
    "  inspect-token --token TEXT\n"
    "  snapshot   --store DIR --out FILE\n"
    "mutating commands (exclusive writer lock required):\n"
    "  init       --store DIR --domain ID --root CONTROLLER --scopes a,b,c [--source ID]\n"
    "  root-authority --store DIR [--source ID]   acquire the root's administrative authority\n"
    "  register   --store DIR --controller ID [--source ID]\n"
    "  grant      --store DIR --controller ID --incarnation HEX --scopes a,b --sponsor TOKEN\n"
    "             [--class mutation|observation] [--source ID]\n"
    "  advance    --store DIR --expected-epoch N --sponsor TOKEN [--reason R] [--source ID]\n"
    "  revoke     --store DIR --target controller|grant --controller ID [--through N] [--grant N]\n"
    "             --sponsor TOKEN [--reason R] [--source ID]\n"
    "  validate   --store DIR --token TEXT --scope NAME [--class mutation|observation]\n";

[[nodiscard]] dccp::epoch::StoreOpenOptions open_options(const cpe_app::Arguments& arguments,
                                                         dccp::epoch::StoreOpenMode mode) {
  dccp::epoch::StoreOpenOptions options;
  options.directory = arguments.require("store");
  options.mode = mode;
  if (const auto policy = arguments.get("recovery-policy"); policy.has_value()) {
    dccp::epoch::Result<dccp::epoch::RecoveryPolicy> parsed = dccp::epoch::parse_recovery_policy(*policy);
    if (!parsed.has_value()) {
      throw cpe_app::UsageError("unknown recovery policy '" + *policy + "'");
    }
    options.recovery_policy = parsed.value();
  }
  if (const auto floor = arguments.get_unsigned("asserted-epoch-floor"); floor.has_value()) {
    options.asserted_epoch_floor = *floor;
  }
  return options;
}

[[nodiscard]] dccp::epoch::Result<dccp::epoch::ProvenanceInput> cli_provenance(
    const cpe_app::Arguments& arguments) {
  const std::string source = arguments.has("source") ? arguments.require("source") : std::string("operator");
  return cpe_app::make_provenance("operator", source, arguments.has("note") ? arguments.require("note") : "");
}

[[nodiscard]] dccp::epoch::Result<dccp::epoch::MutationAuthority> cli_token(const cpe_app::Arguments& arguments) {
  if (arguments.has("sponsor-file")) {
    return dccp::epoch::MutationAuthority::parse(
        cpe_app::Arguments::read_argument_file(arguments.require("sponsor-file")));
  }
  return dccp::epoch::MutationAuthority::parse(arguments.require("sponsor"));
}

[[nodiscard]] dccp::epoch::HistoryQuery history_query(const cpe_app::Arguments& arguments) {
  dccp::epoch::HistoryQuery query;
  if (const auto from = arguments.get_unsigned("from"); from.has_value()) {
    query.from_sequence = dccp::epoch::TransitionSequence::from_trusted(*from);
  }
  if (const auto limit = arguments.get_unsigned("limit"); limit.has_value()) {
    query.limit = static_cast<std::size_t>(*limit);
  }
  return query;
}

void print_transition(const dccp::epoch::EpochTransitionRecord& record) {
  std::cout << "transition " << record.to_string() << '\n';
  std::cout << "  provenance " << record.provenance().to_string() << '\n';
}

void print_revocation(const dccp::epoch::RevocationRecord& record) {
  std::cout << "revocation " << record.to_string() << '\n';
  std::cout << "  provenance " << record.provenance().to_string() << '\n';
}

}  // namespace

int main(int argc, char** argv) {
  using namespace dccp::epoch;

  try {
    const cpe_app::Arguments arguments = cpe_app::Arguments::parse(argc, argv);
    if (arguments.has("help") || arguments.positionals().empty()) {
      std::cout << kUsage;
      return arguments.positionals().empty() ? cpe_app::exit_usage : cpe_app::exit_ok;
    }
    const std::string command = arguments.positionals().front();

    // -- read-only inspection ------------------------------------------------
    if (command == "verify") {
      const StoreInspection inspection = inspect_store(arguments.require("store"));
      std::cout << "store " << inspection.to_string() << '\n';
      for (const std::string& problem : inspection.problems()) {
        std::cout << "problem " << problem << '\n';
      }
      return inspection.verified() ? cpe_app::exit_ok : cpe_app::exit_rejected;
    }

    if (command == "recovery") {
      // A repairing policy writes: it republishes the retained generation or
      // quarantines damaged state. Those policies therefore need the writer lock,
      // while the inspecting default stays read-only and never repairs.
      const std::optional<std::string> policy = arguments.get("recovery-policy");
      const bool repairing = policy.has_value() && *policy != "refuse-on-damage";
      ControlPlaneEpochAuthority authority(open_options(arguments, repairing ? StoreOpenMode::ReadWrite
                                                                            : StoreOpenMode::ReadOnly));
      std::cout << "recovery " << authority.recovery().to_string() << '\n';
      return cpe_app::exit_ok;
    }

    if (command == "inspect-token") {
      const std::string text = arguments.has("token") ? arguments.require("token")
                                                      : cpe_app::Arguments::read_argument_file(
                                                            arguments.require("token-file"));
      Result<MutationAuthority> token = MutationAuthority::parse(text);
      if (!token.has_value()) {
        return cpe_app::report_rejection(token.rejection());
      }
      std::cout << "token domain=" << token.value().domain().to_string()
                << " class=" << authority_class_token(token.value().authority_class())
                << " epoch=" << token.value().epoch().to_string()
                << " controller=" << token.value().controller().to_string()
                << " incarnation=" << token.value().incarnation().to_hex()
                << " grant=" << token.value().grant().to_string()
                << " scopes=" << token.value().scopes().to_string()
                << " fencing=" << token.value().fencing_token().to_hex() << '\n';
      return cpe_app::exit_ok;
    }

    if (command == "snapshot") {
      ControlPlaneEpochAuthority authority(open_options(arguments, StoreOpenMode::ReadOnly));
      authority.write_snapshot_artifact(arguments.require("out"));
      std::cout << "snapshot written=" << arguments.require("out") << '\n';
      return cpe_app::exit_ok;
    }

    if (command == "status" || command == "controllers" || command == "grants" || command == "history" ||
        command == "revocations") {
      ControlPlaneEpochAuthority authority(open_options(arguments, StoreOpenMode::ReadOnly));
      if (!authority.initialized()) {
        std::cout << "status initialized=false\n";
        return cpe_app::exit_ok;
      }
      if (command == "status") {
        std::cout << "status " << authority.status().to_string() << '\n';
        std::cout << "accounting " << authority.accounting().to_string() << '\n';
        std::cout << "recovery " << authority.recovery().to_string() << '\n';
        return cpe_app::exit_ok;
      }
      if (command == "controllers") {
        ControllerQuery query;
        if (arguments.has("from")) {
          Result<ControllerId> from = ControllerId::parse(arguments.require("from"), "controller cursor");
          if (!from.has_value()) {
            return cpe_app::report_rejection(from.rejection());
          }
          query.from_controller = from.move_value();
        }
        if (const auto limit = arguments.get_unsigned("limit"); limit.has_value()) {
          query.limit = static_cast<std::size_t>(*limit);
        }
        Result<ControllerPage> page = authority.controllers(query);
        if (!page.has_value()) {
          return cpe_app::report_rejection(page.rejection());
        }
        std::cout << "controllers total=" << page.value().total_count() << '\n';
        for (const ControllerRecord& record : page.value().records()) {
          std::cout << "controller " << record.to_string() << '\n';
        }
        return cpe_app::exit_ok;
      }
      if (command == "grants") {
        GrantQuery query;
        if (const auto from = arguments.get_unsigned("from"); from.has_value()) {
          query.from_grant = GrantId::from_trusted(*from);
        }
        if (const auto limit = arguments.get_unsigned("limit"); limit.has_value()) {
          query.limit = static_cast<std::size_t>(*limit);
        }
        Result<GrantPage> page = authority.grants(query);
        if (!page.has_value()) {
          return cpe_app::report_rejection(page.rejection());
        }
        std::cout << "grants epoch=" << page.value().epoch().to_string()
                  << " total=" << page.value().total_count() << '\n';
        for (const AuthorityGrantRecord& record : page.value().records()) {
          std::cout << "grant " << record.to_string() << '\n';
        }
        return cpe_app::exit_ok;
      }
      if (command == "history") {
        Result<EpochHistoryPage> page = authority.history(history_query(arguments));
        if (!page.has_value()) {
          return cpe_app::report_rejection(page.rejection());
        }
        std::cout << "history total=" << page.value().total_count()
                  << " first_retained=" << page.value().first_retained_sequence()
                  << " trimmed=" << page.value().trimmed_count()
                  << " anchor=" << cpe_app::digest_or_dash(page.value().history_anchor())
                  << " chain_head=" << cpe_app::digest_or_dash(page.value().chain_head()) << '\n';
        for (const EpochTransitionRecord& record : page.value().records()) {
          print_transition(record);
        }
        return cpe_app::exit_ok;
      }
      RevocationQuery query;
      if (const auto from = arguments.get_unsigned("from"); from.has_value()) {
        query.from_sequence = RevocationSequence::from_trusted(*from);
      }
      if (const auto limit = arguments.get_unsigned("limit"); limit.has_value()) {
        query.limit = static_cast<std::size_t>(*limit);
      }
      Result<RevocationPage> page = authority.revocations(query);
      if (!page.has_value()) {
        return cpe_app::report_rejection(page.rejection());
      }
      std::cout << "revocations total=" << page.value().total_count()
                << " first_retained=" << page.value().first_retained_sequence()
                << " trimmed=" << page.value().trimmed_count()
                << " chain_head=" << cpe_app::digest_or_dash(page.value().chain_head()) << '\n';
      for (const RevocationRecord& record : page.value().records()) {
        print_revocation(record);
      }
      return cpe_app::exit_ok;
    }

    // -- mutating commands ---------------------------------------------------
    ControlPlaneEpochAuthority authority(open_options(arguments, StoreOpenMode::ReadWrite));

    if (command == "init") {
      Result<FacilityAuthorityDomainId> domain =
          FacilityAuthorityDomainId::parse(arguments.require("domain"), "authority domain");
      if (!domain.has_value()) {
        return cpe_app::report_rejection(domain.rejection());
      }
      Result<ControllerId> root = ControllerId::parse(arguments.require("root"), "authority root");
      if (!root.has_value()) {
        return cpe_app::report_rejection(root.rejection());
      }
      Result<ProvenanceInput> provenance = cli_provenance(arguments);
      if (!provenance.has_value()) {
        return cpe_app::report_rejection(provenance.rejection());
      }
      InitializeDomainRequest request;
      request.domain = domain.move_value();
      request.authority_root = root.move_value();
      request.provenance = provenance.move_value();
      for (const std::string& scope : arguments.require_list("scopes")) {
        Result<ScopeName> parsed = ScopeName::parse(scope, "declared scope");
        if (!parsed.has_value()) {
          return cpe_app::report_rejection(parsed.rejection());
        }
        request.scopes.push_back(parsed.move_value());
      }
      const Status initialized = authority.initialize(std::move(request));
      if (!initialized.has_value()) {
        return cpe_app::report_rejection(initialized.rejection());
      }
      std::cout << "initialized " << authority.status().to_string() << '\n';
      std::cout << "commit " << (authority.last_commit().has_value() ? authority.last_commit()->to_string()
                                                                    : std::string("none"))
                << '\n';
      return cpe_app::exit_ok;
    }

    if (command == "register") {
      Result<ControllerId> controller = ControllerId::parse(arguments.require("controller"), "controller");
      if (!controller.has_value()) {
        return cpe_app::report_rejection(controller.rejection());
      }
      Result<ProvenanceInput> provenance = cli_provenance(arguments);
      if (!provenance.has_value()) {
        return cpe_app::report_rejection(provenance.rejection());
      }
      RegisterControllerRequest request;
      request.controller = controller.move_value();
      request.provenance = provenance.move_value();
      Result<ControllerRegistration> registration = authority.register_controller(std::move(request));
      if (!registration.has_value()) {
        return cpe_app::report_rejection(registration.rejection());
      }
      std::cout << "registration " << registration.value().to_string() << '\n';
      return cpe_app::exit_ok;
    }

    if (command == "root-authority") {
      // Bootstrap or refresh the authority root's administrative authority for
      // the current epoch. This uses the documented standing-root path and faces
      // the same validation as every other acquisition; it is not a bypass.
      std::vector<ScopeName> requested{authority_grant_scope(), authority_revoke_scope(), epoch_advance_scope()};
      Result<AuthorityScopeSet> scopes = AuthorityScopeSet::create(std::move(requested));
      if (!scopes.has_value()) {
        return cpe_app::report_rejection(scopes.rejection());
      }
      Result<ControllerRecord> root = authority.controller_record(authority.status().authority_root());
      if (!root.has_value()) {
        return cpe_app::report_rejection(root.rejection());
      }
      Result<ProvenanceInput> provenance = cli_provenance(arguments);
      if (!provenance.has_value()) {
        return cpe_app::report_rejection(provenance.rejection());
      }

      AcquireAuthorityRequest request;
      request.authority_class = AuthorityClass::Mutation;
      request.controller = root.value().controller();
      request.incarnation = root.value().incarnation_id();
      request.scopes = scopes.move_value();
      request.provenance = provenance.move_value();

      Result<AuthorityGrantView> grant = authority.acquire_authority(std::move(request));
      if (!grant.has_value()) {
        return cpe_app::report_rejection(grant.rejection());
      }
      std::cout << "grant " << grant.value().record().to_string()
                << " replayed=" << cpe_app::bool_token(grant.value().replayed()) << '\n';
      if (grant.value().mutation_authority().has_value()) {
        std::cout << "token " << grant.value().mutation_authority()->to_string() << '\n';
      }
      return cpe_app::exit_ok;
    }

    if (command == "grant") {
      Result<ControllerId> controller = ControllerId::parse(arguments.require("controller"), "controller");
      if (!controller.has_value()) {
        return cpe_app::report_rejection(controller.rejection());
      }
      Result<ControllerIncarnationId> incarnation = cpe_app::parse_incarnation(arguments.require("incarnation"));
      if (!incarnation.has_value()) {
        return cpe_app::report_rejection(incarnation.rejection());
      }
      Result<ProvenanceInput> provenance = cli_provenance(arguments);
      if (!provenance.has_value()) {
        return cpe_app::report_rejection(provenance.rejection());
      }
      Result<MutationAuthority> sponsor = cli_token(arguments);
      if (!sponsor.has_value()) {
        return cpe_app::report_rejection(sponsor.rejection());
      }

      AcquireAuthorityRequest request;
      request.controller = controller.move_value();
      request.incarnation = incarnation.value();
      request.provenance = provenance.move_value();
      request.sponsor = sponsor.move_value();
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

      Result<AuthorityGrantView> grant = authority.acquire_authority(std::move(request));
      if (!grant.has_value()) {
        return cpe_app::report_rejection(grant.rejection());
      }
      std::cout << "grant " << grant.value().record().to_string()
                << " replayed=" << cpe_app::bool_token(grant.value().replayed()) << '\n';
      if (grant.value().mutation_authority().has_value()) {
        std::cout << "token " << grant.value().mutation_authority()->to_string() << '\n';
      } else if (grant.value().observation_authority().has_value()) {
        std::cout << "token " << grant.value().observation_authority()->to_string() << '\n';
      }
      return cpe_app::exit_ok;
    }

    if (command == "advance") {
      const std::optional<std::uint64_t> expected = arguments.get_unsigned("expected-epoch");
      if (!expected.has_value()) {
        throw cpe_app::UsageError("--expected-epoch is required for advance");
      }
      Result<Epoch> expected_epoch = Epoch::from_value(*expected);
      if (!expected_epoch.has_value()) {
        return cpe_app::report_rejection(expected_epoch.rejection());
      }
      Result<ProvenanceInput> provenance = cli_provenance(arguments);
      if (!provenance.has_value()) {
        return cpe_app::report_rejection(provenance.rejection());
      }
      Result<MutationAuthority> sponsor = cli_token(arguments);
      if (!sponsor.has_value()) {
        return cpe_app::report_rejection(sponsor.rejection());
      }

      AdvanceEpochRequest request;
      request.expected_current = expected_epoch.value();
      request.authority = sponsor.move_value();
      request.provenance = provenance.move_value();
      if (arguments.has("reason")) {
        Result<EpochTransitionReason> reason = parse_epoch_transition_reason(arguments.require("reason"));
        if (!reason.has_value()) {
          return cpe_app::report_rejection(reason.rejection());
        }
        request.reason = reason.value();
      }

      Result<EpochTransitionRecord> transition = authority.advance_epoch(std::move(request));
      if (!transition.has_value()) {
        return cpe_app::report_rejection(transition.rejection());
      }
      std::cout << "advance " << transition.value().to_string() << '\n';
      return cpe_app::exit_ok;
    }

    if (command == "revoke") {
      Result<ProvenanceInput> provenance = cli_provenance(arguments);
      if (!provenance.has_value()) {
        return cpe_app::report_rejection(provenance.rejection());
      }
      Result<MutationAuthority> sponsor = cli_token(arguments);
      if (!sponsor.has_value()) {
        return cpe_app::report_rejection(sponsor.rejection());
      }
      Result<ControllerId> controller = ControllerId::parse(arguments.require("controller"), "controller");
      if (!controller.has_value()) {
        return cpe_app::report_rejection(controller.rejection());
      }

      const std::string target = arguments.require("target");
      RevokeAuthorityRequest request;
      if (target == "grant") {
        const std::optional<std::uint64_t> grant = arguments.get_unsigned("grant");
        if (!grant.has_value()) {
          throw cpe_app::UsageError("--grant is required for --target grant");
        }
        Result<GrantId> grant_id = GrantId::from_value(*grant, "grant");
        if (!grant_id.has_value()) {
          return cpe_app::report_rejection(grant_id.rejection());
        }
        request.target = RevocationTarget::grant(grant_id.value(), controller.move_value());
      } else if (target == "controller") {
        if (const auto through = arguments.get_unsigned("through"); through.has_value()) {
          request.target = RevocationTarget::controller_through(
              controller.move_value(), IncarnationNumber::from_trusted(*through));
        } else {
          request.target = RevocationTarget::controller_all(controller.move_value());
        }
      } else {
        throw cpe_app::UsageError("--target must be controller or grant");
      }

      request.authority = sponsor.move_value();
      request.provenance = provenance.move_value();
      if (arguments.has("reason")) {
        Result<RevocationReason> reason = parse_revocation_reason(arguments.require("reason"));
        if (!reason.has_value()) {
          return cpe_app::report_rejection(reason.rejection());
        }
        request.reason = reason.value();
      }

      Result<RevocationRecord> revocation = authority.revoke_authority(std::move(request));
      if (!revocation.has_value()) {
        return cpe_app::report_rejection(revocation.rejection());
      }
      std::cout << "revocation " << revocation.value().to_string() << '\n';
      return cpe_app::exit_ok;
    }

    if (command == "validate") {
      const std::string text =
          arguments.has("token") ? arguments.require("token")
                                 : cpe_app::Arguments::read_argument_file(arguments.require("token-file"));
      Result<ScopeName> scope = ScopeName::parse(arguments.require("scope"), "scope name");
      if (!scope.has_value()) {
        return cpe_app::report_rejection(scope.rejection());
      }
      const bool observation = arguments.has("class") && arguments.require("class") == "observation";
      if (observation) {
        Result<ObservationAuthority> token = ObservationAuthority::parse(text);
        if (!token.has_value()) {
          return cpe_app::report_rejection(token.rejection());
        }
        return cpe_app::report_rejection(authority.validate_observation(token.value(), scope.value()));
      }
      Result<MutationAuthority> token = MutationAuthority::parse(text);
      if (!token.has_value()) {
        return cpe_app::report_rejection(token.rejection());
      }
      return cpe_app::report_rejection(authority.validate_mutation(token.value(), scope.value()));
    }

    throw cpe_app::UsageError("unknown command '" + command + "'");
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
