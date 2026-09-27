// Control Plane Epoch 1.0.0 - Summon Software Labs
// control-plane-epoch-authority: the authoritative epoch runtime of one
// facility authority domain.
//
// The runtime owns the store's exclusive writer lock for its lifetime and serves
// remote controllers over the framed transport. Every request is handled by the
// same library call a local consumer would make; the runtime adds transport, not
// authority.
#include <cstdlib>
#include <exception>
#include <iostream>
#include <string>

#include "control_plane_epoch/control_plane_epoch.hpp"

#include "arguments.hpp"
#include "tool_support.hpp"

namespace {

constexpr const char* kUsage =
    "usage: control-plane-epoch-authority --store DIR [options]\n"
    "  --store DIR                     durable store directory (required)\n"
    "  --bind ADDRESS                  listen address (default 127.0.0.1)\n"
    "  --port N                        listen port, 0 for ephemeral (default 0)\n"
    "  --port-file FILE                write the effective endpoint to FILE\n"
    "  --init                          create the authority domain if absent\n"
    "  --domain ID                     domain identifier (with --init)\n"
    "  --root CONTROLLER               authority root controller (with --init)\n"
    "  --scopes a,b,c                  declared scopes (with --init)\n"
    "  --source ID                     provenance source (default operator)\n"
    "  --recovery-policy POLICY        refuse-on-damage | adopt-previous-generation |\n"
    "                                  reinitialize-domain (default refuse-on-damage)\n"
    "  --asserted-epoch-floor N        operator assertion for reinitialize-domain\n"
    "  --read-only                     serve inspection only; never writes\n"
    "  --workers N                     worker threads (default 4)\n"
    "  --queue-depth N                 accepted-session bound (default 256)\n"
    "  --max-connections N             concurrent session bound (default 128)\n"
    "  --max-requests N                stop after N served requests (default 0: unbounded)\n"
    "  --max-requests-per-connection N bound per session (default 1000000)\n";

[[nodiscard]] dccp::epoch::RecoveryPolicy recovery_policy_from(const std::string& token) {
  dccp::epoch::Result<dccp::epoch::RecoveryPolicy> policy = dccp::epoch::parse_recovery_policy(token);
  if (!policy.has_value()) {
    throw cpe_app::UsageError("unknown recovery policy '" + token + "'");
  }
  return policy.value();
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

    StoreOpenOptions options;
    options.directory = arguments.require("store");
    options.mode = arguments.has("read-only") ? StoreOpenMode::ReadOnly : StoreOpenMode::ReadWrite;
    if (const auto policy = arguments.get("recovery-policy"); policy.has_value()) {
      options.recovery_policy = recovery_policy_from(*policy);
    }
    if (const auto floor = arguments.get_unsigned("asserted-epoch-floor"); floor.has_value()) {
      options.asserted_epoch_floor = *floor;
    }

    ControlPlaneEpochAuthority authority(options);

    cpe_app::print_line("authority-recovery " + authority.recovery().to_string());

    if (arguments.has("init")) {
      if (authority.initialized()) {
        cpe_app::print_line("authority-init skipped=already-initialized");
      } else {
        Result<FacilityAuthorityDomainId> domain =
            FacilityAuthorityDomainId::parse(arguments.require("domain"), "authority domain");
        if (!domain.has_value()) {
          return cpe_app::report_rejection(domain.rejection());
        }
        Result<ControllerId> root = ControllerId::parse(arguments.require("root"), "authority root");
        if (!root.has_value()) {
          return cpe_app::report_rejection(root.rejection());
        }
        Result<ProvenanceInput> provenance = cpe_app::make_provenance(
            arguments.has("source") ? "operator" : "initialization",
            arguments.has("source") ? arguments.require("source") : std::string("operator"), std::string{});
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
        cpe_app::print_line("authority-init accepted");
      }
    }

    ServerOptions server_options;
    if (const auto bind = arguments.get("bind"); bind.has_value()) {
      server_options.bind_address = *bind;
    }
    if (const auto port = arguments.get_unsigned("port"); port.has_value()) {
      if (*port > 65535u) {
        throw cpe_app::UsageError("--port must be between 0 and 65535");
      }
      server_options.port = static_cast<std::uint16_t>(*port);
    }
    if (const auto workers = arguments.get_unsigned("workers"); workers.has_value()) {
      server_options.workers = static_cast<std::uint32_t>(*workers);
    }
    if (const auto depth = arguments.get_unsigned("queue-depth"); depth.has_value()) {
      server_options.queue_depth = static_cast<std::size_t>(*depth);
    }
    if (const auto connections = arguments.get_unsigned("max-connections"); connections.has_value()) {
      server_options.max_connections = static_cast<std::size_t>(*connections);
    }
    if (const auto per_connection = arguments.get_unsigned("max-requests-per-connection");
        per_connection.has_value()) {
      server_options.max_requests_per_connection = *per_connection;
    }

    EpochAuthorityServer server(authority, server_options);
    server.start();

    if (const auto port_file = arguments.get("port-file"); port_file.has_value()) {
      cpe_app::Arguments::write_argument_file(*port_file, server.endpoint());
    }

    const std::string epoch_text = authority.initialized() ? authority.current_epoch().to_string() : std::string("-");
    const std::string domain_text = authority.initialized() ? authority.status().domain().to_string() : std::string("-");
    std::string ready = "authority-ready endpoint=" + server.endpoint();
    ready += " domain=" + domain_text;
    ready += " epoch=" + epoch_text;
    ready += " protocol=" + std::to_string(protocol_version);
    cpe_app::print_line(ready);

    const std::uint64_t max_requests = arguments.require_unsigned("max-requests", 0);
    const std::uint64_t served = server.accept_until(max_requests);
    server.stop();

    cpe_app::print_line("authority-stopped served=" + std::to_string(served));
    cpe_app::print_line("authority-accounting " + server.accounting().to_string());
    authority.close();
    return cpe_app::exit_ok;
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
