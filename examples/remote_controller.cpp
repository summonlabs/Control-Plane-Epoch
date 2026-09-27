// Control Plane Epoch 1.0.0 - Summon Software Labs
// Example: an independent controller process talking to a remote authority.
//
// Starts an EpochAuthorityServer on an ephemeral loopback port over an
// in-process authority, connects an EpochAuthorityClient, and performs the
// whole controller lifecycle over the framed transport: register, acquire
// sponsored authority, validate, and advance the epoch. The runtime adds
// transport, not authority: the client sees the same results and the same
// rejection codes a local caller would see.
//
// No timer, sleep, or poll is used anywhere. The acceptor thread blocks in the
// runtime's accept loop, the client blocks on the wire, and shutdown is
// triggered by stop() after the last reply has been received.
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

#include "control_plane_epoch/control_plane_epoch.hpp"

namespace {

using namespace dccp::epoch;

[[nodiscard]] std::filesystem::path prepare_store_directory() {
  const std::filesystem::path directory =
      std::filesystem::temp_directory_path() / "control-plane-epoch-examples" / "remote_controller";
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

/// Owns the acceptor thread of one runtime. The destructor stops the runtime and
/// joins the thread, so the example can never leave a joinable thread or a bound
/// listener behind, not even on an unexpected failure.
class Acceptor {
 public:
  explicit Acceptor(EpochAuthorityServer& server) : server_(&server), thread_([this] { served_ = server_->accept_until(0); }) {}

  ~Acceptor() {
    server_->stop();
    if (thread_.joinable()) {
      thread_.join();
    }
  }

  Acceptor(const Acceptor&) = delete;
  Acceptor& operator=(const Acceptor&) = delete;

  /// Requests served by the acceptor loop. Valid after the destructor has run.
  [[nodiscard]] std::uint64_t served() const noexcept { return served_; }

 private:
  EpochAuthorityServer* server_ = nullptr;
  std::thread thread_;
  std::uint64_t served_ = 0;
};

}  // namespace

int main() {
  using namespace dccp::epoch;

  try {
    const std::filesystem::path directory = prepare_store_directory();
    std::cout << "example=remote_controller\n";
    std::cout << "store=" << directory.string() << '\n';

    StoreOpenOptions store_options;
    store_options.directory = directory;
    ControlPlaneEpochAuthority authority(store_options);

    const FacilityAuthorityDomainId domain =
        unwrap(FacilityAuthorityDomainId::parse("facility-alpha", "authority domain"), "domain");

    InitializeDomainRequest domain_request;
    domain_request.domain = domain;
    domain_request.authority_root = unwrap(ControllerId::parse("authority-root", "authority root"), "authority root");
    for (const std::string_view name : {authority_grant_scope().view(), authority_revoke_scope().view(),
                                        epoch_advance_scope().view(), std::string_view("facility.inventory")}) {
      domain_request.scopes.push_back(scope(name));
    }
    domain_request.provenance = unwrap(ProvenanceInput::from_source(ProvenanceSourceKind::Initialization, "authority"),
                                       "initialization provenance");
    (void)unwrap(authority.initialize(std::move(domain_request)), "domain initialization");

    ServerOptions server_options;
    server_options.bind_address = "127.0.0.1";
    server_options.port = 0;  // ephemeral loopback port
    server_options.workers = 2;
    EpochAuthorityServer server(authority, server_options);
    server.start();
    std::cout << "server endpoint=" << server.endpoint() << " port=" << server.port()
              << " running=" << (server.running() ? "yes" : "no") << '\n';

    Acceptor acceptor(server);

    ClientOptions client_options;
    client_options.host = "127.0.0.1";
    client_options.port = server.port();
    client_options.expected_domain = domain;
    EpochAuthorityClient client(client_options);
    std::cout << "client-endpoint " << client.endpoint().to_string() << '\n';

    // 1. Register the root and the worker over the wire. Registration confers
    //    identity only; it is the discovery step every controller performs.
    RegisterControllerRequest root_register;
    root_register.controller = unwrap(ControllerId::parse("authority-root", "authority root"), "authority root");
    root_register.provenance = unwrap(ProvenanceInput::from_source(ProvenanceSourceKind::Controller, "authority-root"),
                                      "registration provenance");
    const ControllerRegistration root_boot =
        unwrap(client.register_controller(std::move(root_register)), "root registration");
    std::cout << "remote-registration " << root_boot.to_string() << '\n';

    RegisterControllerRequest worker_register;
    worker_register.controller = unwrap(ControllerId::parse("worker-1", "controller"), "controller");
    worker_register.provenance =
        unwrap(ProvenanceInput::from_source(ProvenanceSourceKind::Controller, "worker-1"), "registration provenance");
    const ControllerRegistration worker_boot =
        unwrap(client.register_controller(std::move(worker_register)), "worker registration");
    std::cout << "remote-registration " << worker_boot.to_string() << '\n';

    // 2. The root acquires the reserved administrative scopes through the
    //    standing-root path, over the wire and without a sponsor.
    AcquireAuthorityRequest root_acquire;
    root_acquire.controller = root_boot.controller();
    root_acquire.incarnation = root_boot.incarnation_id();
    root_acquire.scopes =
        scope_set({authority_grant_scope().view(), authority_revoke_scope().view(), epoch_advance_scope().view()});
    root_acquire.provenance =
        unwrap(ProvenanceInput::from_source(ProvenanceSourceKind::Operator, "facility-operator"), "grant provenance");
    const AuthorityGrantView root_grant =
        unwrap(client.acquire_authority(std::move(root_acquire)), "remote standing-root authority");
    if (!root_grant.mutation_authority().has_value()) {
      std::cerr << "the root acquired no mutation authority over the wire\n";
      return 1;
    }
    const MutationAuthority root_token = *root_grant.mutation_authority();
    std::cout << "remote-standing-root " << root_grant.record().to_string() << '\n';

    const ValidationOutcome remote_validation = client.validate_mutation(root_token, epoch_advance_scope());
    std::cout << "remote-validate scope=epoch.advance accepted=" << (remote_validation.accepted() ? "yes" : "no")
              << " code=" << validation_code(remote_validation) << '\n';
    if (!remote_validation.accepted()) {
      std::cerr << "the remotely issued token did not validate over the wire\n";
      return 1;
    }

    // 3. The worker is granted one facility scope, sponsored by the root token,
    //    again entirely over the wire.
    AcquireAuthorityRequest worker_acquire;
    worker_acquire.controller = worker_boot.controller();
    worker_acquire.incarnation = worker_boot.incarnation_id();
    worker_acquire.scopes = scope_set({std::string_view("facility.inventory")});
    worker_acquire.sponsor = root_token;
    worker_acquire.provenance =
        unwrap(ProvenanceInput::from_source(ProvenanceSourceKind::Controller, "worker-1"), "grant provenance");
    const AuthorityGrantView worker_grant =
        unwrap(client.acquire_authority(std::move(worker_acquire)), "remote sponsored authority");
    if (!worker_grant.mutation_authority().has_value()) {
      std::cerr << "the worker acquired no mutation authority over the wire\n";
      return 1;
    }
    const MutationAuthority worker_token = *worker_grant.mutation_authority();
    std::cout << "remote-sponsored-grant " << worker_grant.record().to_string() << '\n';
    const ValidationOutcome worker_validation = client.validate_mutation(worker_token, scope("facility.inventory"));
    std::cout << "remote-validate scope=facility.inventory accepted=" << (worker_validation.accepted() ? "yes" : "no")
              << " code=" << validation_code(worker_validation) << '\n';

    // A scope the remote worker does not hold is refused with the same code a
    // local caller would receive.
    const ValidationOutcome uncovered = client.validate_mutation(worker_token, scope("facility.topology"));
    std::cout << "remote-validate scope=facility.topology accepted=" << (uncovered.accepted() ? "yes" : "no")
              << " code=" << validation_code(uncovered) << '\n';
    if (uncovered.accepted() || uncovered.code() != ErrorCode::ScopeNotGranted) {
      std::cerr << "the remote validation of an uncovered scope was not refused with authority.scope_not_granted\n";
      return 1;
    }

    // 4. Advance the epoch over the wire. The precondition is the epoch the
    //    client learned in the handshake.
    AdvanceEpochRequest advance;
    advance.expected_current = client.endpoint().epoch();
    advance.authority = root_token;
    advance.reason = EpochTransitionReason::OperatorRequest;
    advance.provenance =
        unwrap(ProvenanceInput::from_source(ProvenanceSourceKind::Operator, "facility-operator"), "transition provenance");
    const EpochTransitionRecord transition =
        unwrap(client.advance_epoch(std::move(advance)), "remote epoch advance");
    std::cout << "remote-advance base=" << transition.base_epoch().to_string()
              << " new=" << transition.new_epoch().to_string()
              << " transition=" << transition.sequence().to_string()
              << " fenced-grants=" << transition.fenced_grant_count() << '\n';
    if (transition.new_epoch() != authority.current_epoch()) {
      std::cerr << "the epoch committed over the wire is not the authoritative epoch\n";
      return 1;
    }

    // The same expected epoch is now stale, and the runtime reports the same
    // retryable conflict a local caller sees.
    AdvanceEpochRequest repeated;
    repeated.expected_current = transition.base_epoch();
    repeated.authority = root_token;
    repeated.reason = EpochTransitionReason::OperatorRequest;
    repeated.provenance =
        unwrap(ProvenanceInput::from_source(ProvenanceSourceKind::Operator, "facility-operator"), "transition provenance");
    const Result<EpochTransitionRecord> repeated_result = client.advance_epoch(std::move(repeated));
    std::cout << "remote-advance-repeated accepted=" << (repeated_result.has_value() ? "yes" : "no")
              << " code=" << repeated_result.rejection().token()
              << " retryable=" << (repeated_result.rejection().retryable() ? "yes" : "no") << '\n';
    if (repeated_result.has_value() || repeated_result.rejection().code() != ErrorCode::EpochConflict ||
        !repeated_result.rejection().retryable()) {
      std::cerr << "the repeated remote advancement was not refused with a retryable epoch.conflict\n";
      return 1;
    }

    // 5. Remote inspection sees the committed state.
    const AuthorityStatus remote_status = unwrap(client.status(), "remote status");
    std::cout << "remote-status epoch=" << remote_status.epoch().to_string()
              << " controllers=" << remote_status.controller_count()
              << " live_grants=" << remote_status.live_grant_count()
              << " transitions=" << remote_status.transition_count() << '\n';
    std::cout << "client-requests=" << client.request_count() << '\n';

    client.close();
    std::cout << "client-closed=" << (client.closed() ? "yes" : "no") << '\n';

    // Shutdown is deterministic: stop() closes the listener, shuts down active
    // sessions, and joins every worker. The acceptor thread then returns from
    // accept_until() and is joined by the Acceptor destructor below.
    server.stop();
    std::cout << "server-running=" << (server.running() ? "yes" : "no") << '\n';
    std::cout << "server-accounting " << server.accounting().to_string() << '\n';

    authority.close();
    std::cout << "done=remote_controller\n";
    return 0;
  } catch (const EpochError& error) {
    std::cerr << "failure: " << error.explanation().to_string() << '\n';
    return 1;
  } catch (const std::exception& error) {
    std::cerr << "failure: " << error.what() << '\n';
    return 1;
  }
}
