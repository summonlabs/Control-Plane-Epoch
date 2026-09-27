// Control Plane Epoch 1.0.0 - Summon Software Labs
// Example: initialize a facility authority domain.
//
// Creates a durable store in a temporary directory, declares the three reserved
// administrative scopes together with two ordinary facility scopes, and prints
// the resulting authoritative status and the durable commit report that
// initialization published.
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "control_plane_epoch/control_plane_epoch.hpp"

namespace {

using namespace dccp::epoch;

/// Removes and recreates a fixed scratch directory under the operating system's
/// temporary directory, so every run starts from a clean store.
[[nodiscard]] std::filesystem::path prepare_store_directory() {
  const std::filesystem::path directory =
      std::filesystem::temp_directory_path() / "control-plane-epoch-examples" / "initialize_domain";
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

}  // namespace

int main() {
  using namespace dccp::epoch;

  try {
    const std::filesystem::path directory = prepare_store_directory();
    std::cout << "example=initialize_domain\n";
    std::cout << "store=" << directory.string() << '\n';

    StoreOpenOptions options;
    options.directory = directory;
    ControlPlaneEpochAuthority authority(options);

    std::cout << "recovery-before-initialize " << authority.recovery().to_string() << '\n';
    std::cout << "initialized=" << (authority.initialized() ? "yes" : "no") << '\n';

    const FacilityAuthorityDomainId domain =
        unwrap(FacilityAuthorityDomainId::parse("facility-alpha", "authority domain"), "domain identifier");
    const ControllerId root = unwrap(ControllerId::parse("authority-root", "authority root"), "authority root");
    const ProvenanceInput provenance =
        unwrap(ProvenanceInput::from_source(ProvenanceSourceKind::Initialization, "facility-operator"),
               "initialization provenance");

    std::vector<ScopeName> declared;
    for (const std::string_view name : {authority_grant_scope().view(), authority_revoke_scope().view(),
                                        epoch_advance_scope().view(), std::string_view("facility.inventory"),
                                        std::string_view("facility.topology")}) {
      declared.push_back(unwrap(ScopeName::parse(name, "declared scope"), name));
    }

    InitializeDomainRequest request;
    request.domain = domain;
    request.authority_root = root;
    request.scopes = declared;
    request.provenance = provenance;

    const Status initialized = authority.initialize(request);
    if (!initialized.has_value()) {
      std::cerr << "initialization rejected: " << initialized.rejection().to_string() << '\n';
      return 1;
    }

    std::cout << "initialize accepted\n";
    std::cout << "reserved-scopes " << authority_grant_scope().to_string() << ' ' << authority_revoke_scope().to_string()
              << ' ' << epoch_advance_scope().to_string() << '\n';
    std::cout << "status " << authority.status().to_string() << '\n';

    const std::optional<DurableCommitReport> commit = authority.last_commit();
    if (!commit.has_value()) {
      std::cerr << "initialization reported no durable commit\n";
      return 1;
    }
    std::cout << "commit " << commit->to_string() << '\n';

    // A second initialization is refused: one durable store holds one domain.
    const Status repeated = authority.initialize(request);
    std::cout << "re-initialize accepted=" << (repeated.has_value() ? "yes" : "no")
              << " code=" << repeated.rejection().token() << '\n';

    const StoreInspection inspection = inspect_store(directory);
    std::cout << "inspection " << inspection.to_string() << '\n';
    if (!inspection.verified()) {
      std::cerr << "the store did not verify after initialization\n";
      return 1;
    }

    authority.close();
    std::cout << "authority closed=" << (authority.closed() ? "yes" : "no") << '\n';
    std::cout << "done=initialize_domain\n";
    return 0;
  } catch (const EpochError& error) {
    std::cerr << "failure: " << error.explanation().to_string() << '\n';
    return 1;
  } catch (const std::exception& error) {
    std::cerr << "failure: " << error.what() << '\n';
    return 1;
  }
}
