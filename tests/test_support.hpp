// Control Plane Epoch 1.0.0 - Summon Software Labs
// Shared test fixtures and helpers.
#pragma once

#include <filesystem>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "control_plane_epoch/control_plane_epoch.hpp"

#include "test_harness.hpp"

namespace cpe_test {

/// Renders a value for a failure message when the type is streamable and falls
/// back to a placeholder otherwise, so assertion messages never fail to compile
/// for the strongly typed values this repository uses.
template <class T>
[[nodiscard]] std::string describe_value(const T& value) {
  if constexpr (requires(std::ostream& stream, const T& item) { stream << item; }) {
    std::ostringstream stream;
    stream << value;
    return stream.str();
  } else if constexpr (std::is_enum_v<T>) {
    return std::to_string(static_cast<long long>(value));
  } else if constexpr (std::is_arithmetic_v<T>) {
    return std::to_string(value);
  } else {
    return "<unnamed value>";
  }
}

template <class A, class B>
[[nodiscard]] std::string describe_mismatch(const A& lhs, const B& rhs) {
  return "actual=" + describe_value(lhs) + " expected=" + describe_value(rhs);
}

inline dccp::epoch::FacilityAuthorityDomainId domain_id(std::string_view text = "facility-alpha") {
  auto parsed = dccp::epoch::FacilityAuthorityDomainId::parse(text, "authority domain");
  if (!parsed.has_value()) {
    throw Failure("could not parse test domain '" + std::string(text) + "'");
  }
  return parsed.move_value();
}

inline dccp::epoch::ControllerId controller_id(std::string_view text) {
  auto parsed = dccp::epoch::ControllerId::parse(text, "controller");
  if (!parsed.has_value()) {
    throw Failure("could not parse test controller '" + std::string(text) + "'");
  }
  return parsed.move_value();
}

inline dccp::epoch::ScopeName scope_name(std::string_view text) {
  auto parsed = dccp::epoch::ScopeName::parse(text, "scope");
  if (!parsed.has_value()) {
    throw Failure("could not parse test scope '" + std::string(text) + "'");
  }
  return parsed.move_value();
}

inline std::vector<dccp::epoch::ScopeName> scope_list(const std::vector<std::string>& names) {
  std::vector<dccp::epoch::ScopeName> scopes;
  scopes.reserve(names.size());
  for (const std::string& name : names) {
    scopes.push_back(scope_name(name));
  }
  return scopes;
}

inline dccp::epoch::AuthorityScopeSet scope_set(const std::vector<std::string>& names) {
  auto created = dccp::epoch::AuthorityScopeSet::create(scope_list(names));
  if (!created.has_value()) {
    throw Failure("could not build a scope set: " + created.rejection().to_string());
  }
  return created.move_value();
}

inline dccp::epoch::ProvenanceInput provenance_input(std::string_view source = "operator",
                                                     dccp::epoch::ProvenanceSourceKind kind =
                                                         dccp::epoch::ProvenanceSourceKind::Operator) {
  auto created = dccp::epoch::ProvenanceInput::from_source(kind, source);
  if (!created.has_value()) {
    throw Failure("could not build provenance: " + created.rejection().to_string());
  }
  return created.move_value();
}

inline dccp::epoch::Sha256Digest digest_of(std::string_view text) { return dccp::epoch::sha256(text); }

/// The default scope vocabulary used by tests: the three reserved administrative
/// scopes plus two ordinary facility scopes.
[[nodiscard]] inline std::vector<std::string> default_scopes() {
  return {"authority.grant", "authority.revoke", "epoch.advance", "facility.inventory", "facility.topology"};
}

/// One authority instance over its own temporary store directory, plus the
/// operations every suite needs. Failures inside the fixture are assertion
/// failures, so a suite only has to assert on the behaviour it is testing.
class TestAuthority {
 public:
  explicit TestAuthority(std::string domain = "facility-alpha", std::string root = "authority-root",
                         std::vector<std::string> scopes = default_scopes())
      : directory_(), domain_text_(std::move(domain)), root_text_(std::move(root)) {
    dccp::epoch::StoreOpenOptions options;
    options.directory = directory_.path();
    authority_ = std::make_unique<dccp::epoch::ControlPlaneEpochAuthority>(options);

    dccp::epoch::InitializeDomainRequest request;
    request.domain = domain_id(domain_text_);
    request.authority_root = controller_id(root_text_);
    request.provenance = provenance_input("test-initialization", dccp::epoch::ProvenanceSourceKind::Initialization);
    for (const std::string& scope : scopes) {
      request.scopes.push_back(scope_name(scope));
    }
    const auto initialized = authority_->initialize(std::move(request));
    if (!initialized.has_value()) {
      throw Failure("initialization failed: " + initialized.rejection().to_string());
    }
  }

  /// Reopens the same store with the given mode and policy. The previous
  /// instance is destroyed first, which releases the writer lock exactly as a
  /// restarted process would.
  void reopen(dccp::epoch::StoreOpenMode mode = dccp::epoch::StoreOpenMode::ReadWrite,
              dccp::epoch::RecoveryPolicy policy = dccp::epoch::RecoveryPolicy::RefuseOnDamage,
              std::optional<std::uint64_t> asserted_floor = std::nullopt) {
    authority_.reset();
    dccp::epoch::StoreOpenOptions options;
    options.directory = directory_.path();
    options.mode = mode;
    options.recovery_policy = policy;
    options.asserted_epoch_floor = asserted_floor;
    authority_ = std::make_unique<dccp::epoch::ControlPlaneEpochAuthority>(options);
  }

  void close() { authority_.reset(); }

  [[nodiscard]] dccp::epoch::ControlPlaneEpochAuthority& authority() { return *authority_; }
  [[nodiscard]] const std::filesystem::path& store() const { return directory_.path(); }
  [[nodiscard]] const std::string& domain() const { return domain_text_; }
  [[nodiscard]] const std::string& root() const { return root_text_; }

  [[nodiscard]] std::filesystem::path file(const std::string& name) const { return directory_.file(name); }

  [[nodiscard]] dccp::epoch::ControllerRegistration register_controller(const std::string& controller,
                                                                       dccp::epoch::ProvenanceSourceKind kind =
                                                                           dccp::epoch::ProvenanceSourceKind::Controller) {
    dccp::epoch::RegisterControllerRequest request;
    request.controller = controller_id(controller);
    request.provenance = provenance_input(controller, kind);
    auto registration = authority_->register_controller(std::move(request));
    if (!registration.has_value()) {
      throw Failure("registration of '" + controller + "' failed: " + registration.rejection().to_string());
    }
    return registration.move_value();
  }

  [[nodiscard]] dccp::epoch::AuthorityGrantView acquire(const std::string& controller,
                                                        const dccp::epoch::ControllerIncarnationId& incarnation,
                                                        const std::vector<std::string>& scopes,
                                                        const std::optional<dccp::epoch::MutationAuthority>& sponsor,
                                                        dccp::epoch::AuthorityClass authority_class =
                                                            dccp::epoch::AuthorityClass::Mutation) {
    dccp::epoch::AcquireAuthorityRequest request;
    request.authority_class = authority_class;
    request.controller = controller_id(controller);
    request.incarnation = incarnation;
    request.scopes = scope_set(scopes);
    request.sponsor = sponsor;
    request.provenance = provenance_input(controller, dccp::epoch::ProvenanceSourceKind::Controller);
    auto grant = authority_->acquire_authority(std::move(request));
    if (!grant.has_value()) {
      throw Failure("acquisition for '" + controller + "' failed: " + grant.rejection().to_string());
    }
    return grant.move_value();
  }

  /// Acquires administrative authority for the domain's root controller using
  /// the documented standing-root path (no sponsor).
  [[nodiscard]] dccp::epoch::MutationAuthority root_authority() {
    const auto root_record = authority_->controller_record(controller_id(root_text_));
    if (!root_record.has_value()) {
      throw Failure("the authority root is not registered");
    }
    auto view = acquire(root_text_, root_record.value().incarnation_id(),
                        {"authority.grant", "authority.revoke", "epoch.advance"}, std::nullopt);
    if (!view.mutation_authority().has_value()) {
      throw Failure("the root acquired a non-mutation authority");
    }
    return *view.mutation_authority();
  }

  [[nodiscard]] dccp::epoch::MutationAuthority mutation_authority_of(
      const dccp::epoch::AuthorityGrantView& view) const {
    if (!view.mutation_authority().has_value()) {
      throw Failure("the grant view carries no mutation authority");
    }
    return *view.mutation_authority();
  }

  [[nodiscard]] dccp::epoch::EpochTransitionRecord advance(dccp::epoch::Epoch expected,
                                                           const dccp::epoch::MutationAuthority& authority,
                                                           dccp::epoch::EpochTransitionReason reason =
                                                               dccp::epoch::EpochTransitionReason::OperatorRequest) {
    dccp::epoch::AdvanceEpochRequest request;
    request.expected_current = expected;
    request.authority = authority;
    request.reason = reason;
    request.provenance = provenance_input("operator");
    auto transition = authority_->advance_epoch(std::move(request));
    if (!transition.has_value()) {
      throw Failure("advancement failed: " + transition.rejection().to_string());
    }
    return transition.move_value();
  }

 private:
  TempDirectory directory_;
  std::string domain_text_;
  std::string root_text_;
  std::unique_ptr<dccp::epoch::ControlPlaneEpochAuthority> authority_;
};

}  // namespace cpe_test
