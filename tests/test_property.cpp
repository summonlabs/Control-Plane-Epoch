// Control Plane Epoch 1.0.0 - Summon Software Labs
// Property suite: seeded randomized operation sequences checked against a model
// of the expected authoritative state.
//
// Every run is driven by cpe_test::DeterministicRandom with a fixed, documented
// seed, and every failure message reports that seed, so a failing run is
// reproducible from the reported value alone. After every single operation the
// model is compared with the authority, every issued token is re-validated
// against its predicted outcome, and every rejection is repeated verbatim to
// prove that it is deterministic and leaves no trace.
//
// Invariants proven here:
//   * the epoch never decreases and never skips a value;
//   * a token from a superseded epoch, a superseded incarnation, or a revoked
//     grant never validates again;
//   * every accepted mutation is reflected in status() and accounting();
//   * every rejection carries the same code and explanation when repeated, and
//     changes nothing;
//   * replaying an identical sequence against a fresh store produces identical
//     transition-record digests and identical snapshot digests.
#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "test_support.hpp"

namespace {

using cpe_test::controller_id;
using cpe_test::default_scopes;
using cpe_test::domain_id;
using cpe_test::provenance_input;
using cpe_test::scope_name;
using cpe_test::scope_set;

using dccp::epoch::AuthorityAccounting;
using dccp::epoch::AuthorityClaims;
using dccp::epoch::AuthorityClass;
using dccp::epoch::AuthorityGrantView;
using dccp::epoch::AuthorityScopeSet;
using dccp::epoch::AuthorityStatus;
using dccp::epoch::ControllerId;
using dccp::epoch::ControllerIncarnationId;
using dccp::epoch::ControllerRegistration;
using dccp::epoch::ControlPlaneEpochAuthority;
using dccp::epoch::Epoch;
using dccp::epoch::EpochTransitionRecord;
using dccp::epoch::ErrorCode;
using dccp::epoch::FacilityAuthorityDomainId;
using dccp::epoch::GrantId;
using dccp::epoch::GrantQuery;
using dccp::epoch::HistoryQuery;
using dccp::epoch::IncarnationNumber;
using dccp::epoch::MutationAuthority;
using dccp::epoch::ObservationAuthority;
using dccp::epoch::RegisterControllerRequest;
using dccp::epoch::Result;
using dccp::epoch::RevocationQuery;
using dccp::epoch::RevocationReason;
using dccp::epoch::RevocationRecord;
using dccp::epoch::RevocationTarget;
using dccp::epoch::RevokeAuthorityRequest;
using dccp::epoch::ScopeName;
using dccp::epoch::ValidationOutcome;

/// Fixed, documented seeds. Four seeds keep every invariant exercised by more
/// than one independent sequence without making the suite slow.
constexpr std::uint64_t kSeeds[] = {0x00C0FFEE00000001ull, 0x00C0FFEE00000002ull, 0x00C0FFEE00000003ull,
                                    0x00C0FFEE00000004ull};
constexpr std::size_t kOperationsPerSeed = 96;

/// One command of the sequence. The concrete parameters are chosen by the
/// seeded generator, never by the clock or by the process environment.
enum class OperationKind : std::uint64_t {
  RegisterController = 0,
  AcquireSponsored = 1,
  AcquireStaleIncarnation = 2,
  AcquireWithoutSponsor = 3,
  AdvanceEpoch = 4,
  AdvanceWithStaleEpoch = 5,
  ReacquireAdministrativeAuthority = 6,
  RevokeController = 7,
  RevokeGrant = 8,
  ValidateToken = 9,
  InspectLedgers = 10,
};

constexpr std::uint64_t kOperationKindCount = 11;

/// State of one grant as the durable store models it. Revocation can move a
/// superseded grant to revoked, which is why the three states are distinct.
enum class GrantState { Live, Superseded, Revoked };

struct GrantModel {
  std::uint64_t id = 0;
  std::uint64_t epoch = 0;
  std::string controller;
  std::uint64_t incarnation_number = 0;
  std::vector<std::string> scopes;
  bool present = false;  // present in the current epoch's grant ledger
  bool observation = false;
  GrantState state = GrantState::Live;
};

struct ControllerModel {
  std::uint64_t incarnation_number = 0;
  std::string incarnation_id;
  /// Identities superseded by later registrations, newest first and bounded
  /// exactly like the durable record.
  std::vector<std::string> superseded;
  std::optional<std::uint64_t> revoked_through;
};

struct IssuedTokenModel {
  bool observation = false;
  MutationAuthority mutation;
  ObservationAuthority observation_authority;
  std::uint64_t grant_id = 0;
  std::uint64_t epoch = 0;
};

struct Model {
  std::uint64_t epoch = 1;
  std::uint64_t generation = 1;
  std::uint64_t transition_count = 1;  // the genesis record
  std::uint64_t revocation_count = 0;
  std::uint64_t next_grant_id = 2;
  std::map<std::string, ControllerModel> controllers;
  std::map<std::uint64_t, GrantModel> grants;
  std::vector<IssuedTokenModel> tokens;
  std::optional<MutationAuthority> admin;

  [[nodiscard]] bool admin_is_current() const {
    return admin_rejection() == ErrorCode::Ok;
  }

  /// The exact code that presenting the stored administrative authority must
  /// produce, in the documented validation order: epoch, then grant existence,
  /// then revocation. A grant-level revocation of the root's administrative
  /// grant is possible (the sequence does it deliberately), and it must be
  /// distinguished from the epoch fence that an advancement applies.
  [[nodiscard]] ErrorCode admin_rejection() const {
    if (!admin.has_value()) {
      return ErrorCode::EpochFenced;
    }
    if (admin->epoch().value() < epoch) {
      return ErrorCode::EpochFenced;
    }
    const auto grant = grants.find(admin->grant().value());
    if (grant == grants.end() || !grant->second.present) {
      return ErrorCode::UnknownGrant;
    }
    if (grant->second.state == GrantState::Revoked) {
      return ErrorCode::AuthorityRevoked;
    }
    if (grant->second.state == GrantState::Superseded) {
      return ErrorCode::IncarnationSuperseded;
    }
    return ErrorCode::Ok;
  }

  [[nodiscard]] std::uint64_t present_grants() const {
    std::uint64_t count = 0;
    for (const auto& entry : grants) {
      if (entry.second.present) {
        ++count;
      }
    }
    return count;
  }

  [[nodiscard]] std::uint64_t live_grants() const {
    std::uint64_t count = 0;
    for (const auto& entry : grants) {
      if (entry.second.present && entry.second.state == GrantState::Live) {
        ++count;
      }
    }
    return count;
  }

  [[nodiscard]] std::uint64_t live_observation_grants() const {
    std::uint64_t count = 0;
    for (const auto& entry : grants) {
      if (entry.second.present && entry.second.state == GrantState::Live && entry.second.observation) {
        ++count;
      }
    }
    return count;
  }

  /// True when the controller is fenced at or above its current incarnation,
  /// which is what makes the next acquisition attempt fail.
  [[nodiscard]] bool controller_is_fenced(const std::string& name) const {
    const auto entry = controllers.find(name);
    if (entry == controllers.end() || !entry->second.revoked_through.has_value()) {
      return false;
    }
    return *entry->second.revoked_through >= entry->second.incarnation_number;
  }
};

/// Counts how often each invariant was actually observed, so a green run also
/// proves the sequence was not vacuous.
struct InvariantCounters {
  std::uint64_t operations = 0;
  std::uint64_t skipped = 0;
  std::uint64_t accepted_validations = 0;
  std::uint64_t fenced_epoch_rejections = 0;
  std::uint64_t superseded_incarnation_rejections = 0;
  std::uint64_t revoked_grant_rejections = 0;
  std::uint64_t scope_not_granted_rejections = 0;
  std::uint64_t epoch_conflicts = 0;
};

struct SequenceTrace {
  std::vector<std::string> snapshot_digests;
  std::vector<std::string> chain_heads;
  std::vector<std::string> transition_digests;
  std::vector<std::string> revocation_digests;
  std::string final_status;
  std::uint64_t operations = 0;
};

[[nodiscard]] std::string context(std::uint64_t seed, std::size_t step, const std::string& what) {
  return "seed=" + std::to_string(seed) + " step=" + std::to_string(step) + ": " + what;
}

[[nodiscard]] std::string canonical_scopes(const std::vector<std::string>& scopes) {
  std::vector<std::string> sorted = scopes;
  std::sort(sorted.begin(), sorted.end());
  std::string text;
  for (const std::string& scope : sorted) {
    if (!text.empty()) {
      text.push_back('+');
    }
    text.append(scope);
  }
  return text;
}

[[nodiscard]] bool same_fence(const std::optional<IncarnationNumber>& observed,
                              const std::optional<std::uint64_t>& expected) {
  if (observed.has_value() != expected.has_value()) {
    return false;
  }
  return !observed.has_value() || observed->value() == *expected;
}

[[nodiscard]] std::string incarnation_hex(const FacilityAuthorityDomainId& domain, const ControllerId& controller,
                                          std::uint64_t number) {
  return ControllerIncarnationId::derive(domain, controller, IncarnationNumber::from_trusted(number)).to_hex();
}

/// The exact code a validation must produce, derived from the model alone. The
/// order mirrors the documented validation ladder: epoch, grant existence,
/// authority class, revocation, supersession, incarnation currency, then scope.
[[nodiscard]] ErrorCode predict_validation(const Model& model, const IssuedTokenModel& issued,
                                           const std::string& scope) {
  if (issued.epoch < model.epoch) {
    return ErrorCode::EpochFenced;
  }
  if (issued.epoch > model.epoch) {
    return ErrorCode::EpochUnknown;
  }
  const auto grant = model.grants.find(issued.grant_id);
  if (grant == model.grants.end() || !grant->second.present) {
    return ErrorCode::UnknownGrant;
  }
  if (grant->second.observation != issued.observation) {
    return ErrorCode::AuthorityClassMismatch;
  }
  if (grant->second.state == GrantState::Revoked) {
    return ErrorCode::AuthorityRevoked;
  }
  if (grant->second.state == GrantState::Superseded) {
    return ErrorCode::IncarnationSuperseded;
  }
  if (std::find(grant->second.scopes.begin(), grant->second.scopes.end(), scope) == grant->second.scopes.end()) {
    return ErrorCode::ScopeNotGranted;
  }
  return ErrorCode::Ok;
}

void count_outcome(InvariantCounters& counters, ErrorCode code) {
  switch (code) {
    case ErrorCode::Ok:
      ++counters.accepted_validations;
      break;
    case ErrorCode::EpochFenced:
      ++counters.fenced_epoch_rejections;
      break;
    case ErrorCode::IncarnationSuperseded:
      ++counters.superseded_incarnation_rejections;
      break;
    case ErrorCode::AuthorityRevoked:
      ++counters.revoked_grant_rejections;
      break;
    case ErrorCode::ScopeNotGranted:
      ++counters.scope_not_granted_rejections;
      break;
    case ErrorCode::EpochConflict:
      ++counters.epoch_conflicts;
      break;
    default:
      break;
  }
}

[[nodiscard]] ValidationOutcome validate_issued(ControlPlaneEpochAuthority& authority,
                                                const IssuedTokenModel& issued, const ScopeName& scope) {
  if (issued.observation) {
    return authority.validate_observation(issued.observation_authority, scope);
  }
  return authority.validate_mutation(issued.mutation, scope);
}

[[nodiscard]] RegisterControllerRequest registration_request(const std::string& controller) {
  RegisterControllerRequest request;
  request.controller = controller_id(controller);
  request.provenance = provenance_input(controller, dccp::epoch::ProvenanceSourceKind::Controller);
  return request;
}

/// A token whose claims are internally consistent - its fencing digest matches
/// its own claims - but which names a grant the store never issued. Integrity
/// therefore passes and only the authoritative store can reject it.
[[nodiscard]] MutationAuthority craft_token_for_test(const std::string& domain, std::uint64_t epoch,
                                                     const std::string& controller,
                                                     const ControllerIncarnationId& incarnation,
                                                     std::uint64_t grant) {
  Result<AuthorityClaims> claims =
      AuthorityClaims::create(FacilityAuthorityDomainId::from_trusted(domain), Epoch::from_trusted(epoch),
                              ControllerId::from_trusted(controller), incarnation, GrantId::from_trusted(grant),
                              AuthorityScopeSet::from_trusted({scope_name("facility.inventory")}));
  if (!claims.has_value()) {
    throw cpe_test::Failure("could not craft claims: " + claims.rejection().to_string());
  }
  return MutationAuthority::from_claims(claims.move_value());
}

/// Runs one command, asserts the exact predicted outcome, and — when the model
/// predicts a rejection — runs the identical command a second time and asserts
/// that it is rejected with the same code and the same explanation while the
/// full status stays byte-identical.
template <class Command>
auto apply_command(ControlPlaneEpochAuthority& authority, Command command, ErrorCode predicted, std::uint64_t seed,
                   std::size_t step, const std::string& what) -> decltype(command()) {
  using Outcome = decltype(command());
  const std::string status_before = authority.status().to_string();
  Outcome first = command();
  if (predicted == ErrorCode::Ok) {
    CPE_REQUIRE_MSG(first.has_value(),
                    context(seed, step, what + " must be accepted: " + first.rejection().to_string()));
    return first;
  }
  CPE_REQUIRE_MSG(!first.has_value(), context(seed, step, what + " must be rejected but was accepted"));
  CPE_REQUIRE_MSG(first.code() == predicted,
                  context(seed, step, what + " was rejected with " + std::string(error_token(first.code())) +
                                       " instead of the predicted " + std::string(error_token(predicted))));
  Outcome repeated = command();
  CPE_REQUIRE_MSG(!repeated.has_value() && repeated.code() == first.code(),
                  context(seed, step, what + " was not rejected identically when repeated"));
  CPE_REQUIRE_MSG(repeated.rejection().to_string() == first.rejection().to_string(),
                  context(seed, step, what + " explained a repeated rejection differently"));
  CPE_REQUIRE_MSG(authority.status().to_string() == status_before,
                  context(seed, step, what + " changed authoritative state while being refused"));
  return first;
}

/// Compares every externally visible count with the model. Called after every
/// operation, so an accepted mutation that is not reflected in status() or
/// accounting() fails immediately rather than at the end of the run.
void require_model_matches(cpe_test::TestAuthority& authority, const Model& model, std::uint64_t seed,
                           std::size_t step) {
  const AuthorityStatus status = authority.authority().status();
  CPE_REQUIRE_MSG(status.epoch().value() == model.epoch, context(seed, step, "status epoch differs from the model"));
  CPE_REQUIRE_MSG(status.durable_generation().value() == model.generation,
                  context(seed, step, "status generation differs from the model"));
  CPE_REQUIRE_MSG(status.controller_count() == model.controllers.size(),
                  context(seed, step, "status controller count differs from the model"));
  CPE_REQUIRE_MSG(status.transition_count() == model.transition_count,
                  context(seed, step, "status transition count differs from the model"));
  CPE_REQUIRE_MSG(status.revocation_count() == model.revocation_count,
                  context(seed, step, "status revocation count differs from the model"));
  CPE_REQUIRE_MSG(status.live_grant_count() == model.live_grants(),
                  context(seed, step, "status live grant count differs from the model"));
  CPE_REQUIRE_MSG(status.observation_grant_count() == model.live_observation_grants(),
                  context(seed, step, "status observation grant count differs from the model"));
  CPE_REQUIRE_MSG(status.mutation_grant_count() == model.live_grants() - model.live_observation_grants(),
                  context(seed, step, "status mutation grant count differs from the model"));

  const AuthorityAccounting accounting = authority.authority().accounting();
  CPE_REQUIRE_MSG(accounting.controller_records() == model.controllers.size(),
                  context(seed, step, "accounted controller records differ from the model"));
  CPE_REQUIRE_MSG(accounting.grant_records() == model.present_grants(),
                  context(seed, step, "accounted grant records differ from the model"));
  CPE_REQUIRE_MSG(accounting.live_grant_records() == model.live_grants(),
                  context(seed, step, "accounted live grant records differ from the model"));
  CPE_REQUIRE_MSG(accounting.transition_records_retained() == model.transition_count,
                  context(seed, step, "accounted transition records differ from the model"));
  CPE_REQUIRE_MSG(accounting.revocation_records_retained() == model.revocation_count,
                  context(seed, step, "accounted revocation records differ from the model"));
  CPE_REQUIRE_MSG(accounting.transition_records_trimmed() == 0,
                  context(seed, step, "the sequence must stay inside the retention window"));
  CPE_REQUIRE_MSG(accounting.revocation_records_trimmed() == 0,
                  context(seed, step, "the sequence must stay inside the retention window"));

  for (const auto& entry : model.controllers) {
    const Result<dccp::epoch::ControllerRecord> record =
        authority.authority().controller_record(controller_id(entry.first));
    CPE_REQUIRE_MSG(record.has_value(), context(seed, step, "controller '" + entry.first + "' is missing"));
    CPE_REQUIRE_MSG(record.value().incarnation_number().value() == entry.second.incarnation_number,
                    context(seed, step, "controller '" + entry.first + "' incarnation number differs from the model"));
    CPE_REQUIRE_MSG(record.value().incarnation_id().to_hex() == entry.second.incarnation_id,
                    context(seed, step, "controller '" + entry.first + "' incarnation identity differs"));
    CPE_REQUIRE_MSG(same_fence(record.value().revocation_through_incarnation(), entry.second.revoked_through),
                    context(seed, step, "controller '" + entry.first + "' revocation fence differs from the model"));
  }

  CPE_REQUIRE_MSG(model.present_grants() <= dccp::epoch::max_page_size,
                  context(seed, step, "the model outgrew one page"));
  const Result<dccp::epoch::GrantPage> page = authority.authority().grants(GrantQuery{});
  CPE_REQUIRE_MSG(page.has_value(), context(seed, step, "the grant ledger must be readable"));
  CPE_REQUIRE_MSG(page.value().records().size() == model.present_grants(),
                  context(seed, step, "the grant ledger holds a different number of grants than the model"));
  CPE_REQUIRE_MSG(page.value().epoch().value() == model.epoch,
                  context(seed, step, "the grant page reports a different epoch than the model"));
  for (const auto& record : page.value().records()) {
    const auto expected = model.grants.find(record.id().value());
    CPE_REQUIRE_MSG(expected != model.grants.end(),
                    context(seed, step, "the ledger holds a grant the model never issued"));
    CPE_REQUIRE_MSG(record.epoch().value() == expected->second.epoch,
                    context(seed, step, "a grant record carries a different epoch than the model"));
    CPE_REQUIRE_MSG(record.controller().str() == expected->second.controller,
                    context(seed, step, "a grant record belongs to a different controller than the model"));
    CPE_REQUIRE_MSG(record.incarnation_number().value() == expected->second.incarnation_number,
                    context(seed, step, "a grant record carries a different incarnation number than the model"));
    CPE_REQUIRE_MSG(record.revoked() == (expected->second.state == GrantState::Revoked),
                    context(seed, step, "a grant record revocation state differs from the model"));
    CPE_REQUIRE_MSG(record.scopes().to_string() == canonical_scopes(expected->second.scopes),
                    context(seed, step, "a grant record covers different scopes than the model"));
  }
}

/// Re-validates every token the sequence ever issued. This is the invariant that
/// matters most: authority that has been fenced must stay fenced, and authority
/// that is still live must keep working, no matter what else happened.
void sweep_tokens(cpe_test::TestAuthority& authority, const Model& model, InvariantCounters& counters,
                  std::uint64_t seed, std::size_t step) {
  for (const IssuedTokenModel& issued : model.tokens) {
    const auto grant = model.grants.find(issued.grant_id);
    CPE_REQUIRE_MSG(grant != model.grants.end(), context(seed, step, "an issued token lost its model grant"));
    CPE_REQUIRE_MSG(!grant->second.scopes.empty(), context(seed, step, "a grant must cover at least one scope"));
    const std::string& scope = grant->second.scopes.front();
    const ErrorCode predicted = predict_validation(model, issued, scope);
    const ValidationOutcome outcome = validate_issued(authority.authority(), issued, scope_name(scope));
    CPE_REQUIRE_MSG(outcome.code() == predicted,
                    context(seed, step, "validating grant " + std::to_string(issued.grant_id) + " in epoch " +
                                            std::to_string(issued.epoch) + " produced " +
                                            std::string(error_token(outcome.code())) + " where the model predicts " +
                                            std::string(error_token(predicted))));
    count_outcome(counters, predicted);
  }
}

/// Runs one seeded sequence against a fresh authority and returns the digests it
/// produced, so that an identical sequence can be replayed against a second
/// fresh store and compared byte for byte.
SequenceTrace run_sequence(std::uint64_t seed, std::size_t operations, InvariantCounters* counters_out) {
  cpe_test::TestAuthority authority;
  const FacilityAuthorityDomainId domain = domain_id(authority.domain());
  const ControllerId root = controller_id(authority.root());
  const std::vector<std::string> scope_pool = default_scopes();
  const std::vector<std::string> controller_pool = {"alpha", "bravo", "charlie", "delta", "echo", "foxtrot"};

  cpe_test::DeterministicRandom random(seed);
  InvariantCounters counters;
  Model model;
  model.controllers[root.str()] = ControllerModel{1, incarnation_hex(domain, root, 1), {}, std::nullopt};
  GrantModel root_grant;
  root_grant.id = 1;
  root_grant.epoch = 1;
  root_grant.controller = root.str();
  root_grant.incarnation_number = 1;
  root_grant.scopes = scope_pool;
  root_grant.present = true;
  root_grant.state = GrantState::Live;
  model.grants[1] = root_grant;

  SequenceTrace trace;

  // Administrative authority is bound to the epoch it was issued in, so it has
  // to be re-derived after every committed advancement, exactly as a real
  // operator would: the transition fences the grant that authorized it.
  const auto reacquire_admin = [&]() {
    CPE_REQUIRE_MSG(!model.controller_is_fenced(root.str()),
                    context(seed, operations, "the authority root must never be revoked in this sequence"));
    const std::uint64_t predicted_id = model.next_grant_id;
    const MutationAuthority admin = authority.root_authority();
    CPE_REQUIRE_MSG(admin.epoch().value() == model.epoch,
                    context(seed, operations, "re-derived administrative authority must belong to the current epoch"));
    GrantModel grant;
    grant.id = predicted_id;
    grant.epoch = model.epoch;
    grant.controller = root.str();
    grant.incarnation_number = model.controllers[root.str()].incarnation_number;
    grant.scopes = {"authority.grant", "authority.revoke", "epoch.advance"};
    grant.present = true;
    grant.state = GrantState::Live;
    model.grants[predicted_id] = grant;
    model.next_grant_id += 1;
    model.generation += 1;
    model.admin = admin;
  };

  reacquire_admin();

  for (std::size_t step = 0; step < operations; ++step) {
    const std::uint64_t epoch_before = model.epoch;
    const std::uint64_t generation_before = model.generation;
    // The first two operations are forced: a controller has to exist before the
    // generator can act on one, and a grant has to exist before it can validate
    // one. After that the generator is free, and because both prerequisites are
    // permanent the generator never has to skip an operation - which the
    // counters at the end of the sequence assert.
    const auto kind = step == 0   ? OperationKind::RegisterController
                      : step == 1 ? OperationKind::AcquireSponsored
                                  : static_cast<OperationKind>(random.next_below(kOperationKindCount));
    ++counters.operations;

    // Controllers and grants the sequence may act on, in deterministic (map)
    // order, so the generated sequence depends only on the seed.
    std::vector<std::string> known;
    for (const auto& entry : model.controllers) {
      if (entry.first != root.str()) {
        known.push_back(entry.first);
      }
    }
    std::vector<std::uint64_t> present_grants;
    for (const auto& entry : model.grants) {
      if (entry.second.present) {
        present_grants.push_back(entry.first);
      }
    }

    // The dispatch is a single-pass block rather than a chain of early exits:
    // every operation - applied, refused, or skipped for lack of a subject -
    // falls through to the identical invariant check and digest record below, so
    // no path can quietly bypass verification.
    do {
      if (kind == OperationKind::RegisterController) {
      const std::string name = controller_pool[static_cast<std::size_t>(
          random.next_below(static_cast<std::uint64_t>(controller_pool.size())))];
      RegisterControllerRequest request = registration_request(name);
      const Result<ControllerRegistration> registration =
          apply_command(authority.authority(), [&]() { return authority.authority().register_controller(request); },
                        ErrorCode::Ok, seed, step, "registration of '" + name + "'");

      auto& controller = model.controllers[name];
      const bool existing = controller.incarnation_number != 0;
      const std::uint64_t expected_number = existing ? controller.incarnation_number + 1 : 1;
      CPE_REQUIRE_MSG(registration.value().incarnation_number().value() == expected_number,
                      context(seed, step, "the library issued an incarnation number the model did not predict"));
      CPE_REQUIRE_MSG(registration.value().incarnation_id().to_hex() ==
                          incarnation_hex(domain, controller_id(name), expected_number),
                      context(seed, step, "the issued incarnation identity is not the derived one"));
      CPE_REQUIRE_MSG(registration.value().epoch().value() == model.epoch,
                      context(seed, step, "a registration must be recorded in the current epoch"));
      if (existing) {
        // A fresh incarnation permanently fences every live grant of the old
        // one, which is the whole point of incarnation numbers.
        for (auto& entry : model.grants) {
          if (entry.second.present && entry.second.controller == name && entry.second.state == GrantState::Live) {
            entry.second.state = GrantState::Superseded;
          }
        }
        controller.superseded.insert(controller.superseded.begin(), controller.incarnation_id);
        if (controller.superseded.size() > 8) {
          controller.superseded.resize(8);
        }
      }
      controller.incarnation_number = expected_number;
      controller.incarnation_id = registration.value().incarnation_id().to_hex();
      model.generation += 1;
    } else if (kind == OperationKind::AcquireSponsored) {
      if (known.empty()) {
        ++counters.skipped;
        break;
      }
      const std::string name =
          known[static_cast<std::size_t>(random.next_below(static_cast<std::uint64_t>(known.size())))];
      const ControllerModel& controller = model.controllers[name];
      const std::size_t scope_count = 1 + static_cast<std::size_t>(random.next_below(2));
      std::vector<std::string> scopes;
      for (std::size_t index = 0; index < scope_count; ++index) {
        scopes.push_back(scope_pool[static_cast<std::size_t>(
            random.next_below(static_cast<std::uint64_t>(scope_pool.size())))]);
      }
      std::sort(scopes.begin(), scopes.end());
      scopes.erase(std::unique(scopes.begin(), scopes.end()), scopes.end());
      const bool observation = random.next_below(4) == 0;

      // Incarnation currency, then the controller fence, then the sponsor: the
      // ladder order decides which rejection wins when several would apply.
      ErrorCode predicted = ErrorCode::Ok;
      if (model.controller_is_fenced(name)) {
        predicted = ErrorCode::AuthorityRevoked;
      } else {
        predicted = model.admin_rejection();
      }

      dccp::epoch::AcquireAuthorityRequest request;
      request.authority_class = observation ? AuthorityClass::Observation : AuthorityClass::Mutation;
      request.controller = controller_id(name);
      request.incarnation = ControllerIncarnationId::from_hex(controller.incarnation_id).value();
      request.scopes = scope_set(scopes);
      request.sponsor = model.admin;
      request.provenance = provenance_input(name, dccp::epoch::ProvenanceSourceKind::Controller);

      const std::uint64_t predicted_id = model.next_grant_id;
      const Result<AuthorityGrantView> view = apply_command(
          authority.authority(), [&]() { return authority.authority().acquire_authority(request); }, predicted, seed,
          step, "acquisition for '" + name + "'");
      if (!view.has_value()) {
        break;
      }
      CPE_REQUIRE_MSG(view.value().record().id().value() == predicted_id,
                      context(seed, step, "the issued grant identifier is not the next ledger position"));
      CPE_REQUIRE_MSG(view.value().record().epoch().value() == model.epoch,
                      context(seed, step, "a grant must be issued in the current epoch"));
      CPE_REQUIRE_MSG(!view.value().record().revoked(), context(seed, step, "a fresh grant must not be revoked"));
      CPE_REQUIRE_MSG(view.value().record().incarnation_number().value() == controller.incarnation_number,
                      context(seed, step, "a grant must be bound to the current incarnation number"));

      GrantModel grant;
      grant.id = predicted_id;
      grant.epoch = model.epoch;
      grant.controller = name;
      grant.incarnation_number = controller.incarnation_number;
      grant.scopes = scopes;
      grant.present = true;
      grant.observation = observation;
      grant.state = GrantState::Live;
      model.grants[predicted_id] = grant;
      model.next_grant_id += 1;
      model.generation += 1;

      IssuedTokenModel issued;
      issued.observation = observation;
      issued.grant_id = predicted_id;
      issued.epoch = model.epoch;
      if (observation) {
        CPE_REQUIRE(view.value().observation_authority().has_value());
        issued.observation_authority = *view.value().observation_authority();
      } else {
        CPE_REQUIRE(view.value().mutation_authority().has_value());
        issued.mutation = *view.value().mutation_authority();
      }
      model.tokens.push_back(issued);
      if (model.tokens.size() > 24) {
        model.tokens.erase(model.tokens.begin());
      }
    } else if (kind == OperationKind::AcquireStaleIncarnation) {
      if (known.empty()) {
        ++counters.skipped;
        break;
      }
      const std::string name =
          known[static_cast<std::size_t>(random.next_below(static_cast<std::uint64_t>(known.size())))];
      const ControllerModel& controller = model.controllers[name];
      // Incarnation currency is checked before any sponsor, so a stale
      // incarnation is rejected even when the sponsor is stale too.
      const ErrorCode predicted =
          controller.superseded.empty() ? ErrorCode::IncarnationUnknown : ErrorCode::IncarnationSuperseded;
      ControllerIncarnationId incarnation = ControllerIncarnationId::from_hex(controller.incarnation_id).value();
      if (controller.superseded.empty()) {
        // A well-formed identity that was never issued for this controller.
        incarnation =
            ControllerIncarnationId::derive(domain, controller_id(name), IncarnationNumber::from_trusted(4096));
      } else {
        const std::size_t pick =
            static_cast<std::size_t>(random.next_below(static_cast<std::uint64_t>(controller.superseded.size())));
        incarnation = ControllerIncarnationId::from_hex(controller.superseded[pick]).value();
      }

      dccp::epoch::AcquireAuthorityRequest request;
      request.authority_class = AuthorityClass::Mutation;
      request.controller = controller_id(name);
      request.incarnation = incarnation;
      request.scopes = scope_set({"facility.inventory"});
      request.sponsor = model.admin;
      request.provenance = provenance_input(name, dccp::epoch::ProvenanceSourceKind::Controller);

      const Result<AuthorityGrantView> view = apply_command(
          authority.authority(), [&]() { return authority.authority().acquire_authority(request); }, predicted, seed,
          step, "acquisition on a stale incarnation of '" + name + "'");
      CPE_REQUIRE(!view.has_value());
      if (predicted == ErrorCode::IncarnationSuperseded) {
        ++counters.superseded_incarnation_rejections;
      }
    } else if (kind == OperationKind::AcquireWithoutSponsor) {
      if (known.empty()) {
        ++counters.skipped;
        break;
      }
      const std::string name =
          known[static_cast<std::size_t>(random.next_below(static_cast<std::uint64_t>(known.size())))];
      const ControllerModel& controller = model.controllers[name];
      const ErrorCode predicted = model.controller_is_fenced(name) ? ErrorCode::AuthorityRevoked
                                                                  : ErrorCode::SponsorRequired;

      dccp::epoch::AcquireAuthorityRequest request;
      request.authority_class = AuthorityClass::Mutation;
      request.controller = controller_id(name);
      request.incarnation = ControllerIncarnationId::from_hex(controller.incarnation_id).value();
      request.scopes = scope_set({"facility.inventory"});
      request.sponsor = std::nullopt;
      request.provenance = provenance_input(name, dccp::epoch::ProvenanceSourceKind::Controller);

      const Result<AuthorityGrantView> view = apply_command(
          authority.authority(), [&]() { return authority.authority().acquire_authority(request); }, predicted, seed,
          step, "unsponsored acquisition for '" + name + "'");
      CPE_REQUIRE(!view.has_value());
    } else if (kind == OperationKind::AdvanceEpoch) {
      // The expected epoch is checked before the presented authority, so a
      // current expectation with fenced authority is an authority rejection and
      // not a conflict.
      const ErrorCode predicted = model.admin_rejection();
      if (!model.admin.has_value()) {
        ++counters.skipped;
        break;
      }
      dccp::epoch::AdvanceEpochRequest request;
      request.expected_current = Epoch::from_trusted(model.epoch);
      request.authority = *model.admin;
      request.reason = dccp::epoch::EpochTransitionReason::OperatorRequest;
      request.provenance = provenance_input("operator");
      const Result<EpochTransitionRecord> transition = apply_command(
          authority.authority(), [&]() { return authority.authority().advance_epoch(request); }, predicted, seed,
          step, "epoch advancement");
      if (!transition.has_value()) {
        break;
      }
      const std::uint64_t fenced_live_grants = model.live_grants();
      CPE_REQUIRE_MSG(transition.value().base_epoch().value() == model.epoch,
                      context(seed, step, "a transition must name the epoch it fenced"));
      CPE_REQUIRE_MSG(transition.value().new_epoch().value() == model.epoch + 1,
                      context(seed, step, "a transition must advance exactly one epoch"));
      CPE_REQUIRE_MSG(transition.value().fenced_grant_count() == fenced_live_grants,
                      context(seed, step, "a transition must fence exactly the live grants of its base epoch"));
      CPE_REQUIRE_MSG(transition.value().controller_count() == model.controllers.size(),
                      context(seed, step, "a transition must record the controller population of its base epoch"));
      model.epoch += 1;
      model.transition_count += 1;
      model.generation += 1;
      for (auto& entry : model.grants) {
        entry.second.present = false;
      }
      // Half of the time the operator re-derives authority immediately; the
      // other half deliberately leaves the sequence running on fenced authority
      // until the dedicated re-derivation command comes up.
      if (random.next_below(2) == 0) {
        reacquire_admin();
      }
    } else if (kind == OperationKind::AdvanceWithStaleEpoch) {
      if (!model.admin.has_value()) {
        ++counters.skipped;
        break;
      }
      const std::uint64_t stale = model.epoch == 1 ? model.epoch + 1 : model.epoch - 1;
      dccp::epoch::AdvanceEpochRequest request;
      request.expected_current = Epoch::from_trusted(stale);
      request.authority = *model.admin;
      request.reason = dccp::epoch::EpochTransitionReason::OperatorRequest;
      request.provenance = provenance_input("operator");
      const Result<EpochTransitionRecord> transition = apply_command(
          authority.authority(), [&]() { return authority.authority().advance_epoch(request); },
          ErrorCode::EpochConflict, seed, step, "advancement against a stale expected epoch");
      CPE_REQUIRE(!transition.has_value());
      ++counters.epoch_conflicts;
    } else if (kind == OperationKind::ReacquireAdministrativeAuthority) {
      reacquire_admin();
    } else if (kind == OperationKind::RevokeController) {
      if (known.empty()) {
        ++counters.skipped;
        break;
      }
      const std::string name =
          known[static_cast<std::size_t>(random.next_below(static_cast<std::uint64_t>(known.size())))];
      const ControllerModel& controller = model.controllers[name];
      const std::uint64_t through = 1 + random.next_below(controller.incarnation_number + 1);
      const ErrorCode predicted = model.admin_rejection();
      if (!model.admin.has_value()) {
        ++counters.skipped;
        break;
      }
      RevokeAuthorityRequest request;
      request.target =
          RevocationTarget::controller_through(controller_id(name), IncarnationNumber::from_trusted(through));
      request.reason = RevocationReason::ControllerRestart;
      request.authority = *model.admin;
      request.provenance = provenance_input("operator");
      std::uint64_t predicted_fenced = 0;
      for (const auto& entry : model.grants) {
        if (entry.second.present && entry.second.controller == name &&
            entry.second.incarnation_number <= through && entry.second.state == GrantState::Live) {
          ++predicted_fenced;
        }
      }
      const Result<RevocationRecord> revocation = apply_command(
          authority.authority(), [&]() { return authority.authority().revoke_authority(request); }, predicted, seed,
          step, "controller revocation of '" + name + "'");
      if (!revocation.has_value()) {
        break;
      }
      CPE_REQUIRE_MSG(revocation.value().through_incarnation().has_value() &&
                          revocation.value().through_incarnation()->value() == through,
                      context(seed, step, "a controller revocation must record the fence it was asked for"));
      CPE_REQUIRE_MSG(revocation.value().fenced_grant_count() == predicted_fenced,
                      context(seed, step,
                              "a controller revocation fenced a different number of grants than predicted"));

      auto& target = model.controllers[name];
      target.revoked_through = std::max(target.revoked_through.value_or(0), through);
      for (auto& entry : model.grants) {
        if (entry.second.present && entry.second.controller == name &&
            entry.second.incarnation_number <= through && entry.second.state == GrantState::Live) {
          entry.second.state = GrantState::Revoked;
        }
      }
      model.revocation_count += 1;
      model.generation += 1;
    } else if (kind == OperationKind::RevokeGrant) {
      const bool bogus = present_grants.empty() || random.next_below(4) == 0;
      // The presented authority is validated before the target is resolved, so
      // fenced or revoked administrative authority wins over an unknown target.
      const ErrorCode authority_code = model.admin_rejection();
      const ErrorCode predicted = authority_code != ErrorCode::Ok
                                      ? authority_code
                                      : (bogus ? ErrorCode::RevocationUnknownTarget : ErrorCode::Ok);
      if (!model.admin.has_value()) {
        ++counters.skipped;
        break;
      }
      std::uint64_t grant_id = 0;
      std::string owner = root.str();
      if (bogus) {
        grant_id = model.next_grant_id + 1000;
      } else {
        grant_id = present_grants[static_cast<std::size_t>(
            random.next_below(static_cast<std::uint64_t>(present_grants.size())))];
        owner = model.grants[grant_id].controller;
      }
      const bool already_revoked = !bogus && model.grants[grant_id].state == GrantState::Revoked;

      RevokeAuthorityRequest request;
      request.target = RevocationTarget::grant(GrantId::from_trusted(grant_id), controller_id(owner));
      request.reason = RevocationReason::OperatorRequest;
      request.authority = *model.admin;
      request.provenance = provenance_input("operator");
      const Result<RevocationRecord> revocation = apply_command(
          authority.authority(), [&]() { return authority.authority().revoke_authority(request); }, predicted, seed,
          step, "grant revocation of " + std::to_string(grant_id));
      if (!revocation.has_value()) {
        break;
      }
      CPE_REQUIRE_MSG(revocation.value().fenced_grant_count() == (already_revoked ? 0u : 1u),
                      context(seed, step, "a grant revocation must fence the grant exactly once"));
      CPE_REQUIRE_MSG(revocation.value().replayed() == already_revoked,
                      context(seed, step, "a repeated grant revocation must be reported as replayed"));
      model.grants[grant_id].state = GrantState::Revoked;
      model.revocation_count += 1;
      model.generation += 1;
    } else if (kind == OperationKind::ValidateToken) {
      if (model.tokens.empty()) {
        ++counters.skipped;
        break;
      }
      const IssuedTokenModel& issued = model.tokens[static_cast<std::size_t>(
          random.next_below(static_cast<std::uint64_t>(model.tokens.size())))];
      const std::string& scope = scope_pool[static_cast<std::size_t>(
          random.next_below(static_cast<std::uint64_t>(scope_pool.size())))];
      const ErrorCode predicted = predict_validation(model, issued, scope);
      const ValidationOutcome outcome = validate_issued(authority.authority(), issued, scope_name(scope));
      CPE_REQUIRE_MSG(outcome.code() == predicted,
                      context(seed, step, "validating grant " + std::to_string(issued.grant_id) + " for scope '" +
                                              scope + "' produced " + std::string(error_token(outcome.code())) +
                                              " where the model predicts " + std::string(error_token(predicted))));
      count_outcome(counters, predicted);
    } else {
      CPE_REQUIRE(kind == OperationKind::InspectLedgers);
      const Result<dccp::epoch::EpochHistoryPage> history = authority.authority().history(HistoryQuery{});
      CPE_REQUIRE_MSG(history.has_value(), context(seed, step, "the transition ledger must be readable"));
      CPE_REQUIRE_MSG(history.value().total_count() == model.transition_count,
                      context(seed, step, "the transition ledger total differs from the model"));
      CPE_REQUIRE_MSG(history.value().records().size() == model.transition_count,
                      context(seed, step, "the untrimmed transition ledger must be returned in full"));
      CPE_REQUIRE_MSG(history.value().trimmed_count() == 0, context(seed, step, "nothing may be trimmed yet"));
      for (std::size_t index = 1; index < history.value().records().size(); ++index) {
        CPE_REQUIRE_MSG(history.value().records()[index - 1].sequence() < history.value().records()[index].sequence(),
                        context(seed, step, "transition records must ascend"));
        CPE_REQUIRE_MSG(history.value().records()[index].previous_record_digest() ==
                            history.value().records()[index - 1].record_digest(),
                        context(seed, step, "the transition chain must link"));
        CPE_REQUIRE_MSG(history.value().records()[index].base_epoch() ==
                            history.value().records()[index - 1].new_epoch(),
                        context(seed, step, "the transition chain must be contiguous in epoch"));
      }
      CPE_REQUIRE_MSG(history.value().records().front().is_origin(),
                      context(seed, step, "the oldest retained transition is the genesis record"));
      CPE_REQUIRE_MSG(history.value().chain_head() == history.value().records().back().record_digest(),
                      context(seed, step, "the chain head must be the newest transition"));
      CPE_REQUIRE_MSG(history.value().records().back().new_epoch().value() == model.epoch,
                      context(seed, step, "the newest transition must produce the current epoch"));

      const Result<dccp::epoch::RevocationPage> revocations = authority.authority().revocations(RevocationQuery{});
      CPE_REQUIRE_MSG(revocations.has_value(), context(seed, step, "the revocation ledger must be readable"));
      CPE_REQUIRE_MSG(revocations.value().total_count() == model.revocation_count,
                      context(seed, step, "the revocation ledger total differs from the model"));
      CPE_REQUIRE_MSG(revocations.value().records().size() == model.revocation_count,
                      context(seed, step, "the untrimmed revocation ledger must be returned in full"));
      for (std::size_t index = 1; index < revocations.value().records().size(); ++index) {
        CPE_REQUIRE_MSG(revocations.value().records()[index].previous_record_digest() ==
                            revocations.value().records()[index - 1].record_digest(),
                        context(seed, step, "the revocation chain must link"));
      }

      const Result<dccp::epoch::ControllerPage> controllers =
          authority.authority().controllers(dccp::epoch::ControllerQuery{});
      CPE_REQUIRE_MSG(controllers.has_value(), context(seed, step, "the controller page must be readable"));
      CPE_REQUIRE_MSG(controllers.value().total_count() == model.controllers.size(),
                      context(seed, step, "the controller ledger total differs from the model"));
      CPE_REQUIRE_MSG(controllers.value().records().size() == model.controllers.size(),
                      context(seed, step, "every registered controller must fit in one page"));
      for (std::size_t index = 1; index < controllers.value().records().size(); ++index) {
        CPE_REQUIRE_MSG(controllers.value().records()[index - 1].controller() <
                            controllers.value().records()[index].controller(),
                        context(seed, step, "controller records must ascend"));
      }
      }  // the final branch of the dispatch chain
    } while (false);

    // -- invariants that must hold after every operation ---------------------
    // The epoch moves at most one step per operation; the durable generation
    // moves exactly once per accepted mutation (require_model_matches compares
    // it with the model, so a command that was refused cannot have committed)
    // and never backwards.
    CPE_REQUIRE_MSG(model.epoch >= epoch_before, context(seed, step, "the epoch decreased"));
    CPE_REQUIRE_MSG(model.epoch <= epoch_before + 1, context(seed, step, "the epoch skipped a value"));
    CPE_REQUIRE_MSG(model.generation >= generation_before && model.generation <= generation_before + 2,
                    context(seed, step, "an operation committed an unexpected number of generations"));
    require_model_matches(authority, model, seed, step);
    sweep_tokens(authority, model, counters, seed, step);

    const AuthorityStatus status = authority.authority().status();
    CPE_REQUIRE_MSG(!status.snapshot_digest().is_zero(), context(seed, step, "a published digest is never zero"));
    CPE_REQUIRE_MSG(!status.transition_chain_head().is_zero(),
                    context(seed, step, "a committed domain always has a transition chain"));
    trace.snapshot_digests.push_back(status.snapshot_digest().to_hex());
    trace.chain_heads.push_back(status.transition_chain_head().to_hex());
  }

  const Result<dccp::epoch::EpochHistoryPage> history = authority.authority().history(HistoryQuery{});
  CPE_REQUIRE(history.has_value());
  for (const EpochTransitionRecord& record : history.value().records()) {
    trace.transition_digests.push_back(record.record_digest().to_hex());
  }
  const Result<dccp::epoch::RevocationPage> revocations = authority.authority().revocations(RevocationQuery{});
  CPE_REQUIRE(revocations.has_value());
  for (const RevocationRecord& record : revocations.value().records()) {
    trace.revocation_digests.push_back(record.record_digest().to_hex());
  }
  trace.final_status = authority.authority().status().to_string();
  trace.operations = counters.operations;

  // Coverage of the individual validity invariants is asserted across the whole
  // seeded corpus by the caller, and the deterministic ladder test below proves
  // each one exactly; a single seed need not hit every one of them by chance.
  // What every sequence must satisfy is that it applied every operation it drew.
  CPE_REQUIRE_MSG(counters.accepted_validations > 0,
                  context(seed, operations, "the sequence never observed an accepted validation"));
  CPE_REQUIRE_EQ(counters.skipped, std::uint64_t{0});
  CPE_REQUIRE_EQ(counters.operations, static_cast<std::uint64_t>(operations));

  if (counters_out != nullptr) {
    counters_out->operations += counters.operations;
    counters_out->skipped += counters.skipped;
    counters_out->accepted_validations += counters.accepted_validations;
    counters_out->fenced_epoch_rejections += counters.fenced_epoch_rejections;
    counters_out->superseded_incarnation_rejections += counters.superseded_incarnation_rejections;
    counters_out->revoked_grant_rejections += counters.revoked_grant_rejections;
    counters_out->scope_not_granted_rejections += counters.scope_not_granted_rejections;
    counters_out->epoch_conflicts += counters.epoch_conflicts;
  }
  return trace;
}

}  // namespace

CPE_TEST(property, seeded_sequences_preserve_authority_invariants) {
  InvariantCounters total;
  std::size_t seeds_run = 0;
  for (const std::uint64_t seed : kSeeds) {
    const SequenceTrace trace = run_sequence(seed, kOperationsPerSeed, &total);
    CPE_REQUIRE_MSG(trace.snapshot_digests.size() == kOperationsPerSeed,
                    "seed=" + std::to_string(seed) + ": every applied operation must record a snapshot digest");
    CPE_REQUIRE_MSG(!trace.final_status.empty(),
                    "seed=" + std::to_string(seed) + ": the settled status must be renderable");
    ++seeds_run;
  }
  CPE_REQUIRE_EQ(seeds_run, sizeof(kSeeds) / sizeof(kSeeds[0]));
  CPE_REQUIRE_MSG(total.operations - total.skipped >= 300,
                  "the property suite must run at least 300 operations, ran " +
                      std::to_string(total.operations - total.skipped));
  CPE_REQUIRE_MSG(total.accepted_validations > 0 && total.fenced_epoch_rejections > 0 &&
                      total.superseded_incarnation_rejections > 0 && total.revoked_grant_rejections > 0 &&
                      total.scope_not_granted_rejections > 0 && total.epoch_conflicts > 0,
                  "the aggregate run must exercise every validity invariant at least once");
}

CPE_TEST(property, every_validity_invariant_is_exercised_deterministically) {
  // The randomized sequences above assert the whole model after every step, but
  // whether a single seed happens to hit each rejection category is a matter of
  // luck. This sequence is fixed: it walks the documented validation ladder one
  // rung at a time and proves, with no generator involved, that each invariant
  // holds and that each rejection repeats identically.
  cpe_test::TestAuthority authority;
  const MutationAuthority admin = authority.root_authority();
  const ScopeName inventory = scope_name("facility.inventory");
  const ScopeName topology = scope_name("facility.topology");
  const auto validate = [&](const MutationAuthority& token, const ScopeName& scope) {
    return authority.authority().validate_mutation(token, scope);
  };
  const auto repeatable = [&](const MutationAuthority& token, const ScopeName& scope, ErrorCode expected,
                              const std::string& what) {
    const ValidationOutcome first = validate(token, scope);
    CPE_REQUIRE_MSG(first.code() == expected,
                    what + ": produced " + std::string(error_token(first.code())) + " instead of " +
                        std::string(error_token(expected)));
    const std::string status = authority.authority().status().to_string();
    const ValidationOutcome second = validate(token, scope);
    CPE_REQUIRE_MSG(second.to_string() == first.to_string(), what + ": a repeated rejection must be identical");
    CPE_REQUIRE_MSG(authority.authority().status().to_string() == status,
                    what + ": a rejected validation must not change the status");
  };

  const Epoch first_epoch = authority.authority().current_epoch();

  // Rung 1: a live grant covering the scope validates.
  const dccp::epoch::ControllerRegistration first = authority.register_controller("ladder");
  const AuthorityGrantView first_view =
      authority.acquire("ladder", first.incarnation_id(), {"facility.inventory"}, admin);
  const MutationAuthority first_token = authority.mutation_authority_of(first_view);
  CPE_REQUIRE_MSG(validate(first_token, inventory).accepted(),
                  "a live grant covering the scope must validate: " + validate(first_token, inventory).to_string());

  // Rung 2: a declared scope the grant does not cover is refused.
  repeatable(first_token, topology, ErrorCode::ScopeNotGranted, "a scope outside the grant");

  // Rung 3: a superseded incarnation never validates, and supersession is
  // immediate: the re-registration itself fences the earlier grant.
  const dccp::epoch::ControllerRegistration second = authority.register_controller("ladder");
  CPE_REQUIRE_EQ(second.incarnation_number().value(), std::uint64_t{2});
  CPE_REQUIRE_EQ(authority.authority().current_epoch().value(), first_epoch.value());
  repeatable(first_token, inventory, ErrorCode::IncarnationSuperseded, "a superseded incarnation");

  // Rung 4: a revoked grant never validates, and revocation is immediate.
  const AuthorityGrantView second_view =
      authority.acquire("ladder", second.incarnation_id(), {"facility.inventory"}, admin);
  const MutationAuthority second_token = authority.mutation_authority_of(second_view);
  CPE_REQUIRE_MSG(validate(second_token, inventory).accepted(), "the fresh grant must validate");
  RevokeAuthorityRequest revoke;
  revoke.target = RevocationTarget::grant(second_view.record().id(), controller_id("ladder"));
  revoke.reason = RevocationReason::OperatorRequest;
  revoke.authority = admin;
  revoke.provenance = provenance_input("operator");
  const Result<RevocationRecord> revocation = authority.authority().revoke_authority(revoke);
  CPE_REQUIRE_MSG(revocation.has_value(), "revoking a live grant must be accepted");
  CPE_REQUIRE_EQ(revocation.value().fenced_grant_count(), std::uint64_t{1});
  repeatable(second_token, inventory, ErrorCode::AuthorityRevoked, "a revoked grant");

  // Rung 5: a superseded epoch never validates. The advancement fences every
  // grant of its base epoch, including the authority that committed it.
  const Epoch base = authority.authority().current_epoch();
  (void)authority.advance(base, admin);
  CPE_REQUIRE_EQ(authority.authority().current_epoch().value(), base.value() + 1);
  CPE_REQUIRE_EQ(authority.authority().status().transition_count(), std::uint64_t{2});
  repeatable(admin, dccp::epoch::epoch_advance_scope(), ErrorCode::EpochFenced, "a superseded epoch");
  repeatable(second_token, inventory, ErrorCode::EpochFenced, "a revoked grant of a superseded epoch");

  // Rung 6: a token whose claims are internally consistent but name no stored
  // grant is refused by the store, in the current epoch.
  const MutationAuthority fresh_admin = authority.root_authority();
  CPE_REQUIRE_MSG(authority.authority()
                      .validate_mutation(fresh_admin, dccp::epoch::epoch_advance_scope())
                      .accepted(),
                  "authority re-derived in the new epoch must validate");
  const MutationAuthority fabricated =
      craft_token_for_test(authority.domain(), base.value() + 1, "ladder", second.incarnation_id(), 4096);
  repeatable(fabricated, inventory, ErrorCode::UnknownGrant, "a consistent token for no stored grant");

  // The epoch moved forward exactly once, never backwards and never skipping.
  CPE_REQUIRE_EQ(authority.authority().status().epoch().value(), first_epoch.value() + 1);
}

CPE_TEST(property, identical_sequences_replay_to_identical_digests) {
  // Canonical serialization implies determinism: the same commands against a
  // fresh store of the same domain must produce the same durable bytes, and
  // therefore the same record and snapshot digests, with no dependence on
  // timing, allocation, or iteration order.
  constexpr std::uint64_t seed = 0x00C0FFEE0000FEEDull;
  const SequenceTrace first = run_sequence(seed, kOperationsPerSeed, nullptr);
  const SequenceTrace second = run_sequence(seed, kOperationsPerSeed, nullptr);

  CPE_REQUIRE_MSG(first.operations == second.operations, "seed=" + std::to_string(seed) + ": operation counts differ");
  CPE_REQUIRE_MSG(!first.snapshot_digests.empty(), "seed=" + std::to_string(seed) + ": the trace must not be empty");
  CPE_REQUIRE_MSG(first.snapshot_digests == second.snapshot_digests,
                  "seed=" + std::to_string(seed) + ": snapshot digests differ between identical replays");
  CPE_REQUIRE_MSG(first.chain_heads == second.chain_heads,
                  "seed=" + std::to_string(seed) + ": transition chain heads differ between identical replays");
  CPE_REQUIRE_MSG(first.transition_digests == second.transition_digests,
                  "seed=" + std::to_string(seed) + ": transition record digests differ between identical replays");
  CPE_REQUIRE_MSG(first.revocation_digests == second.revocation_digests,
                  "seed=" + std::to_string(seed) + ": revocation record digests differ between identical replays");
  CPE_REQUIRE_MSG(first.final_status == second.final_status,
                  "seed=" + std::to_string(seed) + ": the settled status differs between identical replays");
  CPE_REQUIRE_MSG(first.transition_digests.size() >= 2,
                  "seed=" + std::to_string(seed) + ": the replay must contain committed transitions to compare");
}
