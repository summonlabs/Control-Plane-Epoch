// Control Plane Epoch 1.0.0 - Summon Software Labs
// The authority state machine.
#include "core.hpp"

#include <algorithm>
#include <utility>

#include "durable.hpp"
#include "encoding.hpp"

namespace dccp::epoch::detail {
namespace {

constexpr std::string_view kRegisterTag = "cpe.cmd.register.v1";
constexpr std::string_view kAcquireTag = "cpe.cmd.acquire.v1";
constexpr std::string_view kAdvanceTag = "cpe.cmd.advance.v1";
constexpr std::string_view kRevokeTag = "cpe.cmd.revoke.v1";

void hash_provenance_input(Sha256& hasher, const ProvenanceInput& input) {
  hash_u32(hasher, static_cast<std::uint32_t>(input.kind()));
  hash_text(hasher, input.source().view());
  hash_bool(hasher, input.external().has_value());
  if (input.external().has_value()) {
    hash_text(hasher, input.external()->kind());
    hash_text(hasher, input.external()->value());
  }
  hash_text(hasher, input.note());
}

[[nodiscard]] Sha256Digest digest_register(const ControllerId& controller, const ProvenanceInput& provenance) {
  Sha256 hasher;
  hash_text(hasher, kRegisterTag);
  hash_text(hasher, controller.view());
  hash_provenance_input(hasher, provenance);
  return hasher.finish();
}

[[nodiscard]] Sha256Digest digest_acquire(AuthorityClass authority_class, const ControllerId& controller,
                                         const ControllerIncarnationId& incarnation,
                                         const AuthorityScopeSet& scopes, const ProvenanceInput& provenance) {
  Sha256 hasher;
  hash_text(hasher, kAcquireTag);
  hash_u32(hasher, static_cast<std::uint32_t>(authority_class));
  hash_text(hasher, controller.view());
  hash_digest(hasher, incarnation.digest());
  hash_u32(hasher, static_cast<std::uint32_t>(scopes.size()));
  for (const ScopeName& scope : scopes.scopes()) {
    hash_text(hasher, scope.view());
  }
  hash_provenance_input(hasher, provenance);
  return hasher.finish();
}

[[nodiscard]] Sha256Digest digest_advance(Epoch expected, EpochTransitionReason reason,
                                         const ProvenanceInput& provenance) {
  Sha256 hasher;
  hash_text(hasher, kAdvanceTag);
  hash_u64(hasher, expected.value());
  hash_u32(hasher, static_cast<std::uint32_t>(reason));
  hash_provenance_input(hasher, provenance);
  return hasher.finish();
}

[[nodiscard]] Sha256Digest digest_revoke(const RevocationTarget& target, RevocationReason reason,
                                        const ProvenanceInput& provenance) {
  Sha256 hasher;
  hash_text(hasher, kRevokeTag);
  hash_u32(hasher, static_cast<std::uint32_t>(target.kind()));
  hash_text(hasher, target.controller().view());
  hash_bool(hasher, target.through_incarnation().has_value());
  if (target.through_incarnation().has_value()) {
    hash_u64(hasher, target.through_incarnation()->value());
  }
  hash_bool(hasher, target.grant().has_value());
  if (target.grant().has_value()) {
    hash_u64(hasher, target.grant()->value());
  }
  hash_u32(hasher, static_cast<std::uint32_t>(reason));
  hash_provenance_input(hasher, provenance);
  return hasher.finish();
}

[[nodiscard]] bool scopes_match(const std::vector<std::string>& stored, const AuthorityScopeSet& claimed) {
  if (stored.size() != claimed.size()) {
    return false;
  }
  for (std::size_t index = 0; index < stored.size(); ++index) {
    if (stored[index] != claimed.scopes()[index].str()) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] bool is_reserved_administrative_scope(const ScopeName& scope) {
  return scope == authority_grant_scope() || scope == authority_revoke_scope() || scope == epoch_advance_scope();
}

/// Guards against a caller leaving an enumeration field uninitialized or outside
/// its domain. A value carried across a trust boundary is validated by value,
/// never assumed valid merely because its type is an enumeration.
[[nodiscard]] bool is_valid_authority_class(AuthorityClass authority_class) noexcept {
  return authority_class == AuthorityClass::Mutation || authority_class == AuthorityClass::Observation;
}

[[nodiscard]] bool contains_digest(const std::vector<Sha256Digest>& digests, const Sha256Digest& digest) {
  return std::find(digests.begin(), digests.end(), digest) != digests.end();
}

}  // namespace

AuthorityCore::AuthorityCore(const StoreOpenOptions& options) : store_(AuthorityStore::open(options)) {}
AuthorityCore::~AuthorityCore() { close(); }

const RecoveryReport& AuthorityCore::recovery() const {
  std::lock_guard<std::mutex> guard(mutex_);
  require_open();
  return store_->report();
}

bool AuthorityCore::initialized() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return store_ != nullptr && store_->initialized();
}

bool AuthorityCore::closed() const noexcept {
  std::lock_guard<std::mutex> guard(mutex_);
  return store_ == nullptr;
}

void AuthorityCore::close() noexcept {
  std::lock_guard<std::mutex> guard(mutex_);
  if (store_ != nullptr) {
    store_->close();
    store_.reset();
  }
}

void AuthorityCore::require_open() const {
  if (store_ == nullptr) {
    throw EpochError(ErrorCode::StoreNotFound, "the authority is closed");
  }
}

void AuthorityCore::require_write(const char* operation) const {
  if (store_->read_only()) {
    throw EpochError(ErrorCode::UnsupportedOperation,
                     std::string(operation) + " is not available on a read-only authority");
  }
}

void AuthorityCore::require_domain() const {
  if (!store_->initialized()) {
    throw EpochError(ErrorCode::StoreNotInitialized, "the authority domain has not been initialized yet");
  }
}

const ControllerData* AuthorityCore::find_controller(const AuthorityImage& image, std::string_view controller) {
  const auto match = std::find_if(image.controllers.begin(), image.controllers.end(),
                                  [controller](const ControllerData& candidate) {
                                    return candidate.controller == controller;
                                  });
  return match == image.controllers.end() ? nullptr : &*match;
}

ControllerData* AuthorityCore::find_controller(AuthorityImage& image, std::string_view controller) {
  const auto match = std::find_if(image.controllers.begin(), image.controllers.end(),
                                  [controller](const ControllerData& candidate) {
                                    return candidate.controller == controller;
                                  });
  return match == image.controllers.end() ? nullptr : &*match;
}

const GrantData* AuthorityCore::find_grant(const AuthorityImage& image, std::uint64_t grant_id) {
  const auto match = std::find_if(image.grants.begin(), image.grants.end(), [grant_id](const GrantData& candidate) {
    return candidate.id == grant_id;
  });
  return match == image.grants.end() ? nullptr : &*match;
}

GrantData* AuthorityCore::find_grant(AuthorityImage& image, std::uint64_t grant_id) {
  const auto match = std::find_if(image.grants.begin(), image.grants.end(), [grant_id](const GrantData& candidate) {
    return candidate.id == grant_id;
  });
  return match == image.grants.end() ? nullptr : &*match;
}

bool AuthorityCore::scope_declared(const AuthorityImage& image, std::string_view scope) {
  return std::find(image.declared_scopes.begin(), image.declared_scopes.end(), scope) != image.declared_scopes.end();
}

std::uint64_t AuthorityCore::live_grant_count(const AuthorityImage& image) {
  return static_cast<std::uint64_t>(
      std::count_if(image.grants.begin(), image.grants.end(),
                    [](const GrantData& grant) { return grant.state == GrantState::Live; }));
}

std::uint64_t AuthorityCore::allocate_sequence(AuthorityImage& image) {
  const std::uint64_t sequence = image.next_mutation_sequence;
  image.next_mutation_sequence += 1;
  return sequence;
}

Sha256Digest AuthorityCore::transition_chain_head(const AuthorityImage& image) {
  if (image.transitions.empty()) {
    return image.transition_anchor;
  }
  return image.transitions.back().record_digest;
}

Sha256Digest AuthorityCore::revocation_chain_head(const AuthorityImage& image) {
  if (image.revocations.empty()) {
    return image.revocation_anchor;
  }
  return image.revocations.back().record_digest;
}

void AuthorityCore::trim_transitions(AuthorityImage& image) {
  while (image.transitions.size() > max_transition_records) {
    image.transition_anchor = image.transitions.front().record_digest;
    image.transitions.erase(image.transitions.begin());
    image.transition_trimmed += 1;
  }
}

void AuthorityCore::trim_revocations(AuthorityImage& image) {
  while (image.revocations.size() > max_revocation_records) {
    image.revocation_anchor = image.revocations.front().record_digest;
    image.revocations.erase(image.revocations.begin());
    image.revocation_trimmed += 1;
  }
}

void AuthorityCore::trim_idempotency(AuthorityImage& image) {
  while (image.idempotency.size() > max_idempotency_records) {
    image.idempotency.erase(image.idempotency.begin());
    image.idempotency_evicted += 1;
  }
}

ProvenanceData AuthorityCore::make_provenance_data(const AuthorityImage& image, const ProvenanceInput& input,
                                                   std::uint64_t sequence) {
  return make_provenance_data(image, input, sequence, image.epoch);
}

ProvenanceData AuthorityCore::make_provenance_data(const AuthorityImage& image, const ProvenanceInput& input,
                                                   std::uint64_t sequence, std::uint64_t epoch) {
  ProvenanceData data;
  data.kind = input.kind();
  data.source = input.source().str();
  data.external = input.external();
  data.note = input.note();
  data.recorded_epoch = epoch == 0 ? image.epoch : epoch;
  data.recorded_sequence = sequence;
  data.record_digest = compute_provenance_digest(data);
  return data;
}

std::optional<Explanation> AuthorityCore::validate_provenance_input(const ProvenanceInput& input,
                                                                   std::string_view what) {
  if (input.empty()) {
    return Explanation(ErrorCode::InvalidArgument, std::string(what) + " was not supplied");
  }
  if (input.source().empty()) {
    return Explanation(ErrorCode::IdentifierEmpty, std::string(what) + " has an empty source");
  }
  return std::nullopt;
}

Result<std::optional<std::vector<std::byte>>> AuthorityCore::lookup_idempotent(
    const AuthorityImage& image, const IdempotencyKey& key, const Sha256Digest& command_digest) const {
  const auto match = std::find_if(image.idempotency.begin(), image.idempotency.end(),
                                  [&key](const IdempotencyData& entry) {
                                    return entry.controller == key.controller().str() &&
                                           entry.incarnation_id == key.incarnation().digest() &&
                                           entry.sequence == key.sequence().value();
                                  });
  if (match == image.idempotency.end()) {
    return std::optional<std::vector<std::byte>>{};
  }
  if (match->command_digest != command_digest) {
    return Explanation(ErrorCode::IdempotencyConflict,
                       "idempotency key " + key.to_string() + " was already used for a different command");
  }
  return std::optional<std::vector<std::byte>>{match->result_blob};
}

void AuthorityCore::record_idempotent(AuthorityImage& image, const IdempotencyKey& key,
                                     const Sha256Digest& command_digest, std::vector<std::byte> result_blob) {
  IdempotencyData entry;
  entry.controller = key.controller().str();
  entry.incarnation_id = key.incarnation().digest();
  entry.sequence = key.sequence().value();
  entry.command_digest = command_digest;
  entry.result_blob = std::move(result_blob);
  if (entry.result_blob.size() > max_idempotency_blob_bytes) {
    throw EpochError(ErrorCode::SizeLimitExceeded, "the idempotency result blob exceeds its bound");
  }

  const auto position = std::lower_bound(
      image.idempotency.begin(), image.idempotency.end(), entry,
      [](const IdempotencyData& lhs, const IdempotencyData& rhs) {
        if (lhs.controller != rhs.controller) {
          return lhs.controller < rhs.controller;
        }
        if (lhs.incarnation_id != rhs.incarnation_id) {
          return lhs.incarnation_id < rhs.incarnation_id;
        }
        return lhs.sequence < rhs.sequence;
      });
  if (position != image.idempotency.end() && position->controller == entry.controller &&
      position->incarnation_id == entry.incarnation_id && position->sequence == entry.sequence) {
    *position = std::move(entry);
  } else {
    image.idempotency.insert(position, std::move(entry));
  }
  image.idempotency_count += 1;
  trim_idempotency(image);
}

void AuthorityCore::commit_image(AuthorityImage image) {
  last_commit_ = store_->commit(image);
}

std::optional<DurableCommitReport> AuthorityCore::last_commit() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return last_commit_;
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

Status AuthorityCore::initialize(InitializeDomainRequest request) {
  std::lock_guard<std::mutex> guard(mutex_);
  require_open();
  require_write("initialize");

  if (store_->initialized()) {
    return Explanation(ErrorCode::StoreAlreadyInitialized,
                       "the store already holds authority domain '" + image().domain + "'");
  }
  if (request.domain.empty()) {
    return Explanation(ErrorCode::IdentifierEmpty, "the authority domain identifier is empty");
  }
  if (request.authority_root.empty()) {
    return Explanation(ErrorCode::IdentifierEmpty, "the authority root controller identifier is empty");
  }
  if (auto bad = validate_provenance_input(request.provenance, "initialization provenance")) {
    return *bad;
  }
  if (request.scopes.empty()) {
    return Explanation(ErrorCode::InvalidArgument, "an authority domain must declare at least one scope");
  }
  if (request.scopes.size() > max_declared_scopes) {
    return Explanation(ErrorCode::SizeLimitExceeded, "declared scope count " + std::to_string(request.scopes.size()) +
                                                         " exceeds the bound of " +
                                                         std::to_string(max_declared_scopes));
  }
  std::vector<ScopeName> scopes = request.scopes;
  std::sort(scopes.begin(), scopes.end());
  for (std::size_t index = 0; index < scopes.size(); ++index) {
    if (scopes[index].empty()) {
      return Explanation(ErrorCode::ScopeUnknown, "the declared scope list contains an empty scope");
    }
    if (index > 0 && scopes[index] == scopes[index - 1]) {
      return Explanation(ErrorCode::ScopeDuplicate, "duplicate declared scope " + scopes[index].to_string());
    }
  }
  // The genesis grant covers the whole declared vocabulary in one grant, and a
  // grant may not exceed the per-authority scope bound. Refusing the declaration
  // here is what keeps every published image decodable by its own reader.
  if (scopes.size() > max_scopes_per_authority) {
    return Explanation(ErrorCode::SizeLimitExceeded,
                       "a domain may declare at most " + std::to_string(max_scopes_per_authority) +
                           " scopes because its genesis grant must cover all of them, received " +
                           std::to_string(scopes.size()));
  }  for (const ScopeName& reserved : {authority_grant_scope(), authority_revoke_scope(), epoch_advance_scope()}) {
    if (std::find(scopes.begin(), scopes.end(), reserved) == scopes.end()) {
      return Explanation(ErrorCode::InvalidArgument,
                         "the reserved administrative scope '" + reserved.to_string() + "' must be declared");
    }
  }

  const InitializationSeed seed = store_->seed();

  AuthorityImage next;
  next.domain = request.domain.str();
  next.domain_instance = seed.domain_instance.value();
  next.epoch = seed.first_epoch.value();
  next.authority_root = request.authority_root.str();
  next.declared_scopes.reserve(scopes.size());
  for (const ScopeName& scope : scopes) {
    next.declared_scopes.push_back(scope.str());
  }
  next.next_grant_id = 1;
  next.next_mutation_sequence = 1;

  ControllerData root;
  root.controller = next.authority_root;
  root.incarnation_number = 1;
  root.incarnation_id =
      ControllerIncarnationId::derive(request.domain, request.authority_root, IncarnationNumber::from_trusted(1))
          .digest();
  root.incarnation_state = IncarnationState::Current;
  root.registration_count = 1;
  root.first_registered_epoch = next.epoch;
  root.latest_registered_epoch = next.epoch;
  root.latest_registration_provenance =
      make_provenance_data(next, request.provenance, allocate_sequence(next));
  root.record_digest = compute_controller_digest(root);
  next.controllers.push_back(root);

  GrantData grant;
  grant.id = next.next_grant_id;
  next.next_grant_id += 1;
  grant.authority_class = AuthorityClass::Mutation;
  grant.epoch = next.epoch;
  grant.controller = next.authority_root;
  grant.incarnation_number = 1;
  grant.incarnation_id = root.incarnation_id;
  grant.scopes.reserve(scopes.size());
  for (const ScopeName& scope : scopes) {
    grant.scopes.push_back(scope.str());
  }
  grant.sequence = allocate_sequence(next);
  grant.state = GrantState::Live;
  grant.provenance = make_provenance_data(next, request.provenance, grant.sequence);
  grant.record_digest = compute_grant_digest(grant);
  next.grants.push_back(grant);

  TransitionData transition;
  transition.sequence = 1;
  transition.origin = true;
  transition.base_epoch = 0;
  transition.new_epoch = next.epoch;
  transition.reason = EpochTransitionReason::Genesis;
  transition.committed_by = next.authority_root;
  transition.committed_by_incarnation = root.incarnation_id;
  transition.committed_by_grant = grant.id;
  transition.fenced_grant_count = 0;
  transition.controller_count = 1;
  transition.provenance = make_provenance_data(next, request.provenance, allocate_sequence(next), next.epoch);
  transition.previous_record_digest = Sha256Digest::zero();
  transition.record_digest = compute_transition_digest(transition);
  next.transitions.push_back(transition);
  next.transition_count = 1;

  commit_image(std::move(next));
  return Unit{};
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

AuthorityStatus AuthorityCore::status() const {
  std::lock_guard<std::mutex> guard(mutex_);
  require_open();
  require_domain();

  const AuthorityImage& img = image();
  AuthorityStatus result;
  result.domain_ = FacilityAuthorityDomainId::from_trusted(img.domain);
  result.domain_instance_ = DomainInstanceNumber::from_trusted(img.domain_instance);
  result.epoch_ = Epoch::from_trusted(img.epoch);
  result.durable_generation_ = DurableGeneration::from_trusted(img.durable_generation);
  result.authority_root_ = ControllerId::from_trusted(img.authority_root);
  result.controller_count_ = img.controllers.size();
  for (const GrantData& grant : img.grants) {
    if (grant.state != GrantState::Live) {
      continue;
    }
    ++result.live_grant_count_;
    if (grant.authority_class == AuthorityClass::Mutation) {
      ++result.mutation_grant_count_;
    } else {
      ++result.observation_grant_count_;
    }
  }
  result.declared_scopes_.reserve(img.declared_scopes.size());
  for (const std::string& scope : img.declared_scopes) {
    result.declared_scopes_.push_back(ScopeName::from_trusted(scope));
  }
  result.transition_count_ = img.transition_count;
  result.revocation_count_ = img.revocation_count;
  result.idempotency_record_count_ = img.idempotency_count;
  result.snapshot_digest_ = store_->snapshot_digest();
  result.transition_chain_head_ = transition_chain_head(img);
  result.recovery_outcome_ = store_->report().outcome();
  result.open_mode_ = store_->read_only() ? StoreOpenMode::ReadOnly : StoreOpenMode::ReadWrite;
  result.initialized_ = true;
  return result;
}

AuthorityAccounting AuthorityCore::accounting() const {
  std::lock_guard<std::mutex> guard(mutex_);
  require_open();

  AuthorityAccounting result;
  if (!store_->initialized()) {
    return result;
  }
  const AuthorityImage& img = image();
  result.controller_records_ = img.controllers.size();
  result.grant_records_ = img.grants.size();
  result.live_grant_records_ = live_grant_count(img);
  result.transition_records_retained_ = img.transitions.size();
  result.transition_records_trimmed_ = img.transition_trimmed;
  result.revocation_records_retained_ = img.revocations.size();
  result.revocation_records_trimmed_ = img.revocation_trimmed;
  result.idempotency_records_ = img.idempotency.size();
  result.idempotency_records_evicted_ = img.idempotency_evicted;
  result.snapshot_bytes_ = store_->snapshot_bytes();
  result.retained_previous_generation_ = store_->retained_previous_generation();
  return result;
}

Epoch AuthorityCore::current_epoch() const {
  std::lock_guard<std::mutex> guard(mutex_);
  require_open();
  require_domain();
  return Epoch::from_trusted(image().epoch);
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

ValidationOutcome AuthorityCore::validate_incarnation(const AuthorityImage& img, const ControllerId& controller,
                                                      const ControllerIncarnationId& incarnation) const {
  const ControllerData* record = find_controller(img, controller.view());
  if (record == nullptr) {
    return ValidationOutcome::reject(
        Explanation(ErrorCode::ControllerUnknown, "controller '" + controller.to_string() + "' is not registered"));
  }
  if (record->incarnation_id == incarnation.digest()) {
    return ValidationOutcome::accept();
  }
  if (contains_digest(record->superseded_incarnations, incarnation.digest())) {
    return ValidationOutcome::reject(Explanation(
        ErrorCode::IncarnationSuperseded, "incarnation " + incarnation.to_hex() + " of controller '" +
                                              controller.to_string() + "' was superseded by incarnation " +
                                              std::to_string(record->incarnation_number)));
  }
  return ValidationOutcome::reject(
      Explanation(ErrorCode::IncarnationUnknown, "incarnation " + incarnation.to_hex() + " is not the current incarnation " +
                                                     std::to_string(record->incarnation_number) +
                                                     " of controller '" + controller.to_string() + "'"));
}

template <class Token>
ValidationOutcome AuthorityCore::validate_token(const AuthorityImage& img, const Token& token,
                                               const ScopeName& scope) const {
  const AuthorityClass kClass = Token::authority_class();

  // 1. Domain.
  if (token.domain().str() != img.domain) {
    return ValidationOutcome::reject(Explanation(ErrorCode::DomainMismatch,
                                                 "token domain '" + token.domain().to_string() +
                                                     "' is not the authoritative domain '" + img.domain + "'"));
  }

  // 2. Token integrity.
  ValidationOutcome integrity = token.verify_integrity();
  if (!integrity.accepted()) {
    return integrity;
  }

  // 3. Epoch above the authoritative epoch: never committed here.
  if (token.epoch().value() > img.epoch) {
    return ValidationOutcome::reject(Explanation(ErrorCode::EpochUnknown,
                                                 "token epoch " + token.epoch().to_string() +
                                                     " was never committed; the authoritative epoch is " +
                                                     std::to_string(img.epoch)));
  }

  // 4. Epoch below the authoritative epoch: permanently fenced.
  if (token.epoch().value() < img.epoch) {
    return ValidationOutcome::reject(Explanation(ErrorCode::EpochFenced,
                                                 "token epoch " + token.epoch().to_string() +
                                                     " was fenced when epoch " + std::to_string(img.epoch) +
                                                     " committed"));
  }

  // 5. Grant existence within the current epoch.
  const GrantData* grant = find_grant(img, token.grant().value());
  if (grant == nullptr) {
    return ValidationOutcome::reject(
        Explanation(ErrorCode::UnknownGrant, "grant " + token.grant().to_string() +
                                                 " does not exist in epoch " + std::to_string(img.epoch)));
  }

  // 6. Authority class.
  if (grant->authority_class != kClass) {
    return ValidationOutcome::reject(Explanation(
        ErrorCode::AuthorityClassMismatch, "grant " + token.grant().to_string() + " authorizes " +
                                               std::string(authority_class_token(grant->authority_class)) +
                                               " authority, not " + std::string(authority_class_token(kClass))));
  }

  // 7. Claims must match the stored grant exactly.
  if (grant->controller != token.controller().str() || grant->incarnation_id != token.incarnation().digest() ||
      !scopes_match(grant->scopes, token.scopes())) {
    return ValidationOutcome::reject(Explanation(ErrorCode::ClaimsMismatch,
                                                 "token claims do not match grant " + token.grant().to_string()));
  }

  // 8. Revoked grant.
  if (grant->state == GrantState::Revoked) {
    return ValidationOutcome::reject(Explanation(
        ErrorCode::AuthorityRevoked, "grant " + token.grant().to_string() + " was revoked by revocation " +
                                         (grant->revoked_by_sequence.has_value()
                                              ? std::to_string(*grant->revoked_by_sequence)
                                              : std::string("an unspecified record"))));
  }

  // 9. Controller existence.
  const ControllerData* controller = find_controller(img, grant->controller);
  if (controller == nullptr) {
    return ValidationOutcome::reject(Explanation(ErrorCode::ControllerUnknown, "controller '" + grant->controller +
                                                                                   "' is no longer registered"));
  }

  // 10. Superseded grant.
  if (grant->state == GrantState::Superseded) {
    return ValidationOutcome::reject(Explanation(
        ErrorCode::IncarnationSuperseded, "grant " + token.grant().to_string() + " belonged to incarnation " +
                                              std::to_string(grant->incarnation_number) + " of controller '" +
                                              grant->controller + "', which is no longer current"));
  }

  // 11. Incarnation currency.
  if (token.incarnation().digest() != controller->incarnation_id) {
    return validate_incarnation(img, ControllerId::from_trusted(controller->controller), token.incarnation());
  }

  // 12. Scope coverage.
  if (!token.covers(scope)) {
    return ValidationOutcome::reject(Explanation(ErrorCode::ScopeNotGranted, "grant " +
                                                                                 token.grant().to_string() +
                                                                                 " does not cover scope '" +
                                                                                 scope.to_string() + "'"));
  }
  return ValidationOutcome::accept();
}

ValidationOutcome AuthorityCore::validate_mutation(const MutationAuthority& authority, const ScopeName& scope) {
  std::lock_guard<std::mutex> guard(mutex_);
  require_open();
  require_domain();
  return validate_token(image(), authority, scope);
}

ValidationOutcome AuthorityCore::validate_observation(const ObservationAuthority& authority, const ScopeName& scope) {
  std::lock_guard<std::mutex> guard(mutex_);
  require_open();
  require_domain();
  return validate_token(image(), authority, scope);
}

// ---------------------------------------------------------------------------
// Controller registration
// ---------------------------------------------------------------------------

Result<ControllerRegistration> AuthorityCore::register_controller(RegisterControllerRequest request) {
  std::lock_guard<std::mutex> guard(mutex_);
  require_open();
  require_write("register_controller");
  require_domain();

  if (request.controller.empty()) {
    return Explanation(ErrorCode::IdentifierEmpty, "the controller identifier is empty");
  }
  if (auto bad = validate_provenance_input(request.provenance, "registration provenance")) {
    return *bad;
  }

  const Sha256Digest command_digest = digest_register(request.controller, request.provenance);
  if (request.idempotency.has_value()) {
    Result<std::optional<std::vector<std::byte>>> recorded =
        lookup_idempotent(image(), *request.idempotency, command_digest);
    if (!recorded.has_value()) {
      return recorded.rejection();
    }
    if (recorded.value().has_value()) {
      CanonicalReader reader(std::span<const std::byte>(*recorded.value()), max_identifier_length);
      ControllerRegistration replayed = decode_registration(reader, true);
      reader.expect_end();
      return replayed;
    }
  }

  AuthorityImage next = image();
  ControllerData* controller = find_controller(next, request.controller.view());
  if (controller == nullptr) {
    if (next.controllers.size() >= max_controllers) {
      return Explanation(ErrorCode::ControllerLimitReached,
                         "the domain already holds " + std::to_string(next.controllers.size()) +
                             " controllers, which is its bound");
    }
    ControllerData created;
    created.controller = request.controller.str();
    created.incarnation_number = 1;
    created.incarnation_id = ControllerIncarnationId::derive(FacilityAuthorityDomainId::from_trusted(next.domain),
                                                             request.controller,
                                                             IncarnationNumber::from_trusted(1))
                                 .digest();
    created.incarnation_state = IncarnationState::Current;
    created.registration_count = 1;
    created.first_registered_epoch = next.epoch;
    created.latest_registered_epoch = next.epoch;
    created.latest_registration_provenance =
        make_provenance_data(next, request.provenance, allocate_sequence(next));
    created.record_digest = compute_controller_digest(created);

    const auto position = std::lower_bound(
        next.controllers.begin(), next.controllers.end(), created.controller,
        [](const ControllerData& candidate, const std::string& key) { return candidate.controller < key; });
    controller = &*next.controllers.insert(position, std::move(created));
  } else {
    if (controller->incarnation_number == UINT64_MAX) {
      return Explanation(ErrorCode::CounterExhausted, "the controller incarnation counter is exhausted");
    }
    // Every grant of the superseded incarnation is fenced immediately.
    for (GrantData& grant : next.grants) {
      if (grant.controller == controller->controller && grant.state == GrantState::Live) {
        grant.state = GrantState::Superseded;
        grant.record_digest = compute_grant_digest(grant);
      }
    }
    controller->superseded_incarnations.insert(controller->superseded_incarnations.begin(),
                                               controller->incarnation_id);
    if (controller->superseded_incarnations.size() > max_superseded_incarnations) {
      controller->superseded_incarnations.resize(max_superseded_incarnations);
    }
    controller->incarnation_number += 1;
    controller->incarnation_id =
        ControllerIncarnationId::derive(FacilityAuthorityDomainId::from_trusted(next.domain), request.controller,
                                        IncarnationNumber::from_trusted(controller->incarnation_number))
            .digest();
    controller->incarnation_state = IncarnationState::Current;
    controller->registration_count += 1;
    controller->latest_registered_epoch = next.epoch;
    controller->latest_registration_provenance =
        make_provenance_data(next, request.provenance, allocate_sequence(next));
    controller->record_digest = compute_controller_digest(*controller);
  }

  const ControllerData snapshot = *controller;
  ControllerRegistration registration =
      RecordFactory::make_registration(snapshot, snapshot.latest_registration_provenance);
  if (request.idempotency.has_value()) {
    CanonicalWriter writer(max_idempotency_blob_bytes);
    encode_registration(writer, registration);
    record_idempotent(next, *request.idempotency, command_digest, writer.take());
  }
  commit_image(std::move(next));
  return registration;
}

// ---------------------------------------------------------------------------
// Authority acquisition
// ---------------------------------------------------------------------------

Result<AuthorityGrantView> AuthorityCore::acquire_authority(AcquireAuthorityRequest request) {
  std::lock_guard<std::mutex> guard(mutex_);
  require_open();
  require_write("acquire_authority");
  require_domain();

  if (request.controller.empty()) {
    return Explanation(ErrorCode::IdentifierEmpty, "the controller identifier is empty");
  }
  if (!is_valid_authority_class(request.authority_class)) {
    return Explanation(ErrorCode::InvalidArgument,
                       "the requested authority class " +
                           std::to_string(static_cast<std::uint32_t>(request.authority_class)) +
                           " is outside the authority class domain");
  }
  if (request.incarnation.is_zero()) {
    return Explanation(ErrorCode::InvalidArgument, "the controller incarnation is not set");
  }
  if (request.scopes.empty()) {
    return Explanation(ErrorCode::InvalidArgument, "an authority grant must cover at least one scope");
  }
  if (auto bad = validate_provenance_input(request.provenance, "grant provenance")) {
    return *bad;
  }
  for (const ScopeName& scope : request.scopes.scopes()) {
    if (!scope_declared(image(), scope.view())) {
      return Explanation(ErrorCode::ScopeUnknown, "scope '" + scope.to_string() +
                                                      "' is not declared by domain '" + image().domain + "'");
    }
  }

  const Sha256Digest command_digest =
      digest_acquire(request.authority_class, request.controller, request.incarnation, request.scopes,
                     request.provenance);
  if (request.idempotency.has_value()) {
    Result<std::optional<std::vector<std::byte>>> recorded =
        lookup_idempotent(image(), *request.idempotency, command_digest);
    if (!recorded.has_value()) {
      return recorded.rejection();
    }
    if (recorded.value().has_value()) {
      CanonicalReader reader(std::span<const std::byte>(*recorded.value()), max_identifier_length);
      GrantData grant = decode_grant(reader);
      reader.expect_end();
      Result<AuthorityGrantView> view =
          to_grant_view(grant, FacilityAuthorityDomainId::from_trusted(image().domain));
      if (!view.has_value()) {
        return view.rejection();
      }
      view.value().mark_replayed();
      return view;
    }
  }

  ValidationOutcome incarnation_currency =
      validate_incarnation(image(), request.controller, request.incarnation);
  if (!incarnation_currency.accepted()) {
    return *incarnation_currency.rejection();
  }
  const ControllerData* controller = find_controller(image(), request.controller.view());
  if (controller->revocation_through_incarnation.has_value() &&
      *controller->revocation_through_incarnation >= controller->incarnation_number) {
    return Explanation(ErrorCode::AuthorityRevoked,
                       "controller '" + request.controller.to_string() + "' is revoked through incarnation " +
                           std::to_string(*controller->revocation_through_incarnation));
  }

  bool standing_root = request.controller.str() == image().authority_root;
  if (standing_root) {
    for (const ScopeName& scope : request.scopes.scopes()) {
      if (!is_reserved_administrative_scope(scope)) {
        standing_root = false;
        break;
      }
    }
  }
  if (!standing_root) {
    if (!request.sponsor.has_value()) {
      return Explanation(ErrorCode::SponsorRequired,
                         "granting authority requires a sponsor holding scope '" +
                             authority_grant_scope().to_string() + "'");
    }
    ValidationOutcome sponsor = validate_token(image(), *request.sponsor, authority_grant_scope());
    if (!sponsor.accepted()) {
      return *sponsor.rejection();
    }
  }

  if (live_grant_count(image()) >= max_grants_per_epoch) {
    return Explanation(ErrorCode::GrantLimitReached, "epoch " + std::to_string(image().epoch) +
                                                         " already holds " + std::to_string(live_grant_count(image())) +
                                                         " live grants, which is its bound");
  }

  AuthorityImage next = image();
  GrantData grant;
  grant.id = next.next_grant_id;
  next.next_grant_id += 1;
  grant.authority_class = request.authority_class;
  grant.epoch = next.epoch;
  grant.controller = request.controller.str();
  grant.incarnation_number = controller->incarnation_number;
  grant.incarnation_id = request.incarnation.digest();
  grant.scopes.reserve(request.scopes.size());
  for (const ScopeName& scope : request.scopes.scopes()) {
    grant.scopes.push_back(scope.str());
  }
  grant.sequence = allocate_sequence(next);
  grant.state = GrantState::Live;
  grant.provenance = make_provenance_data(next, request.provenance, grant.sequence);
  grant.record_digest = compute_grant_digest(grant);
  next.grants.push_back(grant);

  Result<AuthorityGrantView> view =
      to_grant_view(grant, FacilityAuthorityDomainId::from_trusted(next.domain));
  if (!view.has_value()) {
    return view.rejection();
  }
  if (request.idempotency.has_value()) {
    CanonicalWriter writer(max_idempotency_blob_bytes);
    encode_grant(writer, grant);
    record_idempotent(next, *request.idempotency, command_digest, writer.take());
  }
  commit_image(std::move(next));
  return view;
}

// ---------------------------------------------------------------------------
// Epoch advancement
// ---------------------------------------------------------------------------

Result<EpochTransitionRecord> AuthorityCore::advance_epoch(AdvanceEpochRequest request) {
  std::lock_guard<std::mutex> guard(mutex_);
  require_open();
  require_write("advance_epoch");
  require_domain();

  if (auto bad = validate_provenance_input(request.provenance, "transition provenance")) {
    return *bad;
  }
  if (request.idempotency.has_value()) {
    if (request.idempotency->controller() != request.authority.controller() ||
        request.idempotency->incarnation() != request.authority.incarnation()) {
      return Explanation(ErrorCode::IdempotencyConflict,
                         "idempotency key " + request.idempotency->to_string() +
                             " does not belong to the controller incarnation presenting the command");
    }
  }

  const Sha256Digest command_digest = digest_advance(request.expected_current, request.reason, request.provenance);
  if (request.idempotency.has_value()) {
    Result<std::optional<std::vector<std::byte>>> recorded =
        lookup_idempotent(image(), *request.idempotency, command_digest);
    if (!recorded.has_value()) {
      return recorded.rejection();
    }
    if (recorded.value().has_value()) {
      CanonicalReader reader(std::span<const std::byte>(*recorded.value()), max_identifier_length);
      TransitionData replayed = decode_transition(reader);
      reader.expect_end();
      return RecordFactory::make_transition(replayed);
    }
  }

  if (request.expected_current.value() == 0) {
    return Explanation(ErrorCode::EpochZero, "the expected epoch is not set");
  }
  if (request.expected_current.value() != image().epoch) {
    return Explanation(ErrorCode::EpochConflict,
                       "expected epoch " + request.expected_current.to_string() +
                           " but the authoritative epoch is " + std::to_string(image().epoch));
  }

  ValidationOutcome authority = validate_token(image(), request.authority, epoch_advance_scope());
  if (!authority.accepted()) {
    return *authority.rejection();
  }

  Result<Epoch> successor = Epoch::from_trusted(image().epoch).successor();
  if (!successor.has_value()) {
    return successor.rejection();
  }

  AuthorityImage next = image();
  TransitionData transition;
  transition.sequence = next.transition_count + 1;
  transition.origin = false;
  transition.base_epoch = image().epoch;
  transition.new_epoch = successor.value().value();
  transition.reason = request.reason;
  transition.committed_by = request.authority.controller().str();
  transition.committed_by_incarnation = request.authority.incarnation().digest();
  transition.committed_by_grant = request.authority.grant().value();
  transition.fenced_grant_count = live_grant_count(image());
  transition.controller_count = next.controllers.size();
  transition.provenance =
      make_provenance_data(next, request.provenance, allocate_sequence(next), successor.value().value());
  transition.previous_record_digest = transition_chain_head(image());
  transition.record_digest = compute_transition_digest(transition);

  next.transitions.push_back(transition);
  next.transition_count += 1;
  trim_transitions(next);
  next.epoch = successor.value().value();
  // Every grant of the base epoch is fenced permanently by this transition.
  next.grants.clear();

  if (request.idempotency.has_value()) {
    CanonicalWriter writer(max_idempotency_blob_bytes);
    encode_transition(writer, transition);
    record_idempotent(next, *request.idempotency, command_digest, writer.take());
  }
  commit_image(std::move(next));
  return RecordFactory::make_transition(transition);
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

Result<RevocationRecord> AuthorityCore::revoke_authority(RevokeAuthorityRequest request) {
  std::lock_guard<std::mutex> guard(mutex_);
  require_open();
  require_write("revoke_authority");
  require_domain();

  if (auto bad = validate_provenance_input(request.provenance, "revocation provenance")) {
    return *bad;
  }
  if (request.target.controller().empty()) {
    return Explanation(ErrorCode::IdentifierEmpty, "the revocation target controller is empty");
  }
  if (request.idempotency.has_value()) {
    if (request.idempotency->controller() != request.authority.controller() ||
        request.idempotency->incarnation() != request.authority.incarnation()) {
      return Explanation(ErrorCode::IdempotencyConflict,
                         "idempotency key " + request.idempotency->to_string() +
                             " does not belong to the controller incarnation presenting the command");
    }
  }

  const Sha256Digest command_digest = digest_revoke(request.target, request.reason, request.provenance);
  if (request.idempotency.has_value()) {
    Result<std::optional<std::vector<std::byte>>> recorded =
        lookup_idempotent(image(), *request.idempotency, command_digest);
    if (!recorded.has_value()) {
      return recorded.rejection();
    }
    if (recorded.value().has_value()) {
      CanonicalReader reader(std::span<const std::byte>(*recorded.value()), max_identifier_length);
      RevocationData replayed = decode_revocation(reader);
      reader.expect_end();
      return RecordFactory::mark_replayed(RecordFactory::make_revocation(replayed));
    }
  }

  ValidationOutcome authority = validate_token(image(), request.authority, authority_revoke_scope());
  if (!authority.accepted()) {
    return *authority.rejection();
  }

  AuthorityImage next = image();
  RevocationData revocation;
  revocation.sequence = next.revocation_count + 1;
  revocation.target_kind = request.target.kind();
  revocation.controller = request.target.controller().str();
  revocation.reason = request.reason;
  revocation.epoch = next.epoch;
  revocation.issued_by = request.authority.controller().str();
  revocation.issued_by_incarnation = request.authority.incarnation().digest();
  revocation.issued_by_grant = request.authority.grant().value();
  revocation.previous_record_digest = revocation_chain_head(image());

  if (request.target.kind() == RevocationTargetKind::Grant) {
    const GrantData* grant = find_grant(image(), request.target.grant()->value());
    if (grant == nullptr) {
      return Explanation(ErrorCode::RevocationUnknownTarget,
                         "grant " + request.target.grant()->to_string() +
                             " does not exist in epoch " + std::to_string(image().epoch));
    }
    if (grant->controller != request.target.controller().str()) {
      return Explanation(ErrorCode::RevocationUnknownTarget,
                         "grant " + request.target.grant()->to_string() + " belongs to controller '" +
                             grant->controller + "', not '" + request.target.controller().to_string() + "'");
    }
    revocation.grant = grant->id;
    // A grant that is already fenced is not fenced again: superseded and revoked
    // grants both count as already fenced, exactly as the controller-wide path treats
    // them. Only a live grant is newly fenced and counted.
    revocation.replayed = grant->state != GrantState::Live;
    if (!revocation.replayed) {
      GrantData* target = find_grant(next, grant->id);
      target->state = GrantState::Revoked;
      target->revoked_by_sequence = revocation.sequence;
      target->record_digest = compute_grant_digest(*target);
      revocation.fenced_grant_count = 1;
    }
  } else {
    const ControllerData* controller = find_controller(image(), request.target.controller().view());
    if (controller == nullptr) {
      return Explanation(ErrorCode::RevocationUnknownTarget, "controller '" +
                                                                 request.target.controller().to_string() +
                                                                 "' is not registered");
    }
    const std::uint64_t through = request.target.through_incarnation().has_value()
                                      ? request.target.through_incarnation()->value()
                                      : controller->incarnation_number;
    revocation.through_incarnation = through;
    revocation.replayed = controller->revocation_through_incarnation.has_value() &&
                          *controller->revocation_through_incarnation >= through;

    std::uint64_t fenced = 0;
    for (GrantData& grant : next.grants) {
      if (grant.controller != controller->controller || grant.state != GrantState::Live) {
        continue;
      }
      if (grant.incarnation_number <= through) {
        grant.state = GrantState::Revoked;
        grant.revoked_by_sequence = revocation.sequence;
        grant.record_digest = compute_grant_digest(grant);
        fenced += 1;
      }
    }
    revocation.fenced_grant_count = fenced;

    ControllerData* target = find_controller(next, controller->controller);
    if (!target->revocation_through_incarnation.has_value() ||
        *target->revocation_through_incarnation < through) {
      target->revocation_through_incarnation = through;
    }
    if (through >= target->incarnation_number) {
      target->incarnation_state = IncarnationState::Revoked;
    }
    target->record_digest = compute_controller_digest(*target);
  }

  revocation.provenance = make_provenance_data(next, request.provenance, allocate_sequence(next));
  revocation.record_digest = compute_revocation_digest(revocation);
  next.revocations.push_back(revocation);
  next.revocation_count += 1;
  trim_revocations(next);

  if (request.idempotency.has_value()) {
    CanonicalWriter writer(max_idempotency_blob_bytes);
    encode_revocation(writer, revocation);
    record_idempotent(next, *request.idempotency, command_digest, writer.take());
  }
  commit_image(std::move(next));
  return RecordFactory::make_revocation(revocation);
}

// ---------------------------------------------------------------------------
// Recovered state qualification
// ---------------------------------------------------------------------------

Result<RecoveryQualification> AuthorityCore::qualify_recovered_state(const RecoveredStateClaim& claim) {
  std::lock_guard<std::mutex> guard(mutex_);
  require_open();
  require_domain();

  const AuthorityImage& img = image();
  if (claim.domain().str() != img.domain) {
    return RecoveryQualification(RecoveredStateVerdict::Rejected,
                                 Explanation(ErrorCode::RecoveredRejectedDomainMismatch,
                                             "the claim names domain '" + claim.domain().to_string() +
                                                 "' but this authority serves '" + img.domain + "'"),
                                 std::nullopt, false);
  }
  if (claim.producing_epoch().value() > img.epoch) {
    return RecoveryQualification(RecoveredStateVerdict::Rejected,
                                 Explanation(ErrorCode::RecoveredRejectedFutureEpoch,
                                             "the claim names producing epoch " +
                                                 claim.producing_epoch().to_string() +
                                                 " which this domain never committed; the current epoch is " +
                                                 std::to_string(img.epoch)),
                                 std::nullopt, false);
  }
  const ControllerData* producer = find_controller(img, claim.producer().view());
  if (producer == nullptr) {
    return RecoveryQualification(RecoveredStateVerdict::Rejected,
                                 Explanation(ErrorCode::RecoveredRejectedUnknownIncarnation,
                                             "controller '" + claim.producer().to_string() +
                                                 "' is not registered in this domain"),
                                 std::nullopt, false);
  }

  const bool current_incarnation = producer->incarnation_id == claim.producer_incarnation().digest();
  const bool known_superseded = contains_digest(producer->superseded_incarnations,
                                                claim.producer_incarnation().digest());
  if (!current_incarnation && !known_superseded) {
    return RecoveryQualification(RecoveredStateVerdict::Rejected,
                                 Explanation(ErrorCode::RecoveredRejectedUnknownIncarnation,
                                             "incarnation " + claim.producer_incarnation().to_hex() +
                                                 " is not the current incarnation " +
                                                 std::to_string(producer->incarnation_number) +
                                                 " of controller '" + producer->controller + "'"),
                                 std::nullopt, false);
  }

  const bool controller_revoked = producer->revocation_through_incarnation.has_value() &&
                                  *producer->revocation_through_incarnation >= producer->incarnation_number;
  if (!current_incarnation || controller_revoked) {
    return RecoveryQualification(RecoveredStateVerdict::Superseded,
                                 Explanation(ErrorCode::RecoveredSuperseded,
                                             "the producing incarnation is permanently fenced: " +
                                                 (controller_revoked ? std::string("the controller is revoked")
                                                                     : std::string("a newer incarnation is current"))),
                                 std::nullopt, false);
  }

  const GrantData* covering = nullptr;
  for (const GrantData& grant : img.grants) {
    if (grant.controller != producer->controller || grant.state != GrantState::Live) {
      continue;
    }
    if (std::find(grant.scopes.begin(), grant.scopes.end(), claim.scope().str()) != grant.scopes.end()) {
      covering = &grant;
      break;
    }
  }

  if (claim.producing_epoch().value() == img.epoch) {
    if (covering != nullptr) {
      return RecoveryQualification(
          RecoveredStateVerdict::Current,
          Explanation(ErrorCode::RecoveredCurrent, "produced under the current epoch by the current incarnation"),
          GrantId::from_trusted(covering->id), false);
    }
    return RecoveryQualification(RecoveredStateVerdict::Rejected,
                                 Explanation(ErrorCode::RecoveredRejectedNoAuthority,
                                             "the producer holds no live authority over scope '" +
                                                 claim.scope().to_string() + "' in epoch " +
                                                 std::to_string(img.epoch)),
                                 std::nullopt, false);
  }

  if (covering != nullptr) {
    return RecoveryQualification(
        RecoveredStateVerdict::NeedsReconciliation,
        Explanation(ErrorCode::RecoveredNeedsReconciliation,
                    "produced in epoch " + claim.producing_epoch().to_string() +
                        "; the producer is still the current incarnation and still holds scope '" +
                        claim.scope().to_string() + "' in epoch " + std::to_string(img.epoch)),
        GrantId::from_trusted(covering->id), true);
  }

  return RecoveryQualification(RecoveredStateVerdict::Stale,
                               Explanation(ErrorCode::RecoveredStale,
                                           "produced in epoch " + claim.producing_epoch().to_string() +
                                               " which is no longer current; the producer holds no authority over "
                                               "scope '" + claim.scope().to_string() + "' now"),
                               std::nullopt, true);
}

// ---------------------------------------------------------------------------
// Inspection
// ---------------------------------------------------------------------------

Result<EpochHistoryPage> AuthorityCore::history(const HistoryQuery& query) const {
  std::lock_guard<std::mutex> guard(mutex_);
  require_open();
  require_domain();
  if (query.limit == 0 || query.limit > max_page_size) {
    return Explanation(ErrorCode::PageLimitExceeded, "page limit " + std::to_string(query.limit) +
                                                         " is outside 1.." + std::to_string(max_page_size));
  }

  const AuthorityImage& img = image();
  std::vector<EpochTransitionRecord> records;
  for (const TransitionData& transition : img.transitions) {
    if (query.from_sequence.has_value() && transition.sequence < query.from_sequence->value()) {
      continue;
    }
    if (records.size() >= query.limit) {
      break;
    }
    records.push_back(RecordFactory::make_transition(transition));
  }
  return RecordFactory::make_history_page(
      std::move(records), img.transition_count,
      img.transitions.empty() ? 0 : img.transitions.front().sequence, img.transition_trimmed,
      img.transition_anchor, transition_chain_head(img));
}

Result<RevocationPage> AuthorityCore::revocations(const RevocationQuery& query) const {
  std::lock_guard<std::mutex> guard(mutex_);
  require_open();
  require_domain();
  if (query.limit == 0 || query.limit > max_page_size) {
    return Explanation(ErrorCode::PageLimitExceeded, "page limit " + std::to_string(query.limit) +
                                                         " is outside 1.." + std::to_string(max_page_size));
  }

  const AuthorityImage& img = image();
  RevocationPage page;
  for (const RevocationData& revocation : img.revocations) {
    if (query.from_sequence.has_value() && revocation.sequence < query.from_sequence->value()) {
      continue;
    }
    if (page.records_.size() >= query.limit) {
      break;
    }
    page.records_.push_back(RecordFactory::make_revocation(revocation));
  }
  page.total_count_ = img.revocation_count;
  page.first_retained_sequence_ = img.revocations.empty() ? 0 : img.revocations.front().sequence;
  page.trimmed_count_ = img.revocation_trimmed;
  page.chain_head_ = revocation_chain_head(img);
  return page;
}

Result<ControllerPage> AuthorityCore::controllers(const ControllerQuery& query) const {
  std::lock_guard<std::mutex> guard(mutex_);
  require_open();
  require_domain();
  if (query.limit == 0 || query.limit > max_page_size) {
    return Explanation(ErrorCode::PageLimitExceeded, "page limit " + std::to_string(query.limit) +
                                                         " is outside 1.." + std::to_string(max_page_size));
  }

  const AuthorityImage& img = image();
  ControllerPage page;
  page.total_count_ = img.controllers.size();
  const std::string from = query.from_controller.has_value() ? query.from_controller->str() : std::string();
  for (const ControllerData& controller : img.controllers) {
    if (!from.empty() && controller.controller < from) {
      continue;
    }
    if (page.records_.size() >= query.limit) {
      break;
    }
    page.records_.push_back(RecordFactory::make_controller(controller));
  }
  page.offset_ = 0;
  return page;
}

Result<GrantPage> AuthorityCore::grants(const GrantQuery& query) const {
  std::lock_guard<std::mutex> guard(mutex_);
  require_open();
  require_domain();
  if (query.limit == 0 || query.limit > max_page_size) {
    return Explanation(ErrorCode::PageLimitExceeded, "page limit " + std::to_string(query.limit) +
                                                         " is outside 1.." + std::to_string(max_page_size));
  }

  const AuthorityImage& img = image();
  GrantPage page;
  page.total_count_ = img.grants.size();
  page.epoch_ = Epoch::from_trusted(img.epoch);
  for (const GrantData& grant : img.grants) {
    if (query.from_grant.has_value() && grant.id < query.from_grant->value()) {
      continue;
    }
    if (page.records_.size() >= query.limit) {
      break;
    }
    page.records_.push_back(RecordFactory::make_grant(grant));
  }
  return page;
}

Result<ControllerRecord> AuthorityCore::controller_record(const ControllerId& controller) const {
  std::lock_guard<std::mutex> guard(mutex_);
  require_open();
  require_domain();
  const ControllerData* record = find_controller(image(), controller.view());
  if (record == nullptr) {
    return Explanation(ErrorCode::ControllerUnknown, "controller '" + controller.to_string() +
                                                         "' is not registered in domain '" + image().domain + "'");
  }
  return RecordFactory::make_controller(*record);
}

Result<AuthorityGrantRecord> AuthorityCore::grant_record(GrantId grant_id) const {
  std::lock_guard<std::mutex> guard(mutex_);
  require_open();
  require_domain();
  const GrantData* grant = find_grant(image(), grant_id.value());
  if (grant == nullptr) {
    return Explanation(ErrorCode::UnknownGrant, "grant " + grant_id.to_string() +
                                                    " does not exist in epoch " + std::to_string(image().epoch));
  }
  return RecordFactory::make_grant(*grant);
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

void AuthorityCore::write_snapshot_artifact(const std::filesystem::path& path) const {
  std::lock_guard<std::mutex> guard(mutex_);
  require_open();
  if (!store_->initialized()) {
    throw EpochError(ErrorCode::StoreNotInitialized, "there is no authority domain to snapshot");
  }
  if (path.empty()) {
    throw EpochError(ErrorCode::PathInvalid, "the snapshot artifact path is empty");
  }

  const AuthorityImage& img = image();
  FileEnvelope envelope;
  envelope.generation = img.durable_generation;
  envelope.epoch = img.epoch;
  envelope.payload = encode_image(img, store_->limits());
  const std::vector<std::byte> bytes = encode_envelope(envelope, max_snapshot_bytes + envelope_header_bytes);

  const std::filesystem::path directory = path.has_parent_path() ? path.parent_path() : std::filesystem::path(".");
  const std::filesystem::path temporary = directory / next_temp_name(path.filename().string());
  try {
    write_file_exclusive(temporary, std::span<const std::byte>(bytes));
    atomic_replace(temporary, path);
  } catch (...) {
    remove_file_if_exists(temporary);
    throw;
  }
}

}  // namespace dccp::epoch::detail








