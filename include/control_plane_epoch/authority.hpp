// Control Plane Epoch 1.0.0 - Summon Software Labs
// Authority model: epoch-scoped, incarnation-bound, scope-limited grants and
// the fencing tokens derived from them.
//
// Authority is never time-based. There is no wall-clock lease in this
// repository: a grant is valid exactly while (a) its epoch is the current
// committed epoch of the domain, (b) its grant record has not been revoked,
// (c) its controller incarnation is still the controller's current
// incarnation, and (d) the requested scope is covered. Every one of those
// conditions is durable state, so validity cannot drift with a clock.
//
// A token is evidence of claims, not a bearer secret. The fencing token digest
// detects corruption and accidental confusion inside one epoch; it is not a
// credential, and the authoritative store is what actually decides whether the
// claims are still valid.
#pragma once

#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "control_plane_epoch/digest.hpp"
#include "control_plane_epoch/epoch.hpp"
#include "control_plane_epoch/error.hpp"
#include "control_plane_epoch/identity.hpp"
#include "control_plane_epoch/incarnation.hpp"
#include "control_plane_epoch/limits.hpp"
#include "control_plane_epoch/provenance.hpp"

namespace dccp::epoch {

namespace detail {
struct RecordFactory;
}  // namespace detail

/// What a grant authorizes. Numeric values are durable.
enum class AuthorityClass : std::uint32_t {
  /// Authority to mutate authoritative facility state in the domain.
  Mutation = 1,
  /// Authority to publish observations that may be cited as authoritative.
  Observation = 2,
};

inline constexpr std::uint32_t max_authority_class = 2;

[[nodiscard]] std::string_view authority_class_token(AuthorityClass authority_class) noexcept;
[[nodiscard]] Result<AuthorityClass> parse_authority_class(std::string_view token);

// ---------------------------------------------------------------------------
// Scopes
// ---------------------------------------------------------------------------

/// Reserved scopes every authority domain must declare. They are the
/// administrative scopes; ordinary facility scopes are declared by the domain
/// in addition to these.
[[nodiscard]] const ScopeName& authority_grant_scope();
[[nodiscard]] const ScopeName& authority_revoke_scope();
[[nodiscard]] const ScopeName& epoch_advance_scope();

/// An ordered, duplicate-free set of scopes. Iteration order is ascending by
/// scope name bytes and is part of the public, serialized behaviour.
class AuthorityScopeSet {
 public:
  AuthorityScopeSet() = default;

  /// Validates and canonicalises a caller-supplied scope list: at most
  /// max_scopes_per_authority entries, no duplicates, no empty names.
  [[nodiscard]] static Result<AuthorityScopeSet> create(std::vector<ScopeName> scopes);

  /// Constructs from a list already validated and sorted ascending.
  [[nodiscard]] static AuthorityScopeSet from_trusted(std::vector<ScopeName> sorted_unique) noexcept {
    return AuthorityScopeSet(std::move(sorted_unique));
  }

  [[nodiscard]] bool empty() const noexcept { return scopes_.empty(); }
  [[nodiscard]] std::size_t size() const noexcept { return scopes_.size(); }
  [[nodiscard]] const std::vector<ScopeName>& scopes() const noexcept { return scopes_; }
  [[nodiscard]] bool contains(const ScopeName& scope) const noexcept;

  /// Canonical text form: names joined by '+', or "-" for the empty set.
  [[nodiscard]] std::string to_string() const;

  /// Parses the canonical text form produced by to_string().
  [[nodiscard]] static Result<AuthorityScopeSet> parse(std::string_view text);

  friend bool operator==(const AuthorityScopeSet& lhs, const AuthorityScopeSet& rhs) noexcept {
    return lhs.scopes_ == rhs.scopes_;
  }
  friend bool operator!=(const AuthorityScopeSet& lhs, const AuthorityScopeSet& rhs) noexcept { return !(lhs == rhs); }

 private:
  explicit AuthorityScopeSet(std::vector<ScopeName> scopes) noexcept : scopes_(std::move(scopes)) {}

  std::vector<ScopeName> scopes_;
};

// ---------------------------------------------------------------------------
// Claims and fencing tokens
// ---------------------------------------------------------------------------

/// The immutable claims bound into an authority token.
class AuthorityClaims {
 public:
  AuthorityClaims() = default;

  [[nodiscard]] static Result<AuthorityClaims> create(FacilityAuthorityDomainId domain, Epoch epoch,
                                                      ControllerId controller,
                                                      ControllerIncarnationId incarnation, GrantId grant,
                                                      AuthorityScopeSet scopes);

  [[nodiscard]] const FacilityAuthorityDomainId& domain() const noexcept { return domain_; }
  [[nodiscard]] Epoch epoch() const noexcept { return epoch_; }
  [[nodiscard]] const ControllerId& controller() const noexcept { return controller_; }
  [[nodiscard]] const ControllerIncarnationId& incarnation() const noexcept { return incarnation_; }
  [[nodiscard]] GrantId grant() const noexcept { return grant_; }
  [[nodiscard]] const AuthorityScopeSet& scopes() const noexcept { return scopes_; }

  [[nodiscard]] std::string to_string() const;

  friend bool operator==(const AuthorityClaims& lhs, const AuthorityClaims& rhs) noexcept {
    return lhs.domain_ == rhs.domain_ && lhs.epoch_ == rhs.epoch_ && lhs.controller_ == rhs.controller_ &&
           lhs.incarnation_ == rhs.incarnation_ && lhs.grant_ == rhs.grant_ && lhs.scopes_ == rhs.scopes_;
  }
  friend bool operator!=(const AuthorityClaims& lhs, const AuthorityClaims& rhs) noexcept { return !(lhs == rhs); }

 private:
  FacilityAuthorityDomainId domain_;
  Epoch epoch_;
  ControllerId controller_;
  ControllerIncarnationId incarnation_;
  GrantId grant_;
  AuthorityScopeSet scopes_;
};

/// Digest derived from an epoch plus a controller incarnation (and the rest of
/// the claims). Two different (epoch, incarnation) pairs never produce the same
/// fencing token, which is what makes "authority from epoch N is fenced by
/// epoch N+1" observable and machine-checkable.
class FencingToken {
 public:
  FencingToken() = default;

  [[nodiscard]] static FencingToken derive(AuthorityClass authority_class, const AuthorityClaims& claims);

  [[nodiscard]] const Sha256Digest& digest() const noexcept { return digest_; }
  [[nodiscard]] bool is_zero() const noexcept { return digest_.is_zero(); }
  [[nodiscard]] std::string to_hex() const { return digest_.to_hex(); }

  friend bool operator==(const FencingToken& lhs, const FencingToken& rhs) noexcept { return lhs.digest_ == rhs.digest_; }
  friend bool operator!=(const FencingToken& lhs, const FencingToken& rhs) noexcept { return !(lhs == rhs); }

 private:
  explicit FencingToken(Sha256Digest digest) noexcept : digest_(digest) {}

  Sha256Digest digest_;
};

namespace detail {

/// One authority token parameterised by its class, so that mutation authority
/// and observation authority are distinct, non-interchangeable C++ types.
template <AuthorityClass Class>
class AuthorityToken {
 public:
  AuthorityToken() = default;

  /// Builds a token for the supplied claims. Constructing a token grants
  /// nothing: only the authoritative store decides whether the claims are still
  /// valid, and every validation re-checks the store.
  [[nodiscard]] static AuthorityToken from_claims(AuthorityClaims claims) {
    FencingToken token = FencingToken::derive(Class, claims);
    return AuthorityToken(std::move(claims), token);
  }

  /// Parses the canonical text form. Rejects malformed text and any token whose
  /// digest does not match its claims.
  [[nodiscard]] static Result<AuthorityToken> parse(std::string_view text);

  [[nodiscard]] static AuthorityClass authority_class() noexcept { return Class; }

  [[nodiscard]] const AuthorityClaims& claims() const noexcept { return claims_; }
  [[nodiscard]] const FacilityAuthorityDomainId& domain() const noexcept { return claims_.domain(); }
  [[nodiscard]] Epoch epoch() const noexcept { return claims_.epoch(); }
  [[nodiscard]] const ControllerId& controller() const noexcept { return claims_.controller(); }
  [[nodiscard]] const ControllerIncarnationId& incarnation() const noexcept { return claims_.incarnation(); }
  [[nodiscard]] GrantId grant() const noexcept { return claims_.grant(); }
  [[nodiscard]] const AuthorityScopeSet& scopes() const noexcept { return claims_.scopes(); }
  [[nodiscard]] const FencingToken& fencing_token() const noexcept { return token_; }

  /// Digest over the canonical encoding of the token (class, claims, and
  /// fencing token).
  [[nodiscard]] Sha256Digest digest() const;

  [[nodiscard]] bool covers(const ScopeName& scope) const noexcept { return claims_.scopes().contains(scope); }
  [[nodiscard]] bool is_zero() const noexcept { return token_.is_zero(); }

  /// Recomputes the fencing token from the claims; a mismatch means the token
  /// text or the durable image it came from was corrupted or tampered with.
  [[nodiscard]] ValidationOutcome verify_integrity() const;

  [[nodiscard]] std::string to_string() const;

  friend bool operator==(const AuthorityToken& lhs, const AuthorityToken& rhs) noexcept {
    return lhs.claims_ == rhs.claims_ && lhs.token_ == rhs.token_;
  }
  friend bool operator!=(const AuthorityToken& lhs, const AuthorityToken& rhs) noexcept { return !(lhs == rhs); }

 private:
  AuthorityToken(AuthorityClaims claims, FencingToken token) noexcept
      : claims_(std::move(claims)), token_(token) {}

  AuthorityClaims claims_;
  FencingToken token_;
};

}  // namespace detail

/// Authority to mutate authoritative facility state.
using MutationAuthority = detail::AuthorityToken<AuthorityClass::Mutation>;

/// Authority to publish observations that facility state may be derived from.
using ObservationAuthority = detail::AuthorityToken<AuthorityClass::Observation>;

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

/// Immutable view of one durable authority grant.
class AuthorityGrantRecord {
 public:
  AuthorityGrantRecord() = default;

  [[nodiscard]] GrantId id() const noexcept { return id_; }
  [[nodiscard]] AuthorityClass authority_class() const noexcept { return authority_class_; }
  [[nodiscard]] Epoch epoch() const noexcept { return epoch_; }
  [[nodiscard]] const ControllerId& controller() const noexcept { return controller_; }
  [[nodiscard]] const ControllerIncarnationId& incarnation() const noexcept { return incarnation_; }

  /// Incarnation number the grant was issued to. Controller-wide revocation is
  /// decided against this number, so it is part of the public record rather than
  /// an internal detail.
  [[nodiscard]] IncarnationNumber incarnation_number() const noexcept { return incarnation_number_; }

  [[nodiscard]] const AuthorityScopeSet& scopes() const noexcept { return scopes_; }

  /// Position of the grant in the domain's global mutation ledger.
  [[nodiscard]] std::uint64_t sequence() const noexcept { return sequence_; }

  /// Revocation sequence that fenced this grant, if any.
  [[nodiscard]] const std::optional<RevocationSequence>& revoked_by_sequence() const noexcept {
    return revoked_by_sequence_;
  }
  [[nodiscard]] bool revoked() const noexcept { return revoked_by_sequence_.has_value(); }

  [[nodiscard]] const ProvenanceRecord& provenance() const noexcept { return provenance_; }
  [[nodiscard]] const Sha256Digest& record_digest() const noexcept { return record_digest_; }

  [[nodiscard]] std::string to_string() const;

  friend bool operator==(const AuthorityGrantRecord& lhs, const AuthorityGrantRecord& rhs) noexcept {
    return lhs.id_ == rhs.id_ && lhs.authority_class_ == rhs.authority_class_ && lhs.epoch_ == rhs.epoch_ &&
           lhs.controller_ == rhs.controller_ && lhs.incarnation_ == rhs.incarnation_ &&
           lhs.incarnation_number_ == rhs.incarnation_number_ && lhs.scopes_ == rhs.scopes_ &&
           lhs.sequence_ == rhs.sequence_ && lhs.revoked_by_sequence_ == rhs.revoked_by_sequence_;
  }
  friend bool operator!=(const AuthorityGrantRecord& lhs, const AuthorityGrantRecord& rhs) noexcept {
    return !(lhs == rhs);
  }

 private:
  friend struct detail::RecordFactory;

  GrantId id_;
  AuthorityClass authority_class_ = AuthorityClass::Mutation;
  Epoch epoch_;
  ControllerId controller_;
  ControllerIncarnationId incarnation_;
  IncarnationNumber incarnation_number_;
  AuthorityScopeSet scopes_;
  std::uint64_t sequence_ = 0;
  std::optional<RevocationSequence> revoked_by_sequence_;
  ProvenanceRecord provenance_;
  Sha256Digest record_digest_;
};

/// Convenience view used by the operation results: a grant plus the token that
/// was issued for it.
class AuthorityGrantView {
 public:
  AuthorityGrantView() = default;
  AuthorityGrantView(AuthorityGrantRecord record, MutationAuthority authority)
      : record_(std::move(record)), mutation_(std::move(authority)) {}
  AuthorityGrantView(AuthorityGrantRecord record, ObservationAuthority authority)
      : record_(std::move(record)), observation_(std::move(authority)) {}

  [[nodiscard]] const AuthorityGrantRecord& record() const noexcept { return record_; }
  [[nodiscard]] const std::optional<MutationAuthority>& mutation_authority() const noexcept { return mutation_; }
  [[nodiscard]] const std::optional<ObservationAuthority>& observation_authority() const noexcept {
    return observation_;
  }
  [[nodiscard]] bool replayed() const noexcept { return replayed_; }
  void mark_replayed() noexcept { replayed_ = true; }
  [[nodiscard]] bool revoke_of_existing_grant() const noexcept { return revoke_of_existing_grant_; }
  void mark_revoke_of_existing_grant() noexcept { revoke_of_existing_grant_ = true; }

 private:
  AuthorityGrantRecord record_;
  std::optional<MutationAuthority> mutation_;
  std::optional<ObservationAuthority> observation_;
  bool replayed_ = false;
  bool revoke_of_existing_grant_ = false;
};

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

/// What a revocation fences.
enum class RevocationTargetKind : std::uint32_t {
  /// Every incarnation of one controller up to and including a stated number.
  ControllerIncarnations = 1,
  /// Exactly one grant.
  Grant = 2,
};

inline constexpr std::uint32_t max_revocation_target_kind = 2;

[[nodiscard]] std::string_view revocation_target_kind_token(RevocationTargetKind kind) noexcept;
[[nodiscard]] Result<RevocationTargetKind> parse_revocation_target_kind(std::string_view token);

/// Why authority was revoked. Numeric values are durable.
enum class RevocationReason : std::uint32_t {
  OperatorRequest = 1,
  ControllerRestart = 2,
  SuspectedStaleAuthority = 3,
  IncarnationFencing = 4,
  Recovery = 5,
  Decommission = 6,
};

inline constexpr std::uint32_t max_revocation_reason = 6;

[[nodiscard]] std::string_view revocation_reason_token(RevocationReason reason) noexcept;
[[nodiscard]] Result<RevocationReason> parse_revocation_reason(std::string_view token);

/// Immutable view of one durable revocation record.
class RevocationRecord {
 public:
  RevocationRecord() = default;

  [[nodiscard]] RevocationSequence sequence() const noexcept { return sequence_; }
  [[nodiscard]] RevocationTargetKind target_kind() const noexcept { return target_kind_; }
  [[nodiscard]] const ControllerId& controller() const noexcept { return controller_; }

  /// Set for controller-incarnation revocations: the highest incarnation fenced.
  [[nodiscard]] const std::optional<IncarnationNumber>& through_incarnation() const noexcept {
    return through_incarnation_;
  }

  /// Set for grant revocations.
  [[nodiscard]] const std::optional<GrantId>& grant() const noexcept { return grant_; }

  [[nodiscard]] RevocationReason reason() const noexcept { return reason_; }
  [[nodiscard]] Epoch epoch() const noexcept { return epoch_; }
  [[nodiscard]] const ControllerId& issued_by() const noexcept { return issued_by_; }
  [[nodiscard]] const ControllerIncarnationId& issued_by_incarnation() const noexcept {
    return issued_by_incarnation_;
  }
  [[nodiscard]] GrantId issued_by_grant() const noexcept { return issued_by_grant_; }

  /// How many live grants this revocation fenced when it committed.
  [[nodiscard]] std::uint64_t fenced_grant_count() const noexcept { return fenced_grant_count_; }

  /// True when the target was already fully fenced and this record documents
  /// the replayed request rather than new fencing.
  [[nodiscard]] bool replayed() const noexcept { return replayed_; }

  [[nodiscard]] const ProvenanceRecord& provenance() const noexcept { return provenance_; }
  [[nodiscard]] const Sha256Digest& previous_record_digest() const noexcept { return previous_record_digest_; }
  [[nodiscard]] const Sha256Digest& record_digest() const noexcept { return record_digest_; }

  [[nodiscard]] std::string to_string() const;

  friend bool operator==(const RevocationRecord& lhs, const RevocationRecord& rhs) noexcept {
    return lhs.sequence_ == rhs.sequence_ && lhs.target_kind_ == rhs.target_kind_ &&
           lhs.controller_ == rhs.controller_ && lhs.through_incarnation_ == rhs.through_incarnation_ &&
           lhs.grant_ == rhs.grant_ && lhs.reason_ == rhs.reason_ && lhs.epoch_ == rhs.epoch_ &&
           lhs.issued_by_ == rhs.issued_by_ && lhs.issued_by_incarnation_ == rhs.issued_by_incarnation_ &&
           lhs.issued_by_grant_ == rhs.issued_by_grant_ && lhs.fenced_grant_count_ == rhs.fenced_grant_count_;
  }
  friend bool operator!=(const RevocationRecord& lhs, const RevocationRecord& rhs) noexcept { return !(lhs == rhs); }

 private:
  friend struct detail::RecordFactory;

  RevocationSequence sequence_;
  RevocationTargetKind target_kind_ = RevocationTargetKind::ControllerIncarnations;
  ControllerId controller_;
  std::optional<IncarnationNumber> through_incarnation_;
  std::optional<GrantId> grant_;
  RevocationReason reason_ = RevocationReason::OperatorRequest;
  Epoch epoch_;
  ControllerId issued_by_;
  ControllerIncarnationId issued_by_incarnation_;
  GrantId issued_by_grant_;
  std::uint64_t fenced_grant_count_ = 0;
  bool replayed_ = false;
  ProvenanceRecord provenance_;
  Sha256Digest previous_record_digest_;
  Sha256Digest record_digest_;
};

// ---------------------------------------------------------------------------
// Idempotency
// ---------------------------------------------------------------------------

/// Client-chosen key that makes a retryable state-changing command idempotent.
/// The key is scoped to one controller incarnation, so a restarted controller
/// can never collide with its own earlier requests.
class IdempotencyKey {
 public:
  IdempotencyKey() = default;

  [[nodiscard]] static Result<IdempotencyKey> create(ControllerId controller, ControllerIncarnationId incarnation,
                                                     OperationSequence sequence);

  [[nodiscard]] const ControllerId& controller() const noexcept { return controller_; }
  [[nodiscard]] const ControllerIncarnationId& incarnation() const noexcept { return incarnation_; }
  [[nodiscard]] OperationSequence sequence() const noexcept { return sequence_; }
  [[nodiscard]] bool empty() const noexcept { return !sequence_.is_set(); }

  [[nodiscard]] std::string to_string() const;

  friend bool operator==(const IdempotencyKey& lhs, const IdempotencyKey& rhs) noexcept {
    return lhs.controller_ == rhs.controller_ && lhs.incarnation_ == rhs.incarnation_ &&
           lhs.sequence_ == rhs.sequence_;
  }
  friend bool operator!=(const IdempotencyKey& lhs, const IdempotencyKey& rhs) noexcept { return !(lhs == rhs); }
  friend std::strong_ordering operator<=>(const IdempotencyKey& lhs, const IdempotencyKey& rhs) noexcept {
    if (auto cmp = lhs.controller_ <=> rhs.controller_; cmp != 0) {
      return cmp;
    }
    if (auto cmp = lhs.incarnation_ <=> rhs.incarnation_; cmp != 0) {
      return cmp;
    }
    return lhs.sequence_ <=> rhs.sequence_;
  }

 private:
  ControllerId controller_;
  ControllerIncarnationId incarnation_;
  OperationSequence sequence_;
};

}  // namespace dccp::epoch
