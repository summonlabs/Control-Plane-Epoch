// Control Plane Epoch 1.0.0 - Summon Software Labs
// Authority scopes, claims, fencing tokens, and record rendering.
#include "control_plane_epoch/authority.hpp"

#include <algorithm>
#include <array>

#include "encoding.hpp"
#include "format.hpp"

namespace dccp::epoch {
namespace {

struct ClassToken {
  AuthorityClass authority_class;
  std::string_view token;
};

constexpr std::array<ClassToken, 2> kClassTokens{{
    {AuthorityClass::Mutation, "mutation"},
    {AuthorityClass::Observation, "observation"},
}};

struct TargetToken {
  RevocationTargetKind kind;
  std::string_view token;
};

constexpr std::array<TargetToken, 2> kTargetTokens{{
    {RevocationTargetKind::ControllerIncarnations, "controller_incarnations"},
    {RevocationTargetKind::Grant, "grant"},
}};

struct ReasonToken {
  RevocationReason reason;
  std::string_view token;
};

constexpr std::array<ReasonToken, 6> kReasonTokens{{
    {RevocationReason::OperatorRequest, "operator_request"},
    {RevocationReason::ControllerRestart, "controller_restart"},
    {RevocationReason::SuspectedStaleAuthority, "suspected_stale_authority"},
    {RevocationReason::IncarnationFencing, "incarnation_fencing"},
    {RevocationReason::Recovery, "recovery"},
    {RevocationReason::Decommission, "decommission"},
}};

/// Field separator for canonical token text. Identifiers are restricted to
/// [A-Za-z0-9._-] and scope sets use '+' internally, so ':' is unambiguous.
constexpr char kTokenSeparator = ':';
constexpr std::string_view kTokenPrefix = "cpe1";
constexpr std::string_view kEmptyScopeText = "-";

/// Domain separation tags for the two derivations that involve authority.
constexpr std::string_view kFencingTag = "control-plane-epoch.fencing.v1";
constexpr std::string_view kTokenTag = "control-plane-epoch.token.v1";

void hash_claims(Sha256& hasher, AuthorityClass authority_class, const AuthorityClaims& claims) {
  detail::hash_u32(hasher, static_cast<std::uint32_t>(authority_class));
  detail::hash_text(hasher, claims.domain().view());
  detail::hash_u64(hasher, claims.epoch().value());
  detail::hash_text(hasher, claims.controller().view());
  detail::hash_digest(hasher, claims.incarnation().digest());
  detail::hash_u64(hasher, claims.grant().value());
  detail::hash_u32(hasher, static_cast<std::uint32_t>(claims.scopes().size()));
  for (const ScopeName& scope : claims.scopes().scopes()) {
    detail::hash_text(hasher, scope.view());
  }
}

[[nodiscard]] Result<std::vector<std::string_view>> split(std::string_view text, char separator) {
  std::vector<std::string_view> fields;
  std::size_t start = 0;
  while (true) {
    const std::size_t position = text.find(separator, start);
    if (position == std::string_view::npos) {
      fields.push_back(text.substr(start));
      break;
    }
    fields.push_back(text.substr(start, position - start));
    start = position + 1;
  }
  return fields;
}

/// Strict decimal parsing: digits only, no sign, no leading zeros, no overflow,
/// and nothing after the number. Anything else is rejected instead of being
/// partially parsed.
[[nodiscard]] bool parse_u64_strict(std::string_view text, std::uint64_t& out) noexcept {
  if (text.empty() || text.size() > 20) {
    return false;
  }
  if (text.size() > 1 && text.front() == '0') {
    return false;
  }
  std::uint64_t value = 0;
  for (const char character : text) {
    if (character < '0' || character > '9') {
      return false;
    }
    const auto digit = static_cast<std::uint64_t>(character - '0');
    if (value > (UINT64_MAX - digit) / 10u) {
      return false;
    }
    value = (value * 10u) + digit;
  }
  out = value;
  return true;
}

}  // namespace

std::string_view authority_class_token(AuthorityClass authority_class) noexcept {
  for (const ClassToken& entry : kClassTokens) {
    if (entry.authority_class == authority_class) {
      return entry.token;
    }
  }
  return "unknown";
}

Result<AuthorityClass> parse_authority_class(std::string_view token) {
  for (const ClassToken& entry : kClassTokens) {
    if (entry.token == token) {
      return entry.authority_class;
    }
  }
  return Explanation(ErrorCode::EnumOutOfDomain, "unknown authority class " + std::string(token));
}

const ScopeName& authority_grant_scope() {
  static const ScopeName scope = ScopeName::parse("authority.grant", "reserved scope").value();
  return scope;
}

const ScopeName& authority_revoke_scope() {
  static const ScopeName scope = ScopeName::parse("authority.revoke", "reserved scope").value();
  return scope;
}

const ScopeName& epoch_advance_scope() {
  static const ScopeName scope = ScopeName::parse("epoch.advance", "reserved scope").value();
  return scope;
}

Result<AuthorityScopeSet> AuthorityScopeSet::create(std::vector<ScopeName> scopes) {
  if (scopes.size() > max_scopes_per_authority) {
    return Explanation(ErrorCode::SizeLimitExceeded, "scope list has " + std::to_string(scopes.size()) +
                                                        " entries, maximum is " +
                                                        std::to_string(max_scopes_per_authority));
  }
  for (const ScopeName& scope : scopes) {
    if (scope.empty()) {
      return Explanation(ErrorCode::ScopeUnknown, "scope list contains an empty scope name");
    }
  }
  std::sort(scopes.begin(), scopes.end());
  for (std::size_t index = 1; index < scopes.size(); ++index) {
    if (scopes[index] == scopes[index - 1]) {
      return Explanation(ErrorCode::ScopeDuplicate, "duplicate scope " + scopes[index].to_string());
    }
  }
  return AuthorityScopeSet::from_trusted(std::move(scopes));
}

bool AuthorityScopeSet::contains(const ScopeName& scope) const noexcept {
  return std::binary_search(scopes_.begin(), scopes_.end(), scope);
}

std::string AuthorityScopeSet::to_string() const {
  if (scopes_.empty()) {
    return std::string(kEmptyScopeText);
  }
  std::string text;
  for (const ScopeName& scope : scopes_) {
    if (!text.empty()) {
      text.push_back('+');
    }
    text.append(scope.view());
  }
  return text;
}

Result<AuthorityScopeSet> AuthorityScopeSet::parse(std::string_view text) {
  if (text.empty()) {
    return Explanation(ErrorCode::TokenMalformed, "scope set text is empty");
  }
  if (text == kEmptyScopeText) {
    return AuthorityScopeSet::from_trusted({});
  }
  std::vector<ScopeName> scopes;
  Result<std::vector<std::string_view>> fields = split(text, '+');
  scopes.reserve(fields.value().size());
  for (const std::string_view field : fields.value()) {
    Result<ScopeName> parsed = ScopeName::parse(field, "scope name");
    if (!parsed.has_value()) {
      return parsed.rejection();
    }
    scopes.push_back(parsed.move_value());
  }
  // create() rejects duplicates and orders the set canonically, so a
  // non-canonical input text is rejected rather than accepted and reshaped.
  Result<AuthorityScopeSet> created = AuthorityScopeSet::create(std::move(scopes));
  if (!created.has_value()) {
    return created.rejection();
  }
  if (created.value().to_string() != text) {
    return Explanation(ErrorCode::TokenMalformed, "scope set text is not in canonical ascending order");
  }
  return created;
}

Result<AuthorityClaims> AuthorityClaims::create(FacilityAuthorityDomainId domain, Epoch epoch,
                                                ControllerId controller,
                                                ControllerIncarnationId incarnation, GrantId grant,
                                                AuthorityScopeSet scopes) {
  if (domain.empty()) {
    return Explanation(ErrorCode::IdentifierEmpty, "authority claims have an empty domain");
  }
  if (epoch.value() == 0) {
    return Explanation(ErrorCode::EpochZero, "authority claims have an unset epoch");
  }
  if (controller.empty()) {
    return Explanation(ErrorCode::IdentifierEmpty, "authority claims have an empty controller");
  }
  if (incarnation.is_zero()) {
    return Explanation(ErrorCode::InvalidArgument, "authority claims have an unset incarnation");
  }
  if (!grant.is_set()) {
    return Explanation(ErrorCode::InvalidArgument, "authority claims have an unset grant identifier");
  }

  AuthorityClaims claims;
  claims.domain_ = std::move(domain);
  claims.epoch_ = epoch;
  claims.controller_ = std::move(controller);
  claims.incarnation_ = incarnation;
  claims.grant_ = grant;
  claims.scopes_ = std::move(scopes);
  return claims;
}

std::string AuthorityClaims::to_string() const {
  std::string text;
  text.append(domain_.view());
  text.push_back(kTokenSeparator);
  text.append(std::to_string(epoch_.value()));
  text.push_back(kTokenSeparator);
  text.append(controller_.view());
  text.push_back(kTokenSeparator);
  text.append(incarnation_.to_hex());
  text.push_back(kTokenSeparator);
  text.append(grant_.to_string());
  text.push_back(kTokenSeparator);
  text.append(scopes_.to_string());
  return text;
}

FencingToken FencingToken::derive(AuthorityClass authority_class, const AuthorityClaims& claims) {
  Sha256 hasher;
  detail::hash_text(hasher, kFencingTag);
  hash_claims(hasher, authority_class, claims);
  return FencingToken(hasher.finish());
}

namespace detail {

template <AuthorityClass Class>
Result<AuthorityToken<Class>> AuthorityToken<Class>::parse(std::string_view text) {
  Result<std::vector<std::string_view>> fields = split(text, kTokenSeparator);
  const std::vector<std::string_view>& parts = fields.value();
  if (parts.size() != 9) {
    return Explanation(ErrorCode::TokenMalformed, "authority token must have 9 fields, found " +
                                                      std::to_string(parts.size()));
  }
  if (parts[0] != kTokenPrefix) {
    return Explanation(ErrorCode::TokenMalformed, "authority token prefix is not " + std::string(kTokenPrefix));
  }
  Result<AuthorityClass> parsed_class = parse_authority_class(parts[1]);
  if (!parsed_class.has_value()) {
    return parsed_class.rejection();
  }
  if (parsed_class.value() != Class) {
    return Explanation(ErrorCode::AuthorityClassMismatch,
                       "authority token names the " + std::string(authority_class_token(parsed_class.value())) +
                           " class where " + std::string(authority_class_token(Class)) + " was expected");
  }

  Result<FacilityAuthorityDomainId> domain = FacilityAuthorityDomainId::parse(parts[2], "authority domain");
  if (!domain.has_value()) {
    return domain.rejection();
  }
  std::uint64_t epoch_value = 0;
  if (!parse_u64_strict(parts[3], epoch_value)) {
    return Explanation(ErrorCode::TokenMalformed, "authority token epoch field is not a canonical decimal integer");
  }
  Result<Epoch> epoch = Epoch::from_value(epoch_value);
  if (!epoch.has_value()) {
    return epoch.rejection();
  }
  Result<ControllerId> controller = ControllerId::parse(parts[4], "controller");
  if (!controller.has_value()) {
    return controller.rejection();
  }
  Result<ControllerIncarnationId> incarnation = ControllerIncarnationId::from_hex(parts[5]);
  if (!incarnation.has_value()) {
    return incarnation.rejection();
  }
  std::uint64_t grant_value = 0;
  if (!parse_u64_strict(parts[6], grant_value)) {
    return Explanation(ErrorCode::TokenMalformed, "authority token grant field is not a canonical decimal integer");
  }
  Result<GrantId> grant = GrantId::from_value(grant_value, "grant");
  if (!grant.has_value()) {
    return grant.rejection();
  }
  Result<AuthorityScopeSet> scopes = AuthorityScopeSet::parse(parts[7]);
  if (!scopes.has_value()) {
    return scopes.rejection();
  }
  Result<Sha256Digest> fencing = Sha256Digest::from_hex(parts[8]);
  if (!fencing.has_value()) {
    return fencing.rejection();
  }

  Result<AuthorityClaims> claims = AuthorityClaims::create(
      domain.move_value(), epoch.value(), controller.move_value(), incarnation.value(), grant.value(),
      scopes.move_value());
  if (!claims.has_value()) {
    return claims.rejection();
  }

  AuthorityToken token = AuthorityToken::from_claims(claims.move_value());
  if (token.token_.digest() != fencing.value()) {
    return Explanation(ErrorCode::TokenTampered, "authority token fencing digest does not match its claims");
  }
  return token;
}

template <AuthorityClass Class>
Sha256Digest AuthorityToken<Class>::digest() const {
  Sha256 hasher;
  detail::hash_text(hasher, kTokenTag);
  hash_claims(hasher, Class, claims_);
  detail::hash_digest(hasher, token_.digest());
  return hasher.finish();
}

template <AuthorityClass Class>
ValidationOutcome AuthorityToken<Class>::verify_integrity() const {
  const FencingToken expected = FencingToken::derive(Class, claims_);
  if (expected != token_) {
    return ValidationOutcome::reject(Explanation(
        ErrorCode::TokenTampered, "fencing token does not match the claims of grant " + claims_.grant().to_string()));
  }
  return ValidationOutcome::accept();
}

template <AuthorityClass Class>
std::string AuthorityToken<Class>::to_string() const {
  std::string text;
  text.append(kTokenPrefix);
  text.push_back(kTokenSeparator);
  text.append(authority_class_token(Class));
  text.push_back(kTokenSeparator);
  text.append(claims_.domain().view());
  text.push_back(kTokenSeparator);
  text.append(std::to_string(claims_.epoch().value()));
  text.push_back(kTokenSeparator);
  text.append(claims_.controller().view());
  text.push_back(kTokenSeparator);
  text.append(claims_.incarnation().to_hex());
  text.push_back(kTokenSeparator);
  text.append(claims_.grant().to_string());
  text.push_back(kTokenSeparator);
  text.append(claims_.scopes().to_string());
  text.push_back(kTokenSeparator);
  text.append(token_.to_hex());
  return text;
}

template class AuthorityToken<AuthorityClass::Mutation>;
template class AuthorityToken<AuthorityClass::Observation>;

}  // namespace detail

std::string AuthorityGrantRecord::to_string() const {
  std::string text;
  detail::append_field(text, "grant", id_.to_string());
  detail::append_field(text, "class", authority_class_token(authority_class_));
  detail::append_field(text, "epoch", epoch_.to_string());
  detail::append_field(text, "controller", controller_.view());
  detail::append_field(text, "incarnation_id", incarnation_.to_hex());
  detail::append_field(text, "incarnation", incarnation_number_.to_string());
  detail::append_field(text, "scopes", scopes_.to_string());
  detail::append_field(text, "sequence", std::to_string(sequence_));
  detail::append_field(text, "revoked_by", revoked_by_sequence_.has_value()
                                              ? revoked_by_sequence_->to_string()
                                              : std::string("-"));
  return text;
}

std::string_view revocation_target_kind_token(RevocationTargetKind kind) noexcept {
  for (const TargetToken& entry : kTargetTokens) {
    if (entry.kind == kind) {
      return entry.token;
    }
  }
  return "unknown";
}

Result<RevocationTargetKind> parse_revocation_target_kind(std::string_view token) {
  for (const TargetToken& entry : kTargetTokens) {
    if (entry.token == token) {
      return entry.kind;
    }
  }
  return Explanation(ErrorCode::EnumOutOfDomain, "unknown revocation target kind " + std::string(token));
}

std::string_view revocation_reason_token(RevocationReason reason) noexcept {
  for (const ReasonToken& entry : kReasonTokens) {
    if (entry.reason == reason) {
      return entry.token;
    }
  }
  return "unknown";
}

Result<RevocationReason> parse_revocation_reason(std::string_view token) {
  for (const ReasonToken& entry : kReasonTokens) {
    if (entry.token == token) {
      return entry.reason;
    }
  }
  return Explanation(ErrorCode::EnumOutOfDomain, "unknown revocation reason " + std::string(token));
}

std::string RevocationRecord::to_string() const {
  std::string text;
  detail::append_field(text, "revocation", sequence_.to_string());
  detail::append_field(text, "target", revocation_target_kind_token(target_kind_));
  detail::append_field(text, "controller", controller_.view());
  detail::append_field(text, "through_incarnation",
                       through_incarnation_.has_value() ? through_incarnation_->to_string() : std::string("-"));
  detail::append_field(text, "grant", grant_.has_value() ? grant_->to_string() : std::string("-"));
  detail::append_field(text, "reason", revocation_reason_token(reason_));
  detail::append_field(text, "epoch", epoch_.to_string());
  detail::append_field(text, "issued_by", issued_by_.view());
  detail::append_field(text, "issued_by_grant", issued_by_grant_.to_string());
  detail::append_field(text, "fenced_grants", std::to_string(fenced_grant_count_));
  detail::append_field(text, "replayed", detail::yes_no(replayed_));
  return text;
}

Result<IdempotencyKey> IdempotencyKey::create(ControllerId controller, ControllerIncarnationId incarnation,
                                             OperationSequence sequence) {
  if (controller.empty()) {
    return Explanation(ErrorCode::IdentifierEmpty, "idempotency key has an empty controller");
  }
  if (incarnation.is_zero()) {
    return Explanation(ErrorCode::InvalidArgument, "idempotency key has an unset incarnation");
  }
  if (!sequence.is_set()) {
    return Explanation(ErrorCode::InvalidArgument, "idempotency key has an unset sequence");
  }
  IdempotencyKey key;
  key.controller_ = std::move(controller);
  key.incarnation_ = incarnation;
  key.sequence_ = sequence;
  return key;
}

std::string IdempotencyKey::to_string() const {
  std::string text;
  text.append(controller_.view());
  text.push_back(kTokenSeparator);
  text.append(incarnation_.to_hex());
  text.push_back(kTokenSeparator);
  text.append(sequence_.to_string());
  return text;
}

}  // namespace dccp::epoch
