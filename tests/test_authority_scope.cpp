// Control Plane Epoch 1.0.0 - Summon Software Labs
// Authority scope suite: scope sets, claim completeness, fencing-token
// derivation, and the canonical token text with its tamper detection.
//
// Two invariants drive this suite. First, a scope set has exactly one canonical
// form, so two grants that cover the same scopes are the same authority
// regardless of the order the caller listed them in. Second, a token is a
// function of its claims: any edit to the claims inside token text is either
// rejected or produces a different token, never the original one.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "test_support.hpp"

namespace {

using dccp::epoch::AuthorityClaims;
using dccp::epoch::AuthorityClass;
using dccp::epoch::AuthorityScopeSet;
using dccp::epoch::ControllerIncarnationId;
using dccp::epoch::ErrorCode;
using dccp::epoch::FencingToken;
using dccp::epoch::GrantId;
using dccp::epoch::IncarnationNumber;
using dccp::epoch::MutationAuthority;
using dccp::epoch::ObservationAuthority;
using dccp::epoch::Result;
using dccp::epoch::ScopeName;

template <class T>
[[nodiscard]] ErrorCode rejection_code(const Result<T>& result) {
  return result.has_value() ? ErrorCode::Ok : result.rejection().code();
}

/// Canonical token fields are ':' separated; nothing in the grammar of an
/// identifier, a scope set, or a decimal field can collide with that separator.
[[nodiscard]] std::vector<std::string> split_fields(std::string_view text) {
  std::vector<std::string> fields;
  std::size_t start = 0;
  while (true) {
    const std::size_t position = text.find(':', start);
    if (position == std::string_view::npos) {
      fields.emplace_back(text.substr(start));
      return fields;
    }
    fields.emplace_back(text.substr(start, position - start));
    start = position + 1;
  }
}

[[nodiscard]] std::string join_fields(const std::vector<std::string>& fields) {
  std::string text;
  for (const std::string& field : fields) {
    if (!text.empty()) {
      text.push_back(':');
    }
    text.append(field);
  }
  return text;
}

/// Token text with one field replaced: exactly what a corrupted log, a
/// hand-edited artifact, or an attacker produces.
[[nodiscard]] std::string with_field(std::string_view token_text, std::size_t index, std::string_view replacement) {
  std::vector<std::string> fields = split_fields(token_text);
  fields[index] = std::string(replacement);
  return join_fields(fields);
}

[[nodiscard]] std::string without_field(std::string_view token_text, std::size_t index) {
  std::vector<std::string> fields = split_fields(token_text);
  fields.erase(fields.begin() + static_cast<std::ptrdiff_t>(index));
  return join_fields(fields);
}

/// Uppercases only the hexadecimal letters of a digest field. Hex is a numeric
/// encoding, not an identity, so this is *not* tampering.
[[nodiscard]] std::string uppercase_hex_letters(std::string_view text) {
  std::string result(text);
  for (char& character : result) {
    if (character >= 'a' && character <= 'f') {
      character = static_cast<char>(character - 'a' + 'A');
    }
  }
  return result;
}

[[nodiscard]] std::string hex_of(std::size_t count, char digit) { return std::string(count, digit); }

/// Joins names with a separator; the empty list renders as the canonical empty
/// marker, which is what a scope set's text form must be.
[[nodiscard]] std::string join_with(const std::vector<std::string>& names, char separator) {
  if (names.empty()) {
    return "-";
  }
  std::string text;
  for (const std::string& name : names) {
    if (!text.empty()) {
      text.push_back(separator);
    }
    text.append(name);
  }
  return text;
}

/// Inclusion in a failure detail is what makes a randomized failure
/// reproducible: the seed alone regenerates the sequence.
[[nodiscard]] std::string seed_detail(std::uint64_t seed, int iteration) {
  return "seed=" + std::to_string(seed) + " iteration=" + std::to_string(iteration);
}

[[nodiscard]] AuthorityClaims claims_with(const dccp::epoch::FacilityAuthorityDomainId& domain,
                                          std::uint64_t epoch, const dccp::epoch::ControllerId& controller,
                                          const ControllerIncarnationId& incarnation, std::uint64_t grant,
                                          const std::vector<std::string>& scopes) {
  auto created = AuthorityClaims::create(domain, dccp::epoch::Epoch::from_trusted(epoch), controller, incarnation,
                                         GrantId::from_trusted(grant), cpe_test::scope_set(scopes));
  if (!created.has_value()) {
    throw cpe_test::Failure("could not build claims: " + created.rejection().to_string());
  }
  return created.move_value();
}

/// Scope names s0..s{count-1}, distinct and canonical under any ordering.
[[nodiscard]] std::vector<std::string> generated_scopes(std::size_t count) {
  std::vector<std::string> names;
  names.reserve(count);
  for (std::size_t index = 0; index < count; ++index) {
    names.push_back("s" + std::to_string(index));
  }
  return names;
}

}  // namespace

CPE_TEST(authority_scope, scope_sets_are_sorted_unique_and_bounded) {
  const AuthorityScopeSet unsorted = cpe_test::scope_set({"facility.topology", "authority.grant", "facility.inventory"});
  CPE_REQUIRE_EQ(unsorted.size(), std::size_t{3});
  CPE_REQUIRE(!unsorted.empty());
  // Iteration order is ascending by bytes and is public, serialized behaviour.
  CPE_REQUIRE_EQ(unsorted.scopes()[0].to_string(), std::string("authority.grant"));
  CPE_REQUIRE_EQ(unsorted.scopes()[1].to_string(), std::string("facility.inventory"));
  CPE_REQUIRE_EQ(unsorted.scopes()[2].to_string(), std::string("facility.topology"));
  CPE_REQUIRE(unsorted.scopes()[0] < unsorted.scopes()[1]);
  CPE_REQUIRE(unsorted.scopes()[1] < unsorted.scopes()[2]);

  // The same scopes listed differently are the same authority.
  CPE_REQUIRE(unsorted == cpe_test::scope_set({"facility.inventory", "authority.grant", "facility.topology"}));
  CPE_REQUIRE(unsorted != cpe_test::scope_set({"authority.grant", "facility.inventory"}));

  // A duplicate is rejected rather than collapsed: silently deduplicating would
  // hide a caller bug and make the granted set differ from the requested one.
  CPE_REQUIRE_EQ(rejection_code(AuthorityScopeSet::create(cpe_test::scope_list({"a", "b", "a"}))),
                 ErrorCode::ScopeDuplicate);
  CPE_REQUIRE_EQ(
      rejection_code(AuthorityScopeSet::create(
          cpe_test::scope_list({"facility.inventory", "authority.grant", "facility.inventory"}))),
      ErrorCode::ScopeDuplicate);
  // A duplicate is detected after canonicalization, so adjacent input order is
  // not required.
  CPE_REQUIRE_EQ(rejection_code(AuthorityScopeSet::create(cpe_test::scope_list({"b", "c", "b", "a"}))),
                 ErrorCode::ScopeDuplicate);

  // The bound is enforced before anything is stored, so a caller cannot make an
  // authority allocate an unbounded scope list.
  const Result<AuthorityScopeSet> at_bound = AuthorityScopeSet::create(
      cpe_test::scope_list(generated_scopes(dccp::epoch::max_scopes_per_authority)));
  CPE_REQUIRE(at_bound.has_value());
  CPE_REQUIRE_EQ(at_bound.value().size(), dccp::epoch::max_scopes_per_authority);
  CPE_REQUIRE_EQ(rejection_code(AuthorityScopeSet::create(
                     cpe_test::scope_list(generated_scopes(dccp::epoch::max_scopes_per_authority + 1)))),
                 ErrorCode::SizeLimitExceeded);

  // Membership is exact: a scope name that differs by one byte is not covered.
  const ScopeName inventory = cpe_test::scope_name("facility.inventory");
  CPE_REQUIRE(unsorted.contains(inventory));
  CPE_REQUIRE(!unsorted.contains(cpe_test::scope_name("facility.inventor")));
  CPE_REQUIRE(!unsorted.contains(cpe_test::scope_name("facility.inventoryy")));
  CPE_REQUIRE(!unsorted.contains(cpe_test::scope_name("Facility.Inventory")));
  CPE_REQUIRE(!unsorted.contains(cpe_test::scope_name("authority.grants")));
  CPE_REQUIRE(!unsorted.contains(cpe_test::scope_name("authority")));

  const AuthorityScopeSet empty = cpe_test::scope_set({});
  CPE_REQUIRE(empty.empty());
  CPE_REQUIRE_EQ(empty.size(), std::size_t{0});
  CPE_REQUIRE(!empty.contains(inventory));
  CPE_REQUIRE_EQ(empty.to_string(), std::string("-"));
}

CPE_TEST(authority_scope, scope_sets_round_trip_through_canonical_text) {
  const AuthorityScopeSet set = cpe_test::scope_set({"facility.topology", "authority.grant", "facility.inventory"});
  CPE_REQUIRE_EQ(set.to_string(), std::string("authority.grant+facility.inventory+facility.topology"));

  const Result<AuthorityScopeSet> parsed = AuthorityScopeSet::parse(set.to_string());
  CPE_REQUIRE(parsed.has_value());
  CPE_REQUIRE(parsed.value() == set);
  CPE_REQUIRE_EQ(parsed.value().to_string(), set.to_string());

  // The empty set has a canonical rendering too, so "no scopes" survives a
  // round trip instead of collapsing into "unparseable".
  const Result<AuthorityScopeSet> empty = AuthorityScopeSet::parse("-");
  CPE_REQUIRE(empty.has_value());
  CPE_REQUIRE(empty.value().empty());
  CPE_REQUIRE_EQ(empty.value().to_string(), std::string("-"));
  CPE_REQUIRE_EQ(rejection_code(AuthorityScopeSet::parse("")), ErrorCode::TokenMalformed);

  // Non-canonical text is rejected, not silently reshaped: an authority that
  // accepted "b+a" would have two spellings for one authority.
  CPE_REQUIRE_EQ(rejection_code(AuthorityScopeSet::parse("facility.topology+authority.grant")),
                 ErrorCode::TokenMalformed);
  CPE_REQUIRE_EQ(rejection_code(AuthorityScopeSet::parse("authority.grant+authority.grant")), ErrorCode::ScopeDuplicate);
  CPE_REQUIRE_EQ(rejection_code(AuthorityScopeSet::parse("authority.grant+")), ErrorCode::IdentifierEmpty);
  CPE_REQUIRE_EQ(rejection_code(AuthorityScopeSet::parse("+authority.grant")), ErrorCode::IdentifierEmpty);
  CPE_REQUIRE_EQ(rejection_code(AuthorityScopeSet::parse("-+authority.grant")), ErrorCode::InvalidIdentifierSyntax);
  CPE_REQUIRE_EQ(rejection_code(AuthorityScopeSet::parse("authority.grant+facility inventory")),
                 ErrorCode::InvalidIdentifierSyntax);
  CPE_REQUIRE_EQ(rejection_code(AuthorityScopeSet::parse("authority.grant authority.revoke")),
                 ErrorCode::InvalidIdentifierSyntax);

  // A trusted set is the canonical form by construction; it renders identically.
  const AuthorityScopeSet trusted = AuthorityScopeSet::from_trusted({});
  CPE_REQUIRE(trusted == empty.value());
  CPE_REQUIRE_EQ(trusted.to_string(), std::string("-"));
}

CPE_TEST(authority_scope, claims_require_every_field_to_be_set) {
  const auto domain = cpe_test::domain_id("facility-alpha");
  const auto controller = cpe_test::controller_id("worker-a");
  const auto incarnation =
      ControllerIncarnationId::derive(domain, controller, IncarnationNumber::from_trusted(1));
  const dccp::epoch::Epoch epoch = dccp::epoch::Epoch::from_trusted(1);
  const GrantId grant = GrantId::from_trusted(4);
  const AuthorityScopeSet scopes = cpe_test::scope_set({"facility.inventory"});

  const Result<AuthorityClaims> complete =
      AuthorityClaims::create(domain, epoch, controller, incarnation, grant, scopes);
  CPE_REQUIRE(complete.has_value());
  CPE_REQUIRE_EQ(complete.value().domain(), domain);
  CPE_REQUIRE_EQ(complete.value().epoch(), epoch);
  CPE_REQUIRE_EQ(complete.value().controller(), controller);
  CPE_REQUIRE_EQ(complete.value().incarnation(), incarnation);
  CPE_REQUIRE_EQ(complete.value().grant(), grant);
  CPE_REQUIRE_EQ(complete.value().scopes(), scopes);
  // The claims text form is fixed, which is what makes token text stable.
  CPE_REQUIRE_EQ(complete.value().to_string(),
                 domain.to_string() + ":1:" + controller.to_string() + ":" + incarnation.to_hex() +
                     ":4:facility.inventory");

  const dccp::epoch::ControllerId empty_controller;
  const ControllerIncarnationId empty_incarnation;
  const GrantId empty_grant;

  // Every field is required, and the check order is fixed, so the reported code
  // is reproducible for a given input.
  CPE_REQUIRE_EQ(rejection_code(AuthorityClaims::create(dccp::epoch::FacilityAuthorityDomainId{}, epoch, controller,
                                                        incarnation, grant, scopes)),
                 ErrorCode::IdentifierEmpty);
  CPE_REQUIRE_EQ(rejection_code(AuthorityClaims::create(domain, dccp::epoch::Epoch::from_trusted(0), controller,
                                                        incarnation, grant, scopes)),
                 ErrorCode::EpochZero);
  CPE_REQUIRE_EQ(
      rejection_code(AuthorityClaims::create(domain, epoch, empty_controller, incarnation, grant, scopes)),
      ErrorCode::IdentifierEmpty);
  CPE_REQUIRE_EQ(
      rejection_code(AuthorityClaims::create(domain, epoch, controller, empty_incarnation, grant, scopes)),
      ErrorCode::InvalidArgument);
  CPE_REQUIRE_EQ(rejection_code(AuthorityClaims::create(domain, epoch, controller, incarnation, empty_grant, scopes)),
                 ErrorCode::InvalidArgument);
  // The first failing check owns the code: an entirely unset claim set is
  // reported as a missing domain, not as a missing incarnation.
  CPE_REQUIRE_EQ(rejection_code(AuthorityClaims::create(dccp::epoch::FacilityAuthorityDomainId{},
                                                        dccp::epoch::Epoch::from_trusted(0), empty_controller,
                                                        empty_incarnation, empty_grant, scopes)),
                 ErrorCode::IdentifierEmpty);
  CPE_REQUIRE_EQ(rejection_code(AuthorityClaims::create(domain, dccp::epoch::Epoch::from_trusted(0),
                                                        empty_controller, empty_incarnation, empty_grant, scopes)),
                 ErrorCode::EpochZero);
}

CPE_TEST(authority_scope, fencing_tokens_bind_every_claim_field) {
  const auto domain = cpe_test::domain_id("facility-alpha");
  const auto other_domain = cpe_test::domain_id("facility-beta");
  const auto controller = cpe_test::controller_id("worker-a");
  const auto other_controller = cpe_test::controller_id("worker-b");
  const auto incarnation_one =
      ControllerIncarnationId::derive(domain, controller, IncarnationNumber::from_trusted(1));
  const auto incarnation_two =
      ControllerIncarnationId::derive(domain, controller, IncarnationNumber::from_trusted(2));
  const std::vector<std::string> two_scopes = {"facility.inventory", "facility.topology"};
  const std::vector<std::string> one_scope = {"facility.inventory"};

  const AuthorityClaims base = claims_with(domain, 1, controller, incarnation_one, 1, two_scopes);
  const FencingToken base_token = FencingToken::derive(AuthorityClass::Mutation, base);
  CPE_REQUIRE(!base_token.is_zero());
  CPE_REQUIRE_EQ(base_token.to_hex().size(), std::size_t{64});

  // Derivation is a pure function of the class and the claims: the same claims
  // always produce the same token, in this process and in any other.
  CPE_REQUIRE(base_token == FencingToken::derive(AuthorityClass::Mutation, base));
  CPE_REQUIRE(base_token ==
              FencingToken::derive(AuthorityClass::Mutation, claims_with(domain, 1, controller, incarnation_one, 1,
                                                                         two_scopes)));

  // Each claim field participates in the derivation: changing any one of them
  // changes the token, which is what makes "the same token" evidence about the
  // whole claim set.
  CPE_REQUIRE(base_token != FencingToken::derive(AuthorityClass::Observation, base));
  CPE_REQUIRE(base_token != FencingToken::derive(
                                AuthorityClass::Mutation,
                                claims_with(domain, 2, controller, incarnation_one, 1, two_scopes)));
  CPE_REQUIRE(base_token != FencingToken::derive(
                                AuthorityClass::Mutation,
                                claims_with(domain, 1, controller, incarnation_two, 1, two_scopes)));
  CPE_REQUIRE(base_token != FencingToken::derive(
                                AuthorityClass::Mutation,
                                claims_with(domain, 1, other_controller, incarnation_one, 1, two_scopes)));
  CPE_REQUIRE(base_token != FencingToken::derive(
                                AuthorityClass::Mutation,
                                claims_with(domain, 1, controller, incarnation_one, 2, two_scopes)));
  CPE_REQUIRE(base_token != FencingToken::derive(
                                AuthorityClass::Mutation,
                                claims_with(domain, 1, controller, incarnation_one, 1, one_scope)));
  CPE_REQUIRE(base_token != FencingToken::derive(
                                AuthorityClass::Mutation,
                                claims_with(other_domain, 1, controller, incarnation_one, 1, two_scopes)));

  // Scope order is not part of the authority: canonicalization means a caller
  // cannot obtain two tokens for the same granted scope set.
  CPE_REQUIRE(base_token == FencingToken::derive(
                                AuthorityClass::Mutation,
                                claims_with(domain, 1, controller, incarnation_one, 1,
                                            {"facility.topology", "facility.inventory"})));

  // Two controllers with the same incarnation *number* still get different
  // incarnation identities, so a token is never ambiguous across controllers.
  const auto other_incarnation =
      ControllerIncarnationId::derive(domain, other_controller, IncarnationNumber::from_trusted(1));
  CPE_REQUIRE(other_incarnation != incarnation_one);
  CPE_REQUIRE(other_incarnation.to_hex().size() == std::size_t{64});
  CPE_REQUIRE(other_incarnation != ControllerIncarnationId::derive(other_domain, other_controller,
                                                                  IncarnationNumber::from_trusted(1)));
}

CPE_TEST(authority_scope, token_text_round_trips_and_detects_tampering) {
  cpe_test::TestAuthority test_authority;
  const MutationAuthority root = test_authority.root_authority();
  const dccp::epoch::ControllerRegistration registration = test_authority.register_controller("worker-a");
  const dccp::epoch::AuthorityGrantView view = test_authority.acquire(
      "worker-a", registration.incarnation_id(), {"facility.inventory", "facility.topology"}, root);
  const MutationAuthority original = test_authority.mutation_authority_of(view);
  const std::string text = original.to_string();
  const std::vector<std::string> fields = split_fields(text);
  CPE_REQUIRE_EQ(fields.size(), std::size_t{9});
  CPE_REQUIRE_EQ(fields[0], std::string("cpe1"));
  CPE_REQUIRE_EQ(fields[1], std::string("mutation"));
  CPE_REQUIRE_EQ(fields[2], test_authority.domain());
  CPE_REQUIRE_EQ(fields[3], std::string("1"));
  CPE_REQUIRE_EQ(fields[4], std::string("worker-a"));
  CPE_REQUIRE_EQ(fields[5], registration.incarnation_id().to_hex());
  CPE_REQUIRE_EQ(fields[6], view.record().id().to_string());
  CPE_REQUIRE_EQ(fields[7], std::string("facility.inventory+facility.topology"));
  CPE_REQUIRE_EQ(fields[8].size(), std::size_t{64});

  // The canonical text is a lossless encoding of the token.
  const Result<MutationAuthority> reparsed = MutationAuthority::parse(text);
  CPE_REQUIRE(reparsed.has_value());
  CPE_REQUIRE(reparsed.value() == original);
  CPE_REQUIRE_EQ(reparsed.value().to_string(), text);
  CPE_REQUIRE_EQ(reparsed.value().fencing_token(), original.fencing_token());
  CPE_REQUIRE_EQ(reparsed.value().grant(), original.grant());
  CPE_REQUIRE(reparsed.value().verify_integrity().accepted());

  // The class is part of the token's type and its text: the two classes never
  // substitute for one another.
  const dccp::epoch::AuthorityGrantView observed = test_authority.acquire(
      "worker-a", registration.incarnation_id(), {"facility.inventory"}, root, AuthorityClass::Observation);
  CPE_REQUIRE(observed.observation_authority().has_value());
  const ObservationAuthority observation = *observed.observation_authority();
  CPE_REQUIRE_EQ(rejection_code(MutationAuthority::parse(observation.to_string())),
                 ErrorCode::AuthorityClassMismatch);
  const Result<ObservationAuthority> observation_reparsed = ObservationAuthority::parse(observation.to_string());
  CPE_REQUIRE(observation_reparsed.has_value());
  CPE_REQUIRE(observation_reparsed.value() == observation);
  CPE_REQUIRE_EQ(rejection_code(ObservationAuthority::parse(text)), ErrorCode::AuthorityClassMismatch);
  CPE_REQUIRE_EQ(dccp::epoch::authority_class_token(AuthorityClass::Mutation), std::string_view("mutation"));
  CPE_REQUIRE_EQ(rejection_code(dccp::epoch::parse_authority_class("mutation")), ErrorCode::Ok);
  CPE_REQUIRE_EQ(rejection_code(dccp::epoch::parse_authority_class("Mutation")), ErrorCode::EnumOutOfDomain);

  // Hex is an encoding, not an identity: the same digest written in uppercase
  // is the same digest, and this is the one edit that is not tampering.
  const std::string upper_digest = with_field(text, 8, uppercase_hex_letters(fields[8]));
  CPE_REQUIRE(upper_digest != text);
  const Result<MutationAuthority> upper = MutationAuthority::parse(upper_digest);
  CPE_REQUIRE(upper.has_value());
  CPE_REQUIRE(upper.value() == original);

  struct TamperCase {
    std::size_t field;
    std::string replacement;
    ErrorCode expected;
    const char* what;
  };
  const std::vector<TamperCase> tampered = {
      {0, "cpe2", ErrorCode::TokenMalformed, "the format prefix"},
      {0, "", ErrorCode::TokenMalformed, "the format prefix"},
      {1, "observation", ErrorCode::AuthorityClassMismatch, "the authority class"},
      {1, "Mutation", ErrorCode::EnumOutOfDomain, "the authority class"},
      {2, "facility-beta", ErrorCode::TokenTampered, "the domain"},
      {2, "", ErrorCode::IdentifierEmpty, "the domain"},
      {3, "2", ErrorCode::TokenTampered, "the epoch"},
      {3, "0", ErrorCode::EpochZero, "the epoch"},
      {3, "01", ErrorCode::TokenMalformed, "the epoch"},
      {3, "-1", ErrorCode::TokenMalformed, "the epoch"},
      {3, "18446744073709551616", ErrorCode::TokenMalformed, "the epoch"},
      {4, "worker-b", ErrorCode::TokenTampered, "the controller"},
      {4, "worker a", ErrorCode::InvalidIdentifierSyntax, "the controller"},
      {5, hex_of(64, 'a'), ErrorCode::TokenTampered, "the incarnation"},
      {5, hex_of(64, '0'), ErrorCode::InvalidArgument, "the incarnation"},
      {5, "abcd", ErrorCode::DigestInvalidHex, "the incarnation"},
      {6, std::to_string(view.record().id().value() + 1), ErrorCode::TokenTampered, "the grant identifier"},
      {6, "0", ErrorCode::InvalidArgument, "the grant identifier"},
      {7, "facility.inventory", ErrorCode::TokenTampered, "the scopes"},
      {7, "facility.topology+facility.inventory", ErrorCode::TokenMalformed, "the scopes"},
      {7, "-", ErrorCode::TokenTampered, "the scopes"},
      {7, "", ErrorCode::TokenMalformed, "the scopes"},
      {8, hex_of(64, '0'), ErrorCode::TokenTampered, "the fencing digest"},
      {8, "f" + hex_of(63, '0'), ErrorCode::TokenTampered, "the fencing digest"},
      {8, "abcd", ErrorCode::DigestInvalidHex, "the fencing digest"},
  };
  for (const TamperCase& item : tampered) {
    const std::string edited = with_field(text, item.field, item.replacement);
    CPE_REQUIRE_MSG(edited != text, std::string("the tamper case for ") + item.what + " changed nothing");
    const Result<MutationAuthority> parsed = MutationAuthority::parse(edited);
    CPE_REQUIRE_MSG(!parsed.has_value(),
                    std::string("editing ") + item.what + " produced a token: " + edited);
    CPE_REQUIRE_EQ(parsed.rejection().code(), item.expected);
    // Even when the edit is rejected, it must never be the original token.
    if (parsed.has_value()) {
      CPE_REQUIRE(parsed.value() != original);
    }
  }

  // The field count is part of the grammar: a truncated or extended token is
  // malformed rather than partially read.
  CPE_REQUIRE_EQ(rejection_code(MutationAuthority::parse(without_field(text, 8))), ErrorCode::TokenMalformed);
  CPE_REQUIRE_EQ(rejection_code(MutationAuthority::parse(text + ":extra")), ErrorCode::TokenMalformed);
  CPE_REQUIRE_EQ(rejection_code(MutationAuthority::parse("")), ErrorCode::TokenMalformed);
  CPE_REQUIRE_EQ(rejection_code(MutationAuthority::parse("cpe1")), ErrorCode::TokenMalformed);

  // Property: no single-digit edit of the fencing digest may ever be accepted
  // as the original token. The seed is fixed and echoed on failure, so any
  // counterexample is reproducible.
  const std::uint64_t seed = 0xA11CE5ull;
  cpe_test::DeterministicRandom random(seed);
  const std::string hex_digits = "0123456789abcdef";
  for (int iteration = 0; iteration < 250; ++iteration) {
    std::string digest = fields[8];
    const std::size_t position = static_cast<std::size_t>(random.next_below(digest.size()));
    char replacement = hex_digits[static_cast<std::size_t>(random.next_below(hex_digits.size()))];
    if (replacement == digest[position]) {
      replacement = replacement == 'a' ? 'b' : 'a';
    }
    digest[position] = replacement;
    const Result<MutationAuthority> parsed = MutationAuthority::parse(with_field(text, 8, digest));
    const std::string detail = seed_detail(random.seed(), iteration) + " digit=" + std::to_string(position);
    CPE_REQUIRE_MSG(!parsed.has_value(), detail + ": a single-digit digest edit was accepted");
    CPE_REQUIRE_MSG(parsed.rejection().code() == ErrorCode::TokenTampered, detail);
  }
}

CPE_TEST(authority_scope, generated_scope_lists_canonicalize_or_reject) {
  // Property: for an arbitrary caller-supplied scope list, the created set is
  // exactly the sorted, duplicate-free list, or the call is rejected with
  // ScopeDuplicate. Nothing is silently dropped, reordered on read, or
  // accepted twice, and the canonical text round-trips through parse().
  const std::uint64_t seed = 0x5C0FE5ull;
  cpe_test::DeterministicRandom random(seed);
  const std::vector<std::string> vocabulary = {"authority.grant", "authority.revoke", "epoch.advance",
                                               "facility.inventory", "facility.topology", "zzz"};

  std::size_t duplicates = 0;
  std::size_t accepted = 0;
  for (int iteration = 0; iteration < 400; ++iteration) {
    const std::size_t count = static_cast<std::size_t>(random.next_below(7));
    std::vector<std::string> names;
    names.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
      names.push_back(vocabulary[static_cast<std::size_t>(random.next_below(vocabulary.size()))]);
    }
    std::vector<std::string> sorted = names;
    std::sort(sorted.begin(), sorted.end());
    const std::string detail = seed_detail(random.seed(), iteration) + " requested=" + join_with(names, '+');

    const Result<AuthorityScopeSet> created = AuthorityScopeSet::create(cpe_test::scope_list(names));
    if (std::adjacent_find(sorted.begin(), sorted.end()) != sorted.end()) {
      ++duplicates;
      CPE_REQUIRE_MSG(!created.has_value(), detail + ": a duplicate-bearing list was accepted");
      CPE_REQUIRE_MSG(created.rejection().code() == ErrorCode::ScopeDuplicate, detail);
      continue;
    }
    ++accepted;
    CPE_REQUIRE_MSG(created.has_value(), detail + ": a legal list was rejected");
    CPE_REQUIRE_MSG(created.value().to_string() == join_with(sorted, '+'),
                    detail + " rendered=" + created.value().to_string());
    CPE_REQUIRE_EQ(created.value().size(), count);
    const Result<AuthorityScopeSet> reparsed = AuthorityScopeSet::parse(created.value().to_string());
    CPE_REQUIRE_MSG(reparsed.has_value(), detail + ": canonical text did not parse back");
    CPE_REQUIRE_MSG(reparsed.value() == created.value(), detail + ": canonical text changed the set");
    // Membership follows the canonical content exactly.
    for (const std::string& name : vocabulary) {
      const bool expected = std::binary_search(sorted.begin(), sorted.end(), name);
      CPE_REQUIRE_MSG(created.value().contains(cpe_test::scope_name(name)) == expected, detail);
    }
  }
  CPE_REQUIRE_MSG(duplicates > std::size_t{0}, seed_detail(random.seed(), -1) + " never produced a duplicate");
  CPE_REQUIRE_MSG(accepted > std::size_t{0}, seed_detail(random.seed(), -1) + " never produced a legal list");
}
