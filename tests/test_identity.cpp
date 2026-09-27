// Control Plane Epoch 1.0.0 - Summon Software Labs
// Identity suite.
//
// The invariant under test is that an identity which exists in the system has
// already been validated at its construction boundary, and that validation is
// byte-exact: no trimming, no case folding, no Unicode normalization, no
// "repair into something plausible". Everything unchecked is rejected with a
// stable code instead of being reshaped.
#include <concepts>
#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "test_support.hpp"

namespace {

using dccp::epoch::ControllerId;
using dccp::epoch::ErrorCode;
using dccp::epoch::ExternalRef;
using dccp::epoch::FacilityAuthorityDomainId;
using dccp::epoch::GrantId;
using dccp::epoch::IncarnationNumber;
using dccp::epoch::OperationSequence;
using dccp::epoch::Result;
using dccp::epoch::ScopeName;
using dccp::epoch::TransitionSequence;

/// Builds a byte string from explicit code units. Malformed UTF-8, embedded NUL,
/// and control characters are expressed as bytes so that the cases do not depend
/// on the source encoding of this file.
[[nodiscard]] std::string bytes(std::initializer_list<unsigned int> values) {
  std::string text;
  text.reserve(values.size());
  for (const unsigned int value : values) {
    text.push_back(static_cast<char>(value));
  }
  return text;
}

[[nodiscard]] std::string repeat(std::string_view unit, std::size_t count) {
  std::string text;
  text.reserve(unit.size() * count);
  for (std::size_t index = 0; index < count; ++index) {
    text.append(unit);
  }
  return text;
}

/// Code with which a controller-identifier parse rejected, or Ok when accepted.
[[nodiscard]] ErrorCode parse_code(std::string_view text) {
  const Result<ControllerId> parsed = ControllerId::parse(text, "controller");
  return parsed.has_value() ? ErrorCode::Ok : parsed.rejection().code();
}

template <class T>
[[nodiscard]] ErrorCode rejection_code(const Result<T>& result) {
  return result.has_value() ? ErrorCode::Ok : result.rejection().code();
}

/// Cross-type comparability, used to prove at compile time that distinct
/// identity kinds cannot be mixed.
template <class A, class B>
concept EqualityComparableAcross = requires(const A& lhs, const B& rhs) {
  { lhs == rhs } -> std::convertible_to<bool>;
};

template <class A, class B>
concept OrderComparableAcross = requires(const A& lhs, const B& rhs) {
  { lhs < rhs } -> std::convertible_to<bool>;
};

/// The identifier grammar written from its specification, independently of the
/// library implementation: 1..max bytes, alphanumeric first byte, then
/// [A-Za-z0-9._-]. Used as the oracle of the property test below.
[[nodiscard]] bool oracle_alphanumeric(unsigned char byte) {
  return (byte >= static_cast<unsigned char>('0') && byte <= static_cast<unsigned char>('9')) ||
         (byte >= static_cast<unsigned char>('A') && byte <= static_cast<unsigned char>('Z')) ||
         (byte >= static_cast<unsigned char>('a') && byte <= static_cast<unsigned char>('z'));
}

[[nodiscard]] bool oracle_identifier_byte(unsigned char byte) {
  return oracle_alphanumeric(byte) || byte == static_cast<unsigned char>('.') ||
         byte == static_cast<unsigned char>('_') || byte == static_cast<unsigned char>('-');
}

[[nodiscard]] ErrorCode oracle_identifier_code(const std::string& text) {
  if (text.empty()) {
    return ErrorCode::IdentifierEmpty;
  }
  if (text.size() > dccp::epoch::max_identifier_length) {
    return ErrorCode::IdentifierTooLong;
  }
  if (!oracle_alphanumeric(static_cast<unsigned char>(text.front()))) {
    return ErrorCode::InvalidIdentifierSyntax;
  }
  for (const char byte : text) {
    if (!oracle_identifier_byte(static_cast<unsigned char>(byte))) {
      return ErrorCode::InvalidIdentifierSyntax;
    }
  }
  return ErrorCode::Ok;
}

/// Inclusion in a failure detail is what makes a randomized failure
/// reproducible: the seed alone regenerates the sequence.
[[nodiscard]] std::string seed_detail(std::uint64_t seed, int iteration) {
  return "seed=" + std::to_string(seed) + " iteration=" + std::to_string(iteration);
}

}  // namespace

// Distinct identity kinds are distinct C++ types: there is no conversion, no
// construction, no assignment, and no comparison across kinds. A controller
// identity therefore cannot be passed where a domain identity is expected, and
// the mistake is a compile error rather than a runtime mix-up.
static_assert(!std::is_convertible_v<ControllerId, FacilityAuthorityDomainId>);
static_assert(!std::is_convertible_v<FacilityAuthorityDomainId, ControllerId>);
static_assert(!std::is_constructible_v<FacilityAuthorityDomainId, ControllerId>);
static_assert(!std::is_assignable_v<FacilityAuthorityDomainId&, ControllerId>);
static_assert(!std::is_convertible_v<ControllerId, ScopeName>);
static_assert(!EqualityComparableAcross<ControllerId, ScopeName>);
static_assert(!EqualityComparableAcross<FacilityAuthorityDomainId, ControllerId>);
static_assert(!OrderComparableAcross<ControllerId, ScopeName>);
static_assert(EqualityComparableAcross<ControllerId, ControllerId>);
static_assert(std::is_copy_constructible_v<ControllerId>);

// The same separation holds for the monotonic counters, which are otherwise
// indistinguishable bare integers.
static_assert(!std::is_convertible_v<GrantId, TransitionSequence>);
static_assert(!std::is_convertible_v<GrantId, IncarnationNumber>);
static_assert(!std::is_constructible_v<TransitionSequence, GrantId>);
static_assert(!EqualityComparableAcross<GrantId, TransitionSequence>);
static_assert(!OrderComparableAcross<GrantId, IncarnationNumber>);
static_assert(EqualityComparableAcross<GrantId, GrantId>);

CPE_TEST(identity, identifier_syntax_is_byte_exact) {
  // The accepted alphabet is [A-Za-z0-9._-] with an alphanumeric first byte.
  // Uppercase is accepted and preserved, because identifiers are compared as
  // bytes: case carries meaning.
  const std::vector<std::string> accepted = {
      "a", "Z", "9", "A.b_c-d", "0-0.0_0", "FACILITY.Alpha-1_2", repeat("x", 96)};
  for (const std::string& text : accepted) {
    const Result<ControllerId> parsed = ControllerId::parse(text, "controller");
    CPE_REQUIRE_MSG(parsed.has_value(),
                    "expected '" + text + "' to be accepted: " + parsed.rejection().to_string());
    // Round trip is exact: nothing is trimmed, folded, or normalized.
    CPE_REQUIRE_EQ(parsed.value().to_string(), text);
  }

  struct RejectionCase {
    std::string text;
    ErrorCode expected;
  };
  const std::vector<RejectionCase> rejected = {
      {"", ErrorCode::IdentifierEmpty},
      // Length is checked before syntax, so an over-long input with invalid
      // bytes is reported as too long rather than as invalid syntax.
      {repeat("x", 97), ErrorCode::IdentifierTooLong},
      {repeat(".", 97), ErrorCode::IdentifierTooLong},
      {".abc", ErrorCode::InvalidIdentifierSyntax},
      {"-abc", ErrorCode::InvalidIdentifierSyntax},
      {"_abc", ErrorCode::InvalidIdentifierSyntax},
      {" abc", ErrorCode::InvalidIdentifierSyntax},
      {"ab c", ErrorCode::InvalidIdentifierSyntax},
      {"ab:c", ErrorCode::InvalidIdentifierSyntax},
      {"ab/c", ErrorCode::InvalidIdentifierSyntax},
      {"ab+c", ErrorCode::InvalidIdentifierSyntax},
      {"ab\nc", ErrorCode::InvalidIdentifierSyntax},
      {"a\tb", ErrorCode::InvalidIdentifierSyntax},
      {bytes({'a', 0x00, 'b'}), ErrorCode::InvalidIdentifierSyntax},
      {bytes({0xC3, 0xA9, 'a'}), ErrorCode::InvalidIdentifierSyntax},
      {bytes({'a', 0xC3, 0xA9}), ErrorCode::InvalidIdentifierSyntax},
      {bytes({0x80}), ErrorCode::InvalidIdentifierSyntax},
  };
  for (const RejectionCase& item : rejected) {
    CPE_REQUIRE_MSG(parse_code(item.text) == item.expected,
                    "input length " + std::to_string(item.text.size()) + " produced code " +
                        std::string(dccp::epoch::error_token(parse_code(item.text))));
  }

  // The rejection detail is derived only from the input, so it is stable and
  // log-comparable. The offset is the byte offset of the first offending byte.
  const Result<ControllerId> spaced = ControllerId::parse("ab c", "controller");
  CPE_REQUIRE_EQ(spaced.rejection().detail(),
                 std::string("controller contains a character outside [A-Za-z0-9._-] at byte offset 2"));
  const Result<ControllerId> leading = ControllerId::parse(".abc", "controller");
  CPE_REQUIRE_EQ(
      leading.rejection().detail(),
      std::string("controller must start with an ASCII letter or digit, at byte offset 0"));
  const Result<ControllerId> empty = ControllerId::parse("", "controller");
  CPE_REQUIRE_EQ(empty.rejection().detail(), std::string("controller is empty"));
}

CPE_TEST(identity, identifiers_compare_by_bytes_and_never_fold_case) {
  const ControllerId upper = cpe_test::controller_id("Worker-A");
  const ControllerId lower = cpe_test::controller_id("worker-a");
  CPE_REQUIRE_MSG(upper != lower, "identity comparison must not fold case");
  // Ordering is byte ordering: 'A' (0x41) sorts before 'a' (0x61).
  CPE_REQUIRE(upper < lower);
  CPE_REQUIRE_EQ(upper.to_string(), std::string("Worker-A"));
  CPE_REQUIRE_EQ(lower.to_string(), std::string("worker-a"));

  // Punctuation is significant, not decorative: names that differ only in a
  // separator byte are different identities and have a fixed order.
  const ControllerId dash = cpe_test::controller_id("a-b");
  const ControllerId dot = cpe_test::controller_id("a.b");
  const ControllerId underscore = cpe_test::controller_id("a_b");
  CPE_REQUIRE(dash < dot);
  CPE_REQUIRE(dot < underscore);
  CPE_REQUIRE(dash != dot && dot != underscore && dash != underscore);
  CPE_REQUIRE_EQ(dash.size(), std::size_t{3});
  CPE_REQUIRE_EQ(dash.view(), std::string_view("a-b"));
  CPE_REQUIRE(!dash.empty());

  // A default-constructed identity is empty, which is how absence is reported
  // inside the library; empty identities are never produced by parse().
  const ControllerId unset;
  CPE_REQUIRE(unset.empty());
  CPE_REQUIRE_EQ(unset.to_string(), std::string());

  // The same bytes validated for another purpose produce the same text but a
  // different type (see the static_asserts above), which is what makes
  // "controller id where a domain id is expected" impossible to express.
  const ScopeName scope = cpe_test::scope_name("a-b");
  CPE_REQUIRE_EQ(scope.to_string(), dash.to_string());
  const FacilityAuthorityDomainId domain = cpe_test::domain_id("facility-alpha");
  const ControllerId controller = cpe_test::controller_id("facility-alpha");
  CPE_REQUIRE_EQ(domain.to_string(), controller.to_string());
  CPE_REQUIRE_EQ(domain.size(), controller.size());
}

CPE_TEST(identity, counters_reject_zero_and_exhaust_without_wrapping) {
  // Zero means "absent" for every counter kind, so it is never a committed
  // value: a grant id, sequence, or incarnation of 0 would be indistinguishable
  // from "no value yet".
  const Result<GrantId> absent = GrantId::from_value(0, "grant");
  CPE_REQUIRE(!absent.has_value());
  CPE_REQUIRE_EQ(absent.rejection().code(), ErrorCode::InvalidArgument);
  CPE_REQUIRE_EQ(absent.rejection().detail(), std::string("grant value 0 is not a committed value"));

  const Result<GrantId> first = GrantId::from_value(1, "grant");
  CPE_REQUIRE(first.has_value());
  CPE_REQUIRE(first.value().is_set());
  CPE_REQUIRE_EQ(first.value().value(), std::uint64_t{1});
  CPE_REQUIRE_EQ(first.value().to_string(), std::string("1"));

  const GrantId unset;
  CPE_REQUIRE(!unset.is_set());
  CPE_REQUIRE_EQ(unset.value(), std::uint64_t{0});
  const Result<GrantId> unset_successor = unset.successor();
  CPE_REQUIRE(!unset_successor.has_value());
  CPE_REQUIRE_EQ(unset_successor.rejection().code(), ErrorCode::InvalidArgument);

  // Succession is strictly monotonic and never wraps: the maximum value is
  // reported as exhausted instead of silently becoming zero.
  GrantId grant = GrantId::from_trusted(1);
  for (std::uint64_t step = 2; step <= 4; ++step) {
    const Result<GrantId> next = grant.successor();
    CPE_REQUIRE(next.has_value());
    CPE_REQUIRE_EQ(next.value().value(), step);
    CPE_REQUIRE(grant < next.value());
    grant = next.value();
  }
  const GrantId maximum = GrantId::from_trusted(UINT64_MAX);
  const Result<GrantId> exhausted = maximum.successor();
  CPE_REQUIRE(!exhausted.has_value());
  CPE_REQUIRE_EQ(exhausted.rejection().code(), ErrorCode::CounterExhausted);
  CPE_REQUIRE_EQ(maximum.value(), UINT64_MAX);

  // Every counter kind shares one contract, so no kind can have a different
  // exhaustion or absence rule.
  CPE_REQUIRE_EQ(rejection_code(TransitionSequence::from_value(0, "transition sequence")),
                 ErrorCode::InvalidArgument);
  CPE_REQUIRE_EQ(rejection_code(IncarnationNumber::from_value(0, "incarnation")), ErrorCode::InvalidArgument);
  CPE_REQUIRE_EQ(rejection_code(IncarnationNumber::from_trusted(UINT64_MAX).successor()),
                 ErrorCode::CounterExhausted);
  const Result<OperationSequence> operation = OperationSequence::from_value(1, "operation");
  CPE_REQUIRE(operation.has_value());
  CPE_REQUIRE_EQ(operation.value().value(), std::uint64_t{1});
  CPE_REQUIRE(TransitionSequence::from_trusted(7) < TransitionSequence::from_trusted(8));
}

CPE_TEST(identity, external_references_validate_both_parts) {
  const Result<ExternalRef> reference = ExternalRef::parse("asi", "accelerator-7");
  CPE_REQUIRE(reference.has_value());
  CPE_REQUIRE_EQ(reference.value().to_string(), std::string("asi:accelerator-7"));
  CPE_REQUIRE_EQ(reference.value().kind(), std::string("asi"));
  CPE_REQUIRE_EQ(reference.value().value(), std::string("accelerator-7"));
  CPE_REQUIRE(!reference.value().empty());

  // The reference value is opaque to this repository: another layer owns its
  // grammar, so spaces and non-ASCII UTF-8 are acceptable there even though the
  // kind tag is a strict identifier.
  const Result<ExternalRef> opaque =
      ExternalRef::parse("dfi", std::string("topology object ") + bytes({0xE2, 0x82, 0xAC}));
  CPE_REQUIRE(opaque.has_value());

  const ExternalRef unset;
  CPE_REQUIRE(unset.empty());
  CPE_REQUIRE_EQ(unset.to_string(), std::string(":"));

  struct ReferenceCase {
    std::string kind;
    std::string value;
    ErrorCode expected;
  };
  const std::vector<ReferenceCase> rejected = {
      {"", "accelerator-7", ErrorCode::ExternalReferenceInvalid},
      {"asi", "", ErrorCode::ExternalReferenceInvalid},
      {repeat("k", 33), "accelerator-7", ErrorCode::IdentifierTooLong},
      {".kind", "accelerator-7", ErrorCode::InvalidIdentifierSyntax},
      {"asi", repeat("v", 257), ErrorCode::TextTooLong},
      {"asi", "object\nname", ErrorCode::TextControlCharacter},
      {"asi", bytes({0xED, 0xA0, 0x80}), ErrorCode::TextInvalidUtf8},
  };
  for (const ReferenceCase& item : rejected) {
    const Result<ExternalRef> parsed = ExternalRef::parse(item.kind, item.value);
    CPE_REQUIRE_MSG(!parsed.has_value(), "reference (" + item.kind + ", " + item.value + ") was accepted");
    CPE_REQUIRE_EQ(parsed.rejection().code(), item.expected);
  }

  // Equality and ordering are (kind, value) lexicographic over bytes.
  const Result<ExternalRef> az = ExternalRef::parse("a", "z");
  const Result<ExternalRef> ba = ExternalRef::parse("b", "a");
  const Result<ExternalRef> aa = ExternalRef::parse("a", "a");
  const Result<ExternalRef> ab = ExternalRef::parse("a", "b");
  CPE_REQUIRE(az.value() < ba.value());
  CPE_REQUIRE(aa.value() < ab.value());
  CPE_REQUIRE(aa.value() == ExternalRef::parse("a", "a").value());
  CPE_REQUIRE(az.value() != ba.value());
  // An ExternalRef survives a byte-exact round trip through its text form. The
  // parsed value is held in a named result so the assertion compares live
  // objects rather than a reference into a destroyed temporary.
  const Result<ExternalRef> round_trip = ExternalRef::parse(az.value().kind(), az.value().value());
  CPE_REQUIRE(round_trip.has_value());
  CPE_REQUIRE_EQ(round_trip.value(), az.value());
}

CPE_TEST(identity, utf8_validation_rejects_every_malformed_shape) {
  // Well-formed sequences, including the last legal code point U+10FFFF. NUL is
  // well-formed UTF-8; whether it is acceptable *text* is a separate rule.
  const std::vector<std::string> accepted = {
      "", "plain ascii", bytes({0xC2, 0xA2}), bytes({0xE2, 0x82, 0xAC}), bytes({0xF0, 0x9F, 0x98, 0x80}),
      bytes({0xF4, 0x8F, 0xBF, 0xBF}), bytes({'a', 0x00, 'b'})};
  for (const std::string& text : accepted) {
    CPE_REQUIRE_MSG(dccp::epoch::is_valid_utf8(text), "expected a valid UTF-8 sequence");
  }

  // Each rejected shape is a distinct decoder bug class: overlong encodings
  // (which would let two byte strings name one code point), surrogates (invalid
  // in UTF-8 by definition), code points above U+10FFFF, truncated sequences,
  // and stray continuation bytes.
  const std::vector<std::string> rejected = {
      bytes({0xC0, 0x80}),              // overlong two-byte encoding of U+0000
      bytes({0xC1, 0xBF}),              // overlong two-byte encoding of U+007F
      bytes({0xE0, 0x80, 0x80}),        // overlong three-byte encoding
      bytes({0xF0, 0x80, 0x80, 0x80}),  // overlong four-byte encoding
      bytes({0xED, 0xA0, 0x80}),        // U+D800, a UTF-16 surrogate
      bytes({0xED, 0xBF, 0xBF}),        // U+DFFF, the last surrogate
      bytes({0xF4, 0x90, 0x80, 0x80}),  // U+110000, above the last code point
      bytes({0xF5, 0x80, 0x80, 0x80}),  // an impossible lead byte
      bytes({0xE2, 0x82}),              // truncated three-byte sequence
      bytes({0xF0, 0x9F, 0x98}),        // truncated four-byte sequence
      bytes({0xC3}),                    // lead byte with no continuation
      bytes({0x80}),                    // bare continuation byte
      bytes({0xBF}),                    // bare continuation byte
      bytes({'a', 0x80}),               // continuation after valid text
      bytes({0xFE}),                    // never valid in UTF-8
      bytes({0xFF}),                    // never valid in UTF-8
      bytes({0xE2, 0x28, 0xA1}),        // continuation replaced by ASCII
  };
  for (const std::string& text : rejected) {
    CPE_REQUIRE_MSG(!dccp::epoch::is_valid_utf8(text), "a malformed sequence was accepted as UTF-8");
  }
}

CPE_TEST(identity, text_validation_rejects_control_characters_after_encoding) {
  using dccp::epoch::validate_text;

  CPE_REQUIRE(validate_text("", 8, "note").has_value());
  CPE_REQUIRE(validate_text(repeat("x", 8), 8, "note").has_value());
  CPE_REQUIRE(validate_text(bytes({0xE2, 0x82, 0xAC}), 8, "note").has_value());
  CPE_REQUIRE_EQ(rejection_code(validate_text(repeat("x", 9), 8, "note")), ErrorCode::TextTooLong);

  // Control characters (C0 and DEL) are rejected because a note is rendered
  // into single-line, log-comparable detail text; NUL is rejected here even
  // though it is well-formed UTF-8.
  const std::vector<std::string> controls = {
      bytes({0x01}), bytes({0x1F}), bytes({'a', 0x7F}), bytes({'a', '\n'}), bytes({'a', '\t'}),
      bytes({'a', '\r'}), bytes({'a', 0x00, 'b'})};
  for (const std::string& text : controls) {
    const Result<std::string> validated = validate_text(text, 8, "note");
    CPE_REQUIRE_MSG(!validated.has_value(), "a control character was accepted in text");
    CPE_REQUIRE_EQ(validated.rejection().code(), ErrorCode::TextControlCharacter);
  }
  const Result<std::string> tab = validate_text(bytes({'a', '\t'}), 8, "note");
  CPE_REQUIRE_EQ(tab.rejection().detail(),
                 std::string("note contains a control character at byte offset 1"));

  // The check order is fixed and is what makes the code reproducible: length,
  // then encoding, then content. Each case below would fail more than one rule,
  // and the reported code must be the first one.
  CPE_REQUIRE_EQ(rejection_code(validate_text(bytes({0x01, 0x01}) + repeat("x", 9), 8, "note")),
                 ErrorCode::TextTooLong);
  CPE_REQUIRE_EQ(rejection_code(validate_text(bytes({0xED, 0xA0, 0x80, 0x01}), 8, "note")),
                 ErrorCode::TextInvalidUtf8);
  CPE_REQUIRE_EQ(rejection_code(validate_text(bytes({'a', 0x01}), 8, "note")), ErrorCode::TextControlCharacter);
}

CPE_TEST(identity, generated_identifiers_agree_with_an_independent_oracle) {
  // Property: for arbitrary byte strings the parser accepts exactly what the
  // documented grammar accepts, and accepts it byte for byte. The oracle is
  // written from the specification rather than from the implementation, so an
  // accidental widening of the alphabet, of the length bound, or of the
  // first-byte rule fails here instead of in production. The seed is fixed and
  // echoed in every failure detail, so a failure is reproducible from the
  // message alone.
  const std::uint64_t seed = 0x1D3A71F1E5ull;
  cpe_test::DeterministicRandom random(seed);
  const std::string pool =
      bytes({'a', 'Z', '9', '.', '-', '_', ':', ' ', 0x09, 0x0A, 0x00, 0x7F, 0x80, 0xC3, 0xA9, 0xFF, '/'});

  std::size_t accepted = 0;
  for (int iteration = 0; iteration < 600; ++iteration) {
    // Lengths straddle the 96-byte bound, so both the length rule and the
    // character rule are exercised by the same generator.
    const std::size_t length = static_cast<std::size_t>(random.next_below(101));
    std::string text;
    text.reserve(length);
    for (std::size_t index = 0; index < length; ++index) {
      text.push_back(pool[static_cast<std::size_t>(random.next_below(pool.size()))]);
    }

    const std::string detail = seed_detail(random.seed(), iteration) + " length=" + std::to_string(text.size());
    const Result<ControllerId> parsed = ControllerId::parse(text, "controller");
    const ErrorCode expected = oracle_identifier_code(text);
    CPE_REQUIRE_MSG(parsed.has_value() == (expected == ErrorCode::Ok),
                    detail + " but the parser disagreed with the grammar oracle");
    if (expected == ErrorCode::Ok) {
      ++accepted;
      CPE_REQUIRE_MSG(parsed.value().to_string() == text, detail + " but the identifier was not round-tripped");
      CPE_REQUIRE_EQ(parsed.value().size(), text.size());
    } else {
      CPE_REQUIRE_MSG(parsed.rejection().code() == expected,
                      detail + " code=" + std::string(dccp::epoch::error_token(parsed.rejection().code())));
    }
  }
  // The generator must actually reach both outcomes; otherwise the property
  // would be vacuous.
  CPE_REQUIRE_MSG(accepted > std::size_t{0}, seed_detail(random.seed(), -1) + " produced no accepted identifier");
  CPE_REQUIRE_MSG(accepted < std::size_t{600},
                  seed_detail(random.seed(), -1) + " produced only accepted identifiers");
}
