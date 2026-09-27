// Control Plane Epoch 1.0.0 - Summon Software Labs
// Epoch suite.
//
// An epoch is the domain's committed authority generation. It is strictly
// monotonic, never zero, never reused, and it only ever moves forward by exactly
// one step, so "current epoch" cannot drift and a fenced generation can never
// become current again.
#include <algorithm>
#include <compare>
#include <cstdint>
#include <string>
#include <vector>

#include "test_support.hpp"

namespace {

using dccp::epoch::Epoch;
using dccp::epoch::EpochTransitionReason;
using dccp::epoch::EpochTransitionRecord;
using dccp::epoch::ErrorCode;
using dccp::epoch::MutationAuthority;
using dccp::epoch::Result;

template <class T>
[[nodiscard]] ErrorCode rejection_code(const Result<T>& result) {
  return result.has_value() ? ErrorCode::Ok : result.rejection().code();
}

}  // namespace

CPE_TEST(epoch, committed_values_are_never_zero_and_advance_by_exactly_one) {
  // Zero is not a committed epoch, so absence can never be mistaken for the
  // first generation and an uninitialized value can never authorize anything.
  const Result<Epoch> zero = Epoch::from_value(0);
  CPE_REQUIRE(!zero.has_value());
  CPE_REQUIRE_EQ(zero.rejection().code(), ErrorCode::EpochZero);
  CPE_REQUIRE_EQ(zero.rejection().token(), std::string_view("epoch.zero"));
  CPE_REQUIRE_EQ(zero.rejection().detail(), std::string("epoch value 0 is not a committed epoch"));

  const Result<Epoch> first = Epoch::from_value(1);
  CPE_REQUIRE(first.has_value());
  CPE_REQUIRE(first.value().is_initial());
  CPE_REQUIRE_EQ(first.value(), Epoch::initial());
  CPE_REQUIRE_EQ(first.value().value(), std::uint64_t{1});
  CPE_REQUIRE_EQ(first.value().to_string(), std::string("1"));
  CPE_REQUIRE(!Epoch::from_trusted(0).is_initial());
  CPE_REQUIRE_EQ(Epoch::from_trusted(0).value(), std::uint64_t{0});

  // Succession is one step, strictly increasing, and checked.
  const Result<Epoch> second = first.value().successor();
  CPE_REQUIRE(second.has_value());
  CPE_REQUIRE_EQ(second.value().value(), std::uint64_t{2});
  CPE_REQUIRE(first.value() < second.value());
  const Result<Epoch> third = second.value().successor();
  CPE_REQUIRE(third.has_value());
  const Result<Epoch> expected_third = Epoch::from_value(3);
  CPE_REQUIRE(expected_third.has_value());
  CPE_REQUIRE_EQ(third.value(), expected_third.value());
  CPE_REQUIRE(second.value() < third.value());

  // The maximum value is reported as exhausted rather than wrapping to zero,
  // which would silently resurrect the first generation.
  const Epoch maximum = Epoch::from_trusted(UINT64_MAX);
  const Result<Epoch> exhausted = maximum.successor();
  CPE_REQUIRE(!exhausted.has_value());
  CPE_REQUIRE_EQ(exhausted.rejection().code(), ErrorCode::EpochExhausted);
  CPE_REQUIRE_EQ(exhausted.rejection().token(), std::string_view("epoch.exhausted"));
  CPE_REQUIRE_EQ(maximum.value(), UINT64_MAX);
}

CPE_TEST(epoch, epochs_order_totally_by_value) {
  const Epoch one = Epoch::from_trusted(1);
  const Epoch two = Epoch::from_trusted(2);
  const Epoch also_two = Epoch::from_value(2).value();
  const Epoch huge = Epoch::from_trusted(UINT64_MAX);

  CPE_REQUIRE(one == one);
  CPE_REQUIRE(one != two);
  CPE_REQUIRE(two == also_two);
  CPE_REQUIRE(one < two);
  CPE_REQUIRE(one <= two);
  CPE_REQUIRE(one <= one);
  CPE_REQUIRE(two > one);
  CPE_REQUIRE(two >= two);
  CPE_REQUIRE(!(two < one));
  CPE_REQUIRE(!(one > two));
  CPE_REQUIRE(huge > two);
  CPE_REQUIRE((one <=> two) == std::strong_ordering::less);
  CPE_REQUIRE((two <=> also_two) == std::strong_ordering::equal);
  CPE_REQUIRE((huge <=> one) == std::strong_ordering::greater);

  // A sorted collection of epochs stays in value order, which is what the
  // ledger and grant ordering rely on.
  std::vector<Epoch> epochs = {huge, two, one, also_two};
  std::sort(epochs.begin(), epochs.end());
  CPE_REQUIRE_EQ(epochs.front(), one);
  CPE_REQUIRE_EQ(epochs.back(), huge);
  CPE_REQUIRE_EQ(epochs[1], two);
  CPE_REQUIRE_EQ(epochs[2], also_two);
}

CPE_TEST(epoch, transition_reasons_round_trip_through_tokens) {
  // The numeric values are part of the durable schema and never change, so they
  // are pinned here together with their tokens.
  struct ReasonCase {
    EpochTransitionReason reason;
    std::uint32_t value;
    std::string_view token;
  };
  const ReasonCase cases[] = {
      {EpochTransitionReason::Genesis, 1, "genesis"},
      {EpochTransitionReason::OperatorRequest, 2, "operator_request"},
      {EpochTransitionReason::Fencing, 3, "fencing"},
      {EpochTransitionReason::Recovery, 4, "recovery"},
      {EpochTransitionReason::FacilityReconfiguration, 5, "facility_reconfiguration"},
  };
  CPE_REQUIRE_EQ(static_cast<std::uint32_t>(std::size(cases)), dccp::epoch::max_epoch_transition_reason);
  for (const ReasonCase& item : cases) {
    CPE_REQUIRE_EQ(static_cast<std::uint32_t>(item.reason), item.value);
    CPE_REQUIRE_EQ(dccp::epoch::epoch_transition_reason_token(item.reason), item.token);
    const Result<EpochTransitionReason> parsed = dccp::epoch::parse_epoch_transition_reason(item.token);
    CPE_REQUIRE_MSG(parsed.has_value(), "token '" + std::string(item.token) + "' did not parse back");
    CPE_REQUIRE_EQ(parsed.value(), item.reason);
    // Every value in the domain has a real token: "unknown" is the rendering of
    // a value outside the domain, never of a legal one.
    CPE_REQUIRE(dccp::epoch::epoch_transition_reason_token(item.reason) != std::string_view("unknown"));
  }

  // Unknown tokens are rejected instead of defaulting: an unrecognized reason
  // from a newer writer must not be recorded as "operator request".
  for (const std::string_view unknown :
       {std::string_view(), std::string_view("unknown"), std::string_view("GENESIS"),
        std::string_view("Genesis"), std::string_view("genesis "), std::string_view("genesis\n"),
        std::string_view("0"), std::string_view("6"), std::string_view("operator request")}) {
    const Result<EpochTransitionReason> parsed = dccp::epoch::parse_epoch_transition_reason(unknown);
    CPE_REQUIRE_MSG(!parsed.has_value(), "unknown reason token '" + std::string(unknown) + "' was accepted");
    CPE_REQUIRE_EQ(parsed.rejection().code(), ErrorCode::EnumOutOfDomain);
  }
  CPE_REQUIRE_EQ(rejection_code(dccp::epoch::parse_epoch_transition_reason("fencing")), ErrorCode::Ok);
}

CPE_TEST(epoch, transition_records_render_deterministically) {
  cpe_test::TestAuthority test_authority;
  const MutationAuthority root = test_authority.root_authority();
  CPE_REQUIRE_EQ(test_authority.authority().current_epoch().value(), std::uint64_t{1});

  const EpochTransitionRecord first =
      test_authority.advance(Epoch::initial(), root, EpochTransitionReason::OperatorRequest);
  CPE_REQUIRE(!first.is_origin());
  CPE_REQUIRE_EQ(first.sequence().value(), std::uint64_t{2});
  CPE_REQUIRE_EQ(first.base_epoch().value(), std::uint64_t{1});
  CPE_REQUIRE_EQ(first.new_epoch().value(), std::uint64_t{2});
  CPE_REQUIRE_EQ(first.reason(), EpochTransitionReason::OperatorRequest);
  CPE_REQUIRE_EQ(first.committed_by().to_string(), test_authority.root());
  CPE_REQUIRE(first.fenced_grant_count() >= 1);
  CPE_REQUIRE(first.controller_count() >= 1);
  CPE_REQUIRE(!first.record_digest().is_zero());
  // The transition is recorded under the epoch it creates, so a record can be
  // attributed to the generation it belongs to without inference.
  CPE_REQUIRE_EQ(first.provenance().recorded_epoch(), first.new_epoch());
  CPE_REQUIRE_EQ(test_authority.authority().current_epoch(), first.new_epoch());

  const auto ledger = test_authority.authority().history(dccp::epoch::HistoryQuery{});
  CPE_REQUIRE(ledger.has_value());
  const std::vector<EpochTransitionRecord>& records = ledger.value().records();
  CPE_REQUIRE_EQ(records.size(), std::size_t{2});
  CPE_REQUIRE_EQ(ledger.value().total_count(), std::uint64_t{2});
  CPE_REQUIRE_EQ(ledger.value().trimmed_count(), std::uint64_t{0});
  CPE_REQUIRE_EQ(ledger.value().first_retained_sequence(), std::uint64_t{1});

  // The genesis record has no predecessor: its base epoch is absent and its
  // previous digest is zero rather than a fabricated link.
  CPE_REQUIRE(records[0].is_origin());
  CPE_REQUIRE_EQ(records[0].sequence().value(), std::uint64_t{1});
  CPE_REQUIRE_EQ(records[0].base_epoch().value(), std::uint64_t{0});
  CPE_REQUIRE_EQ(records[0].new_epoch().value(), std::uint64_t{1});
  CPE_REQUIRE_EQ(records[0].reason(), EpochTransitionReason::Genesis);
  CPE_REQUIRE(records[0].previous_record_digest().is_zero());
  CPE_REQUIRE(!records[0].record_digest().is_zero());

  // The chain is what makes truncation, reordering, and substitution detectable.
  CPE_REQUIRE_EQ(records[1].previous_record_digest(), records[0].record_digest());
  CPE_REQUIRE_EQ(ledger.value().chain_head(), records[1].record_digest());

  // The record returned by the command is the record in the ledger, and
  // rendering is a pure function of the record.
  CPE_REQUIRE(records[1] == first);
  CPE_REQUIRE_EQ(records[1].to_string(), first.to_string());
  CPE_REQUIRE(first.to_string().find("base_epoch=1") != std::string::npos);
  CPE_REQUIRE(first.to_string().find("new_epoch=2") != std::string::npos);
  CPE_REQUIRE(first.to_string().find("reason=operator_request") != std::string::npos);
  CPE_REQUIRE(first.to_string().find("origin=no") != std::string::npos);
  CPE_REQUIRE(records[0].to_string().find("base_epoch=-") != std::string::npos);
  CPE_REQUIRE(records[0].to_string().find("origin=yes") != std::string::npos);

  // Reading the same ledger again renders identically: no per-call state, no
  // relative times, no addresses.
  const auto repeated = test_authority.authority().history(dccp::epoch::HistoryQuery{});
  CPE_REQUIRE(repeated.has_value());
  CPE_REQUIRE(repeated.value() == ledger.value());
  CPE_REQUIRE_EQ(repeated.value().records().size(), records.size());
  for (std::size_t index = 0; index < records.size(); ++index) {
    CPE_REQUIRE_EQ(repeated.value().records()[index].to_string(), records[index].to_string());
  }
}

CPE_TEST(epoch, advancement_rejects_an_unset_expected_epoch) {
  cpe_test::TestAuthority test_authority;
  const MutationAuthority root = test_authority.root_authority();

  // The expected epoch is a precondition, so an unset one is rejected before
  // the authoritative epoch is even compared.
  dccp::epoch::AdvanceEpochRequest request;
  request.expected_current = Epoch::from_trusted(0);
  request.authority = root;
  request.reason = EpochTransitionReason::OperatorRequest;
  request.provenance = cpe_test::provenance_input("operator");
  const auto rejected = test_authority.authority().advance_epoch(std::move(request));
  CPE_REQUIRE(!rejected.has_value());
  CPE_REQUIRE_EQ(rejected.rejection().code(), ErrorCode::EpochZero);
  CPE_REQUIRE_EQ(test_authority.authority().current_epoch().value(), std::uint64_t{1});
  CPE_REQUIRE_EQ(test_authority.authority().status().transition_count(), std::uint64_t{1});

  // The same request with the committed expectation is accepted, so the
  // rejection was about the precondition and nothing else.
  const EpochTransitionRecord committed =
      test_authority.advance(Epoch::initial(), root, EpochTransitionReason::FacilityReconfiguration);
  CPE_REQUIRE_EQ(committed.reason(), EpochTransitionReason::FacilityReconfiguration);
  CPE_REQUIRE_EQ(test_authority.authority().current_epoch().value(), std::uint64_t{2});
}
