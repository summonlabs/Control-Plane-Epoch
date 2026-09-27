// Control Plane Epoch 1.0.0 - Summon Software Labs
// Strongly typed identities, counters, and validated text.
//
// Every identity in this repository is a distinct C++ type. Two identities of
// different kinds never convert into one another, and no identity, counter, or
// external reference is ever represented by a bare integer or an untyped
// string inside the library. Comparison is byte-exact: no case folding,
// Unicode normalization, or trimming is ever applied to an identity.
#pragma once

#include <compare>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "control_plane_epoch/error.hpp"
#include "control_plane_epoch/limits.hpp"

namespace dccp::epoch {

// ---------------------------------------------------------------------------
// Text validation helpers
// ---------------------------------------------------------------------------

/// Strict UTF-8 validation: rejects overlong encodings, surrogate code points,
/// code points above U+10FFFF, and truncated sequences.
[[nodiscard]] bool is_valid_utf8(std::string_view text) noexcept;

/// Validates an ASCII identifier: 1..max_length bytes, first byte alphanumeric,
/// remaining bytes in [A-Za-z0-9._-]. Returns the validated text on success.
[[nodiscard]] Result<std::string> validate_identifier(std::string_view text, std::size_t max_length,
                                                      std::string_view what);

/// Validates free text: valid UTF-8, no control characters, 0..max_length bytes.
/// Returns the validated text on success.
[[nodiscard]] Result<std::string> validate_text(std::string_view text, std::size_t max_length,
                                                std::string_view what);

namespace detail {

/// Monotonic counter with a caller-chosen zero value meaning "absent". Used for
/// sequences, grant identifiers, incarnation numbers, and generations so that
/// these values can never be interchanged.
template <class Tag>
class Counter {
 public:
  Counter() noexcept = default;

  [[nodiscard]] static Result<Counter> from_value(std::uint64_t value, std::string_view what) {
    if (value == 0) {
      return Explanation(ErrorCode::InvalidArgument,
                         std::string(what) + " value 0 is not a committed value");
    }
    return Counter(value);
  }

  /// Constructs from a value that has already been validated by parse(),
  /// from_value(), successor(), or an integrity-checked durable image.
  [[nodiscard]] static Counter from_trusted(std::uint64_t value) noexcept { return Counter(value); }

  [[nodiscard]] std::uint64_t value() const noexcept { return value_; }
  [[nodiscard]] bool is_set() const noexcept { return value_ != 0; }

  [[nodiscard]] Result<Counter> successor() const {
    if (value_ == 0) {
      return Explanation(ErrorCode::InvalidArgument, "successor of an absent counter");
    }
    if (value_ == UINT64_MAX) {
      return Explanation(ErrorCode::CounterExhausted, "counter is at its maximum value");
    }
    return Counter(value_ + 1);
  }

  [[nodiscard]] std::string to_string() const { return std::to_string(value_); }

  friend bool operator==(const Counter& lhs, const Counter& rhs) noexcept { return lhs.value_ == rhs.value_; }
  friend bool operator!=(const Counter& lhs, const Counter& rhs) noexcept { return !(lhs == rhs); }
  friend std::strong_ordering operator<=>(const Counter& lhs, const Counter& rhs) noexcept {
    return lhs.value_ <=> rhs.value_;
  }

 private:
  explicit Counter(std::uint64_t value) noexcept : value_(value) {}

  std::uint64_t value_ = 0;
};

template <class Tag, std::size_t MaxLength>
class Identifier {
 public:
  Identifier() = default;

  [[nodiscard]] static Result<Identifier> parse(std::string_view text, std::string_view what) {
    Result<std::string> validated = validate_identifier(text, MaxLength, what);
    if (!validated.has_value()) {
      return validated.rejection();
    }
    return Identifier(validated.move_value());
  }

  /// Constructs from a value already validated by parse() or read from an
  /// integrity-checked durable image. Never call this on external input.
  [[nodiscard]] static Identifier from_trusted(std::string text) noexcept { return Identifier(std::move(text)); }

  [[nodiscard]] bool empty() const noexcept { return text_.empty(); }
  [[nodiscard]] const std::string& str() const noexcept { return text_; }
  [[nodiscard]] std::string_view view() const noexcept { return text_; }
  [[nodiscard]] std::size_t size() const noexcept { return text_.size(); }
  [[nodiscard]] std::string to_string() const { return text_; }

  friend bool operator==(const Identifier& lhs, const Identifier& rhs) noexcept { return lhs.text_ == rhs.text_; }
  friend bool operator!=(const Identifier& lhs, const Identifier& rhs) noexcept { return !(lhs == rhs); }
  friend std::strong_ordering operator<=>(const Identifier& lhs, const Identifier& rhs) noexcept {
    return lhs.text_ <=> rhs.text_;
  }

 private:
  explicit Identifier(std::string text) noexcept : text_(std::move(text)) {}

  std::string text_;
};

struct FacilityAuthorityDomainIdTag;
struct ControllerIdTag;
struct ScopeNameTag;
struct ProvenanceSourceIdTag;
struct GrantIdTag;
struct TransitionSequenceTag;
struct RevocationSequenceTag;
struct RegistrationSequenceTag;
struct IncarnationNumberTag;
struct DurableGenerationTag;
struct DomainInstanceNumberTag;
struct OperationSequenceTag;

}  // namespace detail

// ---------------------------------------------------------------------------
// Stable identities
// ---------------------------------------------------------------------------

/// Stable identity of one facility authority domain. A facility may run more
/// than one independent authority domain (for example one per control-plane
/// trust boundary); epochs are monotonic within exactly one domain.
using FacilityAuthorityDomainId = detail::Identifier<detail::FacilityAuthorityDomainIdTag, max_identifier_length>;

/// Stable identity of a DCCP controller. Stable across controller restarts.
using ControllerId = detail::Identifier<detail::ControllerIdTag, max_identifier_length>;

/// Name of an authority scope declared by an authority domain.
using ScopeName = detail::Identifier<detail::ScopeNameTag, max_identifier_length>;

/// Identity of the human or automated source that produced a state change.
using ProvenanceSourceId = detail::Identifier<detail::ProvenanceSourceIdTag, max_identifier_length>;

// ---------------------------------------------------------------------------
// Monotonic counters
// ---------------------------------------------------------------------------

/// Identifier of one durable authority grant. Never reused within a domain.
using GrantId = detail::Counter<detail::GrantIdTag>;

/// Position of an epoch transition in the domain's transition ledger.
using TransitionSequence = detail::Counter<detail::TransitionSequenceTag>;

/// Position of a revocation in the domain's revocation ledger.
using RevocationSequence = detail::Counter<detail::RevocationSequenceTag>;

/// Position of a controller registration in the domain's registration ledger.
using RegistrationSequence = detail::Counter<detail::RegistrationSequenceTag>;

/// One controller boot. Strictly increases for each controller, so a restarted
/// controller can never present the identity of a previous boot.
using IncarnationNumber = detail::Counter<detail::IncarnationNumberTag>;

/// Counts durable commits published by the authority store. Every commit
/// increments it, including commits that do not change the epoch.
using DurableGeneration = detail::Counter<detail::DurableGenerationTag>;

/// Counts initializations of the durable store, including recovery
/// reinitializations. Distinguishes "same domain state" from "same domain id,
/// new durable instance".
using DomainInstanceNumber = detail::Counter<detail::DomainInstanceNumberTag>;

/// Client-chosen sequence of a retryable mutation within one controller boot.
using OperationSequence = detail::Counter<detail::OperationSequenceTag>;

// ---------------------------------------------------------------------------
// Untrusted external references
// ---------------------------------------------------------------------------

/// Opaque reference to an object owned by another DCCP layer (for example an
/// ASI accelerator object or a DFI topology object). This repository stores the
/// reference and never interprets it.
class ExternalRef {
 public:
  ExternalRef() = default;

  [[nodiscard]] static Result<ExternalRef> parse(std::string_view kind, std::string_view value);
  [[nodiscard]] static ExternalRef from_trusted(std::string kind, std::string value) noexcept {
    return ExternalRef(std::move(kind), std::move(value));
  }

  [[nodiscard]] bool empty() const noexcept { return kind_.empty() && value_.empty(); }
  [[nodiscard]] const std::string& kind() const noexcept { return kind_; }
  [[nodiscard]] const std::string& value() const noexcept { return value_; }

  /// "kind:value"; ':' cannot appear in either part.
  [[nodiscard]] std::string to_string() const { return kind_ + ":" + value_; }

  friend bool operator==(const ExternalRef& lhs, const ExternalRef& rhs) noexcept {
    return lhs.kind_ == rhs.kind_ && lhs.value_ == rhs.value_;
  }
  friend bool operator!=(const ExternalRef& lhs, const ExternalRef& rhs) noexcept { return !(lhs == rhs); }
  friend std::strong_ordering operator<=>(const ExternalRef& lhs, const ExternalRef& rhs) noexcept {
    if (const auto cmp = lhs.kind_ <=> rhs.kind_; cmp != 0) {
      return cmp;
    }
    return lhs.value_ <=> rhs.value_;
  }

 private:
  ExternalRef(std::string kind, std::string value) noexcept : kind_(std::move(kind)), value_(std::move(value)) {}

  std::string kind_;
  std::string value_;
};

}  // namespace dccp::epoch
