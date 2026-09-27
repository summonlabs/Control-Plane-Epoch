// Control Plane Epoch 1.0.0 - Summon Software Labs
// Provenance validation and rendering.
#include "control_plane_epoch/provenance.hpp"

#include <array>

#include "format.hpp"

namespace dccp::epoch {
namespace {

struct KindToken {
  ProvenanceSourceKind kind;
  std::string_view token;
};

constexpr std::array<KindToken, 5> kKindTokens{{
    {ProvenanceSourceKind::Initialization, "initialization"},
    {ProvenanceSourceKind::Controller, "controller"},
    {ProvenanceSourceKind::Operator, "operator"},
    {ProvenanceSourceKind::Recovery, "recovery"},
    {ProvenanceSourceKind::Import, "import"},
}};

}  // namespace

std::string_view provenance_source_kind_token(ProvenanceSourceKind kind) noexcept {
  for (const KindToken& entry : kKindTokens) {
    if (entry.kind == kind) {
      return entry.token;
    }
  }
  return "unknown";
}

Result<ProvenanceSourceKind> parse_provenance_source_kind(std::string_view token) {
  for (const KindToken& entry : kKindTokens) {
    if (entry.token == token) {
      return entry.kind;
    }
  }
  return Explanation(ErrorCode::EnumOutOfDomain, "unknown provenance source kind " + std::string(token));
}

ProvenanceSourceKind ProvenanceInput::kind() const {
  if (!kind_.has_value()) {
    throw EpochError(ErrorCode::InvalidArgument, "the provenance input carries no source kind");
  }
  return *kind_;
}

Result<ProvenanceInput> ProvenanceInput::create(ProvenanceSourceKind kind, ProvenanceSourceId source,                                                std::optional<ExternalRef> external, std::string_view note) {
  if (source.empty()) {
    return Explanation(ErrorCode::IdentifierEmpty, "provenance source is empty");
  }
  Result<std::string> validated_note = validate_text(note, max_note_length, "provenance note");
  if (!validated_note.has_value()) {
    return validated_note.rejection();
  }

  ProvenanceInput input;
  input.kind_ = kind;
  input.source_ = std::move(source);
  input.external_ = std::move(external);
  input.note_ = validated_note.move_value();
  return input;
}

Result<ProvenanceInput> ProvenanceInput::from_source(ProvenanceSourceKind kind, std::string_view source) {
  Result<ProvenanceSourceId> parsed = ProvenanceSourceId::parse(source, "provenance source");
  if (!parsed.has_value()) {
    return parsed.rejection();
  }
  return ProvenanceInput::create(kind, parsed.move_value(), std::nullopt, std::string_view{});
}

std::string ProvenanceInput::to_string() const {
  std::string text;
  detail::append_field(text, "provenance_kind",
                       kind_.has_value() ? provenance_source_kind_token(*kind_) : std::string_view{"-"});
  detail::append_field(text, "provenance_source", source_.view());
  detail::append_field(text, "provenance_external",
                       detail::or_dash(external_.has_value() ? external_->to_string() : std::string{}));
  detail::append_field(text, "provenance_note", detail::or_dash(note_));
  return text;
}

std::string ProvenanceRecord::to_string() const {
  std::string text;
  detail::append_field(text, "provenance_kind", provenance_source_kind_token(kind_));
  detail::append_field(text, "provenance_source", source_.view());
  detail::append_field(text, "provenance_external",
                       detail::or_dash(external_.has_value() ? external_->to_string() : std::string{}));
  detail::append_field(text, "provenance_note", detail::or_dash(note_));
  detail::append_field(text, "recorded_epoch", recorded_epoch_.to_string());
  detail::append_field(text, "recorded_sequence", std::to_string(recorded_sequence_));
  detail::append_field(text, "provenance_digest", record_digest_.to_hex());
  return text;
}

}  // namespace dccp::epoch
