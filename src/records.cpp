// Control Plane Epoch 1.0.0 - Summon Software Labs
// Record digests, canonical record encoding, and the record factory.
#include "records.hpp"

#include <algorithm>

namespace dccp::epoch::detail {
namespace {

constexpr std::string_view kProvenanceDigestTag = "cpe.record.provenance.v1";
constexpr std::string_view kControllerDigestTag = "cpe.record.controller.v1";
constexpr std::string_view kGrantDigestTag = "cpe.record.grant.v1";
constexpr std::string_view kRevocationDigestTag = "cpe.record.revocation.v1";
constexpr std::string_view kTransitionDigestTag = "cpe.record.transition.v1";

/// Upper bound for any single text field inside a durable image.
constexpr std::string_view kMissingDigestDetail = "record digest is absent";

void hash_optional_u64(Sha256& hasher, const std::optional<std::uint64_t>& value) {
  hash_bool(hasher, value.has_value());
  if (value.has_value()) {
    hash_u64(hasher, *value);
  }
}

void hash_optional_external(Sha256& hasher, const std::optional<ExternalRef>& value) {
  hash_bool(hasher, value.has_value());
  if (value.has_value()) {
    hash_text(hasher, value->kind());
    hash_text(hasher, value->value());
  }
}

[[nodiscard]] ControllerId read_controller(CanonicalReader& reader, std::string_view what) {
  const std::string text = reader.text();
  Result<ControllerId> parsed = ControllerId::parse(text, what);
  if (!parsed.has_value()) {
    throw EpochError(parsed.rejection());
  }
  return parsed.move_value();
}

[[nodiscard]] ScopeName read_scope(CanonicalReader& reader, std::string_view what) {
  const std::string text = reader.text();
  Result<ScopeName> parsed = ScopeName::parse(text, what);
  if (!parsed.has_value()) {
    throw EpochError(parsed.rejection());
  }
  return parsed.move_value();
}

[[nodiscard]] ProvenanceSourceId read_provenance_source(CanonicalReader& reader) {
  const std::string text = reader.text();
  Result<ProvenanceSourceId> parsed = ProvenanceSourceId::parse(text, "provenance source");
  if (!parsed.has_value()) {
    throw EpochError(parsed.rejection());
  }
  return parsed.move_value();
}

[[nodiscard]] std::uint64_t read_u64_at_least_one(CanonicalReader& reader, std::string_view what) {
  const std::uint64_t value = reader.u64();
  if (value == 0) {
    throw EpochError(ErrorCode::EnumOutOfDomain, std::string(what) + " is zero");
  }
  return value;
}

[[nodiscard]] std::uint32_t read_enum(CanonicalReader& reader, std::uint32_t maximum, std::string_view what) {
  const std::uint32_t value = reader.u32();
  if (value == 0 || value > maximum) {
    throw EpochError(ErrorCode::EnumOutOfDomain, std::string(what) + " value " + std::to_string(value) +
                                                     " is outside its domain");
  }
  return value;
}

[[nodiscard]] IncarnationState read_incarnation_state(CanonicalReader& reader) {
  return static_cast<IncarnationState>(read_enum(reader, max_incarnation_state, "incarnation state"));
}

[[nodiscard]] AuthorityClass read_authority_class(CanonicalReader& reader) {
  return static_cast<AuthorityClass>(read_enum(reader, max_authority_class, "authority class"));
}

[[nodiscard]] GrantState read_grant_state(CanonicalReader& reader) {
  return static_cast<GrantState>(read_enum(reader, max_grant_state, "grant state"));
}

[[nodiscard]] RevocationTargetKind read_target_kind(CanonicalReader& reader) {
  return static_cast<RevocationTargetKind>(read_enum(reader, max_revocation_target_kind, "revocation target kind"));
}

[[nodiscard]] RevocationReason read_revocation_reason(CanonicalReader& reader) {
  return static_cast<RevocationReason>(read_enum(reader, max_revocation_reason, "revocation reason"));
}

[[nodiscard]] EpochTransitionReason read_transition_reason(CanonicalReader& reader) {
  return static_cast<EpochTransitionReason>(
      read_enum(reader, max_epoch_transition_reason, "epoch transition reason"));
}

[[nodiscard]] ProvenanceSourceKind read_provenance_kind(CanonicalReader& reader) {
  return static_cast<ProvenanceSourceKind>(read_enum(reader, max_provenance_source_kind, "provenance source kind"));
}

}  // namespace

// ---------------------------------------------------------------------------
// Digests
// ---------------------------------------------------------------------------

Sha256Digest compute_provenance_digest(const ProvenanceData& data) {
  Sha256 hasher;
  hash_text(hasher, kProvenanceDigestTag);
  hash_u32(hasher, static_cast<std::uint32_t>(data.kind));
  hash_text(hasher, data.source);
  hash_optional_external(hasher, data.external);
  hash_text(hasher, data.note);
  hash_u64(hasher, data.recorded_epoch);
  hash_u64(hasher, data.recorded_sequence);
  return hasher.finish();
}

Sha256Digest compute_controller_digest(const ControllerData& data) {
  Sha256 hasher;
  hash_text(hasher, kControllerDigestTag);
  hash_text(hasher, data.controller);
  hash_u64(hasher, data.incarnation_number);
  hash_digest(hasher, data.incarnation_id);
  hash_u32(hasher, static_cast<std::uint32_t>(data.incarnation_state));
  hash_u64(hasher, data.registration_count);
  hash_u64(hasher, data.first_registered_epoch);
  hash_u64(hasher, data.latest_registered_epoch);
  hash_optional_u64(hasher, data.revocation_through_incarnation);
  hash_u32(hasher, static_cast<std::uint32_t>(data.superseded_incarnations.size()));
  for (const Sha256Digest& digest : data.superseded_incarnations) {
    hash_digest(hasher, digest);
  }
  hash_digest(hasher, compute_provenance_digest(data.latest_registration_provenance));
  return hasher.finish();
}

Sha256Digest compute_grant_digest(const GrantData& data) {
  Sha256 hasher;
  hash_text(hasher, kGrantDigestTag);
  hash_u64(hasher, data.id);
  hash_u32(hasher, static_cast<std::uint32_t>(data.authority_class));
  hash_u64(hasher, data.epoch);
  hash_text(hasher, data.controller);
  hash_u64(hasher, data.incarnation_number);
  hash_digest(hasher, data.incarnation_id);
  hash_u32(hasher, static_cast<std::uint32_t>(data.scopes.size()));
  for (const std::string& scope : data.scopes) {
    hash_text(hasher, scope);
  }
  hash_u64(hasher, data.sequence);
  hash_u32(hasher, static_cast<std::uint32_t>(data.state));
  hash_optional_u64(hasher, data.revoked_by_sequence);
  hash_digest(hasher, compute_provenance_digest(data.provenance));
  return hasher.finish();
}

Sha256Digest compute_revocation_digest(const RevocationData& data) {
  Sha256 hasher;
  hash_text(hasher, kRevocationDigestTag);
  hash_u64(hasher, data.sequence);
  hash_u32(hasher, static_cast<std::uint32_t>(data.target_kind));
  hash_text(hasher, data.controller);
  hash_optional_u64(hasher, data.through_incarnation);
  hash_optional_u64(hasher, data.grant);
  hash_u32(hasher, static_cast<std::uint32_t>(data.reason));
  hash_u64(hasher, data.epoch);
  hash_text(hasher, data.issued_by);
  hash_digest(hasher, data.issued_by_incarnation);
  hash_u64(hasher, data.issued_by_grant);
  hash_u64(hasher, data.fenced_grant_count);
  hash_bool(hasher, data.replayed);
  hash_digest(hasher, compute_provenance_digest(data.provenance));
  hash_digest(hasher, data.previous_record_digest);
  return hasher.finish();
}

Sha256Digest compute_transition_digest(const TransitionData& data) {
  Sha256 hasher;
  hash_text(hasher, kTransitionDigestTag);
  hash_u64(hasher, data.sequence);
  hash_bool(hasher, data.origin);
  hash_u64(hasher, data.base_epoch);
  hash_u64(hasher, data.new_epoch);
  hash_u32(hasher, static_cast<std::uint32_t>(data.reason));
  hash_text(hasher, data.committed_by);
  hash_digest(hasher, data.committed_by_incarnation);
  hash_u64(hasher, data.committed_by_grant);
  hash_u64(hasher, data.fenced_grant_count);
  hash_u64(hasher, data.controller_count);
  hash_digest(hasher, compute_provenance_digest(data.provenance));
  hash_digest(hasher, data.previous_record_digest);
  return hasher.finish();
}

void verify_record_digest(const ProvenanceData& data, std::string_view what) {
  if (data.record_digest.is_zero()) {
    throw EpochError(ErrorCode::DigestMismatch, std::string(what) + " provenance " + std::string(kMissingDigestDetail));
  }
  if (compute_provenance_digest(data) != data.record_digest) {
    throw EpochError(ErrorCode::DigestMismatch, std::string(what) + " provenance digest does not match its content");
  }
}

void verify_record_digest(const ControllerData& data, std::string_view what) {
  if (data.record_digest.is_zero()) {
    throw EpochError(ErrorCode::DigestMismatch,
                     std::string(what) + " controller " + data.controller + " " + std::string(kMissingDigestDetail));
  }
  if (compute_controller_digest(data) != data.record_digest) {
    throw EpochError(ErrorCode::DigestMismatch,
                     std::string(what) + " controller " + data.controller + " record digest does not match its content");
  }
}

void verify_record_digest(const GrantData& data, std::string_view what) {
  if (data.record_digest.is_zero()) {
    throw EpochError(ErrorCode::DigestMismatch, std::string(what) + " grant " + std::to_string(data.id) + " " +
                                                     std::string(kMissingDigestDetail));
  }
  if (compute_grant_digest(data) != data.record_digest) {
    throw EpochError(ErrorCode::DigestMismatch, std::string(what) + " grant " + std::to_string(data.id) +
                                                     " record digest does not match its content");
  }
}

void verify_record_digest(const RevocationData& data, std::string_view what) {
  if (data.record_digest.is_zero()) {
    throw EpochError(ErrorCode::DigestMismatch, std::string(what) + " revocation " +
                                                     std::to_string(data.sequence) + " " +
                                                     std::string(kMissingDigestDetail));
  }
  if (compute_revocation_digest(data) != data.record_digest) {
    throw EpochError(ErrorCode::DigestMismatch, std::string(what) + " revocation " + std::to_string(data.sequence) +
                                                     " record digest does not match its content");
  }
}

void verify_record_digest(const TransitionData& data, std::string_view what) {
  if (data.record_digest.is_zero()) {
    throw EpochError(ErrorCode::DigestMismatch, std::string(what) + " transition " +
                                                     std::to_string(data.sequence) + " " +
                                                     std::string(kMissingDigestDetail));
  }
  if (compute_transition_digest(data) != data.record_digest) {
    throw EpochError(ErrorCode::DigestMismatch, std::string(what) + " transition " + std::to_string(data.sequence) +
                                                     " record digest does not match its content");
  }
}

// ---------------------------------------------------------------------------
// Canonical record encoding
// ---------------------------------------------------------------------------

void encode_provenance(CanonicalWriter& writer, const ProvenanceData& data) {
  writer.u32(static_cast<std::uint32_t>(data.kind));
  writer.text(data.source);
  writer.boolean(data.external.has_value());
  if (data.external.has_value()) {
    writer.text(data.external->kind());
    writer.text(data.external->value());
  }
  writer.text(data.note);
  writer.u64(data.recorded_epoch);
  writer.u64(data.recorded_sequence);
  writer.digest(data.record_digest);
}

ProvenanceData decode_provenance(CanonicalReader& reader) {
  ProvenanceData data;
  data.kind = read_provenance_kind(reader);
  data.source = read_provenance_source(reader).str();
  if (reader.boolean()) {
    const std::string kind = reader.text();
    const std::string value = reader.text();
    Result<ExternalRef> external = ExternalRef::parse(kind, value);
    if (!external.has_value()) {
      throw EpochError(external.rejection());
    }
    data.external = external.move_value();
  }
  data.note = reader.text();
  if (!is_valid_utf8(data.note)) {
    throw EpochError(ErrorCode::TextInvalidUtf8, "provenance note is not valid UTF-8");
  }
  data.recorded_epoch = read_u64_at_least_one(reader, "provenance recorded epoch");
  data.recorded_sequence = read_u64_at_least_one(reader, "provenance recorded sequence");
  data.record_digest = reader.digest();
  return data;
}

void encode_controller(CanonicalWriter& writer, const ControllerData& data) {
  writer.text(data.controller);
  writer.u64(data.incarnation_number);
  writer.digest(data.incarnation_id);
  writer.u32(static_cast<std::uint32_t>(data.incarnation_state));
  writer.u64(data.registration_count);
  writer.u64(data.first_registered_epoch);
  writer.u64(data.latest_registered_epoch);
  writer.boolean(data.revocation_through_incarnation.has_value());
  if (data.revocation_through_incarnation.has_value()) {
    writer.u64(*data.revocation_through_incarnation);
  }
  writer.u32(static_cast<std::uint32_t>(data.superseded_incarnations.size()));
  for (const Sha256Digest& digest : data.superseded_incarnations) {
    writer.digest(digest);
  }
  encode_provenance(writer, data.latest_registration_provenance);
  writer.digest(data.record_digest);
}

ControllerData decode_controller(CanonicalReader& reader) {
  ControllerData data;
  data.controller = read_controller(reader, "controller").str();
  data.incarnation_number = read_u64_at_least_one(reader, "controller incarnation number");
  data.incarnation_id = reader.digest();
  if (data.incarnation_id.is_zero()) {
    throw EpochError(ErrorCode::EnumOutOfDomain, "controller incarnation identity is the zero digest");
  }
  data.incarnation_state = read_incarnation_state(reader);
  data.registration_count = read_u64_at_least_one(reader, "controller registration count");
  data.first_registered_epoch = read_u64_at_least_one(reader, "controller first epoch");
  data.latest_registered_epoch = read_u64_at_least_one(reader, "controller latest epoch");
  if (reader.boolean()) {
    data.revocation_through_incarnation = read_u64_at_least_one(reader, "controller revocation fence");
  }
  const std::uint32_t superseded_count = reader.u32();
  if (superseded_count > max_superseded_incarnations) {
    throw EpochError(ErrorCode::IntegrityLimitExceeded, "superseded incarnation list exceeds its bound");
  }
  data.superseded_incarnations.reserve(superseded_count);
  for (std::uint32_t index = 0; index < superseded_count; ++index) {
    const Sha256Digest digest = reader.digest();
    if (digest.is_zero()) {
      throw EpochError(ErrorCode::EnumOutOfDomain, "superseded incarnation identity is the zero digest");
    }
    data.superseded_incarnations.push_back(digest);
  }
  data.latest_registration_provenance = decode_provenance(reader);
  data.record_digest = reader.digest();
  return data;
}

void encode_grant(CanonicalWriter& writer, const GrantData& data) {
  writer.u64(data.id);
  writer.u32(static_cast<std::uint32_t>(data.authority_class));
  writer.u64(data.epoch);
  writer.text(data.controller);
  writer.u64(data.incarnation_number);
  writer.digest(data.incarnation_id);
  writer.u32(static_cast<std::uint32_t>(data.scopes.size()));
  for (const std::string& scope : data.scopes) {
    writer.text(scope);
  }
  writer.u64(data.sequence);
  writer.u32(static_cast<std::uint32_t>(data.state));
  writer.boolean(data.revoked_by_sequence.has_value());
  if (data.revoked_by_sequence.has_value()) {
    writer.u64(*data.revoked_by_sequence);
  }
  encode_provenance(writer, data.provenance);
  writer.digest(data.record_digest);
}

GrantData decode_grant(CanonicalReader& reader) {
  GrantData data;
  data.id = read_u64_at_least_one(reader, "grant identifier");
  data.authority_class = read_authority_class(reader);
  data.epoch = read_u64_at_least_one(reader, "grant epoch");
  data.controller = read_controller(reader, "grant controller").str();
  data.incarnation_number = read_u64_at_least_one(reader, "grant incarnation number");
  data.incarnation_id = reader.digest();
  if (data.incarnation_id.is_zero()) {
    throw EpochError(ErrorCode::EnumOutOfDomain, "grant incarnation identity is the zero digest");
  }
  const std::uint32_t scope_count = reader.u32();
  if (scope_count > max_scopes_per_authority) {
    throw EpochError(ErrorCode::IntegrityLimitExceeded, "grant scope list exceeds its bound");
  }
  data.scopes.reserve(scope_count);
  std::string previous_scope;
  for (std::uint32_t index = 0; index < scope_count; ++index) {
    const ScopeName scope = read_scope(reader, "grant scope");
    if (index > 0 && !(previous_scope < scope.str())) {
      throw EpochError(ErrorCode::OrderingViolation, "grant scopes are not in canonical ascending order");
    }
    previous_scope = scope.str();
    data.scopes.push_back(scope.str());
  }
  data.sequence = read_u64_at_least_one(reader, "grant sequence");
  data.state = read_grant_state(reader);
  if (reader.boolean()) {
    data.revoked_by_sequence = read_u64_at_least_one(reader, "grant revocation sequence");
  }
  if (data.state == GrantState::Revoked && !data.revoked_by_sequence.has_value()) {
    throw EpochError(ErrorCode::CountMismatch, "a revoked grant must name its revocation sequence");
  }
  if (data.state != GrantState::Revoked && data.revoked_by_sequence.has_value()) {
    throw EpochError(ErrorCode::CountMismatch, "only a revoked grant may name a revocation sequence");
  }
  data.provenance = decode_provenance(reader);
  data.record_digest = reader.digest();
  return data;
}

void encode_revocation(CanonicalWriter& writer, const RevocationData& data) {
  writer.u64(data.sequence);
  writer.u32(static_cast<std::uint32_t>(data.target_kind));
  writer.text(data.controller);
  writer.boolean(data.through_incarnation.has_value());
  if (data.through_incarnation.has_value()) {
    writer.u64(*data.through_incarnation);
  }
  writer.boolean(data.grant.has_value());
  if (data.grant.has_value()) {
    writer.u64(*data.grant);
  }
  writer.u32(static_cast<std::uint32_t>(data.reason));
  writer.u64(data.epoch);
  writer.text(data.issued_by);
  writer.digest(data.issued_by_incarnation);
  writer.u64(data.issued_by_grant);
  writer.u64(data.fenced_grant_count);
  writer.boolean(data.replayed);
  encode_provenance(writer, data.provenance);
  writer.digest(data.previous_record_digest);
  writer.digest(data.record_digest);
}

RevocationData decode_revocation(CanonicalReader& reader) {
  RevocationData data;
  data.sequence = read_u64_at_least_one(reader, "revocation sequence");
  data.target_kind = read_target_kind(reader);
  data.controller = read_controller(reader, "revocation controller").str();
  if (reader.boolean()) {
    data.through_incarnation = read_u64_at_least_one(reader, "revocation incarnation fence");
  }
  if (reader.boolean()) {
    data.grant = read_u64_at_least_one(reader, "revoked grant identifier");
  }
  if (data.target_kind == RevocationTargetKind::Grant) {
    if (!data.grant.has_value() || data.through_incarnation.has_value()) {
      throw EpochError(ErrorCode::CountMismatch, "a grant revocation names exactly one grant");
    }
  } else if (data.grant.has_value()) {
    throw EpochError(ErrorCode::CountMismatch, "a controller revocation must not name a grant");
  }
  data.reason = read_revocation_reason(reader);
  data.epoch = read_u64_at_least_one(reader, "revocation epoch");
  data.issued_by = read_controller(reader, "revocation issuer").str();
  data.issued_by_incarnation = reader.digest();
  data.issued_by_grant = read_u64_at_least_one(reader, "revocation issuer grant");
  data.fenced_grant_count = reader.u64();
  data.replayed = reader.boolean();
  data.provenance = decode_provenance(reader);
  data.previous_record_digest = reader.digest();
  data.record_digest = reader.digest();
  return data;
}

void encode_transition(CanonicalWriter& writer, const TransitionData& data) {
  writer.u64(data.sequence);
  writer.boolean(data.origin);
  writer.u64(data.base_epoch);
  writer.u64(data.new_epoch);
  writer.u32(static_cast<std::uint32_t>(data.reason));
  writer.text(data.committed_by);
  writer.digest(data.committed_by_incarnation);
  writer.u64(data.committed_by_grant);
  writer.u64(data.fenced_grant_count);
  writer.u64(data.controller_count);
  encode_provenance(writer, data.provenance);
  writer.digest(data.previous_record_digest);
  writer.digest(data.record_digest);
}

TransitionData decode_transition(CanonicalReader& reader) {
  TransitionData data;
  data.sequence = read_u64_at_least_one(reader, "transition sequence");
  data.origin = reader.boolean();
  data.base_epoch = reader.u64();
  data.new_epoch = read_u64_at_least_one(reader, "transition new epoch");
  if (data.origin) {
    if (data.base_epoch != 0) {
      throw EpochError(ErrorCode::CountMismatch, "an origin transition must not name a base epoch");
    }
  } else if (data.base_epoch == 0) {
    throw EpochError(ErrorCode::CountMismatch, "a non-origin transition must name its base epoch");
  }
  data.reason = read_transition_reason(reader);
  data.committed_by = read_controller(reader, "transition controller").str();
  data.committed_by_incarnation = reader.digest();
  data.committed_by_grant = read_u64_at_least_one(reader, "transition grant");
  data.fenced_grant_count = reader.u64();
  data.controller_count = reader.u64();
  data.provenance = decode_provenance(reader);
  data.previous_record_digest = reader.digest();
  data.record_digest = reader.digest();
  return data;
}

// ---------------------------------------------------------------------------
// Public results as durable data
// ---------------------------------------------------------------------------

void encode_registration(CanonicalWriter& writer, const ControllerRegistration& record) {
  writer.text(record.controller().str());
  writer.u64(record.incarnation_number().value());
  writer.digest(record.incarnation_id().digest());
  writer.u64(record.epoch().value());
  writer.u64(record.sequence().value());
  encode_provenance(writer, to_data(record.provenance()));
}

ControllerRegistration decode_registration(CanonicalReader& reader, bool replayed) {
  ControllerData controller;
  controller.controller = read_controller(reader, "registration controller").str();
  controller.incarnation_number = read_u64_at_least_one(reader, "registration incarnation number");
  controller.incarnation_id = reader.digest();
  if (controller.incarnation_id.is_zero()) {
    throw EpochError(ErrorCode::EnumOutOfDomain, "registration incarnation identity is the zero digest");
  }
  const std::uint64_t epoch = read_u64_at_least_one(reader, "registration epoch");
  const std::uint64_t sequence = read_u64_at_least_one(reader, "registration sequence");
  ProvenanceData provenance = decode_provenance(reader);
  verify_record_digest(provenance, "registration result");
  if (provenance.recorded_epoch != epoch || provenance.recorded_sequence != sequence) {
    throw EpochError(ErrorCode::CountMismatch,
                     "registration result provenance does not match its epoch and sequence");
  }
  ControllerRegistration record = RecordFactory::make_registration(controller, provenance);
  if (replayed) {
    record = RecordFactory::mark_replayed(record);
  }
  return record;
}

ProvenanceData to_data(const ProvenanceRecord& record) {
  ProvenanceData data;
  data.kind = record.kind();
  data.source = record.source().str();
  data.external = record.external();
  data.note = record.note();
  data.recorded_epoch = record.recorded_epoch().value();
  data.recorded_sequence = record.recorded_sequence();
  data.record_digest = record.record_digest();
  return data;
}

ProvenanceData to_data(const ProvenanceInput& input, std::uint64_t epoch, std::uint64_t sequence) {
  ProvenanceData data;
  data.kind = input.kind();
  data.source = input.source().str();
  data.external = input.external();
  data.note = input.note();
  data.recorded_epoch = epoch;
  data.recorded_sequence = sequence;
  data.record_digest = compute_provenance_digest(data);
  return data;
}

ControllerData to_data(const ControllerRecord& record) {
  ControllerData data;
  data.controller = record.controller().str();
  data.incarnation_number = record.incarnation_number().value();
  data.incarnation_id = record.incarnation_id().digest();
  data.incarnation_state = record.incarnation_state();
  data.registration_count = record.registration_count();
  data.first_registered_epoch = record.first_registered_epoch().value();
  data.latest_registered_epoch = record.latest_registered_epoch().value();
  if (record.revocation_through_incarnation().has_value()) {
    data.revocation_through_incarnation = record.revocation_through_incarnation()->value();
  }
  data.latest_registration_provenance = to_data(record.latest_registration_provenance());
  data.record_digest = record.record_digest();
  return data;
}

GrantData to_data(const AuthorityGrantRecord& record) {
  GrantData data;
  data.id = record.id().value();
  data.authority_class = record.authority_class();
  data.epoch = record.epoch().value();
  data.controller = record.controller().str();
  data.incarnation_number = record.incarnation_number().value();
  data.incarnation_id = record.incarnation().digest();
  for (const ScopeName& scope : record.scopes().scopes()) {
    data.scopes.push_back(scope.str());
  }
  data.sequence = record.sequence();
  if (record.revoked_by_sequence().has_value()) {
    data.state = GrantState::Revoked;
    data.revoked_by_sequence = record.revoked_by_sequence()->value();
  }
  data.provenance = to_data(record.provenance());
  data.record_digest = record.record_digest();
  return data;
}

RevocationData to_data(const RevocationRecord& record) {
  RevocationData data;
  data.sequence = record.sequence().value();
  data.target_kind = record.target_kind();
  data.controller = record.controller().str();
  if (record.through_incarnation().has_value()) {
    data.through_incarnation = record.through_incarnation()->value();
  }
  if (record.grant().has_value()) {
    data.grant = record.grant()->value();
  }
  data.reason = record.reason();
  data.epoch = record.epoch().value();
  data.issued_by = record.issued_by().str();
  data.issued_by_incarnation = record.issued_by_incarnation().digest();
  data.issued_by_grant = record.issued_by_grant().value();
  data.fenced_grant_count = record.fenced_grant_count();
  data.replayed = record.replayed();
  data.provenance = to_data(record.provenance());
  data.previous_record_digest = record.previous_record_digest();
  data.record_digest = record.record_digest();
  return data;
}

TransitionData to_data(const EpochTransitionRecord& record) {
  TransitionData data;
  data.sequence = record.sequence().value();
  data.origin = record.is_origin();
  data.base_epoch = record.base_epoch().value();
  data.new_epoch = record.new_epoch().value();
  data.reason = record.reason();
  data.committed_by = record.committed_by().str();
  data.committed_by_incarnation = record.committed_by_incarnation().digest();
  data.committed_by_grant = record.committed_by_grant().value();
  data.fenced_grant_count = record.fenced_grant_count();
  data.controller_count = record.controller_count();
  data.provenance = to_data(record.provenance());
  data.previous_record_digest = record.previous_record_digest();
  data.record_digest = record.record_digest();
  return data;
}

Result<AuthorityGrantView> to_grant_view(const GrantData& data, const FacilityAuthorityDomainId& domain) {
  Result<AuthorityClaims> claims = AuthorityClaims::create(
      domain, Epoch::from_trusted(data.epoch), ControllerId::from_trusted(data.controller),
      ControllerIncarnationId::from_digest(data.incarnation_id), GrantId::from_trusted(data.id),
      AuthorityScopeSet::create([&data] {
        std::vector<ScopeName> scopes;
        scopes.reserve(data.scopes.size());
        for (const std::string& scope : data.scopes) {
          scopes.push_back(ScopeName::from_trusted(scope));
        }
        return scopes;
      }())
          .value());
  if (!claims.has_value()) {
    return claims.rejection();
  }

  AuthorityGrantRecord record = RecordFactory::make_grant(data);
  if (data.authority_class == AuthorityClass::Mutation) {
    return AuthorityGrantView(std::move(record), MutationAuthority::from_claims(claims.move_value()));
  }
  return AuthorityGrantView(std::move(record), ObservationAuthority::from_claims(claims.move_value()));
}

// ---------------------------------------------------------------------------
// Record factory
// ---------------------------------------------------------------------------

ProvenanceRecord RecordFactory::make_provenance(const ProvenanceData& data) {
  ProvenanceRecord record;
  record.kind_ = data.kind;
  record.source_ = ProvenanceSourceId::from_trusted(data.source);
  record.external_ = data.external;
  record.note_ = data.note;
  record.recorded_epoch_ = Epoch::from_trusted(data.recorded_epoch);
  record.recorded_sequence_ = data.recorded_sequence;
  record.record_digest_ = data.record_digest;
  return record;
}

ControllerRecord RecordFactory::make_controller(const ControllerData& data) {
  ControllerRecord record;
  record.controller_ = ControllerId::from_trusted(data.controller);
  record.incarnation_number_ = IncarnationNumber::from_trusted(data.incarnation_number);
  record.incarnation_id_ = ControllerIncarnationId::from_digest(data.incarnation_id);
  record.incarnation_state_ = data.incarnation_state;
  record.registration_count_ = data.registration_count;
  record.first_registered_epoch_ = Epoch::from_trusted(data.first_registered_epoch);
  record.latest_registered_epoch_ = Epoch::from_trusted(data.latest_registered_epoch);
  if (data.revocation_through_incarnation.has_value()) {
    record.revocation_through_incarnation_ = IncarnationNumber::from_trusted(*data.revocation_through_incarnation);
  }
  record.latest_registration_provenance_ = make_provenance(data.latest_registration_provenance);
  record.record_digest_ = data.record_digest;
  return record;
}

ControllerRegistration RecordFactory::make_registration(const ControllerData& controller,
                                                        const ProvenanceData& provenance) {
  ControllerRegistration record;
  record.controller_ = ControllerId::from_trusted(controller.controller);
  record.incarnation_number_ = IncarnationNumber::from_trusted(controller.incarnation_number);
  record.incarnation_id_ = ControllerIncarnationId::from_digest(controller.incarnation_id);
  record.epoch_ = Epoch::from_trusted(provenance.recorded_epoch);
  record.sequence_ = RegistrationSequence::from_trusted(provenance.recorded_sequence);
  record.replayed_ = false;
  record.provenance_ = make_provenance(provenance);
  return record;
}

ControllerRegistration RecordFactory::mark_replayed(ControllerRegistration record) {
  record.replayed_ = true;
  return record;
}

AuthorityGrantRecord RecordFactory::make_grant(const GrantData& data) {
  AuthorityGrantRecord record;
  record.id_ = GrantId::from_trusted(data.id);
  record.authority_class_ = data.authority_class;
  record.epoch_ = Epoch::from_trusted(data.epoch);
  record.controller_ = ControllerId::from_trusted(data.controller);
  record.incarnation_ = ControllerIncarnationId::from_digest(data.incarnation_id);
  record.incarnation_number_ = IncarnationNumber::from_trusted(data.incarnation_number);
  std::vector<ScopeName> scopes;
  scopes.reserve(data.scopes.size());
  for (const std::string& scope : data.scopes) {
    scopes.push_back(ScopeName::from_trusted(scope));
  }
  record.scopes_ = AuthorityScopeSet::from_trusted(std::move(scopes));
  record.sequence_ = data.sequence;
  if (data.revoked_by_sequence.has_value()) {
    record.revoked_by_sequence_ = RevocationSequence::from_trusted(*data.revoked_by_sequence);
  }
  record.provenance_ = make_provenance(data.provenance);
  record.record_digest_ = data.record_digest;
  return record;
}

EpochTransitionRecord RecordFactory::make_transition(const TransitionData& data) {
  EpochTransitionRecord record;
  record.sequence_ = TransitionSequence::from_trusted(data.sequence);
  record.origin_ = data.origin;
  record.base_epoch_ = Epoch::from_trusted(data.base_epoch);
  record.new_epoch_ = Epoch::from_trusted(data.new_epoch);
  record.reason_ = data.reason;
  record.committed_by_ = ControllerId::from_trusted(data.committed_by);
  record.committed_by_incarnation_ = ControllerIncarnationId::from_digest(data.committed_by_incarnation);
  record.committed_by_grant_ = GrantId::from_trusted(data.committed_by_grant);
  record.fenced_grant_count_ = data.fenced_grant_count;
  record.controller_count_ = data.controller_count;
  record.provenance_ = make_provenance(data.provenance);
  record.previous_record_digest_ = data.previous_record_digest;
  record.record_digest_ = data.record_digest;
  return record;
}

RevocationRecord RecordFactory::make_revocation(const RevocationData& data) {
  RevocationRecord record;
  record.sequence_ = RevocationSequence::from_trusted(data.sequence);
  record.target_kind_ = data.target_kind;
  record.controller_ = ControllerId::from_trusted(data.controller);
  if (data.through_incarnation.has_value()) {
    record.through_incarnation_ = IncarnationNumber::from_trusted(*data.through_incarnation);
  }
  if (data.grant.has_value()) {
    record.grant_ = GrantId::from_trusted(*data.grant);
  }
  record.reason_ = data.reason;
  record.epoch_ = Epoch::from_trusted(data.epoch);
  record.issued_by_ = ControllerId::from_trusted(data.issued_by);
  record.issued_by_incarnation_ = ControllerIncarnationId::from_digest(data.issued_by_incarnation);
  record.issued_by_grant_ = GrantId::from_trusted(data.issued_by_grant);
  record.fenced_grant_count_ = data.fenced_grant_count;
  record.replayed_ = data.replayed;
  record.provenance_ = make_provenance(data.provenance);
  record.previous_record_digest_ = data.previous_record_digest;
  record.record_digest_ = data.record_digest;
  return record;
}

RevocationRecord RecordFactory::mark_replayed(RevocationRecord record) {
  record.replayed_ = true;
  return record;
}

EpochHistoryPage RecordFactory::make_history_page(std::vector<EpochTransitionRecord> records,
                                                  std::uint64_t total_count,
                                                  std::uint64_t first_retained_sequence,
                                                  std::uint64_t trimmed_count, Sha256Digest history_anchor,
                                                  Sha256Digest chain_head) {
  EpochHistoryPage page;
  page.records_ = std::move(records);
  page.total_count_ = total_count;
  page.first_retained_sequence_ = first_retained_sequence;
  page.trimmed_count_ = trimmed_count;
  page.history_anchor_ = history_anchor;
  page.chain_head_ = chain_head;
  return page;
}

}  // namespace dccp::epoch::detail
