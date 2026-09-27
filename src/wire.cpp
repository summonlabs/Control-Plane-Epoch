// Control Plane Epoch 1.0.0 - Summon Software Labs
// Internal wire payload codecs.
#include "wire.hpp"

#include <algorithm>

namespace dccp::epoch::detail {
namespace {

/// Upper bound for any single text field in a wire payload. A frame payload is
/// itself bounded, so this only rejects absurd individual fields before they are
/// materialized.
constexpr std::size_t kWireTextBound = max_frame_payload_bytes;

[[nodiscard]] std::string read_identifier(CanonicalReader& reader, std::size_t maximum, std::string_view what) {
  const std::string text = reader.text();
  Result<std::string> validated = validate_identifier(text, maximum, what);
  if (!validated.has_value()) {
    throw EpochError(validated.rejection());
  }
  return text;
}

[[nodiscard]] std::uint64_t read_positive(CanonicalReader& reader, std::string_view what) {
  const std::uint64_t value = reader.u64();
  if (value == 0) {
    throw EpochError(ErrorCode::MalformedPayload, std::string(what) + " is zero");
  }
  return value;
}

[[nodiscard]] std::uint32_t read_enum(CanonicalReader& reader, std::uint32_t maximum, std::string_view what) {
  const std::uint32_t value = reader.u32();
  if (value == 0 || value > maximum) {
    throw EpochError(ErrorCode::MalformedPayload,
                     std::string(what) + " value " + std::to_string(value) + " is outside its domain");
  }
  return value;
}

[[nodiscard]] std::vector<ScopeName> read_scopes(CanonicalReader& reader) {
  const std::uint32_t count = reader.u32();
  if (static_cast<std::size_t>(count) > max_scopes_per_authority) {
    throw EpochError(ErrorCode::FrameTooLarge, "scope list exceeds its bound");
  }
  std::vector<ScopeName> scopes;
  scopes.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    Result<ScopeName> parsed = ScopeName::parse(reader.text(), "scope name");
    if (!parsed.has_value()) {
      throw EpochError(parsed.rejection());
    }
    scopes.push_back(parsed.move_value());
  }
  Result<AuthorityScopeSet> set = AuthorityScopeSet::create(std::move(scopes));
  if (!set.has_value()) {
    throw EpochError(set.rejection());
  }
  return set.value().scopes();
}

void write_scopes(CanonicalWriter& writer, const std::vector<ScopeName>& scopes) {
  writer.u32(static_cast<std::uint32_t>(scopes.size()));
  for (const ScopeName& scope : scopes) {
    writer.text(scope.view());
  }
}

[[nodiscard]] CanonicalReader reader_for(std::span<const std::byte> payload) {
  return CanonicalReader(payload, kWireTextBound);
}

}  // namespace

void encode_provenance_input(CanonicalWriter& writer, const ProvenanceInput& input) {
  writer.u32(static_cast<std::uint32_t>(input.kind()));
  writer.text(input.source().view());
  writer.boolean(input.external().has_value());
  if (input.external().has_value()) {
    writer.text(input.external()->kind());
    writer.text(input.external()->value());
  }
  writer.text(input.note());
}

ProvenanceInput decode_provenance_input(CanonicalReader& reader) {
  const auto kind = static_cast<ProvenanceSourceKind>(read_enum(reader, max_provenance_source_kind, "provenance kind"));
  Result<ProvenanceSourceId> source = ProvenanceSourceId::parse(reader.text(), "provenance source");
  if (!source.has_value()) {
    throw EpochError(source.rejection());
  }
  std::optional<ExternalRef> external;
  if (reader.boolean()) {
    const std::string external_kind = reader.text();
    const std::string external_value = reader.text();
    Result<ExternalRef> parsed = ExternalRef::parse(external_kind, external_value);
    if (!parsed.has_value()) {
      throw EpochError(parsed.rejection());
    }
    external = parsed.move_value();
  }
  const std::string note = reader.text();
  Result<ProvenanceInput> input = ProvenanceInput::create(kind, source.move_value(), std::move(external), note);
  if (!input.has_value()) {
    throw EpochError(input.rejection());
  }
  return input.move_value();
}

void encode_idempotency_key(CanonicalWriter& writer, const IdempotencyKey& key) {
  writer.text(key.controller().view());
  writer.digest(key.incarnation().digest());
  writer.u64(key.sequence().value());
}

IdempotencyKey decode_idempotency_key(CanonicalReader& reader) {
  Result<ControllerId> controller = ControllerId::parse(reader.text(), "idempotency controller");
  if (!controller.has_value()) {
    throw EpochError(controller.rejection());
  }
  const Sha256Digest incarnation_digest = reader.digest();
  if (incarnation_digest.is_zero()) {
    throw EpochError(ErrorCode::MalformedPayload, "idempotency incarnation is the zero digest");
  }
  Result<OperationSequence> sequence = OperationSequence::from_value(read_positive(reader, "idempotency sequence"), "idempotency sequence");
  if (!sequence.has_value()) {
    throw EpochError(sequence.rejection());
  }
  Result<IdempotencyKey> key = IdempotencyKey::create(controller.move_value(),
                                                      ControllerIncarnationId::from_digest(incarnation_digest),
                                                      sequence.value());
  if (!key.has_value()) {
    throw EpochError(key.rejection());
  }
  return key.move_value();
}

// ---------------------------------------------------------------------------
// Handshake and errors
// ---------------------------------------------------------------------------

Payload encode_hello_request(const HelloPayload& payload) {
  CanonicalWriter writer(kWireTextBound);
  writer.u16(payload.protocol_version);
  writer.u16(payload.max_frame_payload_bytes);
  return writer.take();
}

HelloPayload decode_hello_request(std::span<const std::byte> payload) {
  CanonicalReader reader = reader_for(payload);
  HelloPayload result;
  result.protocol_version = reader.u16();
  result.max_frame_payload_bytes = reader.u16();
  reader.expect_end();
  return result;
}

Payload encode_hello_response(const HelloResponsePayload& payload) {
  CanonicalWriter writer(kWireTextBound);
  writer.u16(payload.protocol_version);
  writer.u16(payload.max_frame_payload_bytes);
  writer.text(payload.domain);
  writer.u64(payload.domain_instance);
  writer.u64(payload.epoch);
  writer.u64(payload.generation);
  writer.boolean(payload.initialized);
  return writer.take();
}

HelloResponsePayload decode_hello_response(std::span<const std::byte> payload) {
  CanonicalReader reader = reader_for(payload);
  HelloResponsePayload result;
  result.protocol_version = reader.u16();
  result.max_frame_payload_bytes = reader.u16();
  result.domain = reader.text();
  if (!result.domain.empty()) {
    Result<std::string> validated = validate_identifier(result.domain, max_identifier_length, "handshake domain");
    if (!validated.has_value()) {
      throw EpochError(validated.rejection());
    }
  }
  result.domain_instance = reader.u64();
  result.epoch = reader.u64();
  result.generation = reader.u64();
  result.initialized = reader.boolean();
  reader.expect_end();
  return result;
}

Payload encode_error(const ErrorPayload& payload) {
  CanonicalWriter writer(kWireTextBound);
  writer.text(error_token(payload.code));
  writer.text(payload.detail);
  return writer.take();
}

ErrorPayload decode_error(std::span<const std::byte> payload) {
  CanonicalReader reader = reader_for(payload);
  const std::string token = reader.text();
  Result<ErrorCode> code = parse_error_code(token);
  if (!code.has_value()) {
    throw EpochError(ErrorCode::MalformedPayload, "unknown error token '" + token + "'");
  }
  ErrorPayload result;
  result.code = code.value();
  result.detail = reader.text();
  reader.expect_end();
  return result;
}

Payload encode_validation(const ValidationPayload& payload) {
  CanonicalWriter writer(kWireTextBound);
  writer.boolean(payload.accepted);
  if (!payload.accepted) {
    writer.text(error_token(payload.code));
    writer.text(payload.detail);
  }
  return writer.take();
}

ValidationPayload decode_validation(std::span<const std::byte> payload) {
  CanonicalReader reader = reader_for(payload);
  ValidationPayload result;
  result.accepted = reader.boolean();
  if (!result.accepted) {
    const std::string token = reader.text();
    Result<ErrorCode> code = parse_error_code(token);
    if (!code.has_value()) {
      throw EpochError(ErrorCode::MalformedPayload, "unknown error token '" + token + "'");
    }
    result.code = code.value();
    result.detail = reader.text();
  }
  reader.expect_end();
  return result;
}

Payload encode_qualification(const QualificationPayload& payload) {
  CanonicalWriter writer(kWireTextBound);
  writer.u32(static_cast<std::uint32_t>(payload.verdict));
  writer.text(error_token(payload.code));
  writer.text(payload.detail);
  writer.boolean(payload.matching_grant.has_value());
  if (payload.matching_grant.has_value()) {
    writer.u64(*payload.matching_grant);
  }
  writer.boolean(payload.requires_revalidation);
  return writer.take();
}

QualificationPayload decode_qualification(std::span<const std::byte> payload) {
  CanonicalReader reader = reader_for(payload);
  QualificationPayload result;
  result.verdict =
      static_cast<RecoveredStateVerdict>(read_enum(reader, max_recovered_state_verdict, "recovered state verdict"));
  const std::string token = reader.text();
  Result<ErrorCode> code = parse_error_code(token);
  if (!code.has_value()) {
    throw EpochError(ErrorCode::MalformedPayload, "unknown error token '" + token + "'");
  }
  result.code = code.value();
  result.detail = reader.text();
  if (reader.boolean()) {
    result.matching_grant = read_positive(reader, "matching grant");
  }
  result.requires_revalidation = reader.boolean();
  reader.expect_end();
  return result;
}

// ---------------------------------------------------------------------------
// Controller registration
// ---------------------------------------------------------------------------

Payload encode_register_request(const RegisterControllerRequest& request) {
  CanonicalWriter writer(kWireTextBound);
  writer.text(request.controller.view());
  encode_provenance_input(writer, request.provenance);
  writer.boolean(request.idempotency.has_value());
  if (request.idempotency.has_value()) {
    encode_idempotency_key(writer, *request.idempotency);
  }
  return writer.take();
}

RegisterControllerRequest decode_register_request(std::span<const std::byte> payload) {
  CanonicalReader reader = reader_for(payload);
  RegisterControllerRequest request;
  Result<ControllerId> controller = ControllerId::parse(reader.text(), "controller");
  if (!controller.has_value()) {
    throw EpochError(controller.rejection());
  }
  request.controller = controller.move_value();
  request.provenance = decode_provenance_input(reader);
  if (reader.boolean()) {
    request.idempotency = decode_idempotency_key(reader);
  }
  reader.expect_end();
  return request;
}

Payload encode_register_response(const ControllerRegistration& registration) {
  CanonicalWriter writer(kWireTextBound);
  encode_registration(writer, registration);
  return writer.take();
}

ControllerRegistration decode_register_response(std::span<const std::byte> payload) {
  CanonicalReader reader = reader_for(payload);
  ControllerRegistration registration = decode_registration(reader, false);
  reader.expect_end();
  return registration;
}

// ---------------------------------------------------------------------------
// Authority acquisition
// ---------------------------------------------------------------------------

Payload encode_acquire_request(const AcquireAuthorityRequest& request) {
  CanonicalWriter writer(kWireTextBound);
  writer.u32(static_cast<std::uint32_t>(request.authority_class));
  writer.text(request.controller.view());
  writer.digest(request.incarnation.digest());
  write_scopes(writer, request.scopes.scopes());
  writer.boolean(request.sponsor.has_value());
  if (request.sponsor.has_value()) {
    writer.text(request.sponsor->to_string());
  }
  encode_provenance_input(writer, request.provenance);
  writer.boolean(request.idempotency.has_value());
  if (request.idempotency.has_value()) {
    encode_idempotency_key(writer, *request.idempotency);
  }
  return writer.take();
}

AcquireAuthorityRequest decode_acquire_request(std::span<const std::byte> payload) {
  CanonicalReader reader = reader_for(payload);
  AcquireAuthorityRequest request;
  request.authority_class =
      static_cast<AuthorityClass>(read_enum(reader, max_authority_class, "authority class"));
  Result<ControllerId> controller = ControllerId::parse(reader.text(), "controller");
  if (!controller.has_value()) {
    throw EpochError(controller.rejection());
  }
  request.controller = controller.move_value();
  const Sha256Digest incarnation_digest = reader.digest();
  if (incarnation_digest.is_zero()) {
    throw EpochError(ErrorCode::MalformedPayload, "the incarnation is the zero digest");
  }
  request.incarnation = ControllerIncarnationId::from_digest(incarnation_digest);
  Result<AuthorityScopeSet> scopes = AuthorityScopeSet::create(read_scopes(reader));
  if (!scopes.has_value()) {
    throw EpochError(scopes.rejection());
  }
  request.scopes = scopes.move_value();
  if (reader.boolean()) {
    Result<MutationAuthority> sponsor = MutationAuthority::parse(reader.text());
    if (!sponsor.has_value()) {
      throw EpochError(sponsor.rejection());
    }
    request.sponsor = sponsor.move_value();
  }
  request.provenance = decode_provenance_input(reader);
  if (reader.boolean()) {
    request.idempotency = decode_idempotency_key(reader);
  }
  reader.expect_end();
  return request;
}

Payload encode_acquire_response(const GrantData& grant) {
  CanonicalWriter writer(kWireTextBound);
  encode_grant(writer, grant);
  return writer.take();
}

GrantData decode_acquire_response(std::span<const std::byte> payload) {
  CanonicalReader reader = reader_for(payload);
  GrantData grant = decode_grant(reader);
  reader.expect_end();
  return grant;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

Payload encode_validate_request(const ValidateRequestPayload& request) {
  CanonicalWriter writer(kWireTextBound);
  writer.text(request.token);
  writer.text(request.scope);
  return writer.take();
}

ValidateRequestPayload decode_validate_request(std::span<const std::byte> payload) {
  CanonicalReader reader = reader_for(payload);
  ValidateRequestPayload request;
  request.token = reader.text();
  Result<ScopeName> scope = ScopeName::parse(reader.text(), "scope name");
  if (!scope.has_value()) {
    throw EpochError(scope.rejection());
  }
  request.scope = scope.value().str();
  reader.expect_end();
  return request;
}

// ---------------------------------------------------------------------------
// Epoch advancement
// ---------------------------------------------------------------------------

Payload encode_advance_request(const AdvanceEpochRequest& request) {
  CanonicalWriter writer(kWireTextBound);
  writer.u64(request.expected_current.value());
  writer.text(request.authority.to_string());
  writer.u32(static_cast<std::uint32_t>(request.reason));
  encode_provenance_input(writer, request.provenance);
  writer.boolean(request.idempotency.has_value());
  if (request.idempotency.has_value()) {
    encode_idempotency_key(writer, *request.idempotency);
  }
  return writer.take();
}

AdvanceEpochRequest decode_advance_request(std::span<const std::byte> payload) {
  CanonicalReader reader = reader_for(payload);
  AdvanceEpochRequest request;
  Result<Epoch> expected = Epoch::from_value(read_positive(reader, "expected epoch"));
  if (!expected.has_value()) {
    throw EpochError(expected.rejection());
  }
  request.expected_current = expected.value();
  Result<MutationAuthority> authority = MutationAuthority::parse(reader.text());
  if (!authority.has_value()) {
    throw EpochError(authority.rejection());
  }
  request.authority = authority.move_value();
  request.reason =
      static_cast<EpochTransitionReason>(read_enum(reader, max_epoch_transition_reason, "transition reason"));
  request.provenance = decode_provenance_input(reader);
  if (reader.boolean()) {
    request.idempotency = decode_idempotency_key(reader);
  }
  reader.expect_end();
  return request;
}

Payload encode_transition_response(const TransitionData& transition) {
  CanonicalWriter writer(kWireTextBound);
  encode_transition(writer, transition);
  return writer.take();
}

TransitionData decode_transition_response(std::span<const std::byte> payload) {
  CanonicalReader reader = reader_for(payload);
  TransitionData transition = decode_transition(reader);
  reader.expect_end();
  return transition;
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

Payload encode_revoke_request(const RevokeAuthorityRequest& request) {
  CanonicalWriter writer(kWireTextBound);
  writer.u32(static_cast<std::uint32_t>(request.target.kind()));
  writer.text(request.target.controller().view());
  writer.boolean(request.target.through_incarnation().has_value());
  if (request.target.through_incarnation().has_value()) {
    writer.u64(request.target.through_incarnation()->value());
  }
  writer.boolean(request.target.grant().has_value());
  if (request.target.grant().has_value()) {
    writer.u64(request.target.grant()->value());
  }
  writer.u32(static_cast<std::uint32_t>(request.reason));
  writer.text(request.authority.to_string());
  encode_provenance_input(writer, request.provenance);
  writer.boolean(request.idempotency.has_value());
  if (request.idempotency.has_value()) {
    encode_idempotency_key(writer, *request.idempotency);
  }
  return writer.take();
}

RevokeAuthorityRequest decode_revoke_request(std::span<const std::byte> payload) {
  CanonicalReader reader = reader_for(payload);
  RevokeAuthorityRequest request;
  const auto kind = static_cast<RevocationTargetKind>(
      read_enum(reader, max_revocation_target_kind, "revocation target kind"));
  Result<ControllerId> controller = ControllerId::parse(reader.text(), "revocation controller");
  if (!controller.has_value()) {
    throw EpochError(controller.rejection());
  }
  const bool has_through = reader.boolean();
  std::uint64_t through = 0;
  if (has_through) {
    through = read_positive(reader, "revocation incarnation fence");
  }
  const bool has_grant = reader.boolean();
  std::uint64_t grant_id = 0;
  if (has_grant) {
    grant_id = read_positive(reader, "revoked grant identifier");
  }
  if (kind == RevocationTargetKind::Grant) {
    if (!has_grant || has_through) {
      throw EpochError(ErrorCode::MalformedPayload, "a grant revocation names exactly one grant");
    }
    Result<GrantId> grant = GrantId::from_value(grant_id, "grant");
    if (!grant.has_value()) {
      throw EpochError(grant.rejection());
    }
    request.target = RevocationTarget::grant(grant.value(), controller.move_value());
  } else {
    if (has_grant) {
      throw EpochError(ErrorCode::MalformedPayload, "a controller revocation must not name a grant");
    }
    if (has_through) {
      request.target =
          RevocationTarget::controller_through(controller.move_value(), IncarnationNumber::from_trusted(through));
    } else {
      request.target = RevocationTarget::controller_all(controller.move_value());
    }
  }
  request.reason = static_cast<RevocationReason>(read_enum(reader, max_revocation_reason, "revocation reason"));
  Result<MutationAuthority> authority = MutationAuthority::parse(reader.text());
  if (!authority.has_value()) {
    throw EpochError(authority.rejection());
  }
  request.authority = authority.move_value();
  request.provenance = decode_provenance_input(reader);
  if (reader.boolean()) {
    request.idempotency = decode_idempotency_key(reader);
  }
  reader.expect_end();
  return request;
}

Payload encode_revocation_response(const RevocationData& revocation) {
  CanonicalWriter writer(kWireTextBound);
  encode_revocation(writer, revocation);
  return writer.take();
}

RevocationData decode_revocation_response(std::span<const std::byte> payload) {
  CanonicalReader reader = reader_for(payload);
  RevocationData revocation = decode_revocation(reader);
  reader.expect_end();
  return revocation;
}

// ---------------------------------------------------------------------------
// Recovered state qualification
// ---------------------------------------------------------------------------

Payload encode_qualify_request(const RecoveredStateClaim& claim) {
  CanonicalWriter writer(kWireTextBound);
  writer.text(claim.domain().view());
  writer.u64(claim.producing_epoch().value());
  writer.text(claim.producer().view());
  writer.digest(claim.producer_incarnation().digest());
  writer.text(claim.scope().view());
  writer.digest(claim.content_digest());
  return writer.take();
}

RecoveredStateClaim decode_qualify_request(std::span<const std::byte> payload) {
  CanonicalReader reader = reader_for(payload);
  Result<FacilityAuthorityDomainId> domain = FacilityAuthorityDomainId::parse(reader.text(), "authority domain");
  if (!domain.has_value()) {
    throw EpochError(domain.rejection());
  }
  Result<Epoch> epoch = Epoch::from_value(read_positive(reader, "producing epoch"));
  if (!epoch.has_value()) {
    throw EpochError(epoch.rejection());
  }
  Result<ControllerId> producer = ControllerId::parse(reader.text(), "producer");
  if (!producer.has_value()) {
    throw EpochError(producer.rejection());
  }
  const Sha256Digest incarnation_digest = reader.digest();
  if (incarnation_digest.is_zero()) {
    throw EpochError(ErrorCode::MalformedPayload, "the producer incarnation is the zero digest");
  }
  Result<ScopeName> scope = ScopeName::parse(reader.text(), "scope name");
  if (!scope.has_value()) {
    throw EpochError(scope.rejection());
  }
  const Sha256Digest content_digest = reader.digest();
  reader.expect_end();

  Result<RecoveredStateClaim> claim =
      RecoveredStateClaim::create(domain.move_value(), epoch.value(), producer.move_value(),
                                  ControllerIncarnationId::from_digest(incarnation_digest), scope.move_value(),
                                  content_digest);
  if (!claim.has_value()) {
    throw EpochError(claim.rejection());
  }
  return claim.move_value();
}

// ---------------------------------------------------------------------------
// Status and ledgers
// ---------------------------------------------------------------------------

Payload encode_status(const StatusPayload& payload) {
  CanonicalWriter writer(kWireTextBound);
  writer.text(payload.domain);
  writer.u64(payload.domain_instance);
  writer.u64(payload.epoch);
  writer.u64(payload.generation);
  writer.text(payload.authority_root);
  writer.u64(payload.controller_count);
  writer.u64(payload.live_grant_count);
  writer.u64(payload.mutation_grant_count);
  writer.u64(payload.observation_grant_count);
  writer.u32(static_cast<std::uint32_t>(payload.declared_scopes.size()));
  for (const std::string& scope : payload.declared_scopes) {
    writer.text(scope);
  }
  writer.u64(payload.transition_count);
  writer.u64(payload.revocation_count);
  writer.u64(payload.idempotency_record_count);
  writer.digest(payload.snapshot_digest);
  writer.digest(payload.transition_chain_head);
  writer.u32(static_cast<std::uint32_t>(payload.recovery_outcome));
  writer.u32(static_cast<std::uint32_t>(payload.open_mode));
  return writer.take();
}

StatusPayload decode_status(std::span<const std::byte> payload) {
  CanonicalReader reader = reader_for(payload);
  StatusPayload result;
  result.domain = read_identifier(reader, max_identifier_length, "status domain");
  result.domain_instance = read_positive(reader, "status domain instance");
  result.epoch = read_positive(reader, "status epoch");
  result.generation = read_positive(reader, "status generation");
  result.authority_root = read_identifier(reader, max_identifier_length, "status authority root");
  result.controller_count = reader.u64();
  result.live_grant_count = reader.u64();
  result.mutation_grant_count = reader.u64();
  result.observation_grant_count = reader.u64();
  const std::uint32_t scope_count = reader.u32();
  if (static_cast<std::size_t>(scope_count) > max_declared_scopes) {
    throw EpochError(ErrorCode::FrameTooLarge, "declared scope list exceeds its bound");
  }
  result.declared_scopes.reserve(scope_count);
  for (std::uint32_t index = 0; index < scope_count; ++index) {
    result.declared_scopes.push_back(read_identifier(reader, max_identifier_length, "declared scope"));
  }
  result.transition_count = reader.u64();
  result.revocation_count = reader.u64();
  result.idempotency_record_count = reader.u64();
  result.snapshot_digest = reader.digest();
  result.transition_chain_head = reader.digest();
  const std::uint32_t outcome = reader.u32();
  if (outcome == 0 || outcome > 4) {
    throw EpochError(ErrorCode::MalformedPayload, "recovery outcome is outside its domain");
  }
  result.recovery_outcome = static_cast<RecoveryOutcome>(outcome);
  const std::uint32_t mode = reader.u32();
  if (mode == 0 || mode > 2) {
    throw EpochError(ErrorCode::MalformedPayload, "store open mode is outside its domain");
  }
  result.open_mode = static_cast<StoreOpenMode>(mode);
  reader.expect_end();
  return result;
}

Payload encode_history_request(const HistoryRequestPayload& payload) {
  CanonicalWriter writer(kWireTextBound);
  writer.boolean(payload.from_sequence.has_value());
  if (payload.from_sequence.has_value()) {
    writer.u64(*payload.from_sequence);
  }
  writer.u64(payload.limit);
  return writer.take();
}

HistoryRequestPayload decode_history_request(std::span<const std::byte> payload) {
  CanonicalReader reader = reader_for(payload);
  HistoryRequestPayload result;
  if (reader.boolean()) {
    result.from_sequence = read_positive(reader, "history start sequence");
  }
  result.limit = read_positive(reader, "history page limit");
  reader.expect_end();
  return result;
}

Payload encode_history_response(const HistoryResponsePayload& payload) {
  CanonicalWriter writer(kWireTextBound);
  writer.u64(payload.page.total_count);
  writer.u64(payload.page.first_retained);
  writer.u64(payload.page.trimmed_count);
  writer.digest(payload.page.anchor);
  writer.digest(payload.page.chain_head);
  writer.u32(static_cast<std::uint32_t>(payload.records.size()));
  for (const TransitionData& record : payload.records) {
    encode_transition(writer, record);
  }
  return writer.take();
}

HistoryResponsePayload decode_history_response(std::span<const std::byte> payload) {
  CanonicalReader reader = reader_for(payload);
  HistoryResponsePayload result;
  result.page.total_count = reader.u64();
  result.page.first_retained = reader.u64();
  result.page.trimmed_count = reader.u64();
  result.page.anchor = reader.digest();
  result.page.chain_head = reader.digest();
  const std::uint32_t count = reader.u32();
  if (static_cast<std::size_t>(count) > max_page_size) {
    throw EpochError(ErrorCode::FrameTooLarge, "transition page exceeds its bound");
  }
  result.records.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    result.records.push_back(decode_transition(reader));
  }
  reader.expect_end();
  return result;
}

Payload encode_revocations_request(const RevocationsRequestPayload& payload) {
  CanonicalWriter writer(kWireTextBound);
  writer.boolean(payload.from_sequence.has_value());
  if (payload.from_sequence.has_value()) {
    writer.u64(*payload.from_sequence);
  }
  writer.u64(payload.limit);
  return writer.take();
}

RevocationsRequestPayload decode_revocations_request(std::span<const std::byte> payload) {
  CanonicalReader reader = reader_for(payload);
  RevocationsRequestPayload result;
  if (reader.boolean()) {
    result.from_sequence = read_positive(reader, "revocation start sequence");
  }
  result.limit = read_positive(reader, "revocation page limit");
  reader.expect_end();
  return result;
}

Payload encode_revocations_response(const RevocationsResponsePayload& payload) {
  CanonicalWriter writer(kWireTextBound);
  writer.u64(payload.page.total_count);
  writer.u64(payload.page.first_retained);
  writer.u64(payload.page.trimmed_count);
  writer.digest(payload.page.anchor);
  writer.digest(payload.page.chain_head);
  writer.u32(static_cast<std::uint32_t>(payload.records.size()));
  for (const RevocationData& record : payload.records) {
    encode_revocation(writer, record);
  }
  return writer.take();
}

RevocationsResponsePayload decode_revocations_response(std::span<const std::byte> payload) {
  CanonicalReader reader = reader_for(payload);
  RevocationsResponsePayload result;
  result.page.total_count = reader.u64();
  result.page.first_retained = reader.u64();
  result.page.trimmed_count = reader.u64();
  result.page.anchor = reader.digest();
  result.page.chain_head = reader.digest();
  const std::uint32_t count = reader.u32();
  if (static_cast<std::size_t>(count) > max_page_size) {
    throw EpochError(ErrorCode::FrameTooLarge, "revocation page exceeds its bound");
  }
  result.records.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    result.records.push_back(decode_revocation(reader));
  }
  reader.expect_end();
  return result;
}

Payload encode_controllers_request(const ControllersRequestPayload& payload) {
  CanonicalWriter writer(kWireTextBound);
  writer.boolean(payload.from_controller.has_value());
  if (payload.from_controller.has_value()) {
    writer.text(*payload.from_controller);
  }
  writer.u64(payload.limit);
  return writer.take();
}

ControllersRequestPayload decode_controllers_request(std::span<const std::byte> payload) {
  CanonicalReader reader = reader_for(payload);
  ControllersRequestPayload result;
  if (reader.boolean()) {
    result.from_controller = read_identifier(reader, max_identifier_length, "controller cursor");
  }
  result.limit = read_positive(reader, "controller page limit");
  reader.expect_end();
  return result;
}

Payload encode_controllers_response(const ControllersResponsePayload& payload) {
  CanonicalWriter writer(kWireTextBound);
  writer.u64(payload.total_count);
  writer.u32(static_cast<std::uint32_t>(payload.records.size()));
  for (const ControllerData& record : payload.records) {
    encode_controller(writer, record);
  }
  return writer.take();
}

ControllersResponsePayload decode_controllers_response(std::span<const std::byte> payload) {
  CanonicalReader reader = reader_for(payload);
  ControllersResponsePayload result;
  result.total_count = reader.u64();
  const std::uint32_t count = reader.u32();
  if (static_cast<std::size_t>(count) > max_page_size) {
    throw EpochError(ErrorCode::FrameTooLarge, "controller page exceeds its bound");
  }
  result.records.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    result.records.push_back(decode_controller(reader));
  }
  reader.expect_end();
  return result;
}

Payload encode_grants_request(const GrantsRequestPayload& payload) {
  CanonicalWriter writer(kWireTextBound);
  writer.boolean(payload.from_grant.has_value());
  if (payload.from_grant.has_value()) {
    writer.u64(*payload.from_grant);
  }
  writer.u64(payload.limit);
  return writer.take();
}

GrantsRequestPayload decode_grants_request(std::span<const std::byte> payload) {
  CanonicalReader reader = reader_for(payload);
  GrantsRequestPayload result;
  if (reader.boolean()) {
    result.from_grant = read_positive(reader, "grant cursor");
  }
  result.limit = read_positive(reader, "grant page limit");
  reader.expect_end();
  return result;
}

Payload encode_grants_response(const GrantsResponsePayload& payload) {
  CanonicalWriter writer(kWireTextBound);
  writer.u64(payload.total_count);
  writer.u64(payload.epoch);
  writer.u32(static_cast<std::uint32_t>(payload.records.size()));
  for (const GrantData& record : payload.records) {
    encode_grant(writer, record);
  }
  return writer.take();
}

GrantsResponsePayload decode_grants_response(std::span<const std::byte> payload) {
  CanonicalReader reader = reader_for(payload);
  GrantsResponsePayload result;
  result.total_count = reader.u64();
  result.epoch = read_positive(reader, "grant page epoch");
  const std::uint32_t count = reader.u32();
  if (static_cast<std::size_t>(count) > max_page_size) {
    throw EpochError(ErrorCode::FrameTooLarge, "grant page exceeds its bound");
  }
  result.records.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    result.records.push_back(decode_grant(reader));
  }
  reader.expect_end();
  return result;
}

}  // namespace dccp::epoch::detail


