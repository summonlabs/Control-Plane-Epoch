// Control Plane Epoch 1.0.0 - Summon Software Labs
// Canonical image encoding, decoding, and full integrity verification.
#include "image.hpp"

#include <algorithm>
#include <array>
#include <limits>

namespace dccp::epoch::detail {
namespace {

constexpr std::array<std::byte, 4> kEnvelopeMagic{std::byte{'C'}, std::byte{'P'}, std::byte{'E'}, std::byte{'1'}};
constexpr std::uint32_t kEnvelopeFlagMask = 0;
constexpr std::size_t kMaxTextBytes = 4096;

[[nodiscard]] std::string read_identifier_text(CanonicalReader& reader, std::string_view what) {
  const std::string text = reader.text();
  Result<std::string> validated = validate_identifier(text, max_identifier_length, what);
  if (!validated.has_value()) {
    throw EpochError(validated.rejection());
  }
  return text;
}

[[nodiscard]] std::uint32_t read_bounded_count(CanonicalReader& reader, std::size_t maximum,
                                               std::string_view what) {
  const std::uint32_t count = reader.u32();
  if (static_cast<std::size_t>(count) > maximum) {
    throw EpochError(ErrorCode::IntegrityLimitExceeded,
                     std::string(what) + " count " + std::to_string(count) + " exceeds the bound of " +
                         std::to_string(maximum));
  }
  return count;
}

[[nodiscard]] std::uint64_t read_required_u64(CanonicalReader& reader, std::string_view what) {
  const std::uint64_t value = reader.u64();
  if (value == 0) {
    throw EpochError(ErrorCode::EnumOutOfDomain, std::string(what) + " is zero");
  }
  return value;
}

[[nodiscard]] bool reserved_scope_present(const std::vector<std::string>& scopes, std::string_view name) {
  return std::find(scopes.begin(), scopes.end(), name) != scopes.end();
}

void verify_ledger_chain(std::string_view what, std::size_t retained_count, std::uint64_t total_count,
                         std::uint64_t trimmed_count, const Sha256Digest& anchor,
                         const std::vector<Sha256Digest>& record_digests,
                         const std::vector<Sha256Digest>& previous_digests) {
  if (total_count == 0) {
    if (retained_count != 0 || trimmed_count != 0 || !anchor.is_zero()) {
      throw EpochError(ErrorCode::CountMismatch, std::string(what) + ": an empty ledger carries no records");
    }
    return;
  }
  if (retained_count == 0) {
    throw EpochError(ErrorCode::CountMismatch, std::string(what) + ": a non-empty ledger retains no records");
  }
  if (trimmed_count + retained_count != total_count) {
    throw EpochError(ErrorCode::CountMismatch,
                     std::string(what) + ": trimmed " + std::to_string(trimmed_count) + " plus retained " +
                         std::to_string(retained_count) + " does not equal the total " + std::to_string(total_count));
  }
  if (trimmed_count == 0) {
    if (!anchor.is_zero()) {
      throw EpochError(ErrorCode::CountMismatch, std::string(what) + ": an untrimmed ledger carries no anchor");
    }
    if (!previous_digests.front().is_zero()) {
      throw EpochError(ErrorCode::ChainBroken,
                       std::string(what) + ": the first record of an untrimmed ledger must start the chain");
    }
  } else {
    if (anchor.is_zero()) {
      throw EpochError(ErrorCode::ChainBroken, std::string(what) + ": a trimmed ledger must carry an anchor");
    }
    if (previous_digests.front() != anchor) {
      throw EpochError(ErrorCode::ChainBroken,
                       std::string(what) + ": the oldest retained record does not link to the trimmed anchor");
    }
  }

  for (std::size_t index = 1; index < retained_count; ++index) {
    if (previous_digests[index] != record_digests[index - 1]) {
      throw EpochError(ErrorCode::ChainBroken, std::string(what) + ": record " + std::to_string(index) +
                                                    " does not link to its predecessor");
    }
  }
}

}  // namespace

ImageLimits default_image_limits() { return ImageLimits{}; }

std::vector<std::byte> encode_image(const AuthorityImage& image, const ImageLimits& limits) {
  CanonicalWriter writer(limits.max_bytes);

  writer.u32(image.schema_version);
  writer.text(image.domain);
  writer.u64(image.domain_instance);
  writer.u64(image.epoch);
  writer.u64(image.durable_generation);
  writer.text(image.authority_root);

  writer.u32(static_cast<std::uint32_t>(image.declared_scopes.size()));
  for (const std::string& scope : image.declared_scopes) {
    writer.text(scope);
  }

  writer.u32(static_cast<std::uint32_t>(image.controllers.size()));
  for (const ControllerData& controller : image.controllers) {
    encode_controller(writer, controller);
  }

  writer.u32(static_cast<std::uint32_t>(image.grants.size()));
  for (const GrantData& grant : image.grants) {
    encode_grant(writer, grant);
  }

  writer.u64(image.revocation_count);
  writer.u64(image.revocation_trimmed);
  writer.digest(image.revocation_anchor);
  writer.u32(static_cast<std::uint32_t>(image.revocations.size()));
  for (const RevocationData& revocation : image.revocations) {
    encode_revocation(writer, revocation);
  }

  writer.u64(image.transition_count);
  writer.u64(image.transition_trimmed);
  writer.digest(image.transition_anchor);
  writer.u32(static_cast<std::uint32_t>(image.transitions.size()));
  for (const TransitionData& transition : image.transitions) {
    encode_transition(writer, transition);
  }

  writer.u64(image.idempotency_count);
  writer.u64(image.idempotency_evicted);
  writer.u32(static_cast<std::uint32_t>(image.idempotency.size()));
  for (const IdempotencyData& entry : image.idempotency) {
    writer.text(entry.controller);
    writer.digest(entry.incarnation_id);
    writer.u64(entry.sequence);
    writer.digest(entry.command_digest);
    writer.u32(static_cast<std::uint32_t>(entry.result_blob.size()));
    writer.raw(entry.result_blob);
  }

  writer.u64(image.next_grant_id);
  writer.u64(image.next_mutation_sequence);
  return writer.take();
}

AuthorityImage decode_image(std::span<const std::byte> payload, const ImageLimits& limits) {
  CanonicalReader reader(payload, kMaxTextBytes);
  AuthorityImage image;

  image.schema_version = reader.u32();
  if (image.schema_version != static_cast<std::uint32_t>(durable_schema_version)) {
    throw EpochError(ErrorCode::SchemaUnsupported,
                     "durable schema version " + std::to_string(image.schema_version) + " is not supported");
  }
  image.domain = read_identifier_text(reader, "authority domain");
  image.domain_instance = read_required_u64(reader, "domain instance");
  image.epoch = read_required_u64(reader, "epoch");
  image.durable_generation = read_required_u64(reader, "durable generation");
  image.authority_root = read_identifier_text(reader, "authority root");

  const std::uint32_t scope_count = read_bounded_count(reader, max_declared_scopes, "declared scope");
  image.declared_scopes.reserve(scope_count);
  for (std::uint32_t index = 0; index < scope_count; ++index) {
    const std::string scope = read_identifier_text(reader, "declared scope");
    if (index > 0 && !(image.declared_scopes.back() < scope)) {
      throw EpochError(ErrorCode::OrderingViolation, "declared scopes are not in canonical ascending order");
    }
    image.declared_scopes.push_back(scope);
  }

  const std::uint32_t controller_count = read_bounded_count(reader, limits.max_controllers, "controller");
  image.controllers.reserve(controller_count);
  for (std::uint32_t index = 0; index < controller_count; ++index) {
    ControllerData controller = decode_controller(reader);
    if (index > 0 && !(image.controllers.back().controller < controller.controller)) {
      throw EpochError(ErrorCode::OrderingViolation, "controllers are not in canonical ascending order");
    }
    image.controllers.push_back(std::move(controller));
  }

  const std::uint32_t grant_count = read_bounded_count(reader, limits.max_grants, "grant");
  image.grants.reserve(grant_count);
  for (std::uint32_t index = 0; index < grant_count; ++index) {
    GrantData grant = decode_grant(reader);
    if (index > 0 && !(image.grants.back().id < grant.id)) {
      throw EpochError(ErrorCode::OrderingViolation, "grants are not in canonical ascending order");
    }
    image.grants.push_back(std::move(grant));
  }

  image.revocation_count = reader.u64();
  image.revocation_trimmed = reader.u64();
  image.revocation_anchor = reader.digest();
  const std::uint32_t revocation_count = read_bounded_count(reader, limits.max_revocations, "revocation");
  image.revocations.reserve(revocation_count);
  for (std::uint32_t index = 0; index < revocation_count; ++index) {
    RevocationData revocation = decode_revocation(reader);
    if (index > 0 && !(image.revocations.back().sequence < revocation.sequence)) {
      throw EpochError(ErrorCode::OrderingViolation, "revocations are not in canonical ascending order");
    }
    image.revocations.push_back(std::move(revocation));
  }

  image.transition_count = reader.u64();
  image.transition_trimmed = reader.u64();
  image.transition_anchor = reader.digest();
  const std::uint32_t transition_count = read_bounded_count(reader, limits.max_transitions, "transition");
  image.transitions.reserve(transition_count);
  for (std::uint32_t index = 0; index < transition_count; ++index) {
    TransitionData transition = decode_transition(reader);
    if (index > 0 && !(image.transitions.back().sequence < transition.sequence)) {
      throw EpochError(ErrorCode::OrderingViolation, "transitions are not in canonical ascending order");
    }
    image.transitions.push_back(std::move(transition));
  }

  image.idempotency_count = reader.u64();
  image.idempotency_evicted = reader.u64();
  const std::uint32_t idempotency_count = read_bounded_count(reader, limits.max_idempotency, "idempotency");
  image.idempotency.reserve(idempotency_count);
  for (std::uint32_t index = 0; index < idempotency_count; ++index) {
    IdempotencyData entry;
    entry.controller = read_identifier_text(reader, "idempotency controller");
    entry.incarnation_id = reader.digest();
    entry.sequence = read_required_u64(reader, "idempotency sequence");
    entry.command_digest = reader.digest();
    const std::uint32_t blob_length = reader.u32();
    if (static_cast<std::size_t>(blob_length) > max_idempotency_blob_bytes) {
      throw EpochError(ErrorCode::IntegrityLimitExceeded, "idempotency result blob exceeds its bound");
    }
    const std::span<const std::byte> blob = reader.raw(blob_length);
    entry.result_blob.assign(blob.begin(), blob.end());
    if (index > 0) {
      const IdempotencyData& previous = image.idempotency.back();
      const bool ordered = previous.controller < entry.controller ||
                           (previous.controller == entry.controller &&
                            (previous.incarnation_id < entry.incarnation_id ||
                             (previous.incarnation_id == entry.incarnation_id && previous.sequence < entry.sequence)));
      if (!ordered) {
        throw EpochError(ErrorCode::OrderingViolation, "idempotency records are not in canonical ascending order");
      }
    }
    image.idempotency.push_back(std::move(entry));
  }

  image.next_grant_id = read_required_u64(reader, "next grant identifier");
  image.next_mutation_sequence = read_required_u64(reader, "next mutation sequence");
  reader.expect_end();

  verify_image(image, limits);
  return image;
}

void verify_image(const AuthorityImage& image, const ImageLimits& limits) {
  if (image.domain.empty()) {
    throw EpochError(ErrorCode::CountMismatch, "a durable generation must name its authority domain");
  }
  if (image.controllers.size() > limits.max_controllers) {
    throw EpochError(ErrorCode::IntegrityLimitExceeded, "controller count exceeds its bound");
  }
  if (image.grants.size() > limits.max_grants) {
    throw EpochError(ErrorCode::IntegrityLimitExceeded, "grant count exceeds its bound");
  }

  if (!reserved_scope_present(image.declared_scopes, authority_grant_scope().view()) ||
      !reserved_scope_present(image.declared_scopes, authority_revoke_scope().view()) ||
      !reserved_scope_present(image.declared_scopes, epoch_advance_scope().view())) {
    throw EpochError(ErrorCode::CountMismatch, "the reserved administrative scopes are not all declared");
  }

  // Controllers.
  const ControllerData* root = nullptr;
  for (const ControllerData& controller : image.controllers) {
    verify_record_digest(controller, "image");
    if (controller.incarnation_number == 0 || controller.registration_count == 0) {
      throw EpochError(ErrorCode::CountMismatch, "a controller record must name an incarnation and a registration");
    }
    if (controller.first_registered_epoch == 0 || controller.latest_registered_epoch == 0 ||
        controller.latest_registered_epoch < controller.first_registered_epoch) {
      throw EpochError(ErrorCode::OrderingViolation, "controller epochs are not monotonic");
    }
    const ControllerIncarnationId derived = ControllerIncarnationId::derive(
        FacilityAuthorityDomainId::from_trusted(image.domain), ControllerId::from_trusted(controller.controller),
        IncarnationNumber::from_trusted(controller.incarnation_number));
    if (derived.digest() != controller.incarnation_id) {
      throw EpochError(ErrorCode::DigestMismatch, "controller " + controller.controller +
                                                     " incarnation identity does not match its incarnation number");
    }
    for (const Sha256Digest& superseded : controller.superseded_incarnations) {
      if (superseded == controller.incarnation_id) {
        throw EpochError(ErrorCode::DuplicateKey, "controller " + controller.controller +
                                                      " lists its current incarnation as superseded");
      }
    }
    if (controller.controller == image.authority_root) {
      root = &controller;
    }
  }
  if (root == nullptr) {
    throw EpochError(ErrorCode::CountMismatch, "the authority root is not a registered controller");
  }
  const auto origin = std::find_if(image.transitions.begin(), image.transitions.end(),
                                   [](const TransitionData& transition) { return transition.origin; });
  if (origin != image.transitions.end()) {
    if (origin->committed_by != image.authority_root) {
      throw EpochError(ErrorCode::CountMismatch, "the origin transition was not committed by the authority root");
    }
    if (root->first_registered_epoch != origin->new_epoch) {
      throw EpochError(ErrorCode::CountMismatch,
                       "the authority root was not registered in the epoch the origin transition created");
    }
  }

  // Grants: all belong to the current epoch, all reference known controllers.
  for (const GrantData& grant : image.grants) {
    verify_record_digest(grant, "image");
    if (grant.epoch != image.epoch) {
      throw EpochError(ErrorCode::CountMismatch, "grant " + std::to_string(grant.id) +
                                                     " does not belong to the current epoch");
    }
    if (grant.id >= image.next_grant_id) {
      throw EpochError(ErrorCode::OrderingViolation, "grant " + std::to_string(grant.id) +
                                                         " is not below the next grant identifier");
    }
    const auto controller = std::find_if(image.controllers.begin(), image.controllers.end(),
                                         [&grant](const ControllerData& candidate) {
                                           return candidate.controller == grant.controller;
                                         });
    if (controller == image.controllers.end()) {
      throw EpochError(ErrorCode::CountMismatch, "grant " + std::to_string(grant.id) +
                                                     " names an unregistered controller");
    }
    if (grant.incarnation_number > controller->incarnation_number) {
      throw EpochError(ErrorCode::OrderingViolation, "grant " + std::to_string(grant.id) +
                                                         " names an incarnation the controller never reached");
    }
    if (grant.state == GrantState::Live && grant.incarnation_number < controller->incarnation_number) {
      throw EpochError(ErrorCode::CountMismatch,
                       "grant " + std::to_string(grant.id) + " is live but its incarnation is superseded");
    }
    for (const std::string& scope : grant.scopes) {
      if (!reserved_scope_present(image.declared_scopes, scope)) {
        throw EpochError(ErrorCode::CountMismatch, "grant " + std::to_string(grant.id) +
                                                       " covers an undeclared scope");
      }
    }
  }

  // Revocation ledger chain.
  std::vector<Sha256Digest> revocation_digests;
  std::vector<Sha256Digest> revocation_previous;
  revocation_digests.reserve(image.revocations.size());
  revocation_previous.reserve(image.revocations.size());
  for (const RevocationData& revocation : image.revocations) {
    verify_record_digest(revocation, "image");
    revocation_digests.push_back(revocation.record_digest);
    revocation_previous.push_back(revocation.previous_record_digest);
    if (revocation.epoch > image.epoch) {
      throw EpochError(ErrorCode::OrderingViolation, "revocation " + std::to_string(revocation.sequence) +
                                                         " was recorded in a future epoch");
    }
  }
  verify_ledger_chain("revocation ledger", image.revocations.size(), image.revocation_count,
                      image.revocation_trimmed, image.revocation_anchor, revocation_digests, revocation_previous);
  if (!image.revocations.empty()) {
    if (image.revocations.front().sequence != image.revocation_count - image.revocations.size() + 1) {
      throw EpochError(ErrorCode::CountMismatch, "revocation sequences are not contiguous");
    }
    for (std::size_t index = 1; index < image.revocations.size(); ++index) {
      if (image.revocations[index].sequence != image.revocations[index - 1].sequence + 1) {
        throw EpochError(ErrorCode::CountMismatch, "revocation sequences are not contiguous");
      }
    }
  }

  // Revoked grants must reference a revocation that exists or was trimmed.
  for (const GrantData& grant : image.grants) {
    if (!grant.revoked_by_sequence.has_value()) {
      continue;
    }
    const std::uint64_t sequence = *grant.revoked_by_sequence;
    if (sequence == 0 || sequence > image.revocation_count) {
      throw EpochError(ErrorCode::CountMismatch, "grant " + std::to_string(grant.id) +
                                                     " names a revocation that was never issued");
    }
    const auto match = std::find_if(image.revocations.begin(), image.revocations.end(),
                                    [sequence](const RevocationData& candidate) {
                                      return candidate.sequence == sequence;
                                    });
    if (match == image.revocations.end()) {
      continue;  // trimmed: the sequence is still within the issued range
    }
    if (match->target_kind != RevocationTargetKind::Grant || !match->grant.has_value() ||
        *match->grant != grant.id) {
      throw EpochError(ErrorCode::CountMismatch, "grant " + std::to_string(grant.id) +
                                                     " names a revocation that does not target it");
    }
  }

  // Transition ledger chain.
  std::vector<Sha256Digest> transition_digests;
  std::vector<Sha256Digest> transition_previous;
  transition_digests.reserve(image.transitions.size());
  transition_previous.reserve(image.transitions.size());
  for (std::size_t index = 0; index < image.transitions.size(); ++index) {
    const TransitionData& transition = image.transitions[index];
    verify_record_digest(transition, "image");
    transition_digests.push_back(transition.record_digest);
    transition_previous.push_back(transition.previous_record_digest);
    if (!transition.origin && transition.new_epoch != transition.base_epoch + 1) {
      throw EpochError(ErrorCode::OrderingViolation, "transition " + std::to_string(transition.sequence) +
                                                         " does not advance the epoch by exactly one");
    }
    if (transition.origin && transition.sequence != 1) {
      throw EpochError(ErrorCode::OrderingViolation, "only the first transition may be an origin transition");
    }
    if (transition.origin && transition.new_epoch == 0) {
      throw EpochError(ErrorCode::OrderingViolation, "an origin transition must create an epoch");
    }
    if (transition.new_epoch > image.epoch) {
      throw EpochError(ErrorCode::OrderingViolation, "transition " + std::to_string(transition.sequence) +
                                                         " names an epoch beyond the current one");
    }
  }
  verify_ledger_chain("transition ledger", image.transitions.size(), image.transition_count,
                      image.transition_trimmed, image.transition_anchor, transition_digests, transition_previous);
  if (!image.transitions.empty()) {
    if (image.transitions.front().sequence != image.transition_count - image.transitions.size() + 1) {
      throw EpochError(ErrorCode::CountMismatch, "transition sequences are not contiguous");
    }
    for (std::size_t index = 1; index < image.transitions.size(); ++index) {
      if (image.transitions[index].sequence != image.transitions[index - 1].sequence + 1) {
        throw EpochError(ErrorCode::CountMismatch, "transition sequences are not contiguous");
      }
    }
    if (image.transitions.back().new_epoch != image.epoch) {
      throw EpochError(ErrorCode::OrderingViolation, "the newest transition does not produce the current epoch");
    }
  }
  if (image.transition_count == 0) {
    throw EpochError(ErrorCode::CountMismatch, "a durable generation always has at least one transition record");
  }

  // Idempotency ledger.
  if (image.idempotency_count < image.idempotency.size()) {
    throw EpochError(ErrorCode::CountMismatch, "retained idempotency records exceed the recorded total");
  }
  for (const IdempotencyData& entry : image.idempotency) {
    if (entry.incarnation_id.is_zero() || entry.command_digest.is_zero() || entry.sequence == 0) {
      throw EpochError(ErrorCode::CountMismatch, "an idempotency record is incomplete");
    }
    if (entry.result_blob.empty() || entry.result_blob.size() > max_idempotency_blob_bytes) {
      throw EpochError(ErrorCode::IntegrityLimitExceeded, "an idempotency result blob is empty or oversized");
    }
  }

  // Counters.
  if (image.next_mutation_sequence == 0 || image.next_mutation_sequence <= image.transition_count) {
    throw EpochError(ErrorCode::OrderingViolation, "the mutation sequence counter is behind the ledger");
  }
}

std::vector<std::byte> encode_envelope(const FileEnvelope& envelope, std::size_t max_total_bytes) {
  if (envelope.payload.size() > std::numeric_limits<std::uint32_t>::max()) {
    throw EpochError(ErrorCode::SizeLimitExceeded, "durable payload exceeds the encodable length");
  }
  const std::size_t total = checked_add(envelope_header_bytes, envelope.payload.size(), "durable envelope");
  if (total > max_total_bytes) {
    throw EpochError(ErrorCode::DurableLimitsExceeded, "durable envelope of " + std::to_string(total) +
                                                           " bytes exceeds the bound of " +
                                                           std::to_string(max_total_bytes));
  }

  std::vector<std::byte> bytes;
  bytes.reserve(total);
  bytes.insert(bytes.end(), kEnvelopeMagic.begin(), kEnvelopeMagic.end());
  CanonicalWriter writer(max_total_bytes);
  writer.u16(envelope.format_version);
  writer.u16(envelope.schema_version);
  writer.u32(envelope.flags);
  writer.u64(envelope.generation);
  writer.u64(envelope.epoch);
  writer.u32(static_cast<std::uint32_t>(envelope.payload.size()));
  writer.digest(sha256(std::span<const std::byte>(envelope.payload)));
  const std::vector<std::byte>& header_tail = writer.data();
  bytes.insert(bytes.end(), header_tail.begin(), header_tail.end());
  bytes.insert(bytes.end(), envelope.payload.begin(), envelope.payload.end());
  return bytes;
}

FileEnvelope decode_envelope(std::span<const std::byte> bytes, std::size_t max_total_bytes) {
  if (bytes.size() < envelope_header_bytes) {
    throw EpochError(ErrorCode::Truncated, "durable file is shorter than its header");
  }
  if (!std::equal(kEnvelopeMagic.begin(), kEnvelopeMagic.end(), bytes.begin())) {
    throw EpochError(ErrorCode::MagicMismatch, "durable file magic is not CPE1");
  }

  CanonicalReader reader(bytes.subspan(kEnvelopeMagic.size(), envelope_header_bytes - kEnvelopeMagic.size()),
                         kMaxTextBytes);
  FileEnvelope envelope;
  envelope.format_version = reader.u16();
  envelope.schema_version = reader.u16();
  envelope.flags = reader.u32();
  envelope.generation = reader.u64();
  envelope.epoch = reader.u64();
  const std::uint32_t payload_length = reader.u32();
  envelope.payload_digest = reader.digest();
  reader.expect_end();

  if (envelope.format_version != static_cast<std::uint16_t>(durable_format_version)) {
    throw EpochError(ErrorCode::FormatVersionUnsupported,
                     "durable format version " + std::to_string(envelope.format_version) + " is not supported");
  }
  // The envelope's own schema field must be validated too: it sits outside the
  // digested payload, so without this check a flipped bit there would be the one
  // part of a durable file that is neither validated nor authenticated.
  if (envelope.schema_version != static_cast<std::uint16_t>(durable_schema_version)) {
    throw EpochError(ErrorCode::SchemaUnsupported,
                     "durable file schema version " + std::to_string(envelope.schema_version) +
                         " is not supported");
  }
  if ((envelope.flags & ~kEnvelopeFlagMask) != 0) {
    throw EpochError(ErrorCode::EnumOutOfDomain, "durable file declares unsupported flags");
  }
  if (payload_length > max_total_bytes || payload_length > max_snapshot_bytes) {
    throw EpochError(ErrorCode::IntegrityLimitExceeded,
                     "durable payload length " + std::to_string(payload_length) + " exceeds the bound");
  }
  const std::size_t expected_total = checked_add(envelope_header_bytes, payload_length, "durable file");
  if (bytes.size() != expected_total) {
    throw EpochError(ErrorCode::SizeMismatch,
                     "durable file is " + std::to_string(bytes.size()) + " bytes but declares " +
                         std::to_string(expected_total));
  }

  envelope.payload.assign(bytes.begin() + static_cast<std::ptrdiff_t>(envelope_header_bytes), bytes.end());
  if (sha256(std::span<const std::byte>(envelope.payload)) != envelope.payload_digest) {
    throw EpochError(ErrorCode::DigestMismatch, "durable payload digest does not match its content");
  }
  return envelope;
}

std::vector<std::byte> encode_floor(const FloorData& floor) {
  CanonicalWriter writer(max_floor_bytes);
  writer.u32(static_cast<std::uint32_t>(durable_schema_version));
  writer.text(floor.domain);
  writer.u64(floor.domain_instance);
  writer.u64(floor.epoch);
  writer.u64(floor.generation);
  writer.digest(floor.snapshot_digest);
  return writer.take();
}

FloorData decode_floor(std::span<const std::byte> payload) {
  CanonicalReader reader(payload, kMaxTextBytes);
  FloorData floor;
  const std::uint32_t schema = reader.u32();
  if (schema != static_cast<std::uint32_t>(durable_schema_version)) {
    throw EpochError(ErrorCode::SchemaUnsupported,
                     "floor schema version " + std::to_string(schema) + " is not supported");
  }
  floor.domain = read_identifier_text(reader, "floor domain");
  floor.domain_instance = read_required_u64(reader, "floor domain instance");
  floor.epoch = read_required_u64(reader, "floor epoch");
  floor.generation = read_required_u64(reader, "floor generation");
  floor.snapshot_digest = reader.digest();
  reader.expect_end();
  return floor;
}

}  // namespace dccp::epoch::detail

