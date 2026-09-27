// Control Plane Epoch 1.0.0 - Summon Software Labs
// Remote controller client.
//
// One client owns one connection and issues one request at a time. The client
// never times a request out: it either receives a complete, digest-verified
// response that answers its outstanding request, or it reports an explicit
// transport failure. Results and rejections are the same types a local consumer
// uses, so a remote controller and a local one see identical semantics.
#include "control_plane_epoch/client.hpp"

#include <utility>

#include "control_plane_epoch/protocol.hpp"
#include "control_plane_epoch/version.hpp"

#include "socket.hpp"
#include "wire.hpp"

namespace dccp::epoch {

namespace detail {

class ClientCore {
 public:
  explicit ClientCore(const ClientOptions& options)
      : max_frame_payload_bytes_(options.max_frame_payload_bytes), socket_(net::connect_to(options.host, options.port)) {
    HelloPayload hello;
    hello.protocol_version = static_cast<std::uint16_t>(protocol_version);
    hello.max_frame_payload_bytes = static_cast<std::uint16_t>(max_frame_payload_bytes_);

    const Frame response = exchange(MessageType::HelloRequest, encode_hello_request(hello));
    if (response.header().type == MessageType::ErrorResponse) {
      const ErrorPayload error = decode_error(response.payload());
      throw EpochError(error.code, "the authority refused the handshake: " + error.detail);
    }
    if (response.header().type != MessageType::HelloResponse) {
      throw EpochError(ErrorCode::HandshakeRejected, "the authority did not answer the handshake");
    }
    const HelloResponsePayload handshake = decode_hello_response(response.payload());
    if (handshake.protocol_version != static_cast<std::uint16_t>(protocol_version)) {
      throw EpochError(ErrorCode::ProtocolVersionUnsupported,
                       "the authority speaks protocol version " + std::to_string(handshake.protocol_version));
    }
    if (options.expected_domain.has_value() && handshake.domain != options.expected_domain->str()) {
      throw EpochError(ErrorCode::ProtocolDomainMismatch,
                       "the authority serves domain '" + handshake.domain + "' but '" +
                           options.expected_domain->to_string() + "' was expected");
    }

    endpoint_.protocol_version_ = handshake.protocol_version;
    if (!handshake.domain.empty()) {
      endpoint_.domain_ = FacilityAuthorityDomainId::from_trusted(handshake.domain);
    }
    if (handshake.domain_instance != 0) {
      endpoint_.domain_instance_ = DomainInstanceNumber::from_trusted(handshake.domain_instance);
    }
    if (handshake.epoch != 0) {
      endpoint_.epoch_ = Epoch::from_trusted(handshake.epoch);
    }
    if (handshake.generation != 0) {
      endpoint_.durable_generation_ = DurableGeneration::from_trusted(handshake.generation);
    }
    endpoint_.initialized_ = handshake.initialized;
  }

  ~ClientCore() { close(); }

  ClientCore(const ClientCore&) = delete;
  ClientCore& operator=(const ClientCore&) = delete;

  [[nodiscard]] const AuthorityEndpointInfo& endpoint() const noexcept { return endpoint_; }
  [[nodiscard]] std::uint64_t request_count() const noexcept { return request_count_; }
  [[nodiscard]] bool closed() const noexcept { return !socket_.valid(); }

  void close() noexcept { socket_.close(); }

  Result<ControllerRegistration> register_controller(RegisterControllerRequest request) {
    const Frame response = exchange(MessageType::RegisterControllerRequest, encode_register_request(request));
    if (auto rejection = check_error(response)) {
      return *rejection;
    }
    require_type(response, MessageType::RegisterControllerResponse);
    return decode_register_response(response.payload());
  }

  Result<AuthorityGrantView> acquire_authority(AcquireAuthorityRequest request) {
    const Frame response = exchange(MessageType::AcquireAuthorityRequest, encode_acquire_request(request));
    if (auto rejection = check_error(response)) {
      return *rejection;
    }
    require_type(response, MessageType::AcquireAuthorityResponse);
    const GrantData grant = decode_acquire_response(response.payload());
    Result<AuthorityGrantView> view = to_grant_view(grant, endpoint_.domain_);
    if (!view.has_value()) {
      return view.rejection();
    }
    return view;
  }

  ValidationOutcome validate_mutation(const MutationAuthority& authority, const ScopeName& scope) {
    return validate(MessageType::ValidateMutationRequest, MessageType::ValidateMutationResponse, authority.to_string(),
                    scope);
  }

  ValidationOutcome validate_observation(const ObservationAuthority& authority, const ScopeName& scope) {
    return validate(MessageType::ValidateObservationRequest, MessageType::ValidateObservationResponse,
                    authority.to_string(), scope);
  }

  Result<EpochTransitionRecord> advance_epoch(AdvanceEpochRequest request) {
    const Frame response = exchange(MessageType::AdvanceEpochRequest, encode_advance_request(request));
    if (auto rejection = check_error(response)) {
      return *rejection;
    }
    require_type(response, MessageType::AdvanceEpochResponse);
    return RecordFactory::make_transition(decode_transition_response(response.payload()));
  }

  Result<RevocationRecord> revoke_authority(RevokeAuthorityRequest request) {
    const Frame response = exchange(MessageType::RevokeRequest, encode_revoke_request(request));
    if (auto rejection = check_error(response)) {
      return *rejection;
    }
    require_type(response, MessageType::RevokeResponse);
    return RecordFactory::make_revocation(decode_revocation_response(response.payload()));
  }

  Result<RecoveryQualification> qualify_recovered_state(const RecoveredStateClaim& claim) {
    const Frame response = exchange(MessageType::QualifyRecoveredStateRequest, encode_qualify_request(claim));
    if (auto rejection = check_error(response)) {
      return *rejection;
    }
    require_type(response, MessageType::QualifyRecoveredStateResponse);
    const QualificationPayload payload = decode_qualification(response.payload());
    std::optional<GrantId> matching;
    if (payload.matching_grant.has_value()) {
      matching = GrantId::from_trusted(*payload.matching_grant);
    }
    return RecoveryQualification(payload.verdict, Explanation(payload.code, payload.detail), matching,
                                 payload.requires_revalidation);
  }

  Result<AuthorityStatus> status() {
    const Frame response = exchange(MessageType::StatusRequest, Payload{});
    if (auto rejection = check_error(response)) {
      return *rejection;
    }
    require_type(response, MessageType::StatusResponse);
    const StatusPayload payload = decode_status(response.payload());

    AuthorityStatus result;
    result.domain_ = FacilityAuthorityDomainId::from_trusted(payload.domain);
    result.domain_instance_ = DomainInstanceNumber::from_trusted(payload.domain_instance);
    result.epoch_ = Epoch::from_trusted(payload.epoch);
    result.durable_generation_ = DurableGeneration::from_trusted(payload.generation);
    result.authority_root_ = ControllerId::from_trusted(payload.authority_root);
    result.controller_count_ = payload.controller_count;
    result.live_grant_count_ = payload.live_grant_count;
    result.mutation_grant_count_ = payload.mutation_grant_count;
    result.observation_grant_count_ = payload.observation_grant_count;
    for (const std::string& scope : payload.declared_scopes) {
      result.declared_scopes_.push_back(ScopeName::from_trusted(scope));
    }
    result.transition_count_ = payload.transition_count;
    result.revocation_count_ = payload.revocation_count;
    result.idempotency_record_count_ = payload.idempotency_record_count;
    result.snapshot_digest_ = payload.snapshot_digest;
    result.transition_chain_head_ = payload.transition_chain_head;
    result.recovery_outcome_ = payload.recovery_outcome;
    result.open_mode_ = payload.open_mode;
    result.initialized_ = true;
    return result;
  }

  Result<EpochHistoryPage> history(const HistoryQuery& query) {
    HistoryRequestPayload request;
    if (query.from_sequence.has_value()) {
      request.from_sequence = query.from_sequence->value();
    }
    request.limit = query.limit;
    const Frame response = exchange(MessageType::HistoryRequest, encode_history_request(request));
    if (auto rejection = check_error(response)) {
      return *rejection;
    }
    require_type(response, MessageType::HistoryResponse);
    const HistoryResponsePayload payload = decode_history_response(response.payload());
    std::vector<EpochTransitionRecord> records;
    records.reserve(payload.records.size());
    for (const TransitionData& record : payload.records) {
      records.push_back(RecordFactory::make_transition(record));
    }
    return RecordFactory::make_history_page(std::move(records), payload.page.total_count,
                                            payload.page.first_retained, payload.page.trimmed_count,
                                            payload.page.anchor, payload.page.chain_head);
  }

  Result<RevocationPage> revocations(const RevocationQuery& query) {
    RevocationsRequestPayload request;
    if (query.from_sequence.has_value()) {
      request.from_sequence = query.from_sequence->value();
    }
    request.limit = query.limit;
    const Frame response = exchange(MessageType::RevocationsRequest, encode_revocations_request(request));
    if (auto rejection = check_error(response)) {
      return *rejection;
    }
    require_type(response, MessageType::RevocationsResponse);
    const RevocationsResponsePayload payload = decode_revocations_response(response.payload());

    RevocationPage page;
    page.total_count_ = payload.page.total_count;
    page.first_retained_sequence_ = payload.page.first_retained;
    page.trimmed_count_ = payload.page.trimmed_count;
    page.chain_head_ = payload.page.chain_head;
    page.records_.reserve(payload.records.size());
    for (const RevocationData& record : payload.records) {
      page.records_.push_back(RecordFactory::make_revocation(record));
    }
    return page;
  }

  Result<ControllerPage> controllers(const ControllerQuery& query) {
    ControllersRequestPayload request;
    if (query.from_controller.has_value()) {
      request.from_controller = query.from_controller->str();
    }
    request.limit = query.limit;
    const Frame response = exchange(MessageType::ControllersRequest, encode_controllers_request(request));
    if (auto rejection = check_error(response)) {
      return *rejection;
    }
    require_type(response, MessageType::ControllersResponse);
    const ControllersResponsePayload payload = decode_controllers_response(response.payload());

    ControllerPage page;
    page.total_count_ = payload.total_count;
    page.records_.reserve(payload.records.size());
    for (const ControllerData& record : payload.records) {
      page.records_.push_back(RecordFactory::make_controller(record));
    }
    return page;
  }

  Result<GrantPage> grants(const GrantQuery& query) {
    GrantsRequestPayload request;
    if (query.from_grant.has_value()) {
      request.from_grant = query.from_grant->value();
    }
    request.limit = query.limit;
    const Frame response = exchange(MessageType::GrantsRequest, encode_grants_request(request));
    if (auto rejection = check_error(response)) {
      return *rejection;
    }
    require_type(response, MessageType::GrantsResponse);
    const GrantsResponsePayload payload = decode_grants_response(response.payload());

    GrantPage page;
    page.total_count_ = payload.total_count;
    page.epoch_ = Epoch::from_trusted(payload.epoch);
    page.records_.reserve(payload.records.size());
    for (const GrantData& record : payload.records) {
      page.records_.push_back(RecordFactory::make_grant(record));
    }
    return page;
  }

 private:
  [[nodiscard]] ValidationOutcome validate(MessageType request_type, MessageType response_type,
                                           const std::string& token, const ScopeName& scope) {
    ValidateRequestPayload request;
    request.token = token;
    request.scope = scope.str();
    const Frame response = exchange(request_type, encode_validate_request(request));
    if (auto rejection = check_error(response)) {
      return ValidationOutcome::reject(*rejection);
    }
    require_type(response, response_type);
    const ValidationPayload payload = decode_validation(response.payload());
    if (payload.accepted) {
      return ValidationOutcome::accept();
    }
    return ValidationOutcome::reject(Explanation(payload.code, payload.detail));
  }

  [[nodiscard]] std::optional<Explanation> check_error(const Frame& response) const {
    if (response.header().type != MessageType::ErrorResponse) {
      return std::nullopt;
    }
    const ErrorPayload error = decode_error(response.payload());
    return Explanation(error.code, error.detail);
  }

  void require_type(const Frame& response, MessageType expected) const {
    if (response.header().type != expected) {
      throw EpochError(ErrorCode::MalformedPayload, "the authority answered with " +
                                                       std::string(message_type_token(response.header().type)) +
                                                       " where " + std::string(message_type_token(expected)) +
                                                       " was expected");
    }
  }

  /// Sends one request and returns the response that answers exactly that
  /// request identifier. A response that does not answer the outstanding request
  /// is a protocol failure, never a silently accepted result.
  [[nodiscard]] Frame exchange(MessageType type, const Payload& payload) {
    if (!socket_.valid()) {
      throw EpochError(ErrorCode::SocketClosed, "the connection to the authority is closed");
    }
    const std::uint64_t request_id = ++request_count_;

    Frame request = make_frame(type, request_id, payload);
    std::vector<std::byte> bytes;
    const Status encoded = encode_frame(request, bytes, max_frame_payload_bytes_);
    if (!encoded.has_value()) {
      throw EpochError(encoded.rejection());
    }
    socket_.send_all(std::span<const std::byte>(bytes));

    std::vector<std::byte> header_bytes(frame_header_bytes);
    if (!socket_.recv_exact(std::span<std::byte>(header_bytes))) {
      throw EpochError(ErrorCode::SocketClosed, "the authority closed the connection before answering");
    }
    const std::uint32_t declared_length =
        static_cast<std::uint32_t>(static_cast<unsigned char>(header_bytes[20])) |
        (static_cast<std::uint32_t>(static_cast<unsigned char>(header_bytes[21])) << 8) |
        (static_cast<std::uint32_t>(static_cast<unsigned char>(header_bytes[22])) << 16) |
        (static_cast<std::uint32_t>(static_cast<unsigned char>(header_bytes[23])) << 24);
    if (declared_length > max_frame_payload_bytes_) {
      throw EpochError(ErrorCode::FrameTooLarge, "the authority declared a payload of " +
                                                    std::to_string(declared_length) + " bytes");
    }

    std::vector<std::byte> frame_bytes(frame_header_bytes + declared_length);
    std::copy(header_bytes.begin(), header_bytes.end(), frame_bytes.begin());
    if (declared_length > 0) {
      std::span<std::byte> body(frame_bytes.data() + frame_header_bytes, declared_length);
      if (!socket_.recv_exact(body)) {
        throw EpochError(ErrorCode::FrameTruncated, "the authority closed the connection inside a frame");
      }
    }

    Result<Frame> decoded = decode_frame(std::span<const std::byte>(frame_bytes), max_frame_payload_bytes_);
    if (!decoded.has_value()) {
      throw EpochError(decoded.rejection());
    }
    if (decoded.value().header().request_id != request_id) {
      throw EpochError(ErrorCode::RequestIdMismatch,
                       "the response answers request " + std::to_string(decoded.value().header().request_id) +
                           " while " + std::to_string(request_id) + " was outstanding");
    }
    return decoded.move_value();
  }

  [[nodiscard]] static Frame make_frame(MessageType type, std::uint64_t request_id, const Payload& payload) {
    FrameHeader header;
    header.type = type;
    header.request_id = request_id;
    header.payload_length = static_cast<std::uint32_t>(payload.size());
    header.payload_digest = sha256(std::span<const std::byte>(payload));
    return Frame(header, payload);
  }

  std::size_t max_frame_payload_bytes_ = max_frame_payload_bytes;
  net::Socket socket_;
  AuthorityEndpointInfo endpoint_;
  std::uint64_t request_count_ = 0;
};

}  // namespace detail

EpochAuthorityClient::EpochAuthorityClient(const ClientOptions& options)
    : core_(std::make_unique<detail::ClientCore>(options)) {}

EpochAuthorityClient::~EpochAuthorityClient() = default;

const AuthorityEndpointInfo& EpochAuthorityClient::endpoint() const noexcept { return core_->endpoint(); }

Result<ControllerRegistration> EpochAuthorityClient::register_controller(RegisterControllerRequest request) {
  return core_->register_controller(std::move(request));
}

Result<AuthorityGrantView> EpochAuthorityClient::acquire_authority(AcquireAuthorityRequest request) {
  return core_->acquire_authority(std::move(request));
}

ValidationOutcome EpochAuthorityClient::validate_mutation(const MutationAuthority& authority,
                                                          const ScopeName& scope) {
  return core_->validate_mutation(authority, scope);
}

ValidationOutcome EpochAuthorityClient::validate_observation(const ObservationAuthority& authority,
                                                             const ScopeName& scope) {
  return core_->validate_observation(authority, scope);
}

Result<EpochTransitionRecord> EpochAuthorityClient::advance_epoch(AdvanceEpochRequest request) {
  return core_->advance_epoch(std::move(request));
}

Result<RevocationRecord> EpochAuthorityClient::revoke_authority(RevokeAuthorityRequest request) {
  return core_->revoke_authority(std::move(request));
}

Result<RecoveryQualification> EpochAuthorityClient::qualify_recovered_state(const RecoveredStateClaim& claim) {
  return core_->qualify_recovered_state(claim);
}

Result<AuthorityStatus> EpochAuthorityClient::status() { return core_->status(); }

Result<EpochHistoryPage> EpochAuthorityClient::history(const HistoryQuery& query) { return core_->history(query); }

Result<RevocationPage> EpochAuthorityClient::revocations(const RevocationQuery& query) {
  return core_->revocations(query);
}

Result<ControllerPage> EpochAuthorityClient::controllers(const ControllerQuery& query) {
  return core_->controllers(query);
}

Result<GrantPage> EpochAuthorityClient::grants(const GrantQuery& query) { return core_->grants(query); }

std::uint64_t EpochAuthorityClient::request_count() const noexcept { return core_->request_count(); }

void EpochAuthorityClient::close() noexcept { core_->close(); }

bool EpochAuthorityClient::closed() const noexcept { return core_->closed(); }

std::string AuthorityEndpointInfo::to_string() const {
  std::string text;
  text += "protocol_version=" + std::to_string(protocol_version_);
  text += " initialized=";
  text += initialized_ ? "yes" : "no";
  text += " domain=";
  text += domain_.empty() ? std::string("-") : domain_.str();
  if (domain_instance_.is_set()) {
    text += " domain_instance=" + domain_instance_.to_string();
  }
  if (epoch_.value() != 0) {
    text += " epoch=" + epoch_.to_string();
  }
  if (durable_generation_.is_set()) {
    text += " durable_generation=" + durable_generation_.to_string();
  }
  return text;
}

}  // namespace dccp::epoch

