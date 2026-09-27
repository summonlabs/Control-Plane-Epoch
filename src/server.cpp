// Control Plane Epoch 1.0.0 - Summon Software Labs
// Remote authority runtime.
//
// The runtime decodes a request, calls exactly the same authority method a local
// consumer would call, and encodes the outcome. It never bypasses an authority,
// generation, or integrity check, and it holds no authority state of its own.
#include "control_plane_epoch/server.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#include "control_plane_epoch/protocol.hpp"
#include "control_plane_epoch/version.hpp"

#include "socket.hpp"
#include "wire.hpp"

namespace dccp::epoch {
namespace {

/// Shutdown responsiveness interval for the accept loop. This is not a request
/// timeout: an accepted session is served with blocking I/O until it finishes or
/// the peer closes.
constexpr std::uint32_t kAcceptWaitMilliseconds = 50;

[[nodiscard]] Frame make_error_frame(std::uint64_t request_id, ErrorCode code, std::string detail) {
  detail::ErrorPayload payload;
  payload.code = code;
  payload.detail = std::move(detail);

  FrameHeader header;
  header.type = MessageType::ErrorResponse;
  header.request_id = request_id;
  detail::Payload encoded = detail::encode_error(payload);
  header.payload_length = static_cast<std::uint32_t>(encoded.size());
  header.payload_digest = sha256(std::span<const std::byte>(encoded));
  return Frame(header, std::move(encoded));
}

[[nodiscard]] Frame make_frame(MessageType type, std::uint64_t request_id, detail::Payload payload) {
  FrameHeader header;
  header.type = type;
  header.request_id = request_id;
  header.payload_length = static_cast<std::uint32_t>(payload.size());
  header.payload_digest = sha256(std::span<const std::byte>(payload));
  return Frame(header, std::move(payload));
}

}  // namespace

namespace detail {

class ServerCore {
 public:
  ServerCore(ControlPlaneEpochAuthority& authority, ServerOptions options)
      : authority_(&authority), options_(std::move(options)) {
    if (options_.workers == 0 || options_.workers > max_server_workers) {
      throw EpochError(ErrorCode::InvalidOption,
                       "worker count must be between 1 and " + std::to_string(max_server_workers));
    }
    if (options_.queue_depth == 0 || options_.max_connections == 0) {
      throw EpochError(ErrorCode::InvalidOption, "queue depth and connection bound must be non-zero");
    }
    if (options_.max_frame_payload_bytes == 0 || options_.max_frame_payload_bytes > max_frame_payload_bytes) {
      throw EpochError(ErrorCode::InvalidOption, "frame payload bound is outside its permitted range");
    }
    if (options_.max_requests_per_connection == 0) {
      throw EpochError(ErrorCode::InvalidOption, "requests-per-connection bound must be non-zero");
    }
    listener_.bind_and_listen(options_.bind_address, options_.port, server_listen_backlog);
  }

  ~ServerCore() { stop(); }

  ServerCore(const ServerCore&) = delete;
  ServerCore& operator=(const ServerCore&) = delete;

  void start() {
    std::lock_guard<std::mutex> guard(lifecycle_mutex_);
    if (running_) {
      return;
    }
    stopping_.store(false);
    running_ = true;
    workers_.reserve(options_.workers);
    for (std::uint32_t index = 0; index < options_.workers; ++index) {
      workers_.emplace_back([this] { worker_loop(); });
    }
  }

  std::uint64_t accept_until(std::uint64_t max_requests) {
    start();
    const std::uint64_t start_count = requests_served_.load();
    while (!stopping_.load()) {
      if (max_requests != 0 && (requests_served_.load() - start_count) >= max_requests) {
        break;
      }
      net::Socket session = listener_.accept_one(kAcceptWaitMilliseconds);
      if (!session.valid()) {
        continue;
      }
      if (stopping_.load()) {
        break;
      }
      if (active_connections_.load() >= options_.max_connections) {
        // Bound reached: answer explicitly instead of accepting unbounded work.
        try {
          const Frame response =
              make_error_frame(0, ErrorCode::ConnectionLimitReached, "the runtime is at its connection bound");
          std::vector<std::byte> bytes;
          (void)encode_frame(response, bytes, options_.max_frame_payload_bytes);
          session.send_all(std::span<const std::byte>(bytes));
        } catch (const EpochError&) {
          // The peer is already gone; nothing to do.
        }
        session.close();
        continue;
      }

      {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        queue_space_.wait(lock, [this] { return stopping_.load() || queue_.size() < options_.queue_depth; });
        if (stopping_.load()) {
          break;
        }
        queue_.push_back(std::move(session));
      }
      queue_ready_.notify_one();
    }
    return requests_served_.load() - start_count;
  }

  void stop() noexcept {
    {
      std::lock_guard<std::mutex> guard(lifecycle_mutex_);
      if (!running_ && workers_.empty()) {
        listener_.close();
        return;
      }
      stopping_.store(true);
    }
    listener_.shutdown();
    listener_.close();

    {
      // Release any worker blocked on a session read. Handles are removed from
      // this registry by the worker before the socket is destroyed, and the
      // registry is only touched under this mutex, so no shutdown can ever land
      // on a recycled handle.
      std::lock_guard<std::mutex> guard(sessions_mutex_);
      for (const std::intptr_t handle : active_sessions_) {
        net::shutdown_handle(handle);
      }
    }

    queue_ready_.notify_all();
    queue_space_.notify_all();

    for (std::thread& worker : workers_) {
      if (worker.joinable()) {
        worker.join();
      }
    }
    workers_.clear();
    running_ = false;
  }

  [[nodiscard]] bool running() const noexcept { return running_; }

  [[nodiscard]] std::uint16_t port() const noexcept { return listener_.bound_port(); }

  [[nodiscard]] std::string endpoint() const {
    return options_.bind_address + ":" + std::to_string(listener_.bound_port());
  }

  [[nodiscard]] ServerAccounting accounting() const {
    ServerAccounting snapshot;
    snapshot.active_connections_ = active_connections_.load();
    snapshot.sessions_accepted_ = sessions_accepted_.load();
    snapshot.sessions_closed_ = sessions_closed_.load();
    snapshot.requests_served_ = requests_served_.load();
    snapshot.requests_rejected_ = requests_rejected_.load();
    snapshot.bytes_received_ = bytes_received_.load();
    snapshot.bytes_sent_ = bytes_sent_.load();
    snapshot.workers_ = options_.workers;
    snapshot.stopping_ = stopping_.load();
    return snapshot;
  }

 private:
  void worker_loop() {
    while (true) {
      net::Socket session;
      {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        queue_ready_.wait(lock, [this] { return stopping_.load() || !queue_.empty(); });
        if (queue_.empty()) {
          if (stopping_.load()) {
            return;
          }
          continue;
        }
        session = std::move(queue_.front());
        queue_.pop_front();
      }
      queue_space_.notify_one();

      if (stopping_.load()) {
        // Work that had not started when shutdown was requested is answered
        // explicitly and never applied.
        try {
          const Frame response = make_error_frame(0, ErrorCode::ServerStopping, "the runtime is shutting down");
          std::vector<std::byte> bytes;
          (void)encode_frame(response, bytes, options_.max_frame_payload_bytes);
          session.send_all(std::span<const std::byte>(bytes));
        } catch (const EpochError&) {
        }
        session.close();
        continue;
      }
      serve_session(std::move(session));
    }
  }

  void register_session(std::intptr_t handle) {
    std::lock_guard<std::mutex> guard(sessions_mutex_);
    active_sessions_.push_back(handle);
  }

  void unregister_session(std::intptr_t handle) noexcept {
    std::lock_guard<std::mutex> guard(sessions_mutex_);
    const auto match = std::find(active_sessions_.begin(), active_sessions_.end(), handle);
    if (match != active_sessions_.end()) {
      active_sessions_.erase(match);
    }
  }

  void serve_session(net::Socket session) {
    const std::intptr_t handle = session.native();
    register_session(handle);
    active_connections_.fetch_add(1);
    sessions_accepted_.fetch_add(1);

    bool handshaken = false;
    bool alive = true;
    std::uint64_t served_here = 0;

    try {
      while (alive && !stopping_.load()) {
        std::vector<std::byte> header_bytes(frame_header_bytes);
        if (!session.recv_exact(std::span<std::byte>(header_bytes))) {
          break;  // clean close between frames
        }
        bytes_received_.fetch_add(header_bytes.size());

        const std::uint32_t declared_length =
            static_cast<std::uint32_t>(static_cast<unsigned char>(header_bytes[20])) |
            (static_cast<std::uint32_t>(static_cast<unsigned char>(header_bytes[21])) << 8) |
            (static_cast<std::uint32_t>(static_cast<unsigned char>(header_bytes[22])) << 16) |
            (static_cast<std::uint32_t>(static_cast<unsigned char>(header_bytes[23])) << 24);

        // The bound is enforced before a single payload byte is allocated.
        if (declared_length > options_.max_frame_payload_bytes) {
          requests_rejected_.fetch_add(1);
          send_frame(session, make_error_frame(0, ErrorCode::FrameTooLarge,
                                               "declared payload length " + std::to_string(declared_length) +
                                                   " exceeds the bound of " +
                                                   std::to_string(options_.max_frame_payload_bytes)));
          break;
        }

        std::vector<std::byte> frame_bytes(frame_header_bytes + declared_length);
        std::copy(header_bytes.begin(), header_bytes.end(), frame_bytes.begin());
        if (declared_length > 0) {
          std::span<std::byte> body(frame_bytes.data() + frame_header_bytes, declared_length);
          if (!session.recv_exact(body)) {
            throw EpochError(ErrorCode::FrameTruncated, "the peer closed the connection inside a frame");
          }
          bytes_received_.fetch_add(declared_length);
        }

        Result<Frame> decoded = decode_frame(std::span<const std::byte>(frame_bytes), options_.max_frame_payload_bytes);
        if (!decoded.has_value()) {
          requests_rejected_.fetch_add(1);
          send_frame(session, make_error_frame(0, decoded.rejection().code(), decoded.rejection().detail()));
          break;  // a framing failure means the stream can no longer be trusted
        }

        const Frame& request = decoded.value();
        if (request.header().type == MessageType::HelloRequest) {
          handshaken = handle_hello(session, request);
          ++served_here;
          requests_served_.fetch_add(1);
          if (!handshaken) {
            break;
          }
          if (served_here >= options_.max_requests_per_connection) {
            break;
          }
          continue;
        }
        if (!handshaken) {
          requests_rejected_.fetch_add(1);
          send_frame(session, make_error_frame(request.header().request_id, ErrorCode::HandshakeRequired,
                                               "a handshake must complete before other requests"));
          break;
        }

        const bool ok = handle_request(session, request);
        ++served_here;
        requests_served_.fetch_add(1);
        if (!ok) {
          alive = false;
        }
        if (served_here >= options_.max_requests_per_connection) {
          break;  // bounded per-session work; the client reconnects
        }
      }
    } catch (const EpochError& error) {
      // A failing session is closed; the runtime itself stays healthy.
      if (error.code() != ErrorCode::SocketClosed && error.code() != ErrorCode::FrameTruncated) {
        requests_rejected_.fetch_add(1);
      }
    }

    unregister_session(handle);
    session.close();
    active_connections_.fetch_sub(1);
    sessions_closed_.fetch_add(1);
  }

  [[nodiscard]] bool handle_hello(net::Socket& session, const Frame& request) {
    detail::HelloPayload hello = detail::decode_hello_request(request.payload());
    if (hello.protocol_version != static_cast<std::uint16_t>(protocol_version)) {
      send_frame(session, make_error_frame(request.header().request_id, ErrorCode::ProtocolVersionUnsupported,
                                           "protocol version " + std::to_string(hello.protocol_version) +
                                               " is not supported"));
      return false;
    }

    detail::HelloResponsePayload response;
    response.protocol_version = static_cast<std::uint16_t>(protocol_version);
    response.max_frame_payload_bytes = static_cast<std::uint16_t>(options_.max_frame_payload_bytes);
    if (authority_->initialized()) {
      const AuthorityStatus status = authority_->status();
      response.initialized = true;
      response.domain = status.domain().str();
      response.domain_instance = status.domain_instance().value();
      response.epoch = status.epoch().value();
      response.generation = status.durable_generation().value();
    }
    send_frame(session, make_frame(MessageType::HelloResponse, request.header().request_id,
                                   detail::encode_hello_response(response)));
    return true;
  }

  /// Returns false when the session must be closed.
  [[nodiscard]] bool handle_request(net::Socket& session, const Frame& request) {
    const std::uint64_t request_id = request.header().request_id;
    try {
      switch (request.header().type) {
        case MessageType::StatusRequest: {
          if (!request.payload().empty()) {
            return reject_and_keep(session, request_id, ErrorCode::MalformedPayload,
                                   "a status request carries no payload");
          }
          if (!authority_->initialized()) {
            return reject_and_keep(session, request_id, ErrorCode::StoreNotInitialized,
                                   "the authority domain has not been initialized yet");
          }
          const AuthorityStatus status = authority_->status();
          detail::StatusPayload payload;
          payload.domain = status.domain().str();
          payload.domain_instance = status.domain_instance().value();
          payload.epoch = status.epoch().value();
          payload.generation = status.durable_generation().value();
          payload.authority_root = status.authority_root().str();
          payload.controller_count = status.controller_count();
          payload.live_grant_count = status.live_grant_count();
          payload.mutation_grant_count = status.mutation_grant_count();
          payload.observation_grant_count = status.observation_grant_count();
          for (const ScopeName& scope : status.declared_scopes()) {
            payload.declared_scopes.push_back(scope.str());
          }
          payload.transition_count = status.transition_count();
          payload.revocation_count = status.revocation_count();
          payload.idempotency_record_count = status.idempotency_record_count();
          payload.snapshot_digest = status.snapshot_digest();
          payload.transition_chain_head = status.transition_chain_head();
          payload.recovery_outcome = status.recovery_outcome();
          payload.open_mode = status.open_mode();
          send_frame(session, make_frame(MessageType::StatusResponse, request_id, detail::encode_status(payload)));
          return true;
        }
        case MessageType::RegisterControllerRequest: {
          const RegisterControllerRequest command = detail::decode_register_request(request.payload());
          Result<ControllerRegistration> result = authority_->register_controller(command);
          if (!result.has_value()) {
            return reject_and_keep(session, request_id, result.rejection().code(), result.rejection().detail());
          }
          send_frame(session, make_frame(MessageType::RegisterControllerResponse, request_id,
                                         detail::encode_register_response(result.value())));
          return true;
        }
        case MessageType::AcquireAuthorityRequest: {
          const AcquireAuthorityRequest command = detail::decode_acquire_request(request.payload());
          Result<AuthorityGrantView> result = authority_->acquire_authority(command);
          if (!result.has_value()) {
            return reject_and_keep(session, request_id, result.rejection().code(), result.rejection().detail());
          }
          const GrantData grant = detail::to_data(result.value().record());
          send_frame(session, make_frame(MessageType::AcquireAuthorityResponse, request_id,
                                         detail::encode_acquire_response(grant)));
          return true;
        }
        case MessageType::ValidateMutationRequest:
        case MessageType::ValidateObservationRequest: {
          const detail::ValidateRequestPayload payload = detail::decode_validate_request(request.payload());
          Result<ScopeName> scope = ScopeName::parse(payload.scope, "scope name");
          if (!scope.has_value()) {
            return reject_and_keep(session, request_id, scope.rejection().code(), scope.rejection().detail());
          }
          detail::ValidationPayload outcome;
          if (request.header().type == MessageType::ValidateMutationRequest) {
            Result<MutationAuthority> token = MutationAuthority::parse(payload.token);
            if (!token.has_value()) {
              outcome.accepted = false;
              outcome.code = token.rejection().code();
              outcome.detail = token.rejection().detail();
            } else {
              const ValidationOutcome validation = authority_->validate_mutation(token.value(), scope.value());
              outcome.accepted = validation.accepted();
              if (!validation.accepted()) {
                outcome.code = validation.rejection()->code();
                outcome.detail = validation.rejection()->detail();
              }
            }
          } else {
            Result<ObservationAuthority> token = ObservationAuthority::parse(payload.token);
            if (!token.has_value()) {
              outcome.accepted = false;
              outcome.code = token.rejection().code();
              outcome.detail = token.rejection().detail();
            } else {
              const ValidationOutcome validation = authority_->validate_observation(token.value(), scope.value());
              outcome.accepted = validation.accepted();
              if (!validation.accepted()) {
                outcome.code = validation.rejection()->code();
                outcome.detail = validation.rejection()->detail();
              }
            }
          }
          const MessageType response_type = request.header().type == MessageType::ValidateMutationRequest
                                                ? MessageType::ValidateMutationResponse
                                                : MessageType::ValidateObservationResponse;
          send_frame(session, make_frame(response_type, request_id, detail::encode_validation(outcome)));
          return true;
        }
        case MessageType::AdvanceEpochRequest: {
          const AdvanceEpochRequest command = detail::decode_advance_request(request.payload());
          Result<EpochTransitionRecord> result = authority_->advance_epoch(command);
          if (!result.has_value()) {
            return reject_and_keep(session, request_id, result.rejection().code(), result.rejection().detail());
          }
          send_frame(session, make_frame(MessageType::AdvanceEpochResponse, request_id,
                                         detail::encode_transition_response(detail::to_data(result.value()))));
          return true;
        }
        case MessageType::RevokeRequest: {
          const RevokeAuthorityRequest command = detail::decode_revoke_request(request.payload());
          Result<RevocationRecord> result = authority_->revoke_authority(command);
          if (!result.has_value()) {
            return reject_and_keep(session, request_id, result.rejection().code(), result.rejection().detail());
          }
          send_frame(session, make_frame(MessageType::RevokeResponse, request_id,
                                         detail::encode_revocation_response(detail::to_data(result.value()))));
          return true;
        }
        case MessageType::QualifyRecoveredStateRequest: {
          const RecoveredStateClaim claim = detail::decode_qualify_request(request.payload());
          Result<RecoveryQualification> result = authority_->qualify_recovered_state(claim);
          if (!result.has_value()) {
            return reject_and_keep(session, request_id, result.rejection().code(), result.rejection().detail());
          }
          detail::QualificationPayload payload;
          payload.verdict = result.value().verdict();
          payload.code = result.value().code();
          payload.detail = result.value().explanation().detail();
          if (result.value().matching_grant().has_value()) {
            payload.matching_grant = result.value().matching_grant()->value();
          }
          payload.requires_revalidation = result.value().requires_revalidation();
          send_frame(session, make_frame(MessageType::QualifyRecoveredStateResponse, request_id,
                                         detail::encode_qualification(payload)));
          return true;
        }
        case MessageType::HistoryRequest: {
          const detail::HistoryRequestPayload query = detail::decode_history_request(request.payload());
          HistoryQuery command;
          if (query.from_sequence.has_value()) {
            command.from_sequence = TransitionSequence::from_trusted(*query.from_sequence);
          }
          command.limit = static_cast<std::size_t>(query.limit);
          Result<EpochHistoryPage> page = authority_->history(command);
          if (!page.has_value()) {
            return reject_and_keep(session, request_id, page.rejection().code(), page.rejection().detail());
          }
          detail::HistoryResponsePayload payload;
          payload.page.total_count = page.value().total_count();
          payload.page.first_retained = page.value().first_retained_sequence();
          payload.page.trimmed_count = page.value().trimmed_count();
          payload.page.anchor = page.value().history_anchor();
          payload.page.chain_head = page.value().chain_head();
          for (const EpochTransitionRecord& record : page.value().records()) {
            payload.records.push_back(detail::to_data(record));
          }
          send_frame(session, make_frame(MessageType::HistoryResponse, request_id,
                                         detail::encode_history_response(payload)));
          return true;
        }
        case MessageType::RevocationsRequest: {
          const detail::RevocationsRequestPayload query = detail::decode_revocations_request(request.payload());
          RevocationQuery command;
          if (query.from_sequence.has_value()) {
            command.from_sequence = RevocationSequence::from_trusted(*query.from_sequence);
          }
          command.limit = static_cast<std::size_t>(query.limit);
          Result<RevocationPage> page = authority_->revocations(command);
          if (!page.has_value()) {
            return reject_and_keep(session, request_id, page.rejection().code(), page.rejection().detail());
          }
          detail::RevocationsResponsePayload payload;
          payload.page.total_count = page.value().total_count();
          payload.page.first_retained = page.value().first_retained_sequence();
          payload.page.trimmed_count = page.value().trimmed_count();
          payload.page.anchor = page.value().chain_head();
          payload.page.chain_head = page.value().chain_head();
          for (const RevocationRecord& record : page.value().records()) {
            payload.records.push_back(detail::to_data(record));
          }
          send_frame(session, make_frame(MessageType::RevocationsResponse, request_id,
                                         detail::encode_revocations_response(payload)));
          return true;
        }
        case MessageType::ControllersRequest: {
          const detail::ControllersRequestPayload query = detail::decode_controllers_request(request.payload());
          ControllerQuery command;
          if (query.from_controller.has_value()) {
            Result<ControllerId> cursor = ControllerId::parse(*query.from_controller, "controller cursor");
            if (!cursor.has_value()) {
              return reject_and_keep(session, request_id, cursor.rejection().code(), cursor.rejection().detail());
            }
            command.from_controller = cursor.move_value();
          }
          command.limit = static_cast<std::size_t>(query.limit);
          Result<ControllerPage> page = authority_->controllers(command);
          if (!page.has_value()) {
            return reject_and_keep(session, request_id, page.rejection().code(), page.rejection().detail());
          }
          detail::ControllersResponsePayload payload;
          payload.total_count = page.value().total_count();
          for (const ControllerRecord& record : page.value().records()) {
            payload.records.push_back(detail::to_data(record));
          }
          send_frame(session, make_frame(MessageType::ControllersResponse, request_id,
                                         detail::encode_controllers_response(payload)));
          return true;
        }
        case MessageType::GrantsRequest: {
          const detail::GrantsRequestPayload query = detail::decode_grants_request(request.payload());
          GrantQuery command;
          if (query.from_grant.has_value()) {
            command.from_grant = GrantId::from_trusted(*query.from_grant);
          }
          command.limit = static_cast<std::size_t>(query.limit);
          Result<GrantPage> page = authority_->grants(command);
          if (!page.has_value()) {
            return reject_and_keep(session, request_id, page.rejection().code(), page.rejection().detail());
          }
          detail::GrantsResponsePayload payload;
          payload.total_count = page.value().total_count();
          payload.epoch = page.value().epoch().value();
          for (const AuthorityGrantRecord& record : page.value().records()) {
            payload.records.push_back(detail::to_data(record));
          }
          send_frame(session, make_frame(MessageType::GrantsResponse, request_id,
                                         detail::encode_grants_response(payload)));
          return true;
        }
        case MessageType::HelloRequest:
          return reject_and_keep(session, request_id, ErrorCode::HandshakeRejected,
                                 "the handshake already completed on this connection");
        default:
          return reject_and_keep(session, request_id, ErrorCode::MessageTypeUnknown,
                                 "the runtime cannot answer this message type");
      }
    } catch (const EpochError& error) {
      requests_rejected_.fetch_add(1);
      send_frame(session, make_error_frame(request_id, error.code(), error.explanation().detail()));
      return true;  // the frame was well formed; the session stays usable
    }
  }

  [[nodiscard]] bool reject_and_keep(net::Socket& session, std::uint64_t request_id, ErrorCode code,
                                     std::string detail) {
    requests_rejected_.fetch_add(1);
    send_frame(session, make_error_frame(request_id, code, std::move(detail)));
    return true;
  }

  void send_frame(net::Socket& session, const Frame& frame) {
    std::vector<std::byte> bytes;
    const Status encoded = encode_frame(frame, bytes, options_.max_frame_payload_bytes);
    if (!encoded.has_value()) {
      throw EpochError(encoded.rejection());
    }
    session.send_all(std::span<const std::byte>(bytes));
    bytes_sent_.fetch_add(bytes.size());
  }

  ControlPlaneEpochAuthority* authority_ = nullptr;
  ServerOptions options_;
  net::Listener listener_;

  mutable std::mutex lifecycle_mutex_;
  std::atomic<bool> stopping_{false};
  bool running_ = false;

  std::mutex queue_mutex_;
  std::condition_variable queue_ready_;
  std::condition_variable queue_space_;
  std::deque<net::Socket> queue_;

  mutable std::mutex sessions_mutex_;
  std::vector<std::intptr_t> active_sessions_;

  std::vector<std::thread> workers_;

  std::atomic<std::uint64_t> active_connections_{0};
  std::atomic<std::uint64_t> sessions_accepted_{0};
  std::atomic<std::uint64_t> sessions_closed_{0};
  std::atomic<std::uint64_t> requests_served_{0};
  std::atomic<std::uint64_t> requests_rejected_{0};
  std::atomic<std::uint64_t> bytes_received_{0};
  std::atomic<std::uint64_t> bytes_sent_{0};
};

}  // namespace detail

EpochAuthorityServer::EpochAuthorityServer(ControlPlaneEpochAuthority& authority, ServerOptions options)
    : core_(std::make_unique<detail::ServerCore>(authority, std::move(options))) {}

EpochAuthorityServer::~EpochAuthorityServer() = default;

std::uint16_t EpochAuthorityServer::port() const noexcept { return core_->port(); }

std::string EpochAuthorityServer::endpoint() const { return core_->endpoint(); }

void EpochAuthorityServer::start() { core_->start(); }

std::uint64_t EpochAuthorityServer::accept_until(std::uint64_t max_requests) {
  return core_->accept_until(max_requests);
}

void EpochAuthorityServer::stop() noexcept { core_->stop(); }

bool EpochAuthorityServer::running() const noexcept { return core_->running(); }

ServerAccounting EpochAuthorityServer::accounting() const { return core_->accounting(); }

std::string ServerAccounting::to_string() const {
  std::string text;
  text += "active_connections=" + std::to_string(active_connections_);
  text += " sessions_accepted=" + std::to_string(sessions_accepted_);
  text += " sessions_closed=" + std::to_string(sessions_closed_);
  text += " requests_served=" + std::to_string(requests_served_);
  text += " requests_rejected=" + std::to_string(requests_rejected_);
  text += " bytes_received=" + std::to_string(bytes_received_);
  text += " bytes_sent=" + std::to_string(bytes_sent_);
  text += " workers=" + std::to_string(workers_);
  text += " stopping=";
  text += stopping_ ? "yes" : "no";
  return text;
}

}  // namespace dccp::epoch


