// Control Plane Epoch 1.0.0 - Summon Software Labs
// Remote authority runtime: serves the same authority API over the framed
// transport to independent controller processes.
//
// The runtime never bypasses authority or generation checks; it decodes a
// request, calls exactly the same ControlPlaneEpochAuthority method a local
// consumer would call, and encodes the outcome. Requests and connections are
// bounded, and shutdown is deterministic: stop() closes the listener, shuts
// down active sessions so no thread is left blocked on a socket, then joins the
// workers. Work that completed before shutdown is committed and answered; work
// that had not started is answered with ErrorCode::ServerStopping.
#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "control_plane_epoch/error.hpp"
#include "control_plane_epoch/limits.hpp"
#include "control_plane_epoch/service.hpp"

namespace dccp::epoch {

namespace detail {
class ServerCore;
}

/// Runtime configuration. Every field is bounded by limits.hpp.
struct ServerOptions {
  /// Loopback by default: this authority is a single-facility service and is
  /// not intended to be reachable from outside the host without an explicit
  /// decision by the operator.
  std::string bind_address = "127.0.0.1";

  /// 0 requests an ephemeral port, which is what tooling and tests use to avoid
  /// collisions.
  std::uint16_t port = 0;

  std::uint32_t workers = default_server_workers;
  std::size_t queue_depth = max_server_queue_depth;
  std::size_t max_connections = max_server_connections;
  std::size_t max_frame_payload_bytes = ::dccp::epoch::max_frame_payload_bytes;
  std::uint64_t max_requests_per_connection = ::dccp::epoch::max_requests_per_connection;
};

/// Accounting for one runtime instance.
class ServerAccounting {
 public:
  ServerAccounting() = default;

  [[nodiscard]] std::uint64_t active_connections() const noexcept { return active_connections_; }
  [[nodiscard]] std::uint64_t sessions_accepted() const noexcept { return sessions_accepted_; }
  [[nodiscard]] std::uint64_t sessions_closed() const noexcept { return sessions_closed_; }
  [[nodiscard]] std::uint64_t requests_served() const noexcept { return requests_served_; }
  [[nodiscard]] std::uint64_t requests_rejected() const noexcept { return requests_rejected_; }
  [[nodiscard]] std::uint64_t bytes_received() const noexcept { return bytes_received_; }
  [[nodiscard]] std::uint64_t bytes_sent() const noexcept { return bytes_sent_; }
  [[nodiscard]] std::uint32_t workers() const noexcept { return workers_; }
  [[nodiscard]] bool stopping() const noexcept { return stopping_; }

  [[nodiscard]] std::string to_string() const;

  friend bool operator==(const ServerAccounting& lhs, const ServerAccounting& rhs) noexcept {
    return lhs.active_connections_ == rhs.active_connections_ && lhs.sessions_accepted_ == rhs.sessions_accepted_ &&
           lhs.sessions_closed_ == rhs.sessions_closed_ && lhs.requests_served_ == rhs.requests_served_ &&
           lhs.requests_rejected_ == rhs.requests_rejected_ && lhs.bytes_received_ == rhs.bytes_received_ &&
           lhs.bytes_sent_ == rhs.bytes_sent_ && lhs.workers_ == rhs.workers_ && lhs.stopping_ == rhs.stopping_;
  }

 private:
  friend class EpochAuthorityServer;
  friend class detail::ServerCore;

  std::uint64_t active_connections_ = 0;
  std::uint64_t sessions_accepted_ = 0;
  std::uint64_t sessions_closed_ = 0;
  std::uint64_t requests_served_ = 0;
  std::uint64_t requests_rejected_ = 0;
  std::uint64_t bytes_received_ = 0;
  std::uint64_t bytes_sent_ = 0;
  std::uint32_t workers_ = 0;
  bool stopping_ = false;
};

class EpochAuthorityServer {
 public:
  /// Binds and listens. Throws EpochError(ListenFailed) when the address is
  /// unusable, or EpochError(InvalidArgument) when an option exceeds a bound.
  EpochAuthorityServer(ControlPlaneEpochAuthority& authority, ServerOptions options);
  ~EpochAuthorityServer();

  EpochAuthorityServer(const EpochAuthorityServer&) = delete;
  EpochAuthorityServer& operator=(const EpochAuthorityServer&) = delete;

  [[nodiscard]] std::uint16_t port() const noexcept;

  /// "address:port" of the bound listener, as clients should connect to it.
  [[nodiscard]] std::string endpoint() const;

  /// Starts the worker pool. Idempotent.
  void start();

  /// Accepts and serves connections in the calling thread until the served
  /// request count reaches max_requests (0 means "no bound") or stop() is
  /// requested. Returns the number of requests served by this call.
  std::uint64_t accept_until(std::uint64_t max_requests);

  /// Signals shutdown, closes the listener, shuts down active sessions, and
  /// joins every worker. Idempotent and safe to call from any thread other than
  /// a worker. Never called while holding authority state, because workers may
  /// be waiting on the authority mutex.
  void stop() noexcept;

  [[nodiscard]] bool running() const noexcept;
  [[nodiscard]] ServerAccounting accounting() const;

 private:
  std::unique_ptr<detail::ServerCore> core_;
};

}  // namespace dccp::epoch
