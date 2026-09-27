// Control Plane Epoch 1.0.0 - Summon Software Labs
// Internal blocking socket helpers with deterministic shutdown. Not installed.
//
// There is no per-request timeout anywhere in this repository: a request either
// completes or the peer closing the connection is observed as an explicit
// error. The accept loop uses a short wait so that a stop request is observed
// promptly; that interval is shutdown responsiveness, not a request timeout.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace dccp::epoch::net {

/// Initializes the platform socket layer once per process.
void ensure_initialized();

/// RAII socket handle. Move-only; closing is idempotent.
class Socket {
 public:
  Socket() = default;
  explicit Socket(std::intptr_t handle) noexcept : handle_(handle) {}
  ~Socket();

  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;
  Socket(Socket&& other) noexcept;
  Socket& operator=(Socket&& other) noexcept;

  [[nodiscard]] bool valid() const noexcept;
  [[nodiscard]] std::intptr_t native() const noexcept { return handle_; }

  /// Shuts the connection down in both directions so a blocked receive on
  /// another thread is released, then closes. Idempotent.
  void close() noexcept;

  /// Shuts down both directions without closing the handle. This is how a
  /// shutdown request releases a worker that is blocked on a read.
  void shutdown_both() noexcept;

  void send_all(std::span<const std::byte> data);

  /// Reads exactly the requested number of bytes. Returns false when the peer
  /// closed cleanly before any byte of this read arrived. Raises EpochError on
  /// a truncated read or a genuine socket error.
  [[nodiscard]] bool recv_exact(std::span<std::byte> data);

 private:
  std::intptr_t handle_ = -1;
};

/// Listening socket bound to an address and port.
class Listener {
 public:
  Listener() = default;
  ~Listener();

  Listener(const Listener&) = delete;
  Listener& operator=(const Listener&) = delete;

  /// Binds and starts listening. Raises EpochError(ListenFailed) on failure.
  /// Port 0 asks the operating system for an ephemeral port.
  void bind_and_listen(const std::string& address, std::uint16_t port, int backlog);

  /// Waits up to the supplied budget for an inbound connection. Returns an
  /// invalid socket when the budget expires, which lets the caller observe a
  /// stop request between waits.
  [[nodiscard]] Socket accept_one(std::uint32_t wait_milliseconds);

  void shutdown() noexcept;
  void close() noexcept;

  [[nodiscard]] std::uint16_t bound_port() const noexcept { return bound_port_; }
  [[nodiscard]] bool valid() const noexcept { return handle_ != -1; }

 private:
  std::intptr_t handle_ = -1;
  std::uint16_t bound_port_ = 0;
};

/// Connects to host:port, blocking until the connection is established or the
/// operating system reports an error.
[[nodiscard]] Socket connect_to(const std::string& host, std::uint16_t port);

/// Shuts down a native socket handle without taking ownership of it. Used by the
/// runtime to release sessions that are blocked on a read during shutdown; the
/// handle is never closed here, so no recycled handle can be affected.
void shutdown_handle(std::intptr_t handle) noexcept;

}  // namespace dccp::epoch::net
