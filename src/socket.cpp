// Control Plane Epoch 1.0.0 - Summon Software Labs
// Internal blocking socket helpers.
#include "socket.hpp"

#include <algorithm>
#include <mutex>
#include <system_error>

#include "control_plane_epoch/error.hpp"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace dccp::epoch::net {
namespace {

#if defined(_WIN32)
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidSocket = INVALID_SOCKET;
#else
using NativeSocket = int;
constexpr NativeSocket kInvalidSocket = -1;
#endif

std::once_flag g_init_once;

[[noreturn]] void throw_socket_error(ErrorCode code, std::string_view what, int error) {
#if defined(_WIN32)
  throw EpochError(code, std::string(what) + " failed with winsock error " + std::to_string(error));
#else
  throw EpochError(code,
                   std::string(what) + " failed: " + std::error_code(error, std::generic_category()).message());
#endif
}

void close_native(std::intptr_t handle) noexcept {
  if (handle < 0) {
    return;
  }
#if defined(_WIN32)
  ::closesocket(static_cast<NativeSocket>(handle));
#else
  ::close(static_cast<NativeSocket>(handle));
#endif
}

[[nodiscard]] bool interrupted(int error) noexcept {
#if defined(_WIN32)
  return error == WSAEINTR;
#else
  return error == EINTR;
#endif
}

[[nodiscard]] int last_socket_error() noexcept {
#if defined(_WIN32)
  return ::WSAGetLastError();
#else
  return errno;
#endif
}

}  // namespace

void ensure_initialized() {
  std::call_once(g_init_once, [] {
#if defined(_WIN32)
    WSADATA data{};
    const int result = ::WSAStartup(MAKEWORD(2, 2), &data);
    if (result != 0) {
      throw EpochError(ErrorCode::ListenFailed, "WSAStartup failed with error " + std::to_string(result));
    }
#endif
  });
}

Socket::~Socket() { close(); }

Socket::Socket(Socket&& other) noexcept : handle_(other.handle_) { other.handle_ = -1; }

Socket& Socket::operator=(Socket&& other) noexcept {
  if (this != &other) {
    close();
    handle_ = other.handle_;
    other.handle_ = -1;
  }
  return *this;
}

bool Socket::valid() const noexcept { return handle_ >= 0; }

void Socket::close() noexcept {
  if (valid()) {
    close_native(handle_);
    handle_ = -1;
  }
}

void Socket::shutdown_both() noexcept {
  if (!valid()) {
    return;
  }
#if defined(_WIN32)
  ::shutdown(static_cast<NativeSocket>(handle_), SD_BOTH);
#else
  ::shutdown(static_cast<NativeSocket>(handle_), SHUT_RDWR);
#endif
}

void Socket::send_all(std::span<const std::byte> data) {
  if (!valid()) {
    throw EpochError(ErrorCode::SocketClosed, "send on a closed socket");
  }
  std::size_t offset = 0;
  while (offset < data.size()) {
    const std::size_t remaining = data.size() - offset;
#if defined(_WIN32)
    const int chunk = static_cast<int>(std::min<std::size_t>(remaining, 1u << 20));
    const int written = ::send(static_cast<NativeSocket>(handle_),
                               reinterpret_cast<const char*>(data.data() + offset), chunk, 0);
#else
    const std::size_t chunk = remaining;
    const std::ptrdiff_t written =
        ::send(static_cast<NativeSocket>(handle_), data.data() + offset, chunk, 0);
#endif
    if (written < 0) {
      const int error = last_socket_error();
      if (interrupted(error)) {
        continue;
      }
      throw_socket_error(ErrorCode::WriteFailed, "send", error);
    }
    if (written == 0) {
      throw EpochError(ErrorCode::WriteFailed, "send made no progress");
    }
    offset += static_cast<std::size_t>(written);
  }
}

bool Socket::recv_exact(std::span<std::byte> data) {
  if (!valid()) {
    throw EpochError(ErrorCode::SocketClosed, "receive on a closed socket");
  }
  std::size_t offset = 0;
  while (offset < data.size()) {
    const std::size_t remaining = data.size() - offset;
#if defined(_WIN32)
    const int chunk = static_cast<int>(std::min<std::size_t>(remaining, 1u << 20));
    const int received = ::recv(static_cast<NativeSocket>(handle_),
                                reinterpret_cast<char*>(data.data() + offset), chunk, 0);
#else
    const std::ptrdiff_t received =
        ::recv(static_cast<NativeSocket>(handle_), data.data() + offset, remaining, 0);
#endif
    if (received < 0) {
      const int error = last_socket_error();
      if (interrupted(error)) {
        continue;
      }
      throw_socket_error(ErrorCode::ReadFailed, "receive", error);
    }
    if (received == 0) {
      if (offset == 0) {
        return false;  // clean close before any byte of this read arrived
      }
      throw EpochError(ErrorCode::FrameTruncated, "the peer closed the connection inside a frame");
    }
    offset += static_cast<std::size_t>(received);
  }
  return true;
}

Listener::~Listener() { close(); }

void Listener::bind_and_listen(const std::string& address, std::uint16_t port, int backlog) {
  ensure_initialized();
  if (valid()) {
    throw EpochError(ErrorCode::ListenFailed, "the listener is already bound");
  }

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE;

  addrinfo* resolved = nullptr;
  const std::string service = std::to_string(port);
  const int lookup = ::getaddrinfo(address.empty() ? nullptr : address.c_str(), service.c_str(), &hints, &resolved);
  if (lookup != 0 || resolved == nullptr) {
    throw EpochError(ErrorCode::ListenFailed, "could not resolve bind address '" + address + "'");
  }
  struct ResolvedGuard {
    addrinfo* value;
    ~ResolvedGuard() { ::freeaddrinfo(value); }
  } guard{resolved};

  NativeSocket bound = kInvalidSocket;
  for (addrinfo* candidate = resolved; candidate != nullptr; candidate = candidate->ai_next) {
    const NativeSocket created = ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (created == kInvalidSocket) {
      continue;
    }
#if defined(_WIN32)
    // The authority holds an exclusive writer lock on the store, but two
    // runtimes must still never share a listening port.
    BOOL exclusive = TRUE;
    ::setsockopt(created, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive),
                 sizeof(exclusive));
#else
    int reuse = 1;
    ::setsockopt(created, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#endif
    if (::bind(created, candidate->ai_addr, static_cast<int>(candidate->ai_addrlen)) == 0 &&
        ::listen(created, backlog) == 0) {
      bound = created;
      break;
    }
    close_native(static_cast<std::intptr_t>(created));
  }

  if (bound == kInvalidSocket) {
    throw EpochError(ErrorCode::ListenFailed, "could not bind " + address + ":" + service);
  }
  handle_ = static_cast<std::intptr_t>(bound);

  sockaddr_storage local{};
#if defined(_WIN32)
  int local_length = sizeof(local);
#else
  socklen_t local_length = sizeof(local);
#endif
  if (::getsockname(bound, reinterpret_cast<sockaddr*>(&local), &local_length) == 0) {
    if (local.ss_family == AF_INET) {
      bound_port_ = ntohs(reinterpret_cast<sockaddr_in*>(&local)->sin_port);
    } else if (local.ss_family == AF_INET6) {
      bound_port_ = ntohs(reinterpret_cast<sockaddr_in6*>(&local)->sin6_port);
    }
  }
}

Socket Listener::accept_one(std::uint32_t wait_milliseconds) {
  if (!valid()) {
    return Socket{};
  }

  const auto descriptor = static_cast<NativeSocket>(handle_);
#if defined(_WIN32)
  WSAPOLLFD poll_descriptor{};
  poll_descriptor.fd = descriptor;
  poll_descriptor.events = POLLRDNORM;
  const int ready = ::WSAPoll(&poll_descriptor, 1, static_cast<INT>(wait_milliseconds));
#else
  pollfd poll_descriptor{};
  poll_descriptor.fd = descriptor;
  poll_descriptor.events = POLLIN;
  const int ready = ::poll(&poll_descriptor, 1, static_cast<int>(wait_milliseconds));
#endif
  if (ready <= 0 || !valid()) {
    return Socket{};  // budget expired, stop requested, or the listener was closed
  }

  const NativeSocket accepted = ::accept(descriptor, nullptr, nullptr);
  if (accepted == kInvalidSocket) {
    return Socket{};
  }
  return Socket(static_cast<std::intptr_t>(accepted));
}

void Listener::shutdown() noexcept {
  if (valid()) {
#if defined(_WIN32)
    ::shutdown(static_cast<NativeSocket>(handle_), SD_BOTH);
#else
    ::shutdown(static_cast<NativeSocket>(handle_), SHUT_RDWR);
#endif
  }
}

void Listener::close() noexcept {
  if (valid()) {
    close_native(handle_);
    handle_ = -1;
  }
}

void shutdown_handle(std::intptr_t handle) noexcept {
  if (handle < 0) {
    return;
  }
#if defined(_WIN32)
  ::shutdown(static_cast<NativeSocket>(handle), SD_BOTH);
#else
  ::shutdown(static_cast<NativeSocket>(handle), SHUT_RDWR);
#endif
}

Socket connect_to(const std::string& host, std::uint16_t port) {  ensure_initialized();

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  addrinfo* resolved = nullptr;
  const std::string service = std::to_string(port);
  const int lookup = ::getaddrinfo(host.c_str(), service.c_str(), &hints, &resolved);
  if (lookup != 0 || resolved == nullptr) {
    throw EpochError(ErrorCode::ConnectFailed, "could not resolve '" + host + ":" + service + "'");
  }
  struct ResolvedGuard {
    addrinfo* value;
    ~ResolvedGuard() { ::freeaddrinfo(value); }
  } guard{resolved};

  for (addrinfo* candidate = resolved; candidate != nullptr; candidate = candidate->ai_next) {
    const NativeSocket created = ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (created == kInvalidSocket) {
      continue;
    }
    if (::connect(created, candidate->ai_addr, static_cast<int>(candidate->ai_addrlen)) == 0) {
      return Socket(static_cast<std::intptr_t>(created));
    }
    close_native(static_cast<std::intptr_t>(created));
  }

  throw EpochError(ErrorCode::ConnectFailed, "could not connect to '" + host + ":" + service + "'");
}

}  // namespace dccp::epoch::net
