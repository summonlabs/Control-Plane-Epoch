// Control Plane Epoch 1.0.0 - Summon Software Labs
// SHA-256 over in-repository implementation. No third-party dependency is
// taken for the one cryptographic primitive this repository needs: durable
// image integrity, record chaining, and token derivation.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include "control_plane_epoch/error.hpp"

namespace dccp::epoch {

/// A 256-bit digest. Ordered so that digests can be used as deterministic map
/// keys and compared without ambiguity.
class Sha256Digest {
 public:
  static constexpr std::size_t byte_size = 32;

  Sha256Digest() noexcept = default;

  [[nodiscard]] static Sha256Digest zero() noexcept { return Sha256Digest(); }
  [[nodiscard]] static Sha256Digest from_bytes(std::span<const std::byte, byte_size> bytes) noexcept;

  /// Parses exactly 64 lowercase or uppercase hexadecimal characters. Any other
  /// length or character is rejected; nothing is normalized or truncated.
  [[nodiscard]] static Result<Sha256Digest> from_hex(std::string_view text);

  [[nodiscard]] bool is_zero() const noexcept;
  [[nodiscard]] std::span<const std::byte, byte_size> bytes() const noexcept { return bytes_; }
  [[nodiscard]] std::string to_hex() const;

  friend bool operator==(const Sha256Digest& lhs, const Sha256Digest& rhs) noexcept {
    return lhs.bytes_ == rhs.bytes_;
  }
  friend bool operator!=(const Sha256Digest& lhs, const Sha256Digest& rhs) noexcept {
    return !(lhs == rhs);
  }
  friend bool operator<(const Sha256Digest& lhs, const Sha256Digest& rhs) noexcept {
    return lhs.bytes_ < rhs.bytes_;
  }

 private:
  std::array<std::byte, byte_size> bytes_{};
};

/// Streaming SHA-256. finish() may be called once; further updates are an
/// internal invariant violation.
class Sha256 {
 public:
  Sha256() noexcept;

  void update(std::span<const std::byte> data);
  void update(std::string_view text);
  [[nodiscard]] Sha256Digest finish();

 private:
  std::array<std::uint32_t, 8> state_{};
  std::array<std::byte, 64> buffer_{};
  std::size_t buffered_ = 0;
  std::uint64_t total_bytes_ = 0;
  bool finalized_ = false;
};

[[nodiscard]] Sha256Digest sha256(std::span<const std::byte> data);
[[nodiscard]] Sha256Digest sha256(std::string_view text);

}  // namespace dccp::epoch
