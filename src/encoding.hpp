// Control Plane Epoch 1.0.0 - Summon Software Labs
// Canonical deterministic encoding. Internal; never installed.
//
// Encoding rules, applied identically to durable images and wire payloads:
//   * little-endian fixed-width integers;
//   * text is a u32 byte length followed by the raw bytes (never a terminator);
//   * optionals are a u8 presence flag followed by the value when present;
//   * collections are a u32 count followed by the elements in the canonical
//     order documented for that collection;
//   * every length and count is checked against a bound before allocation.
//
// A reader never trusts a length field: it validates against the remaining
// buffer and a caller-supplied bound first, and raises a stable EpochError code
// rather than allocating on a hostile length.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "control_plane_epoch/digest.hpp"
#include "control_plane_epoch/error.hpp"

namespace dccp::epoch::detail {

[[nodiscard]] std::size_t checked_add(std::size_t lhs, std::size_t rhs, std::string_view what);
[[nodiscard]] std::size_t checked_multiply(std::size_t lhs, std::size_t rhs, std::string_view what);

/// Appends canonically encoded bytes to a bounded buffer.
class CanonicalWriter {
 public:
  explicit CanonicalWriter(std::size_t limit) : limit_(limit) {}

  void u8(std::uint8_t value);
  void u16(std::uint16_t value);
  void u32(std::uint32_t value);
  void u64(std::uint64_t value);
  void boolean(bool value) { u8(value ? 1u : 0u); }
  void raw(std::span<const std::byte> bytes);
  void text(std::string_view value);
  void digest(const Sha256Digest& value) { raw(value.bytes()); }

  [[nodiscard]] const std::vector<std::byte>& data() const noexcept { return data_; }
  [[nodiscard]] std::vector<std::byte> take() noexcept { return std::move(data_); }
  [[nodiscard]] std::size_t size() const noexcept { return data_.size(); }
  [[nodiscard]] std::size_t limit() const noexcept { return limit_; }

  /// SHA-256 over the bytes written so far.
  [[nodiscard]] Sha256Digest digest() const;

 private:
  void reserve_for(std::size_t count, std::string_view what);

  std::vector<std::byte> data_;
  std::size_t limit_ = 0;
};

/// Reads canonically encoded bytes. Malformed input raises EpochError with an
/// integrity code; protocol callers remap it to a protocol code.
class CanonicalReader {
 public:
  explicit CanonicalReader(std::span<const std::byte> data, std::size_t max_text_bytes)
      : data_(data), max_text_bytes_(max_text_bytes) {}

  [[nodiscard]] std::uint8_t u8();
  [[nodiscard]] std::uint16_t u16();
  [[nodiscard]] std::uint32_t u32();
  [[nodiscard]] std::uint64_t u64();
  [[nodiscard]] bool boolean();
  [[nodiscard]] std::span<const std::byte> raw(std::size_t count);
  [[nodiscard]] std::string text();
  [[nodiscard]] Sha256Digest digest();

  /// Number of bytes still unread.
  [[nodiscard]] std::size_t remaining() const noexcept { return data_.size() - offset_; }
  [[nodiscard]] std::size_t offset() const noexcept { return offset_; }

  /// Raises TrailingBytes when any byte is left unread, which is how a payload
  /// with appended junk is rejected instead of silently tolerated.
  void expect_end() const;

 private:
  void require(std::size_t count, std::string_view what) const;

  std::span<const std::byte> data_;
  std::size_t offset_ = 0;
  std::size_t max_text_bytes_ = 0;
};

/// Length-prefixed hashing helpers, used to derive identities and record
/// digests without ever concatenating unbounded fields ambiguously.
void hash_text(Sha256& hasher, std::string_view value);
void hash_raw(Sha256& hasher, std::span<const std::byte> value);
void hash_u64(Sha256& hasher, std::uint64_t value);
void hash_u32(Sha256& hasher, std::uint32_t value);
void hash_bool(Sha256& hasher, bool value);
void hash_digest(Sha256& hasher, const Sha256Digest& value);

}  // namespace dccp::epoch::detail
