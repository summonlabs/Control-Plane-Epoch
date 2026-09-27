// Control Plane Epoch 1.0.0 - Summon Software Labs
// Canonical deterministic encoding implementation.
#include "encoding.hpp"

#include <algorithm>
#include <array>
#include <cstring>

namespace dccp::epoch::detail {
namespace {

void store_le(std::byte* target, std::uint64_t value, std::size_t width) noexcept {
  for (std::size_t index = 0; index < width; ++index) {
    target[index] = static_cast<std::byte>((value >> (8u * index)) & 0xFFu);
  }
}

[[nodiscard]] std::uint64_t load_le(const std::byte* source, std::size_t width) noexcept {
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < width; ++index) {
    value |= static_cast<std::uint64_t>(source[index]) << (8u * index);
  }
  return value;
}

}  // namespace

std::size_t checked_add(std::size_t lhs, std::size_t rhs, std::string_view what) {
  if (lhs > SIZE_MAX - rhs) {
    throw EpochError(ErrorCode::ArithmeticOverflow, std::string(what) + ": size addition overflowed");
  }
  return lhs + rhs;
}

std::size_t checked_multiply(std::size_t lhs, std::size_t rhs, std::string_view what) {
  if (lhs != 0 && rhs > SIZE_MAX / lhs) {
    throw EpochError(ErrorCode::ArithmeticOverflow, std::string(what) + ": size multiplication overflowed");
  }
  return lhs * rhs;
}

void CanonicalWriter::reserve_for(std::size_t count, std::string_view what) {
  const std::size_t required = checked_add(data_.size(), count, what);
  if (required > limit_) {
    throw EpochError(ErrorCode::DurableLimitsExceeded, std::string(what) + ": encoded size " +
                                                           std::to_string(required) +
                                                           " exceeds the limit of " + std::to_string(limit_));
  }
  data_.reserve(required);
}

void CanonicalWriter::u8(std::uint8_t value) {
  reserve_for(1, "encode u8");
  data_.push_back(static_cast<std::byte>(value));
}

void CanonicalWriter::u16(std::uint16_t value) {
  reserve_for(2, "encode u16");
  std::byte buffer[2];
  store_le(buffer, value, 2);
  data_.insert(data_.end(), buffer, buffer + 2);
}

void CanonicalWriter::u32(std::uint32_t value) {
  reserve_for(4, "encode u32");
  std::byte buffer[4];
  store_le(buffer, value, 4);
  data_.insert(data_.end(), buffer, buffer + 4);
}

void CanonicalWriter::u64(std::uint64_t value) {
  reserve_for(8, "encode u64");
  std::byte buffer[8];
  store_le(buffer, value, 8);
  data_.insert(data_.end(), buffer, buffer + 8);
}

void CanonicalWriter::raw(std::span<const std::byte> bytes) {
  reserve_for(bytes.size(), "encode bytes");
  data_.insert(data_.end(), bytes.begin(), bytes.end());
}

void CanonicalWriter::text(std::string_view value) {
  if (value.size() > UINT32_MAX) {
    throw EpochError(ErrorCode::SizeLimitExceeded, "text field exceeds the encodable length");
  }
  u32(static_cast<std::uint32_t>(value.size()));
  reserve_for(value.size(), "encode text");
  const auto* first = reinterpret_cast<const std::byte*>(value.data());
  data_.insert(data_.end(), first, first + value.size());
}

Sha256Digest CanonicalWriter::digest() const { return sha256(std::span<const std::byte>(data_)); }

void CanonicalReader::require(std::size_t count, std::string_view what) const {
  if (count > data_.size() - offset_) {
    throw EpochError(ErrorCode::Truncated, std::string(what) + ": need " + std::to_string(count) +
                                              " bytes, " + std::to_string(data_.size() - offset_) + " remain");
  }
}

std::uint8_t CanonicalReader::u8() {
  require(1, "decode u8");
  const auto value = static_cast<std::uint8_t>(data_[offset_]);
  ++offset_;
  return value;
}

std::uint16_t CanonicalReader::u16() {
  require(2, "decode u16");
  const std::uint16_t value = static_cast<std::uint16_t>(load_le(data_.data() + offset_, 2));
  offset_ += 2;
  return value;
}

std::uint32_t CanonicalReader::u32() {
  require(4, "decode u32");
  const std::uint32_t value = static_cast<std::uint32_t>(load_le(data_.data() + offset_, 4));
  offset_ += 4;
  return value;
}

std::uint64_t CanonicalReader::u64() {
  require(8, "decode u64");
  const std::uint64_t value = load_le(data_.data() + offset_, 8);
  offset_ += 8;
  return value;
}

bool CanonicalReader::boolean() {
  const std::uint8_t value = u8();
  if (value > 1u) {
    throw EpochError(ErrorCode::EnumOutOfDomain, "boolean field is neither 0 nor 1");
  }
  return value == 1u;
}

std::span<const std::byte> CanonicalReader::raw(std::size_t count) {
  require(count, "decode bytes");
  const std::span<const std::byte> view(data_.data() + offset_, count);
  offset_ += count;
  return view;
}

std::string CanonicalReader::text() {
  const std::uint32_t length = u32();
  if (static_cast<std::size_t>(length) > max_text_bytes_) {
    throw EpochError(ErrorCode::IntegrityLimitExceeded,
                     "text field length " + std::to_string(length) + " exceeds the bound of " +
                         std::to_string(max_text_bytes_));
  }
  const std::span<const std::byte> view = raw(length);
  return std::string(reinterpret_cast<const char*>(view.data()), view.size());
}

Sha256Digest CanonicalReader::digest() {
  const std::span<const std::byte> view = raw(Sha256Digest::byte_size);
  std::array<std::byte, Sha256Digest::byte_size> bytes{};
  std::copy(view.begin(), view.end(), bytes.begin());
  return Sha256Digest::from_bytes(bytes);
}

void CanonicalReader::expect_end() const {
  if (offset_ != data_.size()) {
    throw EpochError(ErrorCode::TrailingBytes, std::to_string(data_.size() - offset_) +
                                                  " trailing bytes after the declared end of the payload");
  }
}

void hash_text(Sha256& hasher, std::string_view value) {
  const auto length = static_cast<std::uint32_t>(value.size());
  std::byte buffer[4];
  store_le(buffer, length, 4);
  hasher.update(std::span<const std::byte>(buffer, 4));
  hasher.update(value);
}

void hash_raw(Sha256& hasher, std::span<const std::byte> value) {
  const auto length = static_cast<std::uint32_t>(value.size());
  std::byte buffer[4];
  store_le(buffer, length, 4);
  hasher.update(std::span<const std::byte>(buffer, 4));
  hasher.update(value);
}

void hash_u64(Sha256& hasher, std::uint64_t value) {
  std::byte buffer[8];
  store_le(buffer, value, 8);
  hasher.update(std::span<const std::byte>(buffer, 8));
}

void hash_u32(Sha256& hasher, std::uint32_t value) {
  std::byte buffer[4];
  store_le(buffer, value, 4);
  hasher.update(std::span<const std::byte>(buffer, 4));
}

void hash_bool(Sha256& hasher, bool value) {
  const std::byte buffer[1] = {static_cast<std::byte>(value ? 1u : 0u)};
  hasher.update(std::span<const std::byte>(buffer, 1));
}

void hash_digest(Sha256& hasher, const Sha256Digest& value) { hasher.update(value.bytes()); }

}  // namespace dccp::epoch::detail
