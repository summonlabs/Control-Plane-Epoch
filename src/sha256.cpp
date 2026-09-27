// Control Plane Epoch 1.0.0 - Summon Software Labs
// SHA-256 (FIPS 180-4) implementation and digest value type.
#include "control_plane_epoch/digest.hpp"

#include <algorithm>
#include <cstring>

namespace dccp::epoch {
namespace {

constexpr std::uint32_t round_constants[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

[[nodiscard]] constexpr std::uint32_t rotr(std::uint32_t value, unsigned int count) noexcept {
  return (value >> count) | (value << (32u - count));
}

[[nodiscard]] std::uint32_t load_be32(const std::byte* bytes) noexcept {
  return (static_cast<std::uint32_t>(bytes[0]) << 24) | (static_cast<std::uint32_t>(bytes[1]) << 16) |
         (static_cast<std::uint32_t>(bytes[2]) << 8) | static_cast<std::uint32_t>(bytes[3]);
}

void store_be32(std::byte* out, std::uint32_t value) noexcept {
  out[0] = static_cast<std::byte>((value >> 24) & 0xFFu);
  out[1] = static_cast<std::byte>((value >> 16) & 0xFFu);
  out[2] = static_cast<std::byte>((value >> 8) & 0xFFu);
  out[3] = static_cast<std::byte>(value & 0xFFu);
}

[[nodiscard]] int hex_value(char character) noexcept {
  if (character >= '0' && character <= '9') {
    return character - '0';
  }
  if (character >= 'a' && character <= 'f') {
    return character - 'a' + 10;
  }
  if (character >= 'A' && character <= 'F') {
    return character - 'A' + 10;
  }
  return -1;
}

constexpr char hex_digits[] = "0123456789abcdef";

}  // namespace

namespace {

void compress_block(std::array<std::uint32_t, 8>& state, const std::byte* block) noexcept {
  std::uint32_t schedule[64];
  for (int index = 0; index < 16; ++index) {
    schedule[index] = load_be32(block + (static_cast<std::size_t>(index) * 4u));
  }
  for (int index = 16; index < 64; ++index) {
    const std::uint32_t s0 =
        rotr(schedule[index - 15], 7) ^ rotr(schedule[index - 15], 18) ^ (schedule[index - 15] >> 3);
    const std::uint32_t s1 =
        rotr(schedule[index - 2], 17) ^ rotr(schedule[index - 2], 19) ^ (schedule[index - 2] >> 10);
    schedule[index] = schedule[index - 16] + s0 + schedule[index - 7] + s1;
  }

  std::uint32_t a = state[0];
  std::uint32_t b = state[1];
  std::uint32_t c = state[2];
  std::uint32_t d = state[3];
  std::uint32_t e = state[4];
  std::uint32_t f = state[5];
  std::uint32_t g = state[6];
  std::uint32_t h = state[7];

  for (int index = 0; index < 64; ++index) {
    const std::uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const std::uint32_t choose = (e & f) ^ ((~e) & g);
    const std::uint32_t temp1 = h + s1 + choose + round_constants[index] + schedule[index];
    const std::uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = s0 + majority;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

void absorb(std::array<std::uint32_t, 8>& state, std::array<std::byte, 64>& buffer, std::size_t& buffered,
            const std::byte* data, std::size_t size) noexcept {
  std::size_t offset = 0;
  while (offset < size) {
    const std::size_t space = 64u - buffered;
    const std::size_t take = std::min(space, size - offset);
    std::memcpy(buffer.data() + buffered, data + offset, take);
    buffered += take;
    offset += take;
    if (buffered == 64u) {
      compress_block(state, buffer.data());
      buffered = 0;
    }
  }
}

}  // namespace

Sha256::Sha256() noexcept
    : state_{0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au, 0x510e527fu, 0x9b05688cu, 0x1f83d9abu,
             0x5be0cd19u} {}

void Sha256::update(std::span<const std::byte> data) {
  if (finalized_) {
    throw EpochError(ErrorCode::InvariantViolation, "Sha256::update after finish");
  }
  if (data.empty()) {
    return;
  }
  total_bytes_ += static_cast<std::uint64_t>(data.size());
  absorb(state_, buffer_, buffered_, data.data(), data.size());
}

void Sha256::update(std::string_view text) {
  update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(text.data()), text.size()));
}

Sha256Digest Sha256::finish() {
  if (finalized_) {
    throw EpochError(ErrorCode::InvariantViolation, "Sha256::finish called twice");
  }
  finalized_ = true;

  const std::uint64_t total_bits = total_bytes_ * 8u;
  std::byte padding[128] = {};
  padding[0] = std::byte{0x80};
  const std::size_t pad_length = (buffered_ < 56u) ? (56u - buffered_) : (120u - buffered_);
  absorb(state_, buffer_, buffered_, padding, pad_length);

  std::byte length_bytes[8];
  for (int index = 0; index < 8; ++index) {
    length_bytes[index] = static_cast<std::byte>((total_bits >> (56 - (8 * index))) & 0xFFu);
  }
  // Absorbing the length never crosses a block boundary: the padding above
  // leaves exactly eight bytes of space in the final block.
  std::memcpy(buffer_.data() + buffered_, length_bytes, 8);
  buffered_ += 8;
  compress_block(state_, buffer_.data());
  buffered_ = 0;

  std::array<std::byte, Sha256Digest::byte_size> digest{};
  for (std::size_t index = 0; index < state_.size(); ++index) {
    store_be32(digest.data() + (index * 4u), state_[index]);
  }
  return Sha256Digest::from_bytes(digest);
}

Sha256Digest Sha256Digest::from_bytes(std::span<const std::byte, byte_size> bytes) noexcept {
  Sha256Digest digest;
  std::copy(bytes.begin(), bytes.end(), digest.bytes_.begin());
  return digest;
}

Result<Sha256Digest> Sha256Digest::from_hex(std::string_view text) {
  if (text.size() != byte_size * 2u) {
    return Explanation(ErrorCode::DigestInvalidHex,
                       "expected 64 hexadecimal characters, received " + std::to_string(text.size()));
  }
  Sha256Digest digest;
  for (std::size_t index = 0; index < byte_size; ++index) {
    const int high = hex_value(text[index * 2u]);
    const int low = hex_value(text[index * 2u + 1u]);
    if (high < 0 || low < 0) {
      return Explanation(ErrorCode::DigestInvalidHex,
                         "non-hexadecimal character at offset " + std::to_string(index * 2u));
    }
    digest.bytes_[index] = static_cast<std::byte>((high << 4) | low);
  }
  return digest;
}

bool Sha256Digest::is_zero() const noexcept {
  for (const std::byte value : bytes_) {
    if (value != std::byte{0}) {
      return false;
    }
  }
  return true;
}

std::string Sha256Digest::to_hex() const {
  std::string text;
  text.reserve(byte_size * 2u);
  for (const std::byte value : bytes_) {
    const auto byte_value = static_cast<unsigned int>(value);
    text.push_back(hex_digits[(byte_value >> 4) & 0xFu]);
    text.push_back(hex_digits[byte_value & 0xFu]);
  }
  return text;
}

Sha256Digest sha256(std::span<const std::byte> data) {
  Sha256 hasher;
  hasher.update(data);
  return hasher.finish();
}

Sha256Digest sha256(std::string_view text) {
  Sha256 hasher;
  hasher.update(text);
  return hasher.finish();
}

}  // namespace dccp::epoch
