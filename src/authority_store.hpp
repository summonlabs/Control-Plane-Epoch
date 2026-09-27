// Control Plane Epoch 1.0.0 - Summon Software Labs
// Internal durable authority store: open, recover, commit, quarantine. Not
// installed.
#pragma once

#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "control_plane_epoch/epoch.hpp"
#include "control_plane_epoch/error.hpp"
#include "control_plane_epoch/incarnation.hpp"
#include "control_plane_epoch/store.hpp"

#include "file_lock.hpp"
#include "image.hpp"

namespace dccp::epoch::detail {

struct StorePaths {
  std::filesystem::path directory;
  std::filesystem::path lock;
  std::filesystem::path snapshot;
  std::filesystem::path previous;
  std::filesystem::path floor;
  std::filesystem::path quarantine;

  [[nodiscard]] static StorePaths for_directory(const std::filesystem::path& directory);
};

/// Epoch and instance the caller must use when initializing a domain in this
/// store. For a fresh directory that is epoch 1 of instance 1; for a
/// reinitialized directory it is strictly above every recoverable floor value.
struct InitializationSeed {
  Epoch first_epoch;
  DomainInstanceNumber domain_instance;
};

/// One durable store directory, owned exclusively for writing.
class AuthorityStore {
 public:
  /// Opens the store, applying the recovery policy. Throws EpochError on
  /// infrastructure failure: an unusable directory, a store already locked by
  /// another writer process, damaged state under RecoveryPolicy::RefuseOnDamage,
  /// a generation that sits below the durable floor, or a missing floor.
  [[nodiscard]] static std::unique_ptr<AuthorityStore> open(const StoreOpenOptions& options);

  ~AuthorityStore();
  AuthorityStore(const AuthorityStore&) = delete;
  AuthorityStore& operator=(const AuthorityStore&) = delete;
  AuthorityStore(AuthorityStore&&) = delete;
  AuthorityStore& operator=(AuthorityStore&&) = delete;

  [[nodiscard]] const RecoveryReport& report() const noexcept { return report_; }
  [[nodiscard]] const AuthorityImage& image() const noexcept { return image_; }
  [[nodiscard]] bool initialized() const noexcept { return initialized_; }
  [[nodiscard]] bool read_only() const noexcept { return mode_ == StoreOpenMode::ReadOnly; }
  [[nodiscard]] const std::filesystem::path& directory() const noexcept { return paths_.directory; }
  [[nodiscard]] std::uint64_t snapshot_bytes() const noexcept { return snapshot_bytes_; }
  [[nodiscard]] bool retained_previous_generation() const noexcept { return retained_previous_; }
  [[nodiscard]] const Sha256Digest& snapshot_digest() const noexcept { return snapshot_digest_; }
  [[nodiscard]] const ImageLimits& limits() const noexcept { return limits_; }

  /// Values the caller must use when creating the domain. Rejected with
  /// EpochError(StoreAlreadyInitialized) when a domain already exists.
  [[nodiscard]] InitializationSeed seed() const;

  /// Read-only verification of a store directory: integrity of the live
  /// generation, the retained previous generation, the durable floor, and the
  /// transition chain. Never writes, never locks, never repairs.
  [[nodiscard]] static StoreInspection inspect(const std::filesystem::path& directory);

  /// Publishes one new generation transactionally. `image` receives the durable
  /// generation that was assigned. Throws EpochError on any failure, and in
  /// that case the previous durable state remains authoritative.
  [[nodiscard]] DurableCommitReport commit(AuthorityImage& image);

  void close() noexcept;

 private:
  AuthorityStore() = default;

  StorePaths paths_;
  StoreOpenMode mode_ = StoreOpenMode::ReadWrite;
  RecoveryPolicy policy_ = RecoveryPolicy::RefuseOnDamage;
  ImageLimits limits_;
  std::optional<WriterLock> lock_;
  AuthorityImage image_;
  RecoveryReport report_;
  bool initialized_ = false;
  bool open_ = false;
  bool retained_previous_ = false;
  std::uint64_t snapshot_bytes_ = 0;
  Sha256Digest snapshot_digest_;
  std::vector<std::byte> snapshot_bytes_cache_;
  std::optional<FloorData> floor_;
  bool floor_asserted_ = false;
};

}  // namespace dccp::epoch::detail
