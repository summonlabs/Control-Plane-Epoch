// Control Plane Epoch 1.0.0 - Summon Software Labs
// Exclusive process-level writer lock for one store directory.
//
// The lock is advisory and operating-system enforced: exactly one process may
// hold it at a time. It is taken once when the store is opened for writing and
// released once when the store is closed, so no commit ever re-enters the
// operating-system lock and there is no lock inversion between the in-process
// mutex and the file lock.
#pragma once

#include <filesystem>
#include <string>

namespace dccp::epoch::detail {

/// Holds an exclusive lock on one lock file for its lifetime.
class WriterLock {
 public:
  WriterLock() = default;
  ~WriterLock() { release(); }

  WriterLock(const WriterLock&) = delete;
  WriterLock& operator=(const WriterLock&) = delete;
  WriterLock(WriterLock&& other) noexcept;
  WriterLock& operator=(WriterLock&& other) noexcept;

  /// Acquires the lock without waiting. Throws
  /// EpochError(StoreLocked) when another process holds it, and
  /// EpochError(PermissionDenied) / EpochError(PathInvalid) when the lock file
  /// cannot be used at all.
  static WriterLock acquire(const std::filesystem::path& lock_path);

  [[nodiscard]] bool held() const noexcept;
  void release() noexcept;

 private:
  void* handle_ = nullptr;
};

}  // namespace dccp::epoch::detail
