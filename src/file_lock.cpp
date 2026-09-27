// Control Plane Epoch 1.0.0 - Summon Software Labs
// Exclusive writer lock implementation.
#include "file_lock.hpp"

#include "control_plane_epoch/error.hpp"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace dccp::epoch::detail {

WriterLock::WriterLock(WriterLock&& other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }

WriterLock& WriterLock::operator=(WriterLock&& other) noexcept {
  if (this != &other) {
    release();
    handle_ = other.handle_;
    other.handle_ = nullptr;
  }
  return *this;
}

bool WriterLock::held() const noexcept { return handle_ != nullptr; }

WriterLock WriterLock::acquire(const std::filesystem::path& lock_path) {
#if defined(_WIN32)
  HANDLE handle = ::CreateFileW(lock_path.c_str(), GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    const unsigned long error = ::GetLastError();
    const ErrorCode code = (error == ERROR_ACCESS_DENIED)     ? ErrorCode::PermissionDenied
                           : (error == ERROR_PATH_NOT_FOUND)  ? ErrorCode::PathInvalid
                                                              : ErrorCode::StoreLocked;
    throw EpochError(code, "could not open the store lock file " + lock_path.string() + ": system error " +
                               std::to_string(error));
  }

  OVERLAPPED overlapped{};
  if (::LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped) == 0) {
    const unsigned long error = ::GetLastError();
    ::CloseHandle(handle);
    if (error == ERROR_LOCK_VIOLATION || error == ERROR_IO_PENDING || error == ERROR_SHARING_VIOLATION) {
      throw EpochError(ErrorCode::StoreLocked,
                       "another process holds the exclusive writer lock on " + lock_path.string());
    }
    throw EpochError(ErrorCode::PermissionDenied, "could not lock " + lock_path.string() + ": system error " +
                                                      std::to_string(error));
  }

  WriterLock lock;
  lock.handle_ = handle;
  return lock;
#else
  const int fd = ::open(lock_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  if (fd < 0) {
    const ErrorCode code = (errno == EACCES || errno == EROFS) ? ErrorCode::PermissionDenied
                           : (errno == ENOENT || errno == ENOTDIR) ? ErrorCode::PathInvalid
                                                                   : ErrorCode::StoreLocked;
    throw EpochError(code, "could not open the store lock file " + lock_path.string() + ": errno " +
                               std::to_string(errno));
  }
  if (::flock(fd, LOCK_EX | LOCK_NB) != 0) {
    const int error = errno;
    ::close(fd);
    if (error == EWOULDBLOCK || error == EAGAIN) {
      throw EpochError(ErrorCode::StoreLocked,
                       "another process holds the exclusive writer lock on " + lock_path.string());
    }
    throw EpochError(ErrorCode::PermissionDenied, "could not lock " + lock_path.string() + ": errno " +
                                                      std::to_string(error));
  }

  WriterLock lock;
  lock.handle_ = reinterpret_cast<void*>(static_cast<std::intptr_t>(fd));
  return lock;
#endif
}

void WriterLock::release() noexcept {
  if (handle_ == nullptr) {
    return;
  }
#if defined(_WIN32)
  auto* handle = static_cast<HANDLE>(handle_);
  OVERLAPPED overlapped{};
  ::UnlockFileEx(handle, 0, 1, 0, &overlapped);
  ::CloseHandle(handle);
#else
  const int fd = static_cast<int>(reinterpret_cast<std::intptr_t>(handle_));
  ::flock(fd, LOCK_UN);
  ::close(fd);
#endif
  handle_ = nullptr;
}

}  // namespace dccp::epoch::detail
