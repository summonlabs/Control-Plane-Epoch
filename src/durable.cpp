// Control Plane Epoch 1.0.0 - Summon Software Labs
// Durable file primitives.
#include "durable.hpp"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <system_error>

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
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace dccp::epoch::detail {
namespace {

std::atomic<std::uint64_t> g_temp_counter{0};

[[nodiscard]] std::uint64_t process_id() noexcept {
#if defined(_WIN32)
  return static_cast<std::uint64_t>(::GetCurrentProcessId());
#else
  return static_cast<std::uint64_t>(::getpid());
#endif
}

[[noreturn]] void throw_file_error(ErrorCode code, const std::filesystem::path& path, std::string reason) {
  throw EpochError(code, std::move(reason) + " for " + path.string());
}

#if defined(_WIN32)

[[nodiscard]] std::string describe_system_error(unsigned long code) { return "system error " + std::to_string(code); }

[[nodiscard]] ErrorCode classify_error(unsigned long code) noexcept {
  switch (code) {
    case ERROR_ACCESS_DENIED:
    case ERROR_SHARING_VIOLATION:
    case ERROR_LOCK_VIOLATION:
    case ERROR_WRITE_PROTECT:
      return ErrorCode::PermissionDenied;
    case ERROR_PATH_NOT_FOUND:
    case ERROR_INVALID_NAME:
    case ERROR_BAD_PATHNAME:
    case ERROR_DIRECTORY:
      return ErrorCode::PathInvalid;
    case ERROR_DISK_FULL:
    case ERROR_HANDLE_DISK_FULL:
      return ErrorCode::DurableLimitsExceeded;
    case ERROR_FILE_NOT_FOUND:
      return ErrorCode::StoreNotFound;
    default:
      return ErrorCode::PublishFailed;
  }
}

/// Owns one Windows file handle and always closes it.
class WinHandle {
 public:
  WinHandle() = default;
  explicit WinHandle(HANDLE handle) noexcept : handle_(handle) {}
  ~WinHandle() { close(); }

  WinHandle(const WinHandle&) = delete;
  WinHandle& operator=(const WinHandle&) = delete;

  WinHandle(WinHandle&& other) noexcept : handle_(other.handle_) { other.handle_ = INVALID_HANDLE_VALUE; }
  WinHandle& operator=(WinHandle&& other) noexcept {
    if (this != &other) {
      close();
      handle_ = other.handle_;
      other.handle_ = INVALID_HANDLE_VALUE;
    }
    return *this;
  }

  [[nodiscard]] bool valid() const noexcept { return handle_ != INVALID_HANDLE_VALUE; }
  [[nodiscard]] HANDLE get() const noexcept { return handle_; }

  void close() noexcept {
    if (valid()) {
      ::CloseHandle(handle_);
      handle_ = INVALID_HANDLE_VALUE;
    }
  }

 private:
  HANDLE handle_ = INVALID_HANDLE_VALUE;
};

#else

[[nodiscard]] std::string describe_system_error(int code) {
  return std::error_code(code, std::generic_category()).message();
}

[[nodiscard]] ErrorCode classify_error(int code) noexcept {
  switch (code) {
    case EACCES:
    case EPERM:
    case EROFS:
      return ErrorCode::PermissionDenied;
    case ENOENT:
    case ENOTDIR:
    case ENAMETOOLONG:
      return ErrorCode::PathInvalid;
    case ENOSPC:
    case EDQUOT:
    case EFBIG:
      return ErrorCode::DurableLimitsExceeded;
    default:
      return ErrorCode::PublishFailed;
  }
}

/// Owns one POSIX file descriptor and always closes it.
class PosixFd {
 public:
  PosixFd() = default;
  explicit PosixFd(int fd) noexcept : fd_(fd) {}
  ~PosixFd() { close(); }

  PosixFd(const PosixFd&) = delete;
  PosixFd& operator=(const PosixFd&) = delete;

  PosixFd(PosixFd&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
  PosixFd& operator=(PosixFd&& other) noexcept {
    if (this != &other) {
      close();
      fd_ = other.fd_;
      other.fd_ = -1;
    }
    return *this;
  }

  [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }
  [[nodiscard]] int get() const noexcept { return fd_; }

  void close() noexcept {
    if (valid()) {
      ::close(fd_);
      fd_ = -1;
    }
  }

 private:
  int fd_ = -1;
};

#endif

}  // namespace

bool path_exists(const std::filesystem::path& path) {
  std::error_code error;
  return std::filesystem::exists(path, error);
}

bool directory_exists(const std::filesystem::path& path) {
  std::error_code error;
  return std::filesystem::is_directory(path, error);
}

void ensure_directories(const std::filesystem::path& path) {
  std::error_code error;
  std::filesystem::create_directories(path, error);
  if (error && !directory_exists(path)) {
    throw_file_error(ErrorCode::PathInvalid, path, "could not create directory: " + error.message());
  }
}

std::uint64_t file_size_bytes(const std::filesystem::path& path) {
  std::error_code error;
  const auto size = std::filesystem::file_size(path, error);
  if (error) {
    throw_file_error(ErrorCode::PathInvalid, path, "could not read file size: " + error.message());
  }
  return size;
}

std::optional<std::vector<std::byte>> read_file_optional(const std::filesystem::path& path, std::size_t max_bytes) {
#if defined(_WIN32)
  WinHandle handle(::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
  if (!handle.valid()) {
    const unsigned long error = ::GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
      return std::nullopt;
    }
    throw_file_error(classify_error(error), path, "could not open: " + describe_system_error(error));
  }

  LARGE_INTEGER size{};
  if (::GetFileSizeEx(handle.get(), &size) == 0) {
    throw_file_error(ErrorCode::ReadFailed, path, "could not read file size");
  }
  if (size.QuadPart < 0) {
    throw_file_error(ErrorCode::ReadFailed, path, "file reports a negative size");
  }
  const auto declared = static_cast<std::uint64_t>(size.QuadPart);
  if (declared > max_bytes) {
    throw EpochError(ErrorCode::SizeLimitExceeded, "file " + path.string() + " is " + std::to_string(declared) +
                                                       " bytes, bound is " + std::to_string(max_bytes));
  }

  std::vector<std::byte> bytes(static_cast<std::size_t>(declared));
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(bytes.size() - offset, 1u << 20));
    DWORD read = 0;
    if (::ReadFile(handle.get(), bytes.data() + offset, chunk, &read, nullptr) == 0) {
      throw_file_error(ErrorCode::ReadFailed, path, "read failed");
    }
    if (read == 0) {
      throw_file_error(ErrorCode::Truncated, path, "file ended before its declared size");
    }
    offset += read;
  }
  return bytes;
#else
  PosixFd fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
  if (!fd.valid()) {
    if (errno == ENOENT) {
      return std::nullopt;
    }
    if (errno == EACCES) {
      throw_file_error(ErrorCode::PermissionDenied, path, "could not open");
    }
    throw_file_error(ErrorCode::ReadFailed, path, "could not open: " + describe_system_error(errno));
  }
  struct stat status {};
  if (::fstat(fd.get(), &status) != 0) {
    throw_file_error(ErrorCode::ReadFailed, path, "could not stat");
  }
  const auto declared = static_cast<std::uint64_t>(status.st_size);
  if (declared > max_bytes) {
    throw EpochError(ErrorCode::SizeLimitExceeded, "file " + path.string() + " is " + std::to_string(declared) +
                                                       " bytes, bound is " + std::to_string(max_bytes));
  }
  std::vector<std::byte> bytes(static_cast<std::size_t>(declared));
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t read = ::read(fd.get(), bytes.data() + offset, bytes.size() - offset);
    if (read < 0) {
      if (errno == EINTR) {
        continue;
      }
      throw_file_error(ErrorCode::ReadFailed, path, "read failed: " + describe_system_error(errno));
    }
    if (read == 0) {
      throw_file_error(ErrorCode::Truncated, path, "file ended before its declared size");
    }
    offset += static_cast<std::size_t>(read);
  }
  return bytes;
#endif
}

std::vector<std::byte> read_file_bounded(const std::filesystem::path& path, std::size_t max_bytes) {
  std::optional<std::vector<std::byte>> bytes = read_file_optional(path, max_bytes);
  if (!bytes.has_value()) {
    throw_file_error(ErrorCode::StoreNotFound, path, "file does not exist");
  }
  return std::move(*bytes);
}

void write_file_exclusive(const std::filesystem::path& path, std::span<const std::byte> bytes) {
#if defined(_WIN32)
  WinHandle handle(::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                 FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr));
  if (!handle.valid()) {
    const unsigned long error = ::GetLastError();
    if (error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS) {
      throw_file_error(ErrorCode::TempCreateFailed, path, "temporary file already exists");
    }
    throw_file_error(classify_error(error), path, "could not create: " + describe_system_error(error));
  }

  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(bytes.size() - offset, 1u << 20));
    DWORD written = 0;
    if (::WriteFile(handle.get(), bytes.data() + offset, chunk, &written, nullptr) == 0) {
      throw_file_error(classify_error(::GetLastError()), path, "write failed");
    }
    if (written == 0) {
      throw_file_error(ErrorCode::WriteFailed, path, "write made no progress");
    }
    offset += written;
  }
  if (::FlushFileBuffers(handle.get()) == 0) {
    throw_file_error(ErrorCode::SyncFailed, path, "device flush failed");
  }
  handle.close();
#else
  PosixFd fd(::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
  if (!fd.valid()) {
    if (errno == EEXIST) {
      throw_file_error(ErrorCode::TempCreateFailed, path, "temporary file already exists");
    }
    if (errno == EACCES || errno == EROFS) {
      throw_file_error(ErrorCode::PermissionDenied, path, "could not create");
    }
    throw_file_error(ErrorCode::PublishFailed, path, "could not create: " + describe_system_error(errno));
  }

  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t written = ::write(fd.get(), bytes.data() + offset, bytes.size() - offset);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      throw_file_error(classify_error(errno), path, "write failed: " + describe_system_error(errno));
    }
    if (written == 0) {
      throw_file_error(ErrorCode::WriteFailed, path, "write made no progress");
    }
    offset += static_cast<std::size_t>(written);
  }
  if (::fsync(fd.get()) != 0) {
    throw_file_error(ErrorCode::SyncFailed, path, "device flush failed: " + describe_system_error(errno));
  }
  fd.close();
#endif
}

void flush_existing_file(const std::filesystem::path& path) {
#if defined(_WIN32)
  WinHandle handle(::CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
  if (!handle.valid()) {
    throw_file_error(classify_error(::GetLastError()), path, "could not open for flush");
  }
  if (::FlushFileBuffers(handle.get()) == 0) {
    throw_file_error(ErrorCode::SyncFailed, path, "device flush failed");
  }
#else
  PosixFd fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
  if (!fd.valid()) {
    throw_file_error(classify_error(errno), path, "could not open for flush");
  }
  if (::fsync(fd.get()) != 0) {
    throw_file_error(ErrorCode::SyncFailed, path, "device flush failed: " + describe_system_error(errno));
  }
#endif
}

void atomic_replace(const std::filesystem::path& source, const std::filesystem::path& target) {
#if defined(_WIN32)
  // A reader that holds the target open without FILE_SHARE_DELETE, or a filter
  // driver scanning it, can make the replace fail transiently. The retry is
  // bounded and only covers sharing and access violations; every other failure
  // is reported immediately. Nothing is ever deleted before the replacement is
  // in place, so a failed replace leaves the previous generation authoritative.
  constexpr int kReplaceAttempts = 20;
  for (int attempt = 0; attempt < kReplaceAttempts; ++attempt) {
    if (::MoveFileExW(source.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0) {
      return;
    }
    const unsigned long error = ::GetLastError();
    if (error != ERROR_ACCESS_DENIED && error != ERROR_SHARING_VIOLATION && error != ERROR_LOCK_VIOLATION) {
      throw_file_error(classify_error(error), target, "atomic replace of " + source.string() + " failed");
    }
    ::Sleep(5);
  }
  throw_file_error(ErrorCode::PublishFailed, target,
                   "atomic replace of " + source.string() + " was denied while the target was held open");
#else
  if (::rename(source.c_str(), target.c_str()) != 0) {
    throw_file_error(classify_error(errno), target,
                     "atomic replace of " + source.string() + " failed: " + describe_system_error(errno));
  }
#endif
}

void remove_file_if_exists(const std::filesystem::path& path) noexcept {
#if defined(_WIN32)
  ::DeleteFileW(path.c_str());
#else
  ::unlink(path.c_str());
#endif
}

void sync_directory(const std::filesystem::path& path) noexcept {
#if defined(_WIN32)
  (void)path;  // MoveFileEx with MOVEFILE_WRITE_THROUGH already flushes the rename.
#else
  PosixFd fd(::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  if (fd.valid()) {
    ::fsync(fd.get());
  }
#endif
}

std::string next_temp_name(std::string_view base) {
  const std::uint64_t counter = g_temp_counter.fetch_add(1) + 1;
  std::string name(base);
  name.append(".tmp.");
  name.append(std::to_string(process_id()));
  name.push_back('.');
  name.append(std::to_string(counter));
  return name;
}

std::string sanitize_file_name_component(std::string_view text) {
  std::string sanitized;
  sanitized.reserve(text.size());
  for (const char character : text) {
    const bool allowed = (character >= '0' && character <= '9') || (character >= 'A' && character <= 'Z') ||
                         (character >= 'a' && character <= 'z') || character == '.' || character == '_' ||
                         character == '-';
    sanitized.push_back(allowed ? character : '_');
  }
  if (sanitized.empty()) {
    sanitized = "unnamed";
  }
  return sanitized;
}

}  // namespace dccp::epoch::detail



