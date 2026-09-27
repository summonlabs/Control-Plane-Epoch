// Control Plane Epoch 1.0.0 - Summon Software Labs
// Durable file primitives: exclusive temporary creation, device flush, atomic
// replace, and bounded reads. Internal; not installed.
//
// Publication protocol used by the authority store:
//   create temporary exclusively -> write -> flush to device -> verify by
//   reading back -> retain the superseded generation -> atomic replace ->
//   flush the directory (POSIX) so the rename itself is durable.
//
// Nothing here deletes the target before the replacement is in place, so a
// crash can never leave the store without a readable generation.
#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "control_plane_epoch/error.hpp"

namespace dccp::epoch::detail {

[[nodiscard]] bool path_exists(const std::filesystem::path& path);
[[nodiscard]] bool directory_exists(const std::filesystem::path& path);

/// Creates every missing component. Throws EpochError(PathInvalid) on failure.
void ensure_directories(const std::filesystem::path& path);

/// Reads a file after checking its size against the bound, so a hostile or
/// corrupt file cannot make the process allocate without limit. A missing file
/// raises EpochError(StoreNotFound).
[[nodiscard]] std::vector<std::byte> read_file_bounded(const std::filesystem::path& path, std::size_t max_bytes);

/// Reads a file, returning std::nullopt when it does not exist.
[[nodiscard]] std::optional<std::vector<std::byte>> read_file_optional(const std::filesystem::path& path,
                                                                      std::size_t max_bytes);

/// Creates a new file exclusively (failing if it exists), writes the whole
/// buffer, and flushes it to the device. The caller-supplied name must be inside
/// the store directory; no component is ever interpreted as a path.
void write_file_exclusive(const std::filesystem::path& path, std::span<const std::byte> bytes);

/// Flushes an existing file to the device.
void flush_existing_file(const std::filesystem::path& path);

/// Atomically replaces target with source. On POSIX this is rename(2); on
/// Windows it is MoveFileEx with replace-existing and write-through.
void atomic_replace(const std::filesystem::path& source, const std::filesystem::path& target);

void remove_file_if_exists(const std::filesystem::path& path) noexcept;

/// Flushes a directory entry so a rename survives a crash. A no-op on Windows,
/// where MoveFileEx with MOVEFILE_WRITE_THROUGH provides the guarantee.
void sync_directory(const std::filesystem::path& path) noexcept;

[[nodiscard]] std::uint64_t file_size_bytes(const std::filesystem::path& path);

/// Unique-per-process temporary name: "<base>.tmp.<pid>.<counter>". The counter
/// is process local and monotonic, so two writers can never target the same
/// temporary path; exclusive creation is still used as the authoritative guard.
[[nodiscard]] std::string next_temp_name(std::string_view base);

/// Replaces characters that cannot appear in a file name so that a damaged
/// file's content-addressed quarantine name is always valid.
[[nodiscard]] std::string sanitize_file_name_component(std::string_view text);

}  // namespace dccp::epoch::detail

