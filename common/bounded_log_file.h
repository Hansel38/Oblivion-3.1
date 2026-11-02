#pragma once

#include <cstdint>
#include <filesystem>
#include <system_error>

namespace Oblivion::Logging {

inline bool PrepareBoundedAppendLog(
    const std::filesystem::path& path,
    std::uintmax_t maxBytes,
    std::error_code& error) {
    error.clear();
    if (path.empty() || maxBytes == 0) {
        error = std::make_error_code(std::errc::invalid_argument);
        return false;
    }

    const auto status = std::filesystem::symlink_status(path, error);
    if (error == std::errc::no_such_file_or_directory) {
        error.clear();
        return true;
    }
    if (error) {
        return false;
    }
    if (!std::filesystem::exists(status)) {
        return true;
    }
    if (std::filesystem::is_symlink(status) ||
        !std::filesystem::is_regular_file(status)) {
        error = std::make_error_code(std::errc::operation_not_permitted);
        return false;
    }

    const std::uintmax_t currentSize = std::filesystem::file_size(path, error);
    if (error) {
        return false;
    }
    if (currentSize < maxBytes) {
        return true;
    }

    std::filesystem::path archivePath = path;
    archivePath += ".1";

    const auto archiveStatus = std::filesystem::symlink_status(archivePath, error);
    if (error == std::errc::no_such_file_or_directory) {
        error.clear();
    } else if (error) {
        return false;
    }

    // remove() removes the archive entry itself; it does not follow a symlink.
    if (std::filesystem::exists(archiveStatus)) {
        if (!std::filesystem::remove(archivePath, error) || error) {
            return false;
        }
    }

    std::filesystem::rename(path, archivePath, error);
    return !error;
}

} // namespace Oblivion::Logging
