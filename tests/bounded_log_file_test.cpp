#include "../common/bounded_log_file.h"

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

namespace {
void Expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::exit(1);
    }
}

std::string ReadAll(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input),
                       std::istreambuf_iterator<char>());
}
}

int main() {
    namespace fs = std::filesystem;
    std::error_code error;
    const auto unique = std::chrono::steady_clock::now().time_since_epoch().count();
    const fs::path directory = fs::temp_directory_path() /
        ("oblivion-log-rotation-" + std::to_string(unique));
    Expect(fs::create_directory(directory, error) && !error,
        "create isolated temporary directory");

    const fs::path log = directory / "violations.log";
    constexpr std::uintmax_t kLimit = 8;

    Expect(Oblivion::Logging::PrepareBoundedAppendLog(log, kLimit, error) && !error,
        "allow first write to a missing log");
    {
        std::ofstream out(log, std::ios::binary);
        out << "small";
    }
    Expect(Oblivion::Logging::PrepareBoundedAppendLog(log, kLimit, error) && !error,
        "leave a log below the size limit in place");
    Expect(fs::exists(log) && !fs::exists(directory / "violations.log.1"),
        "do not rotate a small log");

    {
        std::ofstream out(log, std::ios::binary | std::ios::trunc);
        out << "oversized-record";
    }
    Expect(Oblivion::Logging::PrepareBoundedAppendLog(log, kLimit, error) && !error,
        "rotate a log at or above its configured size limit");
    Expect(!fs::exists(log) && ReadAll(directory / "violations.log.1") == "oversized-record",
        "preserve the previous active log as the rotated archive");

    {
        std::ofstream out(log, std::ios::binary);
        out << "next";
    }
    Expect(Oblivion::Logging::PrepareBoundedAppendLog(log, kLimit, error) && !error,
        "accept a new active log after rotation");
    Expect(ReadAll(log) == "next", "leave the new active log untouched");

#ifndef _WIN32
    const fs::path target = directory / "target.txt";
    {
        std::ofstream out(target, std::ios::binary);
        out << "do-not-overwrite";
    }
    const fs::path symlink = directory / "linked-log";
    fs::create_symlink(target.filename(), symlink, error);
    Expect(!error, "create symlink fixture");
    error.clear();
    Expect(!Oblivion::Logging::PrepareBoundedAppendLog(symlink, kLimit, error),
        "reject a symlink as an active log file");
    Expect(ReadAll(target) == "do-not-overwrite",
        "leave the symlink target unchanged");
#endif

    error.clear();
    fs::remove_all(directory, error);
    std::cout << "Bounded violation log tests passed\n";
    return 0;
}
