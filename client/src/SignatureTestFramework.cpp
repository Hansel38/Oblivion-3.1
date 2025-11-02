#include "../pch.h"
#include "SignatureTestFramework.h"
#include "YaraRuleEngine.h"
#include <fstream>
#include <sstream>
#include <algorithm>

static std::wstring TrimW(const std::wstring& s) {
    size_t b = s.find_first_not_of(L" \t\r\n");
    size_t e = s.find_last_not_of(L" \t\r\n");
    if (b == std::wstring::npos) return L"";
    return s.substr(b, e - b + 1);
}

static std::vector<std::wstring> SplitW(const std::wstring& s, wchar_t sep) {
    std::vector<std::wstring> parts; std::wstring cur;
    for (size_t i=0;i<=s.size();++i){ wchar_t c=(i<s.size()?s[i]:sep); if(c==sep){ parts.push_back(cur); cur.clear(); } else cur.push_back(c);} return parts;
}

static std::vector<std::string> SplitUtf8List(const std::wstring& w, wchar_t sep) {
    std::vector<std::string> out; auto parts = SplitW(w, sep);
    for (auto& p : parts) {
        auto tp = TrimW(p);
        if (!tp.empty()) {
            int len = WideCharToMultiByte(CP_UTF8,0,tp.c_str(),(int)tp.size(),nullptr,0,nullptr,nullptr);
            std::string s(len,0); WideCharToMultiByte(CP_UTF8,0,tp.c_str(),(int)tp.size(),&s[0],len,nullptr,nullptr);
            out.push_back(s);
        }
    }
    return out;
}

bool SignatureTestFramework::LoadTestsFromCsv(const std::wstring& csvPath, std::vector<SigTestCase>& outCases) {
    outCases.clear();
    std::wifstream f(csvPath);
    if (!f.is_open()) return false;
    f.imbue(std::locale(""));

    std::wstring line;
    // Optional header line; we'll accept either with or without
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        auto cols = SplitW(line, L',');
        if (cols.size() < 1) continue;

        SigTestCase tc{};
        tc.filePath = TrimW(cols[0]);
        if (cols.size() >= 2) tc.expectMatch = SplitUtf8List(cols[1], L';');
        if (cols.size() >= 3) tc.expectNone  = SplitUtf8List(cols[2], L';');
        if (!tc.filePath.empty()) outCases.push_back(std::move(tc));
    }
    return !outCases.empty();
}

bool SignatureTestFramework::RunYaraTests(const std::wstring& rulesPath,
                                          const std::vector<SigTestCase>& cases,
                                          SigTestReport& outReport) {
    outReport = {};
    if (cases.empty()) return false;

    YaraRuleEngine engine;
    // Convert path to UTF-8 since the engine expects std::string internally for IDs
    int len = WideCharToMultiByte(CP_UTF8,0,rulesPath.c_str(),(int)rulesPath.size(),nullptr,0,nullptr,nullptr);
    std::string rulesUtf8(len,0); WideCharToMultiByte(CP_UTF8,0,rulesPath.c_str(),(int)rulesPath.size(),&rulesUtf8[0],len,nullptr,nullptr);

    if (!engine.LoadRulesFromFile(rulesPath)) {
        return false;
    }

    ULONGLONG tStartAll = GetTickCount64();

    for (const auto& tc : cases) {
        SigTestResult tr{}; tr.filePath = tc.filePath; tr.passed = false; tr.scanTimeMs = 0.0;
        ULONGLONG t0 = GetTickCount64();
        auto matches = engine.ScanFile(tc.filePath);
        tr.scanTimeMs = (double)(GetTickCount64() - t0);

        std::unordered_set<std::string> matched(matches.begin(), matches.end());
        tr.matchedRules.assign(matches.begin(), matches.end());

        // Check expectations
        for (const auto& exp : tc.expectMatch) {
            if (matched.find(exp) == matched.end()) tr.missingExpected.push_back(exp);
        }
        for (const auto& bad : tc.expectNone) {
            if (matched.find(bad) != matched.end()) tr.unexpectedHits.push_back(bad);
        }

        tr.passed = tr.missingExpected.empty() && tr.unexpectedHits.empty();
        outReport.results.push_back(std::move(tr));
    }

    outReport.total = (int)outReport.results.size();
    outReport.passed = 0; outReport.failed = 0; outReport.totalTimeMs = (double)(GetTickCount64() - tStartAll);
    for (const auto& r : outReport.results) {
        if (r.passed) outReport.passed++; else outReport.failed++;
    }
    return true;
}

static std::string ToUtf8(const std::wstring& ws) {
    if (ws.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8,0,ws.c_str(),(int)ws.size(),nullptr,0,nullptr,nullptr);
    std::string s(len,0); WideCharToMultiByte(CP_UTF8,0,ws.c_str(),(int)ws.size(),&s[0],len,nullptr,nullptr);
    return s;
}

bool SignatureTestFramework::SaveReportCsv(const std::wstring& outPath, const SigTestReport& report) {
    std::ofstream f(ToUtf8(outPath));
    if (!f.is_open()) return false;
    f << "file,passed,scan_ms,matched,missing_expected,unexpected_hits\n";
    for (const auto& r : report.results) {
        f << '"' << ToUtf8(r.filePath) << "\"," << (r.passed?"1":"0") << ',' << r.scanTimeMs << ',';
        // matched
        {
            bool first = true; f << '"';
            for (const auto& m : r.matchedRules) { if(!first) f<<';'; f << m; first=false; }
            f << '"' << ',';
        }
        // missing
        {
            bool first = true; f << '"';
            for (const auto& m : r.missingExpected) { if(!first) f<<';'; f << m; first=false; }
            f << '"' << ',';
        }
        // unexpected
        {
            bool first = true; f << '"';
            for (const auto& m : r.unexpectedHits) { if(!first) f<<';'; f << m; first=false; }
            f << '"';
        }
        f << "\n";
    }
    return true;
}

bool SignatureTestFramework::SaveReportJson(const std::wstring& outPath, const SigTestReport& report) {
    std::ofstream f(ToUtf8(outPath));
    if (!f.is_open()) return false;
    f << "{\n";
    f << "  \"total\": " << report.total << ",\n";
    f << "  \"passed\": " << report.passed << ",\n";
    f << "  \"failed\": " << report.failed << ",\n";
    f << "  \"total_time_ms\": " << report.totalTimeMs << "\n";
    f << "}\n";
    return true;
}

bool SignatureTestFramework::BenchmarkYaraScan(const std::wstring& rulesPath,
                                               const std::wstring& filePath,
                                               int iterations,
                                               double& outMBps,
                                               double& outAvgMs) {
    outMBps = 0.0; outAvgMs = 0.0;
    if (iterations <= 0) return false;

    YaraRuleEngine engine;
    if (!engine.LoadRulesFromFile(rulesPath)) return false;

    // Get file size
    HANDLE h = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{}; GetFileSizeEx(h, &sz); CloseHandle(h);
    if (sz.QuadPart <= 0) return false;

    ULONGLONG totalMs = 0;
    for (int i=0;i<iterations;++i) {
        ULONGLONG t0 = GetTickCount64();
        auto matches = engine.ScanFile(filePath);
        (void)matches;
        totalMs += (GetTickCount64() - t0);
    }

    outAvgMs = (double)totalMs / (double)iterations;
    double mb = (double)sz.QuadPart / (1024.0*1024.0);
    if (outAvgMs > 0.0) outMBps = (mb) / (outAvgMs / 1000.0);
    return true;
}
