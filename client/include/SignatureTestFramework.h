#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <unordered_set>

// Lightweight signature testing framework for offline validation of YARA rules
// and signature packs. Focuses on test execution and simple reporting.

struct SigTestCase {
    std::wstring filePath;                 // File to scan
    std::vector<std::string> expectMatch;  // Expected YARA rule names to match (any order)
    std::vector<std::string> expectNone;   // Rules that must NOT match
};

struct SigTestResult {
    std::wstring filePath;
    std::vector<std::string> matchedRules;
    std::vector<std::string> missingExpected;  // Expected but not found
    std::vector<std::string> unexpectedHits;   // Not expected but matched
    bool passed;
    double scanTimeMs;
};

struct SigTestReport {
    int total = 0;
    int passed = 0;
    int failed = 0;
    double totalTimeMs = 0.0;
    std::vector<SigTestResult> results;
};

class SignatureTestFramework {
public:
    // Load test cases from a simple CSV file:
    // file,expect_match(semi-colon),expect_none(semi-colon)
    static bool LoadTestsFromCsv(const std::wstring& csvPath, std::vector<SigTestCase>& outCases);

    // Run YARA tests using client YARA engine on files
    // rulesPath: path to YARA rules (e.g., signatures\\yara_rules.txt)
    static bool RunYaraTests(const std::wstring& rulesPath,
                             const std::vector<SigTestCase>& cases,
                             SigTestReport& outReport);

    // Save report to CSV (compact) and JSON (summary-only)
    static bool SaveReportCsv(const std::wstring& outPath, const SigTestReport& report);
    static bool SaveReportJson(const std::wstring& outPath, const SigTestReport& report);

    // Simple throughput benchmark (MB/s) by scanning a file N times
    static bool BenchmarkYaraScan(const std::wstring& rulesPath,
                                  const std::wstring& filePath,
                                  int iterations,
                                  double& outMBps,
                                  double& outAvgMs);
};
