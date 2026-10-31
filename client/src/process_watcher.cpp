#include "pch.h"
#include "process_watcher.h"
#include "blacklist.h"
#include "AntiDebug.h"
#include "injection_scanner.h"
#include "anti_suspend.h"
#include "overlay_scanner.h"
#include "memory_scanner.h"
#include "digital_signature_validator.h"
#include "iat_hook_scanner.h"
#include "advanced_process_heuristics.h"
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <unordered_set>

// Forward declaration
extern void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details);

namespace Oblivion {
    ProcessWatcher::ProcessWatcher()
        : m_isRunning(false)
        , m_pAntiDebug(nullptr)
        , m_pInjectionScanner(nullptr)
        , m_pAntiSuspend(nullptr)
        , m_pOverlayScanner(nullptr)
        , m_pMemoryScanner(nullptr)
        , m_pDigitalSignatureValidator(nullptr)
        , m_pIATHookScanner(nullptr)
        , m_pAdvancedHeuristics(nullptr) {
        std::cout << "[ProcessWatcher] Initializing components..." << std::endl;
        try {
            m_pAntiDebug = new AntiDebug();
            m_pInjectionScanner = new InjectionScanner();
            m_pAntiSuspend = new AntiSuspend();
            m_pOverlayScanner = new OverlayScanner();
            m_pMemoryScanner = new MemoryScanner();
            m_pDigitalSignatureValidator = new DigitalSignatureValidator();
            m_pIATHookScanner = new IATHookScanner();
            m_pAdvancedHeuristics = new AdvancedProcessHeuristics();
            
            // Set heartbeat callback untuk AdvancedHeuristics
            m_pAdvancedHeuristics->SetHeartbeatCallback([this]() {
                if (m_isRunning && m_pAntiSuspend) {
                    m_pAntiSuspend->UpdateHeartbeat();
                }
            });
            
            std::cout << "[ProcessWatcher] All components initialized successfully" << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "[ProcessWatcher] ERROR: Failed to initialize: " << e.what() << std::endl;
            throw;
        }
    }

    ProcessWatcher::~ProcessWatcher() {
        std::cout << "[ProcessWatcher] Destructor called, stopping..." << std::endl;
        Stop();
        
        // Delete all components safely
        if (m_pAntiDebug) { delete m_pAntiDebug; m_pAntiDebug = nullptr; }
        if (m_pInjectionScanner) { delete m_pInjectionScanner; m_pInjectionScanner = nullptr; }
        if (m_pAntiSuspend) { delete m_pAntiSuspend; m_pAntiSuspend = nullptr; }
        if (m_pOverlayScanner) { delete m_pOverlayScanner; m_pOverlayScanner = nullptr; }
        if (m_pMemoryScanner) { delete m_pMemoryScanner; m_pMemoryScanner = nullptr; }
        if (m_pDigitalSignatureValidator) { delete m_pDigitalSignatureValidator; m_pDigitalSignatureValidator = nullptr; }
        if (m_pIATHookScanner) { delete m_pIATHookScanner; m_pIATHookScanner = nullptr; }
        if (m_pAdvancedHeuristics) { delete m_pAdvancedHeuristics; m_pAdvancedHeuristics = nullptr; }
        
        std::cout << "[ProcessWatcher] Destructor complete" << std::endl;
    }

    void ProcessWatcher::Start() {
        if (m_isRunning) {
            std::cout << "[ProcessWatcher] Already running, ignoring Start() call" << std::endl;
            return;
        }
        
        std::cout << "[ProcessWatcher] Starting monitoring system..." << std::endl;
        m_isRunning = true;
        try {
            if (m_pAntiSuspend) {
                m_pAntiSuspend->Start();
            }
            m_watcherThread = std::thread(&ProcessWatcher::WatcherLoop, this);
        } catch (...) {
            m_isRunning = false;
            if (m_pAntiSuspend) {
                m_pAntiSuspend->Stop();
            }
            throw;
        }
        std::cout << "[ProcessWatcher] Monitoring thread started" << std::endl;
    }

    void ProcessWatcher::Stop() {
        // KRITIS: tidak boleh early-return berdasar m_isRunning. Flag itu juga
        // dipatok `false` oleh thread pemantau saat mendeteksi pelanggaran, sehingga
        // early-return akan melewati join() dan std::thread yang masih joinable
        // dihancurkan -> std::terminate (crash saat game ditutup).
        std::cout << "[ProcessWatcher] Stopping monitoring system..." << std::endl;

        // 1) Hentikan guardian anti-suspend LEBIH DULU. Jika tidak, selagi kita
        //    menunggu join() thread pemantau (bisa lama karena satu scan sedang
        //    berjalan dan heartbeat berhenti diperbarui) guardian akan salah
        //    melaporkan THREAD_SUSPENDED dan menutup client pemain sah.
        if (m_pAntiSuspend) {
            m_pAntiSuspend->Stop();
        }

        // 2) Hentikan loop pemantauan lalu join tanpa syarat.
        m_isRunning = false;
        if (m_watcherThread.joinable()) {
            m_watcherThread.join();
        }

        std::cout << "[ProcessWatcher] Stopped successfully" << std::endl;
    }

    bool ProcessWatcher::IsAntiSuspendRunning() const {
        return m_pAntiSuspend != nullptr && m_pAntiSuspend->IsRunning();
    }

    void ProcessWatcher::WatcherLoop() {
        auto heartbeat = [this]() {
            if (m_isRunning) {
                m_pAntiSuspend->UpdateHeartbeat();
            }
        };

        // Jalur cepat selalu responsif; jalur mahal dipisahkan supaya proses game
        // tidak melakukan snapshot, verifikasi signature, dan disk I/O bersamaan.
        // Jitter kecil menghindari pola pemindaian yang benar-benar deterministik.
        using Clock = std::chrono::steady_clock;
        using Milliseconds = std::chrono::milliseconds;
        std::mt19937 rng(static_cast<unsigned int>(
            Clock::now().time_since_epoch().count()));
        const auto nextDue = [&rng](Milliseconds interval, int jitterMs) {
            std::uniform_int_distribution<int> jitter(-jitterMs, jitterMs);
            return Clock::now() + interval + Milliseconds(jitter(rng));
        };

        auto nextProcessScan = Clock::now();
        auto nextAntiDebugScan = Clock::now();
        auto nextInjectionScan = Clock::now();
        auto nextOverlayScan = Clock::now();
        auto nextIatScan = Clock::now();
        auto nextMemoryScan = Clock::now();
        auto nextSignatureScan = Clock::now();
        auto nextHeuristicScan = Clock::now();

        while (m_isRunning) {
            heartbeat();
            const auto now = Clock::now();

            // Fast checks: maksimal ~1 detik sampai proses/DLL terlarang terdeteksi.
            if (now >= nextProcessScan) {
                PerformScan();
                nextProcessScan = nextDue(Milliseconds(1000), 125);
            }

            if (m_isRunning && now >= nextAntiDebugScan) {
                m_pAntiDebug->PerformCheck();
                nextAntiDebugScan = nextDue(Milliseconds(1500), 150);
            }

            if (m_isRunning && now >= nextInjectionScan) {
                m_pInjectionScanner->PerformScan();
                nextInjectionScan = nextDue(Milliseconds(1000), 125);
            }

            if (m_isRunning && now >= nextOverlayScan) {
                m_pOverlayScanner->PerformScan();
                nextOverlayScan = nextDue(Milliseconds(1000), 125);
            }

            if (m_isRunning && now >= nextIatScan) {
                m_pIATHookScanner->PerformScan();
                nextIatScan = nextDue(Milliseconds(5000), 500);
            }

            // Integrity scan memakai baseline memori, sedangkan disk re-check
            // dilakukan internal setiap 60 detik.
            if (m_isRunning && now >= nextMemoryScan) {
                m_pMemoryScanner->PerformScan();
                nextMemoryScan = nextDue(Milliseconds(5000), 500);
            }

            if (m_isRunning && now >= nextSignatureScan) {
                m_pDigitalSignatureValidator->PerformScan();
                nextSignatureScan = nextDue(Milliseconds(15000), 1500);
            }

            // Enumerasi handle sistem dan modul lintas-proses adalah pemeriksaan
            // termahal, sehingga dijalankan terpisah tanpa mengurangi lapisan deteksi.
            if (m_isRunning && now >= nextHeuristicScan) {
                m_pAdvancedHeuristics->PerformScan();
                nextHeuristicScan = nextDue(Milliseconds(5000), 500);
            }

            // Tick pendek menjaga anti-suspend heartbeat dan mempercepat Stop().
            Sleep(100);
        }
    }

    void ProcessWatcher::PerformScan() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return;
        }

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        std::unordered_set<DWORD> activeProcesses;
        if (Process32First(hSnapshot, &pe32)) {
            do {
                std::wstring processName = pe32.szExeFile;
                DWORD processId = pe32.th32ProcessID;
                activeProcesses.insert(processId);

                // Deteksi blacklist
                if (IsProcessBlacklisted(processName)) {
                    std::wcout << L"[DETECTION] Blacklisted process detected: " << processName << std::endl;
                    m_isRunning = false;
                    std::string details_utf8;
                    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &processName[0], (int)processName.size(), NULL, 0, NULL, NULL);
                    if (size_needed > 0) {
                        details_utf8.assign(size_needed, 0);
                        WideCharToMultiByte(CP_UTF8, 0, &processName[0], (int)processName.size(), &details_utf8[0], size_needed, NULL, NULL);
                    }
                    std::cout << "[VIOLATION] Reporting to server: PROCESS_DETECTED - " << details_utf8 << std::endl;
                    ReportViolationAndExit(L"", "PROCESS_DETECTED", details_utf8);
                }

                // Cek apakah proses sudah pernah di-scan
                const bool isNewProcess = m_scannedProcesses.insert(processId).second;
                
                if (isNewProcess) {
                    // Memory scan untuk proses non-whitelist
                    if (Oblivion::ShouldPerformMemoryScan(processName)) {
                        std::wcout << L"[SCAN] Memory scan scheduled for: " << processName << L" (PID: " << processId << L")" << std::endl;
                    }

                    // Heuristik perilaku
                    if (Oblivion::IsSuspiciousBehavior(processId)) {
                        Oblivion::LogSuspiciousProcess(processName, processId, "Suspicious module or injection detected");
                        // Optional: langsung blokir
                        std::string details_utf8;
                        int size_needed = WideCharToMultiByte(CP_UTF8, 0, &processName[0], (int)processName.size(), NULL, 0, NULL, NULL);
                        if (size_needed > 0) {
                            details_utf8.assign(size_needed, 0);
                            WideCharToMultiByte(CP_UTF8, 0, &processName[0], (int)processName.size(), &details_utf8[0], size_needed, NULL, NULL);
                        }
                        ReportViolationAndExit(L"", "SUSPICIOUS_BEHAVIOR", details_utf8);
                    }
                }

            } while (Process32Next(hSnapshot, &pe32) && m_isRunning);
        }

        CloseHandle(hSnapshot);
        m_scannedProcesses.swap(activeProcesses);
    }
}
