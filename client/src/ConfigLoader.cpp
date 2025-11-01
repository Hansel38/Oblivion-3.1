#include "../pch.h"
#include "ConfigLoader.h"
#include <fstream>
#include <sstream>

static std::string Trim(const std::string& s) { size_t b=s.find_first_not_of(" \t\r\n"); size_t e=s.find_last_not_of(" \t\r\n"); if (b==std::string::npos) return {}; return s.substr(b,e-b+1);} 
static bool ParseString(const std::string& v, std::string& out){ std::string t=Trim(v); if (t.size()>=2 && t.front()=='"' && t.back()=='"'){ out=t.substr(1,t.size()-2); return true;} return false; }
static bool ParseInt(const std::string& v, int& out){ try{ out=std::stoi(Trim(v)); return true;}catch(...){return false;}}
static bool ParseUInt(const std::string& v, DWORD& out){ try{ out=(DWORD)std::stoul(Trim(v)); return true;}catch(...){return false;}}
static bool ParseBool(const std::string& v, bool& out){ std::string t=Trim(v); if(t=="true"||t=="True"||t=="TRUE"){out=true;return true;} if(t=="false"||t=="False"||t=="FALSE"){out=false;return true;} return false;}
static std::wstring ToW(const std::string& s){ if(s.empty()) return L""; int len=MultiByteToWideChar(CP_UTF8,0,s.c_str(),(int)s.size(),nullptr,0); std::wstring w(len,0); MultiByteToWideChar(CP_UTF8,0,s.c_str(),(int)s.size(),&w[0],len); return w; }

static bool LoadJsonFile(const std::wstring& path, ClientConfig& cfg) {
    std::ifstream f(path);
    if (!f.is_open()) return false;
    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    f.close();

    std::istringstream iss(content);
    std::string line; bool any=false;
    while (std::getline(iss, line)) {
        auto colon=line.find(':'); if (colon==std::string::npos) continue;
        std::string key=Trim(line.substr(0,colon)); std::string val=line.substr(colon+1);
        if (!val.empty() && val.back()==',') val.pop_back();
        if (key.size()>=2 && key.front()=='"' && key.back()=='"') key=key.substr(1,key.size()-2);

        if (key=="server_ip") { std::string s; if (ParseString(val,s)){ cfg.serverIp=s; any=true; } }
        else if (key=="server_port") { int v; if (ParseInt(val,v)){ cfg.serverPort=v; any=true; } }
        else if (key=="polling_interval_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.pollingIntervalMs=v; any=true; } }
        else if (key=="close_threshold") { int v; if (ParseInt(val,v)){ cfg.closeThreshold=v; any=true; } }
        else if (key=="detection_message") { std::string s; if (ParseString(val,s)){ cfg.detectionMessage=ToW(s); any=true; } }
        else if (key=="enable_background_watcher") { bool b; if (ParseBool(val,b)){ cfg.enableBackgroundWatcher=b; any=true; } }
        else if (key=="enable_logging") { bool b; if (ParseBool(val,b)){ cfg.enableLogging=b; any=true; } }
        else if (key=="enable_tls_client") { bool b; if (ParseBool(val,b)){ cfg.enableTlsClient=b; any=true; } }
        else if (key=="tls_server_name") { std::string s; if (ParseString(val,s)){ cfg.tlsServerName=s; any=true; } }
        else if (key=="enable_overlay_scanner") { bool b; if (ParseBool(val,b)){ cfg.enableOverlayScanner=b; any=true; } }
        else if (key=="overlay_threshold") { int v; if (ParseInt(val,v)){ cfg.overlayThreshold=v; any=true; } }
        else if (key=="enable_anti_debug") { bool b; if (ParseBool(val,b)){ cfg.enableAntiDebug=b; any=true; } }
        else if (key=="anti_debug_threshold") { int v; if (ParseInt(val,v)){ cfg.antiDebugThreshold=v; any=true; } }
        else if (key=="enable_injection_scanner") { bool b; if (ParseBool(val,b)){ cfg.enableInjectionScanner=b; any=true; } }
        else if (key=="injection_threshold") { int v; if (ParseInt(val,v)){ cfg.injectionThreshold=v; any=true; } }
        else if (key=="module_whitelist_prefixes") { std::string s; if (ParseString(val,s)){ cfg.moduleWhitelistPrefixes=ToW(s); any=true; } }
        else if (key=="enable_signature_validator") { bool b; if (ParseBool(val,b)){ cfg.enableSignatureValidator=b; any=true; } }
        else if (key=="signature_threshold") { int v; if (ParseInt(val,v)){ cfg.signatureThreshold=v; any=true; } }
        else if (key=="signature_skip_names") { std::string s; if (ParseString(val,s)){ cfg.signatureSkipNames=ToW(s); any=true; } }
        else if (key=="enable_anti_suspend") { bool b; if (ParseBool(val,b)){ cfg.enableAntiSuspend=b; any=true; } }
        else if (key=="anti_suspend_heartbeat_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.antiSuspendHeartbeatMs=v; any=true; } }
        else if (key=="anti_suspend_stall_window_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.antiSuspendStallWindowMs=v; any=true; } }
        else if (key=="anti_suspend_misses_threshold") { int v; if (ParseInt(val,v)){ cfg.antiSuspendMissesThreshold=v; any=true; } }
        else if (key=="enable_hijacked_thread_scanner") { bool b; if (ParseBool(val,b)){ cfg.enableHijackedThreadScanner=b; any=true; } }
        else if (key=="hijacked_thread_threshold") { int v; if (ParseInt(val,v)){ cfg.hijackedThreadThreshold=v; any=true; } }
        else if (key=="enable_iat_hook_scanner") { bool b; if (ParseBool(val,b)){ cfg.enableIATHookScanner=b; any=true; } }
        else if (key=="iat_hook_threshold") { int v; if (ParseInt(val,v)){ cfg.iatHookThreshold=v; any=true; } }
        else if (key=="enable_file_integrity_check") { bool b; if (ParseBool(val,b)){ cfg.enableFileIntegrityCheck=b; any=true; } }
        else if (key=="integrity_items") { std::string s; if (ParseString(val,s)){ cfg.integrityItems=ToW(s); any=true; } }
        else if (key=="enable_memory_signature_scanner") { bool b; if (ParseBool(val,b)){ cfg.enableMemorySignatureScanner=b; any=true; } }
        else if (key=="memory_signature_threshold") { int v; if (ParseInt(val,v)){ cfg.memorySignatureThreshold=v; any=true; } }
        else if (key=="memory_signatures") { std::string s; if (ParseString(val,s)){ cfg.memorySignatures=ToW(s); any=true; } }
        else if (key=="memory_module_whitelist_prefixes") { std::string s; if (ParseString(val,s)){ cfg.memoryModuleWhitelistPrefixes=ToW(s); any=true; } }
        else if (key=="memory_images_only") { bool b; if (ParseBool(val,b)){ cfg.memoryImagesOnly=b; any=true; } }
        else if (key=="enable_hmac_auth") { bool b; if (ParseBool(val,b)){ cfg.enableHmacAuth=b; any=true; } }
        else if (key=="hmac_secret") { std::string s; if (ParseString(val,s)){ cfg.hmacSecret=s; any=true; } }
        else if (key=="enable_heartbeat") { bool b; if (ParseBool(val,b)){ cfg.enableHeartbeat=b; any=true; } }
        else if (key=="heartbeat_interval_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.heartbeatIntervalMs=v; any=true; } }
        else if (key=="enable_periodic_scans") { bool b; if (ParseBool(val,b)){ cfg.enablePeriodicScans=b; any=true; } }
        else if (key=="periodic_scan_interval_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.periodicScanIntervalMs=v; any=true; } }
        else if (key=="detection_cooldown_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.detectionCooldownMs=v; any=true; } }
        else if (key=="cooldown_process_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownProcessMs=v; any=true; } }
        else if (key=="cooldown_overlay_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownOverlayMs=v; any=true; } }
        else if (key=="cooldown_antidebug_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownAntiDebugMs=v; any=true; } }
        else if (key=="cooldown_injection_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownInjectionMs=v; any=true; } }
        else if (key=="cooldown_sigcheck_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownSigcheckMs=v; any=true; } }
        else if (key=="cooldown_hijackedthread_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownHijackedThreadMs=v; any=true; } }
        else if (key=="cooldown_iathook_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownIatHookMs=v; any=true; } }
        else if (key=="cooldown_integrity_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownIntegrityMs=v; any=true; } }
        else if (key=="cooldown_memsig_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownMemsigMs=v; any=true; } }
        else if (key=="enable_kernel_bridge") { bool b; if (ParseBool(val,b)) { cfg.enableKernelBridge=b; any=true; } }
        else if (key=="ce_artifact_tokens") { std::string s; if (ParseString(val, s)) { cfg.ceArtifactTokens = ToW(s); any=true; } }
    // Aggressive detection profile and ETW tuning
    else if (key=="aggressive_detection") { bool b; if (ParseBool(val,b)){ cfg.aggressiveDetection=b; any=true; } }
    else if (key=="etw_burst_threshold") { int v; if (ParseInt(val,v)){ cfg.etwBurstThreshold=v; any=true; } }
    else if (key=="etw_window_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.etwWindowMs=v; any=true; } }
    else if (key=="etw_memscan_min_streak") { int v; if (ParseInt(val,v)){ cfg.etwMemscanMinStreak=v; any=true; } }
        // New: CE Behavior Monitor
        else if (key=="enable_ce_behavior_monitor") { bool b; if (ParseBool(val,b)){ cfg.enableCEBehaviorMonitor=b; any=true; } }
        else if (key=="ce_behavior_threshold") { int v; if (ParseInt(val,v)){ cfg.ceBehaviorThreshold=v; any=true; } }
        else if (key=="ce_behavior_window_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.ceBehaviorWindowMs=v; any=true; } }
        else if (key=="ce_behavior_poll_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.ceBehaviorPollMs=v; any=true; } }
        // New: CE Registry & Window scanners
        else if (key=="enable_ce_registry_scanner") { bool b; if (ParseBool(val,b)){ cfg.enableCERegistryScanner=b; any=true; } }
        else if (key=="enable_ce_window_scanner") { bool b; if (ParseBool(val,b)){ cfg.enableCEWindowScanner=b; any=true; } }
        // New: Speed Hack Detector
        else if (key=="enable_speedhack_detector") { bool b; if (ParseBool(val,b)){ cfg.enableSpeedHackDetector=b; any=true; } }
        else if (key=="speedhack_sensitivity") { int v; if (ParseInt(val,v)){ cfg.speedHackSensitivity=v; any=true; } }
        else if (key=="speedhack_monitor_interval_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.speedHackMonitorIntervalMs=v; any=true; } }
        // New cooldowns
        else if (key=="cooldown_ce_behavior_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownCEBehaviorMs=v; any=true; } }
        else if (key=="cooldown_ce_registry_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownCERegistryMs=v; any=true; } }
        else if (key=="cooldown_ce_window_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownCEWindowMs=v; any=true; } }
        else if (key=="cooldown_speed_hack_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownSpeedHackMs=v; any=true; } }
    else if (key=="cooldown_memory_scanning_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownMemoryScanningMs=v; any=true; } }
    }
    return any;
}

bool LoadClientConfig(ClientConfig& outCfg, const std::wstring& dllDirectory) {
    std::wstring path = dllDirectory + L"\\client_config.json";
    if (LoadJsonFile(path, outCfg)) return true;
    wchar_t cwd[MAX_PATH];
    if (GetCurrentDirectoryW(MAX_PATH, cwd)) {
        std::wstring alt = std::wstring(cwd) + L"\\client_config.json";
        if (LoadJsonFile(alt, outCfg)) return true;
    }
    return false;
}
