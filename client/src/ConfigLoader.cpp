#include "../pch.h"
#include "ConfigLoader.h"
#include <fstream>
#include <sstream>

static std::string Trim(const std::string& s) { size_t b=s.find_first_not_of(" \t\r\n"); size_t e=s.find_last_not_of(" \t\r\n"); if (b==std::string::npos) return {}; return s.substr(b,e-b+1);} 
static bool ParseString(const std::string& v, std::string& out){ std::string t=Trim(v); if (t.size()>=2 && t.front()=='"' && t.back()=='"'){ out=t.substr(1,t.size()-2); return true;} return false; }
static bool ParseInt(const std::string& v, int& out){ try{ out=std::stoi(Trim(v)); return true;}catch(...){return false;}}
static bool ParseUInt(const std::string& v, DWORD& out){ try{ out=(DWORD)std::stoul(Trim(v)); return true;}catch(...){return false;}}
static bool ParseULongLong(const std::string& v, ULONGLONG& out){ try{ out=(ULONGLONG)std::stoull(Trim(v)); return true;}catch(...){return false;}}
static bool ParseBool(const std::string& v, bool& out){ std::string t=Trim(v); if(t=="true"||t=="True"||t=="TRUE"){out=true;return true;} if(t=="false"||t=="False"||t=="FALSE"){out=false;return true;} return false;}
static bool ParseDouble(const std::string& v, double& out){ try{ out=std::stod(Trim(v)); return true;}catch(...){return false;}}
static std::wstring ToW(const std::string& s){ if(s.empty()) return L""; int len=MultiByteToWideChar(CP_UTF8,0,s.c_str(),(int)s.size(),nullptr,0); std::wstring w(len,0); MultiByteToWideChar(CP_UTF8,0,s.c_str(),(int)s.size(),&w[0],len); return w; }

static bool ParseConfigLine(const std::string& key, const std::string& val, ClientConfig& cfg);
static bool ParseConfigLineP2(const std::string& key, const std::string& val, ClientConfig& cfg);
static bool ParseConfigLineP3(const std::string& key, const std::string& val, ClientConfig& cfg);

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

        if (ParseConfigLine(key, val, cfg)) any = true;
        else if (ParseConfigLineP2(key, val, cfg)) any = true;
        else if (ParseConfigLineP3(key, val, cfg)) any = true;
    }
    return any;
}

static bool ParseConfigLine(const std::string& key, const std::string& val, ClientConfig& cfg) {

        if (key=="server_ip") { std::string s; if (ParseString(val,s)){ cfg.serverIp=s; return true; } }
        else if (key=="server_port") { int v; if (ParseInt(val,v)){ cfg.serverPort=v; return true; } }
        else if (key=="polling_interval_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.pollingIntervalMs=v; return true; } }
        else if (key=="close_threshold") { int v; if (ParseInt(val,v)){ cfg.closeThreshold=v; return true; } }
        else if (key=="detection_message") { std::string s; if (ParseString(val,s)){ cfg.detectionMessage=ToW(s); return true; } }
        else if (key=="enable_background_watcher") { bool b; if (ParseBool(val,b)){ cfg.enableBackgroundWatcher=b; return true; } }
        else if (key=="enable_logging") { bool b; if (ParseBool(val,b)){ cfg.enableLogging=b; return true; } }
        else if (key=="enable_tls_client") { bool b; if (ParseBool(val,b)){ cfg.enableTlsClient=b; return true; } }
        else if (key=="tls_server_name") { std::string s; if (ParseString(val,s)){ cfg.tlsServerName=s; return true; } }
        else if (key=="enable_overlay_scanner") { bool b; if (ParseBool(val,b)){ cfg.enableOverlayScanner=b; return true; } }
        else if (key=="overlay_threshold") { int v; if (ParseInt(val,v)){ cfg.overlayThreshold=v; return true; } }
        else if (key=="enable_anti_debug") { bool b; if (ParseBool(val,b)){ cfg.enableAntiDebug=b; return true; } }
        else if (key=="anti_debug_threshold") { int v; if (ParseInt(val,v)){ cfg.antiDebugThreshold=v; return true; } }
        else if (key=="enable_injection_scanner") { bool b; if (ParseBool(val,b)){ cfg.enableInjectionScanner=b; return true; } }
        else if (key=="injection_threshold") { int v; if (ParseInt(val,v)){ cfg.injectionThreshold=v; return true; } }
        else if (key=="module_whitelist_prefixes") { std::string s; if (ParseString(val,s)){ cfg.moduleWhitelistPrefixes=ToW(s); return true; } }
        else if (key=="enable_signature_validator") { bool b; if (ParseBool(val,b)){ cfg.enableSignatureValidator=b; return true; } }
        else if (key=="signature_threshold") { int v; if (ParseInt(val,v)){ cfg.signatureThreshold=v; return true; } }
        else if (key=="signature_skip_names") { std::string s; if (ParseString(val,s)){ cfg.signatureSkipNames=ToW(s); return true; } }
        else if (key=="enable_anti_suspend") { bool b; if (ParseBool(val,b)){ cfg.enableAntiSuspend=b; return true; } }
        else if (key=="anti_suspend_heartbeat_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.antiSuspendHeartbeatMs=v; return true; } }
        else if (key=="anti_suspend_stall_window_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.antiSuspendStallWindowMs=v; return true; } }
        else if (key=="anti_suspend_misses_threshold") { int v; if (ParseInt(val,v)){ cfg.antiSuspendMissesThreshold=v; return true; } }
        else if (key=="enable_hijacked_thread_scanner") { bool b; if (ParseBool(val,b)){ cfg.enableHijackedThreadScanner=b; return true; } }
        else if (key=="hijacked_thread_threshold") { int v; if (ParseInt(val,v)){ cfg.hijackedThreadThreshold=v; return true; } }
        else if (key=="enable_iat_hook_scanner") { bool b; if (ParseBool(val,b)){ cfg.enableIATHookScanner=b; return true; } }
        else if (key=="iat_hook_threshold") { int v; if (ParseInt(val,v)){ cfg.iatHookThreshold=v; return true; } }
        else if (key=="enable_file_integrity_check") { bool b; if (ParseBool(val,b)){ cfg.enableFileIntegrityCheck=b; return true; } }
        else if (key=="integrity_items") { std::string s; if (ParseString(val,s)){ cfg.integrityItems=ToW(s); return true; } }
        else if (key=="enable_memory_signature_scanner") { bool b; if (ParseBool(val,b)){ cfg.enableMemorySignatureScanner=b; return true; } }
        else if (key=="memory_signature_threshold") { int v; if (ParseInt(val,v)){ cfg.memorySignatureThreshold=v; return true; } }
        else if (key=="memory_signatures") { std::string s; if (ParseString(val,s)){ cfg.memorySignatures=ToW(s); return true; } }
        else if (key=="memory_module_whitelist_prefixes") { std::string s; if (ParseString(val,s)){ cfg.memoryModuleWhitelistPrefixes=ToW(s); return true; } }
        else if (key=="memory_images_only") { bool b; if (ParseBool(val,b)){ cfg.memoryImagesOnly=b; return true; } }
        else if (key=="enable_hmac_auth") { bool b; if (ParseBool(val,b)){ cfg.enableHmacAuth=b; return true; } }
        else if (key=="hmac_secret") { std::string s; if (ParseString(val,s)){ cfg.hmacSecret=s; return true; } }
        else if (key=="enable_heartbeat") { bool b; if (ParseBool(val,b)){ cfg.enableHeartbeat=b; return true; } }
        else if (key=="heartbeat_interval_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.heartbeatIntervalMs=v; return true; } }
        else if (key=="enable_periodic_scans") { bool b; if (ParseBool(val,b)){ cfg.enablePeriodicScans=b; return true; } }
        else if (key=="periodic_scan_interval_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.periodicScanIntervalMs=v; return true; } }
        else if (key=="detection_cooldown_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.detectionCooldownMs=v; return true; } }
        else if (key=="cooldown_process_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownProcessMs=v; return true; } }
        else if (key=="cooldown_overlay_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownOverlayMs=v; return true; } }
        else if (key=="cooldown_antidebug_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownAntiDebugMs=v; return true; } }
        else if (key=="cooldown_injection_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownInjectionMs=v; return true; } }
        else if (key=="cooldown_sigcheck_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownSigcheckMs=v; return true; } }
        else if (key=="cooldown_hijackedthread_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownHijackedThreadMs=v; return true; } }
        else if (key=="cooldown_iathook_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownIatHookMs=v; return true; } }
        else if (key=="cooldown_integrity_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownIntegrityMs=v; return true; } }
        else if (key=="cooldown_memsig_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownMemsigMs=v; return true; } }
        else if (key=="enable_kernel_bridge") { bool b; if (ParseBool(val,b)) { cfg.enableKernelBridge=b; return true; } }
        else if (key=="ce_artifact_tokens") { std::string s; if (ParseString(val, s)) { cfg.ceArtifactTokens = ToW(s); return true; } }
    return false;
}

static bool ParseConfigLineP2(const std::string& key, const std::string& val, ClientConfig& cfg) {
    // ===== PRIORITY 4: Telemetry Configuration =====
    if (key=="enable_telemetry") { bool b; if (ParseBool(val,b)){ cfg.enableTelemetry=b; return true; } }
    else if (key=="telemetry_collection_interval_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.telemetryCollectionIntervalMs=v; return true; } }
    else if (key=="telemetry_aggregation_period_ms") { ULONGLONG v; if (ParseULongLong(val,v)){ cfg.telemetryAggregationPeriodMs=v; return true; } }
    else if (key=="telemetry_export_on_exit") { bool b; if (ParseBool(val,b)){ cfg.telemetryExportOnExit=b; return true; } }
    else if (key=="telemetry_export_path") { std::string s; if (ParseString(val, s)) { cfg.telemetryExportPath = ToW(s); return true; } }
    
    // ===== PRIORITY 4: ML Anomaly Detection Configuration =====
    else if (key=="enable_ml_anomaly_detection") { bool b; if (ParseBool(val,b)){ cfg.enableMLAnomalyDetection=b; return true; } }
    else if (key=="ml_use_isolation_forest") { bool b; if (ParseBool(val,b)){ cfg.mlUseIsolationForest=b; return true; } }
    else if (key=="ml_use_one_class") { bool b; if (ParseBool(val,b)){ cfg.mlUseOneClass=b; return true; } }
    else if (key=="ml_use_ensemble") { bool b; if (ParseBool(val,b)){ cfg.mlUseEnsemble=b; return true; } }
    else if (key=="ml_ensemble_weight") { double v; if (ParseDouble(val,v)){ cfg.mlEnsembleWeight=static_cast<float>(v); return true; } }
    else if (key=="ml_isolation_forest_trees") { int v; if (ParseInt(val,v)){ cfg.mlIsolationForestTrees=v; return true; } }
    else if (key=="ml_isolation_forest_subsample_size") { int v; if (ParseInt(val,v)){ cfg.mlIsolationForestSubsampleSize=v; return true; } }
    else if (key=="ml_isolation_forest_max_depth") { int v; if (ParseInt(val,v)){ cfg.mlIsolationForestMaxDepth=v; return true; } }
    else if (key=="ml_one_class_nu") { double v; if (ParseDouble(val,v)){ cfg.mlOneClassNu=static_cast<float>(v); return true; } }
    else if (key=="ml_anomaly_threshold") { double v; if (ParseDouble(val,v)){ cfg.mlAnomalyThreshold=static_cast<float>(v); return true; } }
    else if (key=="ml_min_training_samples") { int v; if (ParseInt(val,v)){ cfg.mlMinTrainingSamples=v; return true; } }
    else if (key=="ml_max_training_samples") { int v; if (ParseInt(val,v)){ cfg.mlMaxTrainingSamples=v; return true; } }
    else if (key=="ml_enable_online_learning") { bool b; if (ParseBool(val,b)){ cfg.mlEnableOnlineLearning=b; return true; } }
    else if (key=="ml_online_update_interval") { int v; if (ParseInt(val,v)){ cfg.mlOnlineUpdateInterval=v; return true; } }
    else if (key=="ml_online_learning_rate") { double v; if (ParseDouble(val,v)){ cfg.mlOnlineLearningRate=static_cast<float>(v); return true; } }
    else if (key=="ml_enable_model_persistence") { bool b; if (ParseBool(val,b)){ cfg.mlEnableModelPersistence=b; return true; } }
    else if (key=="ml_model_save_path") { std::string s; if (ParseString(val, s)) { cfg.mlModelSavePath = ToW(s); return true; } }
    
    // ===== PRIORITY 4.1.5: ML Integration Configuration =====
    else if (key=="enable_ml_integration") { bool b; if (ParseBool(val,b)){ cfg.enableMLIntegration=b; return true; } }
    else if (key=="ml_hybrid_mode") { bool b; if (ParseBool(val,b)){ cfg.mlHybridMode=b; return true; } }
    else if (key=="ml_detection_threshold") { double v; if (ParseDouble(val,v)){ cfg.mlDetectionThreshold=static_cast<float>(v); return true; } }
    else if (key=="ml_confidence_threshold") { double v; if (ParseDouble(val,v)){ cfg.mlConfidenceThreshold=static_cast<float>(v); return true; } }
    else if (key=="ml_boost_indicators") { bool b; if (ParseBool(val,b)){ cfg.mlBoostIndicators=b; return true; } }
    else if (key=="ml_indicator_multiplier") { double v; if (ParseDouble(val,v)){ cfg.mlIndicatorMultiplier=static_cast<float>(v); return true; } }
    else if (key=="ml_enable_veto") { bool b; if (ParseBool(val,b)){ cfg.mlEnableVeto=b; return true; } }
    else if (key=="ml_veto_threshold") { double v; if (ParseDouble(val,v)){ cfg.mlVetoThreshold=static_cast<float>(v); return true; } }
    else if (key=="ml_log_scores") { bool b; if (ParseBool(val,b)){ cfg.mlLogScores=b; return true; } }
    
    // ===== PRIORITY 4: Adaptive Threshold Configuration =====
    else if (key=="enable_adaptive_thresholds") { bool b; if (ParseBool(val,b)){ cfg.enableAdaptiveThresholds=b; return true; } }
    else if (key=="use_per_player_profiles") { bool b; if (ParseBool(val,b)){ cfg.usePerPlayerProfiles=b; return true; } }
    else if (key=="use_global_baseline") { bool b; if (ParseBool(val,b)){ cfg.useGlobalBaseline=b; return true; } }
    else if (key=="default_sigma_multiplier") { double v; if (ParseDouble(val,v)){ cfg.defaultSigmaMultiplier=v; return true; } }
    else if (key=="min_baseline_samples") { int v; if (ParseInt(val,v)){ cfg.minBaselineSamples=v; return true; } }
    else if (key=="max_profile_age_hours") { int v; if (ParseInt(val,v)){ cfg.maxProfileAgeHours=v; return true; } }
    else if (key=="adaptive_min_threshold") { int v; if (ParseInt(val,v)){ cfg.adaptiveMinThreshold=v; return true; } }
    else if (key=="adaptive_max_threshold") { int v; if (ParseInt(val,v)){ cfg.adaptiveMaxThreshold=v; return true; } }
    else if (key=="adaptive_decay_rate") { double v; if (ParseDouble(val,v)){ cfg.adaptiveDecayRate=v; return true; } }
    else if (key=="enable_auto_decay") { bool b; if (ParseBool(val,b)){ cfg.enableAutoDecay=b; return true; } }
    else if (key=="trust_score_initial") { double v; if (ParseDouble(val,v)){ cfg.trustScoreInitial=v; return true; } }
    else if (key=="trust_score_increment") { double v; if (ParseDouble(val,v)){ cfg.trustScoreIncrement=v; return true; } }
    else if (key=="trust_score_decrement") { double v; if (ParseDouble(val,v)){ cfg.trustScoreDecrement=v; return true; } }
    
    // Aggressive detection profile and ETW tuning
    else if (key=="aggressive_detection") { bool b; if (ParseBool(val,b)){ cfg.aggressiveDetection=b; return true; } }
    else if (key=="etw_burst_threshold") { int v; if (ParseInt(val,v)){ cfg.etwBurstThreshold=v; return true; } }
    else if (key=="etw_window_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.etwWindowMs=v; return true; } }
    else if (key=="etw_memscan_min_streak") { int v; if (ParseInt(val,v)){ cfg.etwMemscanMinStreak=v; return true; } }
        // New: CE Behavior Monitor
        else if (key=="enable_ce_behavior_monitor") { bool b; if (ParseBool(val,b)){ cfg.enableCEBehaviorMonitor=b; return true; } }
        else if (key=="ce_behavior_threshold") { int v; if (ParseInt(val,v)){ cfg.ceBehaviorThreshold=v; return true; } }
        else if (key=="ce_behavior_window_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.ceBehaviorWindowMs=v; return true; } }
        else if (key=="ce_behavior_poll_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.ceBehaviorPollMs=v; return true; } }
        // New: CE Registry & Window scanners
        else if (key=="enable_ce_registry_scanner") { bool b; if (ParseBool(val,b)){ cfg.enableCERegistryScanner=b; return true; } }
        else if (key=="enable_ce_window_scanner") { bool b; if (ParseBool(val,b)){ cfg.enableCEWindowScanner=b; return true; } }
        // New: Speed Hack Detector
        else if (key=="enable_speedhack_detector") { bool b; if (ParseBool(val,b)){ cfg.enableSpeedHackDetector=b; return true; } }
        else if (key=="speedhack_sensitivity") { int v; if (ParseInt(val,v)){ cfg.speedHackSensitivity=v; return true; } }
        else if (key=="speedhack_monitor_interval_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.speedHackMonitorIntervalMs=v; return true; } }
        // New cooldowns
        else if (key=="cooldown_ce_behavior_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownCEBehaviorMs=v; return true; } }
        else if (key=="cooldown_ce_registry_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownCERegistryMs=v; return true; } }
        else if (key=="cooldown_ce_window_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownCEWindowMs=v; return true; } }
        else if (key=="cooldown_speed_hack_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownSpeedHackMs=v; return true; } }
        else if (key=="cooldown_memory_scanning_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownMemoryScanningMs=v; return true; } }
        // ===== PRIORITY 3: Stealth & Evasion Detection =====
        else if (key=="enable_peb_manipulation_detector") { bool v; if (ParseBool(val,v)){ cfg.enablePEBManipulationDetector=v; return true; } }
        else if (key=="peb_enable_memory_scan") { bool v; if (ParseBool(val,v)){ cfg.pebEnableMemoryScan=v; return true; } }
        else if (key=="peb_enable_toolhelp_validation") { bool v; if (ParseBool(val,v)){ cfg.pebEnableToolHelpValidation=v; return true; } }
        else if (key=="cooldown_peb_manipulation_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownPEBManipulationMs=v; return true; } }
        else if (key=="enable_hardware_breakpoint_monitor") { bool v; if (ParseBool(val,v)){ cfg.enableHardwareBreakpointMonitor=v; return true; } }
        else if (key=="hwbp_max_threshold") { int v; if (ParseInt(val,v)){ cfg.hwbpMaxThreshold=v; return true; } }
        else if (key=="hwbp_enable_anomaly_detection") { bool v; if (ParseBool(val,v)){ cfg.hwbpEnableAnomalyDetection=v; return true; } }
        else if (key=="hwbp_track_history") { bool v; if (ParseBool(val,v)){ cfg.hwbpTrackHistory=v; return true; } }
        else if (key=="cooldown_hardware_breakpoint_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownHardwareBreakpointMs=v; return true; } }
        else if (key=="enable_suspicious_memory_scanner") { bool v; if (ParseBool(val,v)){ cfg.enableSuspiciousMemoryScanner=v; return true; } }
        else if (key=="susp_mem_min_region_size") { DWORD v; if (ParseUInt(val,v)){ cfg.suspMemMinRegionSize=v; return true; } }
        else if (key=="susp_mem_enable_pattern_analysis") { bool v; if (ParseBool(val,v)){ cfg.suspMemEnablePatternAnalysis=v; return true; } }
        else if (key=="susp_mem_enable_entropy_check") { bool v; if (ParseBool(val,v)){ cfg.suspMemEnableEntropyCheck=v; return true; } }
        else if (key=="susp_mem_flag_rwx") { bool v; if (ParseBool(val,v)){ cfg.suspMemFlagRWX=v; return true; } }
        else if (key=="susp_mem_flag_private_executable") { bool v; if (ParseBool(val,v)){ cfg.suspMemFlagPrivateExecutable=v; return true; } }
        else if (key=="cooldown_suspicious_memory_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownSuspiciousMemoryMs=v; return true; } }
        else if (key=="enable_heap_spray_analyzer") { bool v; if (ParseBool(val,v)){ cfg.enableHeapSprayAnalyzer=v; return true; } }
        else if (key=="heap_spray_min_size") { DWORD v; if (ParseUInt(val,v)){ cfg.heapSprayMinSize=v; return true; } }
        else if (key=="heap_spray_min_repeat_count") { int v; if (ParseInt(val,v)){ cfg.heapSprayMinRepeatCount=v; return true; } }
        else if (key=="heap_spray_min_density") { double v; if (ParseDouble(val,v)){ cfg.heapSprayMinDensity=v; return true; } }
        else if (key=="heap_spray_enable_nop_detection") { bool v; if (ParseBool(val,v)){ cfg.heapSprayEnableNOPDetection=v; return true; } }
        else if (key=="heap_spray_enable_address_spray") { bool v; if (ParseBool(val,v)){ cfg.heapSprayEnableAddressSpray=v; return true; } }
        else if (key=="cooldown_heap_spray_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownHeapSprayMs=v; return true; } }
        else if (key=="enable_ethread_detector") { bool v; if (ParseBool(val,v)){ cfg.enableETHREADDetector=v; return true; } }
        else if (key=="cooldown_ethread_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownETHREADMs=v; return true; } }
        else if (key=="enable_callback_scanner") { bool v; if (ParseBool(val,v)){ cfg.enableCallbackScanner=v; return true; } }
        else if (key=="cooldown_callback_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownCallbackMs=v; return true; } }
        else if (key=="enable_vad_detector") { bool v; if (ParseBool(val,v)){ cfg.enableVADDetector=v; return true; } }
        else if (key=="vad_size_threshold") { DWORD v; if (ParseUInt(val,v)){ cfg.vadSizeThreshold=v; return true; } }
        else if (key=="cooldown_vad_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.cooldownVADMs=v; return true; } }
    return false;
}

static bool ParseConfigLineP3(const std::string& key, const std::string& val, ClientConfig& cfg) {
    // ===== PRIORITY 4.2.4: Signature Testing Framework =====
    if (key=="enable_signature_testing") { bool b; if (ParseBool(val,b)){ cfg.enableSignatureTesting=b; return true; } }
    else if (key=="signature_tests_csv_path") { std::string s; if (ParseString(val,s)){ cfg.signatureTestsCsvPath=ToW(s); return true; } }
    else if (key=="signature_yara_rules_path") { std::string s; if (ParseString(val,s)){ cfg.signatureYaraRulesPath=ToW(s); return true; } }
    else if (key=="signature_benchmark_iterations") { int v; if (ParseInt(val,v)){ cfg.signatureBenchmarkIterations=v; return true; } }
    
    // ===== PRIORITY 4.3.1: Scan Prioritization Manager =====
    else if (key=="enable_scan_prioritization") { bool b; if (ParseBool(val,b)){ cfg.enableScanPrioritization=b; return true; } }
    else if (key=="enable_dynamic_priority_adjustment") { bool b; if (ParseBool(val,b)){ cfg.enableDynamicPriorityAdjustment=b; return true; } }
    else if (key=="enable_load_balancing") { bool b; if (ParseBool(val,b)){ cfg.enableLoadBalancing=b; return true; } }
    else if (key=="cpu_threshold_percent") { double v; if (ParseDouble(val,v)){ cfg.cpuThresholdPercent=(float)v; return true; } }
    else if (key=="critical_scan_max_delay_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.criticalScanMaxDelayMs=v; return true; } }
    else if (key=="high_scan_max_delay_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.highScanMaxDelayMs=v; return true; } }
    else if (key=="scan_prioritization_budget_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.scanPrioritizationBudgetMs=v; return true; } }
    else if (key=="recent_detection_boost_weight") { double v; if (ParseDouble(val,v)){ cfg.recentDetectionBoostWeight=(float)v; return true; } }
    else if (key=="detection_rate_boost_weight") { double v; if (ParseDouble(val,v)){ cfg.detectionRateBoostWeight=(float)v; return true; } }
    else if (key=="false_positive_penalty_weight") { double v; if (ParseDouble(val,v)){ cfg.falsePositivePenaltyWeight=(float)v; return true; } }
    else if (key=="recent_detection_window_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.recentDetectionWindowMs=v; return true; } }
    else if (key=="statistics_update_interval_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.statisticsUpdateIntervalMs=v; return true; } }
    
    // ===== PRIORITY 4.3.2: Adaptive Polling Interval =====
    else if (key=="enable_adaptive_polling") { bool b; if (ParseBool(val,b)){ cfg.enableAdaptivePolling=b; return true; } }
    else if (key=="adaptive_min_interval_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.adaptiveMinIntervalMs=v; return true; } }
    else if (key=="adaptive_max_interval_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.adaptiveMaxIntervalMs=v; return true; } }
    else if (key=="adaptive_change_cooldown_ms") { DWORD v; if (ParseUInt(val,v)){ cfg.adaptiveChangeCooldownMs=v; return true; } }
    else if (key=="adaptive_min_change_percent") { double v; if (ParseDouble(val,v)){ cfg.adaptiveMinChangePercent=(float)v; return true; } }
    else if (key=="adaptive_medium_rate_threshold") { double v; if (ParseDouble(val,v)){ cfg.adaptiveMediumRateThreshold=v; return true; } }
    else if (key=="adaptive_high_rate_threshold") { double v; if (ParseDouble(val,v)){ cfg.adaptiveHighRateThreshold=v; return true; } }
    else if (key=="adaptive_critical_rate_threshold") { double v; if (ParseDouble(val,v)){ cfg.adaptiveCriticalRateThreshold=v; return true; } }
    else if (key=="adaptive_cpu_low_percent") { double v; if (ParseDouble(val,v)){ cfg.adaptiveCpuLowPercent=(float)v; return true; } }
    else if (key=="adaptive_cpu_high_percent") { double v; if (ParseDouble(val,v)){ cfg.adaptiveCpuHighPercent=(float)v; return true; } }

    // ===== PRIORITY 4.3.3: SIMD Acceleration =====
    else if (key=="enable_simd_acceleration") { bool b; if (ParseBool(val,b)){ cfg.enableSimdAcceleration=b; return true; } }
    else if (key=="enable_simd_benchmark") { bool b; if (ParseBool(val,b)){ cfg.enableSimdBenchmark=b; return true; } }
    else if (key=="simd_benchmark_iterations") { int v; if (ParseInt(val,v)){ cfg.simdBenchmarkIterations=v; return true; } }
    
    return false;
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
