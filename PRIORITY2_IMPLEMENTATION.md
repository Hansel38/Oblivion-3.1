# Oblivion Anti-Cheat - Priority 2 Advanced Pattern Detection

## Overview
Dokumen ini menjelaskan peningkatan yang telah diimplementasikan untuk sistem Oblivion Anti-Cheat berdasarkan **Priority 2 - Advanced Pattern Detection**. Peningkatan ini fokus pada deteksi pola-pola canggih yang digunakan oleh Cheat Engine dan tools sejenis.

## Status Implementasi

### ✅ 2.1 Instruction Pattern Detection

#### 2.1.1 Code Cave Pattern Detection
**Status: COMPLETED**
- **File**: `client/src/MemorySignatureScanner.cpp`
- **Fungsi**: `DetectCodeCavePattern()`

**Fitur:**
- Deteksi NOP sled pattern (8+ consecutive NOPs)
- Deteksi PUSHAD/POPAD + JMP/RET pattern (khas CE auto-assembler)
- Deteksi MOV [address], immediate patterns (value-write scripts)
- Deteksi CALL+POP (GetEIP technique untuk position-independent code)
- Deteksi high density direct memory operations
- Fokus pada region executable 4KB-64KB dengan proteksi PAGE_EXECUTE_READWRITE

**Scoring System:**
- NOP sled 8+ NOPs: +3 points
- PUSHAD/POPAD pattern: +4 points
- MOV memory immediate (3+ occurrences): +2 points
- GetEIP technique: +3 points
- Direct memory ops (5+ occurrences): +2 points

#### 2.1.2 AOB (Array of Bytes) Injection Detection
**Status: COMPLETED**
- **File**: `client/src/MemorySignatureScanner.cpp`
- **Fungsi**: `DetectAOBInjectionPattern()`

**Fitur:**
- Deteksi code tanpa PE header dengan high instruction density (>40%)
- Deteksi alternating code/data sections (pattern injection)
- Deteksi repeated identical instruction sequences (copy-paste injection)
- Statistical analysis of instruction opcodes

**Detection Criteria:**
- Instruction density > 40% tanpa PE header: +3 points
- Instruction density > 25%: +1 point
- Code-data transitions (4+ transitions): +2 points
- Repeated 16-byte sequences: +1 point

#### 2.1.3 Enhanced Inline Hook Detection
**Status: COMPLETED**
- **File**: `client/src/InlineHookScanner.cpp`
- **Upgrade**: `ScanModuleExports()`

**Fitur Baru:**
- Deteksi JMP ke executable non-image regions (code caves)
- Deteksi target dengan proteksi PAGE_EXECUTE_READWRITE (+2 bonus)
- Enhanced scoring untuk unmapped memory targets (+4 points)
- Memory region analysis via VirtualQuery untuk setiap hook target

**Hook Pattern Detection:**
- JMP rel32/rel8
- PUSH+RET trampoline
- MOV rax + JMP rax (x64)
- CALL rel32
- INT3 breakpoint
- Early RET

### ✅ 2.2 Enhanced Driver Detection

#### 2.2.1 DBK Driver IOCTL Detection
**Status: COMPLETED**
- **File**: `client/src/DeviceObjectScanner.cpp`
- **Fungsi**: `DetectDBKIoctlPattern()`

**Fitur:**
- Scan IOCTL range 0x9C402000-0x9C402FFF (DBK characteristic range)
- Test known DBK IOCTL codes:
  - 0x9C402000: READMSR
  - 0x9C402004: WRITEMSR
  - 0x9C402008: READMEM
  - 0x9C40200C: WRITEMEM
  - 0x9C402010: READPCI
- Safe probing tanpa execute harmful operations

#### 2.2.2 Device Object Scanner
**Status: COMPLETED**
- **Files**: 
  - `client/include/DeviceObjectScanner.h`
  - `client/src/DeviceObjectScanner.cpp`

**Fitur:**
- Query `\Device\` directory via NtQueryDirectoryObject
- Deteksi device objects: `\Device\DBK*`, `\Device\CEDRIVER*`, `\Device\speedhack*`
- Scan symbolic links: `\DosDevices\DBK*`, `\DosDevices\CEDRIVER*`
- Probe known CE device paths:
  - `\\.\DBK32`
  - `\\.\DBK64`
  - `\\.\CEDRIVER`
  - `\\.\CEDRIVER32`
  - `\\.\CEDRIVER64`
  - `\\.\speedhack`
  - `\\.\kernelcheatengine`

**Scoring:**
- Device name match: +5 points
- DBK IOCTL confirmed: +3 additional points

#### 2.2.3 Kernel Driver Enhancement
**Status: PENDING**
- Requires update to `driver/OblivionAC/OblivionAC.c`
- TODO: Add device object creation monitoring
- TODO: Add IOCTL registration detection

### ✅ 2.3 Network Artifact Detection

#### 2.3.1 CE Server Port Detection
**Status: COMPLETED**
- **Files**:
  - `client/include/NetworkArtifactScanner.h`
  - `client/src/NetworkArtifactScanner.cpp`

**Fitur:**
- Scan listening TCP ports via GetExtendedTcpTable
- Deteksi CE default port: 52736
- Deteksi suspicious range: 52000-53000
- Process name correlation (CheatEngine.exe, ce.exe, ce-x64.exe)
- Active connection monitoring

**Detection Methods:**
1. **ScanListeningPorts()**: Scan all listening ports
2. **ScanActiveTCPConnections()**: Scan established connections
3. **Process correlation**: Identify CE process by name

**Scoring:**
- Exact CE port (52736): +5 points
- CE port range: +3 points
- CheatEngine process name: +5 additional points

#### 2.3.2 Network Speedhack Detection
**Status: COMPLETED**
- **File**: `client/src/SpeedHackDetector.cpp`
- **Fungsi baru**: 
  - `RecordNetworkPacket()`
  - `DetectNetworkTimingAnomaly()`
  - `AnalyzeNetworkPacketTiming()`

**Fitur:**
- Network packet timestamp recording
- Packet interval analysis
- Local time vs network time divergence detection
- Statistical analysis (Coefficient of Variation)
- Erratic timing pattern detection

**Detection Criteria:**
- Network-local divergence > 20%: Speed hack detected
- Coefficient of Variation > 1.5: Erratic timing
- Timestamp anomalies (zero/negative intervals)
- Large jumps (>5 seconds) detection

**How to Use:**
```cpp
// Record packet when sending/receiving
g_pSpeedHack->RecordNetworkPacket(GetTickCount64(), packetSize, isOutgoing);

// Check for anomalies
SpeedHackDetector::SpeedHackFinding finding;
if (g_pSpeedHack->DetectNetworkTimingAnomaly(finding)) {
    // Speed hack detected via network timing
}
```

## Integration dengan Sistem Utama

### Periodic Scanner Integration
Semua modul baru telah diintegrasikan ke `SchedulePeriodicScans()` di `dllmain.cpp`:

```cpp
// Priority 2 scanners added to periodic checks:
- DeviceObjectScanner (every periodic tick)
- NetworkArtifactScanner (every periodic tick)
- Enhanced SpeedHackDetector with network timing (every periodic tick)
```

### Initialization
Scanner baru diinisialisasi saat DLL attach:

```cpp
// Device Object Scanner
g_pDeviceScanner = new DeviceObjectScanner();
g_pDeviceScanner->SetThreshold(2);

// Network Artifact Scanner
g_pNetArtifact = new NetworkArtifactScanner();
g_pNetArtifact->SetThreshold(2);
```

### Cleanup
Proper cleanup di `CleanupGlobals()`:

```cpp
if (g_pDeviceScanner) { delete g_pDeviceScanner; g_pDeviceScanner = nullptr; }
if (g_pNetArtifact) { delete g_pNetArtifact; g_pNetArtifact = nullptr; }
```

## Performance Considerations

### Memory Signature Scanner
- Fokus pada region 4KB-64KB untuk code cave detection
- Skip large regions untuk performa
- Sample-based analysis (max 4KB per region)

### Device Object Scanner
- Efficient NT native API calls
- Cached results untuk directory queries
- Safe IOCTL probing tanpa harmful operations

### Network Artifact Scanner
- Lightweight TCP table enumeration
- Process name caching
- Minimal memory footprint

### Speed Hack Detector
- Circular buffer (max 60 timing samples, 100 network packets)
- Statistical analysis only when sufficient data
- Background monitoring dengan configurable interval

## False Positive Mitigation

### Threshold System
Semua scanner menggunakan configurable threshold:
- Low threshold (1-2): Aggressive detection
- Medium threshold (2-3): Balanced (default)
- High threshold (4-5): Conservative

### Whitelist Support
- Module path whitelisting (InlineHookScanner)
- Process name filtering
- System module exclusion

### Multi-indicator Scoring
Setiap detection menggunakan scoring system dengan multiple indicators untuk mengurangi false positives.

## Testing Recommendations

### Unit Testing
1. Test code cave detection dengan known CE scripts
2. Test DBK driver detection dengan DBK64/32 installed
3. Test CE server detection dengan CE network mode
4. Test network timing dengan synthetic speedhack

### Integration Testing
1. Monitor false positive rate pada game normal
2. Validate detection dengan CheatEngine 7.x
3. Test performa impact pada sistem
4. Verify cleanup pada DLL detach

### Stress Testing
1. High network packet rate scenarios
2. Multiple concurrent CE instances
3. Memory-intensive games
4. Low-end hardware compatibility

## Konfigurasi yang Direkomendasikan

### Production Settings
```json
{
  "enablePeriodicScans": true,
  "enableSpeedHackDetector": true,
  "speedHackSensitivity": 3,
  "speedHackMonitorIntervalMs": 1000,
  "closeThreshold": 3,
  "aggressiveDetection": false
}
```

### Testing/Development Settings
```json
{
  "enablePeriodicScans": true,
  "enableSpeedHackDetector": true,
  "speedHackSensitivity": 4,
  "speedHackMonitorIntervalMs": 500,
  "closeThreshold": 2,
  "aggressiveDetection": true,
  "enableLogging": true
}
```

## Roadmap & Future Enhancements

### Priority 2.2.3 - Kernel Driver Enhancement
- [ ] Monitor device object creation in kernel mode
- [ ] Detect IOCTL handler registration
- [ ] Track driver load/unload events
- [ ] Implement driver signature validation

### Additional Enhancements
- [ ] Machine learning-based pattern recognition
- [ ] Cloud-based signature updates
- [ ] Automated pattern extraction from CE scripts
- [ ] Hardware breakpoint detection enhancement

## Known Limitations

1. **Device Object Scanner**: Requires elevated privileges untuk full directory enumeration
2. **Network Artifact Scanner**: Dapat miss CE jika running pada non-standard port
3. **Code Cave Detection**: Pattern-based, dapat miss obfuscated code
4. **Network Timing**: Requires consistent network packets untuk accurate analysis

## Credits & References

- CheatEngine source code analysis
- DBK driver reverse engineering documentation
- Windows Internals (Russinovich et al.)
- NT Native API documentation

## Changelog

### Version 2.0 (Current)
- ✅ Implemented code cave pattern detection
- ✅ Implemented AOB injection detection
- ✅ Enhanced inline hook detection with memory region analysis
- ✅ Implemented DBK driver IOCTL detection
- ✅ Implemented device object scanner
- ✅ Implemented CE server port detection
- ✅ Implemented network packet timing analysis for speedhack
- ✅ Integrated all modules into main detection loop

### Version 1.x (Previous)
- Basic process monitoring
- Simple signature scanning
- Basic speedhack detection via timing
- CE registry scanner
- CE window scanner
- CE behavior monitor

---

**Last Updated**: November 2, 2025
**Status**: Priority 2 Implementation COMPLETE (7/8 items)
**Next**: Priority 2.2.3 Kernel Driver Enhancement
