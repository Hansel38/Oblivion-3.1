# Oblivion Anti-Cheat - Arsitektur Priority 2 Advanced Detection

## Diagram Arsitektur Sistem

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         OBLIVION ANTI-CHEAT SYSTEM                          │
│                         Priority 2: Advanced Detection                      │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLIENT (DLL)                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────┐            │
│  │              PRIORITY 2.1: INSTRUCTION PATTERN             │            │
│  ├────────────────────────────────────────────────────────────┤            │
│  │                                                              │            │
│  │  [MemorySignatureScanner] - ENHANCED                        │            │
│  │  ├─ DetectCodeCavePattern()                                 │            │
│  │  │  ├─ NOP sled detection (8+ consecutive NOPs)            │            │
│  │  │  ├─ PUSHAD/POPAD + JMP/RET pattern                      │            │
│  │  │  ├─ MOV [addr], imm pattern (value-write)               │            │
│  │  │  ├─ CALL+POP (GetEIP technique)                         │            │
│  │  │  └─ High density direct memory ops                      │            │
│  │  │                                                           │            │
│  │  ├─ DetectAOBInjectionPattern()                             │            │
│  │  │  ├─ High instruction density (>40% without PE)          │            │
│  │  │  ├─ Alternating code/data sections                      │            │
│  │  │  ├─ Repeated instruction sequences                      │            │
│  │  │  └─ Instruction opcode statistical analysis             │            │
│  │  │                                                           │            │
│  │  └─ RunOnceScan() - ENHANCED                                │            │
│  │     ├─ Focus on 4KB-64KB executable regions                │            │
│  │     ├─ Priority: PAGE_EXECUTE_READWRITE regions            │            │
│  │     └─ Non-image memory scanning                           │            │
│  │                                                              │            │
│  │  [InlineHookScanner] - ENHANCED                             │            │
│  │  ├─ ScanModuleExports() - UPGRADED                          │            │
│  │  │  ├─ Detect JMP to non-image regions                     │            │
│  │  │  ├─ Memory region analysis via VirtualQuery             │            │
│  │  │  ├─ RWX protection bonus scoring (+2)                   │            │
│  │  │  └─ Unmapped memory target detection (+4)               │            │
│  │  │                                                           │            │
│  │  └─ ScanCriticalFunctions()                                 │            │
│  │     └─ Enhanced scoring for non-image targets              │            │
│  └──────────────────────────────────────────────────────────── │            │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────┐            │
│  │             PRIORITY 2.2: DRIVER DETECTION                 │            │
│  ├────────────────────────────────────────────────────────────┤            │
│  │                                                              │            │
│  │  [DeviceObjectScanner] - NEW MODULE                         │            │
│  │  ├─ ScanDeviceObjects()                                     │            │
│  │  │  ├─ Query \Device\ via NtQueryDirectoryObject           │            │
│  │  │  ├─ Detect: \Device\DBK*                                │            │
│  │  │  ├─ Detect: \Device\CEDRIVER*                           │            │
│  │  │  ├─ Detect: \Device\speedhack*                          │            │
│  │  │  └─ Detect: \Device\kernelcheatengine*                  │            │
│  │  │                                                           │            │
│  │  ├─ ScanSymbolicLinks()                                     │            │
│  │  │  ├─ Query \DosDevices\ directory                        │            │
│  │  │  ├─ Detect: \DosDevices\DBK*                            │            │
│  │  │  └─ Detect: \DosDevices\CEDRIVER*                       │            │
│  │  │                                                           │            │
│  │  ├─ ProbeKnownCEDevices()                                   │            │
│  │  │  ├─ Test: \\.\DBK32                                     │            │
│  │  │  ├─ Test: \\.\DBK64                                     │            │
│  │  │  ├─ Test: \\.\CEDRIVER                                  │            │
│  │  │  ├─ Test: \\.\CEDRIVER32                                │            │
│  │  │  ├─ Test: \\.\CEDRIVER64                                │            │
│  │  │  ├─ Test: \\.\speedhack                                 │            │
│  │  │  └─ Test: \\.\kernelcheatengine                         │            │
│  │  │                                                           │            │
│  │  └─ DetectDBKIoctlPattern()                                 │            │
│  │     ├─ IOCTL range: 0x9C402000-0x9C402FFF                  │            │
│  │     ├─ Test: READMSR (0x9C402000)                          │            │
│  │     ├─ Test: WRITEMSR (0x9C402004)                         │            │
│  │     ├─ Test: READMEM (0x9C402008)                          │            │
│  │     ├─ Test: WRITEMEM (0x9C40200C)                         │            │
│  │     └─ Test: READPCI (0x9C402010)                          │            │
│  └──────────────────────────────────────────────────────────── │            │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────┐            │
│  │           PRIORITY 2.3: NETWORK ARTIFACTS                  │            │
│  ├────────────────────────────────────────────────────────────┤            │
│  │                                                              │            │
│  │  [NetworkArtifactScanner] - NEW MODULE                      │            │
│  │  ├─ ScanForCEServerPort()                                   │            │
│  │  │  ├─ Detect CE default port: 52736                       │            │
│  │  │  ├─ Detect CE range: 52000-53000                        │            │
│  │  │  └─ Process name correlation                            │            │
│  │  │                                                           │            │
│  │  ├─ ScanListeningPorts()                                    │            │
│  │  │  ├─ GetExtendedTcpTable enumeration                     │            │
│  │  │  ├─ Filter by suspicious ports                          │            │
│  │  │  └─ Match against CE process names                      │            │
│  │  │                                                           │            │
│  │  └─ ScanActiveTCPConnections()                              │            │
│  │     ├─ Enumerate established connections                   │            │
│  │     ├─ Check remote port for CE signature                  │            │
│  │     └─ Detect game process bound to CE port                │            │
│  │                                                              │            │
│  │  [SpeedHackDetector] - ENHANCED                             │            │
│  │  ├─ RecordNetworkPacket() - NEW                             │            │
│  │  │  ├─ Timestamp recording                                 │            │
│  │  │  ├─ Interval calculation                                │            │
│  │  │  └─ Circular buffer (max 100 packets)                   │            │
│  │  │                                                           │            │
│  │  ├─ DetectNetworkTimingAnomaly() - NEW                      │            │
│  │  │  ├─ Network timing consistency check                    │            │
│  │  │  ├─ Local vs network time divergence                    │            │
│  │  │  ├─ Statistical analysis (CV > 1.5)                     │            │
│  │  │  └─ Timestamp anomaly detection                         │            │
│  │  │                                                           │            │
│  │  └─ CheckSpeedHack() - EXISTING                             │            │
│  │     ├─ QPC manipulation detection                          │            │
│  │     ├─ GetTickCount jump detection                         │            │
│  │     └─ Time source inconsistency                           │            │
│  └──────────────────────────────────────────────────────────── │            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                         DETECTION FLOW DIAGRAM                               │
└─────────────────────────────────────────────────────────────────────────────┘

    DLL_PROCESS_ATTACH
           │
           ├─────> Initialize NetworkClient
           │
           ├─────> Initialize DeviceObjectScanner ◄───┐
           │                                           │ Priority 2.2
           ├─────> Initialize NetworkArtifactScanner ◄┘
           │
           ├─────> Initialize SpeedHackDetector (Enhanced) ◄── Priority 2.3.2
           │
           └─────> SchedulePeriodicScans()
                        │
                        ├─── Every N milliseconds ───┐
                        │                             │
                        ▼                             │
              ┌──────────────────────┐               │
              │  Periodic Scanner    │               │
              └──────────────────────┘               │
                        │                             │
                        ├─ CE Artifact Sweep          │
                        ├─ CE Driver Detection        │
                        ├─ Remote Handle Scan         │
                        ├─ CE Behavior Monitor        │
                        ├─ CE Registry Scanner        │
                        ├─ CE Window Scanner          │
                        ├─ Speed Hack Detector ◄──────┼── Priority 2.3.2 Enhanced
                        │                             │
                        ├─ DeviceObjectScanner ◄──────┼── Priority 2.2 NEW
                        │  ├─ Scan device objects     │
                        │  ├─ Scan symbolic links     │
                        │  └─ Probe known devices     │
                        │                             │
                        ├─ NetworkArtifactScanner ◄───┼── Priority 2.3.1 NEW
                        │  ├─ Scan listening ports    │
                        │  └─ Scan TCP connections    │
                        │                             │
                        ├─ MemorySignatureScanner ◄───┼── Priority 2.1 Enhanced
                        │  ├─ Code cave detection     │
                        │  └─ AOB injection detection │
                        │                             │
                        └─ InlineHookScanner ◄────────┘── Priority 2.1.3 Enhanced
                           └─ Non-image JMP detection

    Detection Found
           │
           ├─────> ProcessDetection()
           │           │
           │           ├─ Build JSON report
           │           ├─ Send to server
           │           └─ Log locally
           │
           └─────> CleanupGlobals() (if threshold exceeded)
                        │
                        ├─ Stop all scanners
                        ├─ Delete DeviceObjectScanner
                        ├─ Delete NetworkArtifactScanner
                        └─ Terminate process

┌─────────────────────────────────────────────────────────────────────────────┐
│                            SCORING MATRIX                                    │
└─────────────────────────────────────────────────────────────────────────────┘

Detection Type                          Base Score    Bonus Conditions
─────────────────────────────────────────────────────────────────────────────
Code Cave Pattern:
  NOP sled (8+ consecutive)                  +3       
  PUSHAD/POPAD pattern                       +4       
  MOV [addr], imm (3+ occurrences)           +2       
  GetEIP technique                           +3       
  Direct mem ops (5+)                        +2       
  
AOB Injection:
  High instruction density (>40%)            +3       
  Moderate density (>25%)                    +1       
  Code-data transitions (4+)                 +2       
  Repeated sequences                         +1       
  
Inline Hook (Enhanced):
  JMP to non-image region                    +4       
  RWX protection                                      +2
  Unmapped memory target                     +4       
  System module redirect                     +1       
  
Device Object:
  Known CE device pattern                    +5       
  DBK IOCTL confirmed                                 +3
  
Network Artifact:
  CE default port (52736)                    +5       
  CE port range                              +3       
  CheatEngine process name                            +5
  
Network Speedhack:
  Timing divergence (>20%)                   +5       
  Erratic timing (CV>1.5)                    +3       
  Timestamp anomaly                          +4       

THRESHOLD LEVELS:
├─ 1-2: Aggressive detection (high false positive risk)
├─ 2-3: Balanced detection (recommended)
└─ 4-5: Conservative detection (low false positive)

┌─────────────────────────────────────────────────────────────────────────────┐
│                        PERFORMANCE METRICS                                   │
└─────────────────────────────────────────────────────────────────────────────┘

Module                          Frequency    CPU Impact    Memory Impact
─────────────────────────────────────────────────────────────────────────────
MemorySignatureScanner          Per scan     Medium        Low (4KB samples)
InlineHookScanner               Per scan     Low           Low
DeviceObjectScanner             Periodic     Low           Low (<1KB)
NetworkArtifactScanner          Periodic     Low           Low (<10KB)
SpeedHackDetector               Background   Very Low      Low (<50KB)
  ├─ Timing monitor             1s interval  Very Low      Minimal
  └─ Network packet tracking    Per packet   Minimal       Minimal

TOTAL OVERHEAD (Estimated):
├─ CPU: < 2% on average CPU
├─ Memory: < 5MB total
└─ Network: Minimal (monitoring only)
```

## File Baru yang Ditambahkan

### Header Files
1. `client/include/DeviceObjectScanner.h` - DBK/CE driver detection
2. `client/include/NetworkArtifactScanner.h` - CE server network detection

### Implementation Files
1. `client/src/DeviceObjectScanner.cpp` - Device object scanning implementation
2. `client/src/NetworkArtifactScanner.cpp` - Network scanning implementation

### Enhanced Files
1. `client/src/MemorySignatureScanner.cpp` - Added code cave & AOB detection
2. `client/src/InlineHookScanner.cpp` - Enhanced with non-image JMP detection
3. `client/src/SpeedHackDetector.cpp` - Added network timing analysis
4. `client/include/SpeedHackDetector.h` - Added network packet tracking
5. `client/dllmain.cpp` - Integrated all new modules

### Documentation
1. `PRIORITY2_IMPLEMENTATION.md` - Detailed implementation guide
2. `ARCHITECTURE_DIAGRAM.md` - Visual system architecture

## Statistik Implementasi

- **Total Lines of Code Added**: ~2,000+ lines
- **New Modules Created**: 2 complete modules
- **Enhanced Modules**: 3 major modules
- **Detection Patterns Added**: 15+ new patterns
- **Integration Points**: 4 main integration points
- **TODO Items Completed**: 9/10 (90%)
