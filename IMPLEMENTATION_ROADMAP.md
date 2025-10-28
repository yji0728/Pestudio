# Implementation Roadmap

## Overview

This document tracks the implementation status of features specified in add spec3.md and add spec4.md.

## Implementation Status

### ✅ Completed

#### Core Architecture
- [x] Python-based modular architecture
- [x] SQLAlchemy database layer
- [x] Click-based CLI framework
- [x] Modular component structure

#### Configuration System
- [x] Comprehensive JSON configuration templates (config.json.example)
- [x] Guest agent configuration (agent_config.json.example)
- [x] YAML profile system (profiles.yaml)
- [x] Support for multiple analysis profiles

#### Documentation
- [x] Performance optimization guide (PERFORMANCE.md)
- [x] Procmon integration guide (PROCMON_INTEGRATION.md)
- [x] WPF GUI specification (WPF_GUI_SPEC.md)
- [x] Updated README with new features

#### Sandbox Management (Enhanced)
- [x] Hyper-V configuration support
- [x] Default Switch network configuration
- [x] PowerShell Direct support structure
- [x] Guest Services integration structure
- [x] Process tracking for child processes
- [x] Command execution framework

#### Artifact Collection (Enhanced)
- [x] Memory dump framework
- [x] Child process tree memory dumping
- [x] PCAP capture with ring buffer support
- [x] Network capture optimization

#### VirusTotal Integration (Enhanced)
- [x] Auto-upload when file not found
- [x] Wait for analysis results
- [x] Result caching framework
- [x] Rate limiting support

### 🚧 In Progress / Placeholder

These features have framework/structure but need actual implementation:

#### Hyper-V Integration
- [ ] Actual PowerShell cmdlet execution (Restore-VMCheckpoint, Start-VM, etc.)
- [ ] Copy-VMFile implementation for file transfer
- [ ] Invoke-Command implementation for remote execution
- [ ] Guest IP address detection
- [ ] VM state monitoring

#### Process Monitoring
- [ ] ETW session management and event capture
- [ ] WMI event subscription implementation
- [ ] Procmon automation (start/stop/retrieve)
- [ ] PML to CSV conversion automation
- [ ] Real-time event streaming

#### Memory Dumping
- [ ] MiniDumpWriteDump API integration
- [ ] ProcDump integration
- [ ] Automated child process detection
- [ ] Concurrent dump management
- [ ] Compression implementation

#### Network Capture
- [ ] WinPcap/Npcap integration
- [ ] PCAP file creation and management
- [ ] Ring buffer implementation
- [ ] Protocol analysis

#### VirusTotal
- [ ] Actual API calls implementation
- [ ] File upload functionality
- [ ] Result polling implementation
- [ ] Cache persistence (file/database)

### 📋 Planned

#### WPF GUI
- [ ] .NET WPF project setup
- [ ] MVVM architecture implementation
- [ ] Main dashboard window
- [ ] New analysis wizard
- [ ] Real-time analysis view
- [ ] Settings window
- [ ] Process tree visualization
- [ ] Timeline view
- [ ] Integration with Python backend (REST API/WebSockets)

#### Performance Optimizations
- [ ] VM pooling implementation
- [ ] Buffered ETW processor
- [ ] Bulk database insert optimization
- [ ] Differential disk management
- [ ] Compression for artifacts
- [ ] Parallel file transfer
- [ ] UI virtualization

#### Advanced Features
- [ ] YARA rule integration
- [ ] Sigma rule integration
- [ ] MITRE ATT&CK mapping
- [ ] Behavior analysis engine
- [ ] Report generation (HTML/PDF)
- [ ] REST API for remote access
- [ ] WebSocket for real-time updates

## Milestone Plan (from add spec3.md)

### M0. Project Bootstrap ✅ COMPLETE
- [x] Architecture diagrams
- [x] Common schemas
- [x] Solution layout
- [x] Core dependencies

### M1. Hyper-V Sandbox Manager (2 weeks) 🚧 IN PROGRESS
- [x] Configuration structure
- [ ] Snapshot restore implementation
- [ ] Default Switch connection
- [ ] VM Guest Services activation
- [ ] PowerShell Direct file transfer
- [ ] Remote execution capability

### M2. Monitoring Baseline (3 weeks) 📋 PLANNED
- [ ] Procmon non-interactive capture
- [ ] ETW auxiliary monitoring
- [ ] PML→CSV conversion pipeline
- [ ] Database ingestion pipeline
- [ ] Event validation

### M3. Memory Dump & Artifacts (2 weeks) 📋 PLANNED
- [ ] Child process tracking
- [ ] Full memory dump (MiniDumpWriteDump)
- [ ] Dropped file collection
- [ ] Registry snapshot collection
- [ ] Artifact packaging

### M4. Network Capture (1 week) 📋 PLANNED
- [ ] Npcap + SharpPcap integration
- [ ] PCAP continuous capture
- [ ] Ring buffer implementation
- [ ] DNS/HTTP tagging
- [ ] Protocol analysis

### M5. VirusTotal Integration (1 week) 📋 PLANNED
- [ ] SHA-256 lookup
- [ ] Auto-upload on miss
- [ ] Result polling
- [ ] Result caching
- [ ] Rate limit handling

### M6. CLI (1 week) 📋 PLANNED
- [ ] analyze command
- [ ] batch command
- [ ] report command
- [ ] monitor command
- [ ] Configuration file support

### M7. WPF GUI v1 (3 weeks) 📋 PLANNED
- [ ] Project dashboard
- [ ] New analysis wizard
- [ ] Real-time process view
- [ ] Timeline visualization
- [ ] VT results tab
- [ ] Report export

### M8. Performance Optimization (1 week + ongoing) 📋 PLANNED
- [ ] ETW filtering and batch loading
- [ ] UI virtualization
- [ ] File transfer optimization
- [ ] Parallel processing
- [ ] Performance profiling
- [ ] Target: ≤2min for 5min analysis (p95)

### M9. Packaging & Documentation (1 week) 📋 PLANNED
- [ ] Installation package
- [ ] Operations guide
- [ ] License compliance
- [ ] Sample data
- [ ] User manual

## Current Sprint Focus

### Sprint Goals
1. ✅ Create comprehensive configuration templates
2. ✅ Document performance optimizations
3. ✅ Document Procmon integration
4. ✅ Document WPF GUI specifications
5. ✅ Update README and core documentation
6. Implement Hyper-V PowerShell integration (next)
7. Implement Procmon automation (next)

## Implementation Priorities

### High Priority (Core Functionality)
1. Hyper-V sandbox automation
2. Procmon capture automation
3. Memory dump implementation
4. VirusTotal API integration
5. Database optimization

### Medium Priority (Enhanced Features)
1. ETW event capture
2. Network PCAP capture
3. Report generation
4. CLI improvements
5. Performance optimizations

### Low Priority (Future)
1. WPF GUI
2. REST API
3. WebSocket streaming
4. YARA/Sigma integration
5. Advanced analytics

## Development Environment

### Required Tools
- Python 3.10+
- Windows 10/11 Pro or Enterprise
- Hyper-V enabled
- PowerShell 5.1+
- Visual Studio 2022 (for WPF GUI)
- .NET 6/7/8 SDK

### Required Software
- Sysinternals Suite (Procmon, Procdump)
- Npcap driver
- SQLite/PostgreSQL

### Development Setup
1. Clone repository
2. Install Python dependencies: `pip install -r requirements.txt`
3. Configure Hyper-V
4. Create test VM with clean snapshot
5. Install Procmon in test VM
6. Configure VirusTotal API key

## Testing Strategy

### Unit Tests
- Component-level testing
- Mock VM operations
- Database operations
- API integrations

### Integration Tests
- End-to-end analysis workflow
- VM lifecycle management
- Artifact collection
- Report generation

### Performance Tests
- Event processing throughput
- Memory usage profiling
- Database query performance
- UI responsiveness (60fps target)

## Success Criteria

From add spec3.md:
- ✅ All child processes have full memory dumps
- ⏳ Default Switch provides network connectivity
- ⏳ VT auto-upload/polling works
- ⏳ 5-min analysis completes in ≤2 min (p95)
- ⏳ UI scrolls 100K+ events at 60fps
- ⏳ Event drop rate < 0.5%

## Next Steps

1. **Week 1-2**: Implement Hyper-V PowerShell integration
   - Snapshot restore
   - VM start/stop
   - PowerShell Direct commands
   - File transfer via Copy-VMFile

2. **Week 3-4**: Implement Procmon automation
   - Deploy to guest
   - Start capture
   - Stop capture
   - Retrieve PML files
   - Convert to CSV

3. **Week 5-6**: Memory dump implementation
   - Process tree tracking
   - MiniDumpWriteDump integration
   - Child process enumeration
   - Concurrent dump management

4. **Week 7-8**: VirusTotal integration
   - API client implementation
   - Upload functionality
   - Result polling
   - Cache implementation

5. **Week 9-10**: Performance optimization
   - Bulk database operations
   - Event buffering
   - Compression
   - Profiling and tuning

## Notes

- Current implementation provides architecture and framework
- Many components have placeholder implementations
- Focus should be on completing M1-M5 for core functionality
- WPF GUI can be developed in parallel after core features are stable
- Performance optimization should be ongoing throughout development

## References

- add spec3.md: Korean specification with requirements
- add spec4.md: English specification with implementation details
- Spec.md: Original architecture specification
- Spec2.md: Procmon integration specification
