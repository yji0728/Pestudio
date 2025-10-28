# MalwareAnalyzer Pro

Advanced PE Dynamic Analysis System for safe malware analysis in isolated sandbox environments.

## Overview

MalwareAnalyzer Pro is a comprehensive Windows PE file analysis tool that provides:

- **PE File Validation**: Deep validation and metadata extraction from PE files
- **Sandbox Execution**: Safe execution in isolated VM environments (VirtualBox, VMware, Hyper-V)
- **Process Monitoring**: Real-time monitoring of process behavior, API calls, and system events
- **Artifact Collection**: Automatic collection of dropped files, memory dumps, and network traffic
- **VirusTotal Integration**: Automated hash checking and file submission to VirusTotal
- **CLI & GUI**: Both command-line and graphical interfaces
- **Detailed Reporting**: Comprehensive analysis reports in JSON, HTML, and PDF formats

## Architecture

The system consists of the following core modules:

### Core Components

1. **PE File Validator** - Validates PE files and extracts metadata
   - PE header validation
   - Digital signature verification
   - Entropy analysis and packing detection
   - Import/Export table extraction
   - Section and resource information

2. **Sandbox Manager** - Manages VM-based sandbox environments
   - VM lifecycle management (VirtualBox, VMware, **Hyper-V**)
   - **Hyper-V Default Switch** support for network connectivity
   - **PowerShell Direct** for file transfer and command execution
   - **Guest Services** integration for efficient VM communication
   - Snapshot management and restoration
   - Network isolation and configuration
   - File deployment and execution

3. **Process Monitor** - Monitors process behavior
   - Process creation/termination events
   - **Process tree tracking** for parent-child relationships
   - Thread creation and DLL loading
   - File system operations
   - Registry modifications
   - Network connections
   - API call tracking (ETW/WMI based)
   - **Procmon integration** for comprehensive behavior logging

4. **Artifact Collector** - Collects execution artifacts
   - Dropped files
   - **Process memory dumps (ALL child processes)**
   - **Full memory dumps** with MiniDumpWriteDump
   - Network traffic capture (**PCAP with ring buffer**)
   - Registry changes

5. **VirusTotal Client** - VirusTotal API integration
   - File hash lookup
   - **Auto-upload when file not found in VT**
   - **Wait for analysis results** with polling
   - **Result caching** to avoid repeated API calls
   - File submission
   - Report retrieval
   - Similar sample search

6. **Storage & Database** - Data persistence
   - SQLite/PostgreSQL support
   - **Bulk insert optimization** for performance
   - Execution history
   - Event logging
   - Artifact management

## Installation

### Prerequisites

- Python 3.10 or higher
- Windows (for full functionality)
- Hypervisor (VirtualBox, VMware, or Hyper-V)
- Administrator privileges (for sandbox management)

### Install from source

```bash
# Clone the repository
git clone https://github.com/yji0728/Pestudio.git
cd Pestudio

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

### Optional Dependencies

```bash
# For GUI support
pip install PyQt6

# For development
pip install -e ".[dev]"
```

## Configuration

Create a `config.yaml` file to customize behavior:

```yaml
sandbox:
  type: hyperv  # virtualbox, vmware, or hyperv
  vm_name: "Win11_Analysis"
  snapshot: "clean_2025-10"
  use_default_switch: true  # Use Hyper-V Default Switch
  enable_guest_services: true  # Enable Guest Services
  powershell_direct: true  # Use PowerShell Direct
  time_sync: true  # Enable time synchronization
  memory: 4096
  cpu_cores: 2
  
monitoring:
  dump_all_child_processes: true  # Dump ALL child processes
  memory_dump_type: "Full"  # Full memory dumps
  api_hooks: true
  network_capture: true
  pcap_ring_buffer_mb: 500  # PCAP ring buffer size
  screenshot_interval: 5
  procmon_enabled: true  # Enable Procmon integration
  etw_enabled: true  # Enable ETW monitoring
  
analysis:
  timeout: 300
  kill_on_timeout: true
  collect_artifacts: true
  
virustotal:
  api_key: "YOUR_API_KEY"
  auto_submit: true
  auto_upload_if_missing: true  # Auto-upload if not in VT
  wait_for_results: true  # Wait for analysis completion
  max_wait_time: 300
  cache_results: true  # Cache VT results
  cache_duration: 86400  # 24 hours
  
output:
  directory: "./reports"
  format: "json"
  include_pcap: true
  include_memory_dump: false

performance:
  enable_caching: true
  batch_insert_size: 1000  # Bulk insert optimization
  thread_pool_size: 16
  enable_compression: true
```

See `config.yaml.example`, `config.json.example`, and `profiles.yaml` for more detailed configuration options.

## Usage

### CLI Interface

#### Basic Analysis

```bash
# Analyze a PE file
python malanalyzer.py analyze sample.exe

# With options
python malanalyzer.py analyze sample.exe \
  --timeout 300 \
  --sandbox virtualbox \
  --network isolated \
  --dump-memory \
  --vt-scan \
  --verbose
```

#### Report Generation

```bash
# Generate report
python malanalyzer.py report <execution_id> --format html

# List recent executions
python malanalyzer.py list --limit 20
```

#### VirusTotal Integration

```bash
# Check file hash in VirusTotal
export VT_API_KEY="your_api_key"
python malanalyzer.py vt-check <sha256_hash>
```

### Command Options

- `--timeout`: Execution timeout in seconds (default: 300)
- `--sandbox`: Sandbox type (virtualbox/vmware/hyperv)
- `--network`: Network mode (isolated/limited/full)
- `--dump-memory`: Enable process memory dumping
- `--vt-scan`: Enable VirusTotal scanning
- `--output`: Output format (json/html/pdf)
- `--verbose`: Enable verbose output

## Specifications

This implementation is based on four detailed specifications:

1. **Spec.md** - Overall system architecture and design
2. **Spec2.md** - Detailed implementation guide with Procmon integration
3. **add spec3.md** (Korean) - Advanced features including:
   - Hyper-V integration with Default Switch
   - Memory dumps for ALL child processes
   - VirusTotal auto-upload functionality
   - WPF .NET GUI specification
   - Performance optimization requirements
4. **add spec4.md** (English) - Comprehensive implementation guide with:
   - Detailed Hyper-V configuration and PowerShell Direct
   - Child process tracking and full memory dumps
   - VirusTotal integration with caching
   - Performance optimization strategies
   - Configuration templates and profiles

Key features from all specifications:

- PE file dynamic analysis in sandbox environments
- **Hyper-V sandbox with Default Switch network**
- **PowerShell Direct for efficient VM communication**
- Procmon-based behavior tracking
- **ETW (Event Tracing for Windows) integration**
- File/Registry/Process/Network event collection
- **Memory dumping of parent and ALL child processes**
- **PCAP network capture with ring buffer**
- API call logging
- **VirusTotal integration with auto-upload**
- **Performance optimizations (buffering, VM pooling, etc.)**
- Both CLI and **WPF GUI** interfaces

## Safety and Security

### Safety Guidelines

⚠️ **IMPORTANT**: This tool is designed for malware analysis in controlled environments.

- Always run analysis in isolated VM environments
- Use network isolation (offline or simulated internet)
- Restore VM snapshots after each execution
- Use standard user accounts for sample execution
- Never run untrusted samples on production systems

### Recommended Setup

1. **Isolated Network**: Configure sandbox VMs with no direct internet access
2. **Snapshot Management**: Always start from clean snapshots
3. **Limited Permissions**: Run samples with restricted user privileges
4. **Time Limits**: Set appropriate execution timeouts
5. **Artifact Isolation**: Store collected artifacts securely

## Database Schema

The system uses a relational database to store analysis data:

- `executions` - Main execution records
- `process_events` - Process creation/termination events
- `api_calls` - API call records
- `file_operations` - File system operations
- `registry_operations` - Registry modifications
- `network_connections` - Network activity

## Output and Reporting

### Execution Artifacts

Each analysis generates:

```
artifacts/
└── {execution_id}/
    ├── raw/
    │   ├── run.pml       # Procmon log
    │   └── run.csv       # Converted CSV
    ├── normalized/
    │   └── events.jsonl  # Normalized events
    ├── artifacts/
    │   ├── files/        # Dropped files
    │   ├── dumps/        # Memory dumps
    │   └── network/      # Network captures
    └── reports/
        ├── summary.json  # Analysis summary
        └── report.html   # HTML report
```

### Report Contents

- Execution overview (hashes, VT detection rate, execution time)
- Process tree visualization
- File system changes
- Registry modifications
- Network connections
- API call summary
- Behavioral indicators
- MITRE ATT&CK mapping (basic)

## Development

### Project Structure

```
Pestudio/
├── src/
│   └── malanalyzer/
│       ├── validators/      # PE validation
│       ├── sandbox/         # VM management
│       ├── monitoring/      # Process monitoring
│       ├── collectors/      # Artifact collection
│       ├── api/            # VirusTotal client
│       ├── storage/        # Database
│       ├── cli/            # CLI interface
│       └── utils/          # Utilities
├── tests/                  # Test suite
├── requirements.txt        # Dependencies
├── setup.py               # Package setup
├── config.yaml            # Configuration
├── Spec.md                # Design specification
├── Spec2.md               # Implementation specification
└── README.md              # This file
```

### Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Run with coverage
pytest --cov=malanalyzer tests/
```

### Code Style

```bash
# Format code
black src/

# Lint code
flake8 src/
```

## Technical Stack

- **Language**: Python 3.10+
- **CLI Framework**: Click
- **Database**: SQLAlchemy (SQLite/PostgreSQL)
- **VM Management**: Platform-specific APIs
  - **Hyper-V**: PowerShell cmdlets and PowerShell Direct
  - VirtualBox: VBoxManage API
  - VMware: VMware API
- **API Integration**: Requests
- **Monitoring**: 
  - ETW (Event Tracing for Windows)
  - WMI (Windows Management Instrumentation)
  - **Procmon** (Sysinternals Process Monitor)
- **Network Capture**: WinPcap/Npcap for PCAP
- **GUI** (planned): WPF (.NET) for Windows

## Additional Documentation

- **PERFORMANCE.md** - Performance optimization guide
- **PROCMON_INTEGRATION.md** - Procmon integration details
- **WPF_GUI_SPEC.md** - WPF GUI specification
- **config.json.example** - Comprehensive JSON configuration
- **agent_config.json.example** - Guest agent configuration
- **profiles.yaml** - Analysis profile templates

## Limitations

This implementation provides the core architecture and interfaces. For production use, additional components are needed:

- Full hypervisor integration (VirtualBox/VMware/Hyper-V APIs)
- Complete ETW/WMI event collection implementation
- Procmon automation and PML parsing
- Process memory dumping (Procdump integration)
- Network traffic capture (WinPcap/Npcap)
- GUI implementation (PyQt6/WPF)

## Future Enhancements

- Multiple OS profile support (Windows 10/11/Server)
- Automated VM snapshot updates
- YARA rule engine integration
- Enhanced MITRE ATT&CK mapping
- REST API for remote access
- Team collaboration features
- Advanced anti-analysis detection
- **WPF GUI implementation** (specification complete)
- **VM pooling** for instant analysis startup
- **Real-time event streaming** via WebSockets
- **Advanced performance monitoring** and profiling

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please submit pull requests or open issues for bugs and feature requests.

## Acknowledgments

- Based on specifications in Spec.md, Spec2.md, add spec3.md, and add spec4.md
- Uses Sysinternals tools (Procmon, Procdump)
- Hyper-V PowerShell cmdlets and PowerShell Direct
- Integrates with VirusTotal API v3
- WinPcap/Npcap for network capture

## Support

For questions or issues:
- Open an issue on GitHub
- Check the specifications (Spec.md, Spec2.md)
- Review the code documentation

## Disclaimer

This tool is for legitimate security research and malware analysis only. Users are responsible for complying with all applicable laws and regulations. The authors are not responsible for misuse of this tool.
