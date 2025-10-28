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
   - VM lifecycle management (VirtualBox, VMware, Hyper-V)
   - Snapshot management and restoration
   - Network isolation
   - File deployment and execution

3. **Process Monitor** - Monitors process behavior
   - Process creation/termination events
   - Thread creation and DLL loading
   - File system operations
   - Registry modifications
   - Network connections
   - API call tracking (ETW/WMI based)

4. **Artifact Collector** - Collects execution artifacts
   - Dropped files
   - Process memory dumps
   - Network traffic capture (PCAP)
   - Registry changes

5. **VirusTotal Client** - VirusTotal API integration
   - File hash lookup
   - File submission
   - Report retrieval
   - Similar sample search

6. **Storage & Database** - Data persistence
   - SQLite/PostgreSQL support
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
  type: virtualbox  # virtualbox, vmware, or hyperv
  vm_name: "Windows10_Sandbox"
  snapshot: "clean_state"
  memory: 4096
  cpu_cores: 2
  
monitoring:
  api_hooks: true
  network_capture: true
  screenshot_interval: 5
  memory_dump: true
  
analysis:
  timeout: 300
  kill_on_timeout: true
  collect_artifacts: true
  
virustotal:
  api_key: "YOUR_API_KEY"
  auto_submit: true
  wait_for_results: true
  
output:
  directory: "./reports"
  format: "json"
  include_pcap: true
  include_memory_dump: false
```

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

This implementation is based on two detailed specifications:

1. **Spec.md** - Overall system architecture and design
2. **Spec2.md** - Detailed implementation guide with Procmon integration

Key features from specifications:

- PE file dynamic analysis in sandbox environments
- Procmon-based behavior tracking
- File/Registry/Process/Network event collection
- Memory and disk artifact dumping
- API call logging
- VirusTotal integration
- Both CLI and GUI interfaces

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
- **API Integration**: Requests
- **Monitoring**: ETW/WMI (Windows)

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

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please submit pull requests or open issues for bugs and feature requests.

## Acknowledgments

- Based on specifications in Spec.md and Spec2.md
- Uses Sysinternals tools (Procmon, Procdump)
- Integrates with VirusTotal API v3

## Support

For questions or issues:
- Open an issue on GitHub
- Check the specifications (Spec.md, Spec2.md)
- Review the code documentation

## Disclaimer

This tool is for legitimate security research and malware analysis only. Users are responsible for complying with all applicable laws and regulations. The authors are not responsible for misuse of this tool.
