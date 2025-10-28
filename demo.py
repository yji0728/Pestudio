#!/usr/bin/env python3
"""
Demo script showing MalwareAnalyzer capabilities
This creates a simple test file and analyzes it
"""

import os
import sys
import tempfile

# Add src directory to path once
sys.path.insert(0, 'src')

# Create a simple test file (not a real PE file, just for demo)
def create_test_file():
    """Create a test file for demonstration"""
    temp_dir = tempfile.gettempdir()
    test_file = os.path.join(temp_dir, "test_sample.exe")
    
    # Create a minimal DOS stub (MZ header)
    with open(test_file, 'wb') as f:
        # MZ header
        f.write(b'MZ')
        f.write(b'\x90' * 60)
        
        # Add some dummy PE header
        f.write(b'PE\x00\x00')
        f.write(b'\x00' * 100)
    
    return test_file


def demo_pe_validation():
    """Demo: PE File Validation"""
    print("\n" + "="*70)
    print("DEMO 1: PE File Validation")
    print("="*70)
    
    from malanalyzer.validators import PEFileValidator
    
    # Create test file
    test_file = create_test_file()
    print(f"\nCreated test file: {test_file}")
    
    # Validate
    validator = PEFileValidator()
    result = validator.validate(test_file)
    
    print(f"\nValidation Result:")
    print(f"  Valid: {result.is_valid}")
    print(f"  Is PE: {result.is_pe}")
    print(f"  Size: {result.file_size} bytes")
    print(f"  SHA256: {result.file_hash.get('sha256', 'N/A')[:16]}...")
    
    if result.warnings:
        print(f"  Warnings: {len(result.warnings)}")
    if result.errors:
        print(f"  Errors: {len(result.errors)}")
    
    # Cleanup
    os.remove(test_file)


def demo_sandbox_config():
    """Demo: Sandbox Configuration"""
    print("\n" + "="*70)
    print("DEMO 2: Sandbox Configuration")
    print("="*70)
    
    from malanalyzer.sandbox import SandboxManager, SandboxConfig, VMType
    
    config = SandboxConfig(
        vm_type=VMType.VIRTUALBOX,
        vm_name="Windows10_Sandbox",
        snapshot="clean_state",
        timeout=300,
        memory_mb=4096,
        cpu_cores=2,
        network_mode="isolated"
    )
    
    print(f"\nSandbox Configuration:")
    print(f"  VM Type: {config.vm_type.value}")
    print(f"  VM Name: {config.vm_name}")
    print(f"  Snapshot: {config.snapshot}")
    print(f"  Memory: {config.memory_mb} MB")
    print(f"  CPU Cores: {config.cpu_cores}")
    print(f"  Network: {config.network_mode}")
    print(f"  Timeout: {config.timeout} seconds")
    
    # Create manager
    manager = SandboxManager(config)
    vm_info = manager.get_vm_info()
    print(f"\nVM Manager Status: {vm_info['status']}")


def demo_process_monitor():
    """Demo: Process Monitoring"""
    print("\n" + "="*70)
    print("DEMO 3: Process Monitoring")
    print("="*70)
    
    from malanalyzer.monitoring import ProcessMonitor
    import time
    
    monitor = ProcessMonitor()
    
    print(f"\nMonitored Events:")
    for event_type, enabled in monitor.monitored_events.items():
        status = "✓" if enabled else "✗"
        print(f"  {status} {event_type}")
    
    print(f"\nStarting monitoring...")
    monitor.start_monitoring()
    
    # Simulate some monitoring
    time.sleep(1)
    
    # Stop monitoring
    monitor.stop_monitoring()
    
    summary = monitor.get_summary()
    print(f"\nMonitoring Summary:")
    print(f"  Total Events: {summary['total_events']}")
    print(f"  API Calls: {summary['total_api_calls']}")
    print(f"  Process Events: {summary['process_events']}")
    print(f"  File Events: {summary['file_events']}")
    print(f"  Registry Events: {summary['registry_events']}")
    print(f"  Network Events: {summary['network_events']}")


def demo_artifact_collector():
    """Demo: Artifact Collection"""
    print("\n" + "="*70)
    print("DEMO 4: Artifact Collection")
    print("="*70)
    
    from malanalyzer.collectors import ArtifactCollector
    import shutil
    
    # Create collector
    exec_id = "demo_execution_001"
    collector = ArtifactCollector(exec_id)
    
    print(f"\nArtifact Collection:")
    print(f"  Execution ID: {collector.execution_id}")
    print(f"  Artifacts Dir: {collector.artifacts_dir}")
    
    # Check directories created
    print(f"\n  Directories created:")
    print(f"    ✓ {os.path.join(collector.artifacts_dir, 'files')}")
    print(f"    ✓ {os.path.join(collector.artifacts_dir, 'dumps')}")
    print(f"    ✓ {os.path.join(collector.artifacts_dir, 'network')}")
    
    summary = collector.get_summary()
    print(f"\n  Summary:")
    print(f"    Dropped Files: {summary['dropped_files_count']}")
    print(f"    Memory Dumps: {summary['memory_dumps_count']}")
    print(f"    Network Captures: {summary['network_captures_count']}")
    
    # Cleanup
    if os.path.exists("./artifacts"):
        shutil.rmtree("./artifacts")


def demo_virustotal():
    """Demo: VirusTotal Integration"""
    print("\n" + "="*70)
    print("DEMO 5: VirusTotal Integration")
    print("="*70)
    
    from malanalyzer.api import VirusTotalClient
    
    # Create client (with dummy API key for demo)
    client = VirusTotalClient("demo_api_key_12345")
    
    print(f"\nVirusTotal Client:")
    print(f"  Base URL: {client.base_url}")
    print(f"  Rate Limit: {client.rate_limit_delay} seconds")
    
    print(f"\n  Available Methods:")
    print(f"    ✓ submit_file() - Submit file for analysis")
    print(f"    ✓ get_file_report() - Get analysis report")
    print(f"    ✓ search_similar_samples() - Find similar malware")
    print(f"    ✓ wait_for_analysis() - Wait for completion")


def demo_database():
    """Demo: Database Storage"""
    print("\n" + "="*70)
    print("DEMO 6: Database Storage")
    print("="*70)
    
    from malanalyzer.storage import init_database
    
    # Create database in temp directory for cross-platform compatibility
    db_path = os.path.join(tempfile.gettempdir(), "demo_malanalyzer.db")
    if os.path.exists(db_path):
        os.remove(db_path)
    
    db = init_database(db_path)
    
    print(f"\nDatabase Schema:")
    print(f"  ✓ executions - Main execution records")
    print(f"  ✓ process_events - Process activity")
    print(f"  ✓ api_calls - API call records")
    print(f"  ✓ file_operations - File system changes")
    print(f"  ✓ registry_operations - Registry changes")
    print(f"  ✓ network_connections - Network activity")
    
    # Create a sample execution
    exec_id = db.create_execution(
        file_hash="abc123def456",
        file_name="sample.exe",
        sandbox_id="virtualbox_001"
    )
    
    print(f"\nCreated Execution:")
    print(f"  Execution ID: {exec_id}")
    
    # List executions
    executions = db.list_executions()
    print(f"\n  Total Executions: {len(executions)}")
    
    # Cleanup
    if os.path.exists(db_path):
        os.remove(db_path)


def demo_config():
    """Demo: Configuration Management"""
    print("\n" + "="*70)
    print("DEMO 7: Configuration Management")
    print("="*70)
    
    from malanalyzer.config import load_config, create_default_config
    
    print(f"\nDefault Configuration:")
    config = load_config()
    
    print(f"\n  Sandbox:")
    print(f"    Type: {config.sandbox.type}")
    print(f"    VM Name: {config.sandbox.vm_name}")
    print(f"    Snapshot: {config.sandbox.snapshot}")
    
    print(f"\n  Analysis:")
    print(f"    Timeout: {config.analysis.timeout} seconds")
    print(f"    Kill on Timeout: {config.analysis.kill_on_timeout}")
    
    print(f"\n  Monitoring:")
    print(f"    API Hooks: {config.monitoring.api_hooks}")
    print(f"    Network Capture: {config.monitoring.network_capture}")
    
    print(f"\n  Output:")
    print(f"    Directory: {config.output.directory}")
    print(f"    Format: {config.output.format}")


def main():
    """Run all demos"""
    print("\n" + "="*70)
    print(" MalwareAnalyzer Pro - Feature Demonstration")
    print("="*70)
    
    demos = [
        demo_pe_validation,
        demo_sandbox_config,
        demo_process_monitor,
        demo_artifact_collector,
        demo_virustotal,
        demo_database,
        demo_config,
    ]
    
    for demo in demos:
        try:
            demo()
        except Exception as e:
            print(f"\n  Error in demo: {e}")
    
    print("\n" + "="*70)
    print(" Demonstration Complete")
    print("="*70)
    print("\nFor more information, see:")
    print("  - README.md")
    print("  - Spec.md")
    print("  - Spec2.md")
    print("\nTo run analysis:")
    print("  python malanalyzer.py analyze <file_path>")
    print("  python malanalyzer.py --help")
    print()


if __name__ == '__main__':
    main()
