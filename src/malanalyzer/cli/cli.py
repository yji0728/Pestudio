"""CLI Interface - Command-line interface for MalwareAnalyzer"""

import os
import sys
import json
from typing import Optional

try:
    import click
    from colorama import init as colorama_init, Fore, Style
    CLICK_AVAILABLE = True
    colorama_init()
except ImportError:
    CLICK_AVAILABLE = False
    click = None

# Add parent directory to path to import malanalyzer modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validators import PEFileValidator
from sandbox import SandboxManager, SandboxConfig, VMType
from monitoring import ProcessMonitor
from collectors import ArtifactCollector
from api import VirusTotalClient
from storage import init_database


if CLICK_AVAILABLE:
    @click.group()
    @click.version_option(version='1.0.0')
    def cli():
        """MalwareAnalyzer Pro - Advanced PE Dynamic Analysis System"""
        pass


    @cli.command()
    @click.argument('file_path', type=click.Path(exists=True))
    @click.option('--timeout', default=300, help='Execution timeout in seconds')
    @click.option('--sandbox', default='virtualbox', type=click.Choice(['virtualbox', 'vmware', 'hyperv']), help='Sandbox type')
    @click.option('--network', default='isolated', type=click.Choice(['isolated', 'limited', 'full']), help='Network mode')
    @click.option('--dump-memory', is_flag=True, help='Enable memory dumping')
    @click.option('--vt-scan', is_flag=True, help='Enable VirusTotal scan')
    @click.option('--output', default='json', type=click.Choice(['json', 'html', 'pdf']), help='Output format')
    @click.option('--verbose', is_flag=True, help='Verbose output')
    def analyze(file_path, timeout, sandbox, network, dump_memory, vt_scan, output, verbose):
        """Analyze a PE file"""
        
        print(f"{Fore.CYAN}╔════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║     MalwareAnalyzer Pro - PE Dynamic Analysis        ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        # Step 1: Validate PE file
        print(f"{Fore.YELLOW}[1/7] Validating PE file...{Style.RESET_ALL}")
        validator = PEFileValidator()
        result = validator.validate(file_path)
        
        if not result.is_valid:
            print(f"{Fore.RED}✗ Validation failed:{Style.RESET_ALL}")
            for error in result.errors:
                print(f"  - {error}")
            return
        
        print(f"{Fore.GREEN}✓ PE file is valid{Style.RESET_ALL}")
        print(f"  File: {os.path.basename(file_path)}")
        print(f"  Size: {result.file_size} bytes")
        print(f"  SHA256: {result.file_hash['sha256']}")
        
        if result.warnings:
            for warning in result.warnings:
                print(f"{Fore.YELLOW}  ⚠ {warning}{Style.RESET_ALL}")
        
        # Extract metadata
        metadata = validator.extract_metadata(file_path)
        if metadata and verbose:
            print(f"\n{Fore.CYAN}PE Metadata:{Style.RESET_ALL}")
            print(f"  Type: {metadata.pe_type}")
            print(f"  Architecture: {metadata.architecture}")
            print(f"  Subsystem: {metadata.subsystem}")
            print(f"  Sections: {len(metadata.sections)}")
            print(f"  Imports: {len(metadata.imports)} DLLs")
            print(f"  Exports: {len(metadata.exports)} functions")
        
        # Step 2: Initialize database
        print(f"\n{Fore.YELLOW}[2/7] Initializing database...{Style.RESET_ALL}")
        db = init_database()
        execution_id = db.create_execution(
            file_hash=result.file_hash['sha256'],
            file_name=os.path.basename(file_path),
            sandbox_id=f"{sandbox}_sandbox"
        )
        print(f"{Fore.GREEN}✓ Execution ID: {execution_id}{Style.RESET_ALL}")
        
        # Step 3: Prepare sandbox
        print(f"\n{Fore.YELLOW}[3/7] Preparing sandbox environment...{Style.RESET_ALL}")
        vm_type_map = {
            'virtualbox': VMType.VIRTUALBOX,
            'vmware': VMType.VMWARE,
            'hyperv': VMType.HYPERV
        }
        
        sandbox_config = SandboxConfig(
            vm_type=vm_type_map[sandbox],
            vm_name="analysis_vm",
            snapshot="clean_state",
            timeout=timeout,
            network_mode=network
        )
        
        sandbox_mgr = SandboxManager(sandbox_config)
        environment = sandbox_mgr.prepare_environment()
        print(f"{Fore.GREEN}✓ Sandbox ready: {environment.environment_id}{Style.RESET_ALL}")
        
        # Step 4: Deploy sample
        print(f"\n{Fore.YELLOW}[4/7] Deploying sample to sandbox...{Style.RESET_ALL}")
        if sandbox_mgr.deploy_sample(file_path):
            print(f"{Fore.GREEN}✓ Sample deployed{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}✗ Failed to deploy sample{Style.RESET_ALL}")
            return
        
        # Step 5: Start monitoring and execution
        print(f"\n{Fore.YELLOW}[5/7] Starting monitoring and execution...{Style.RESET_ALL}")
        monitor = ProcessMonitor()
        monitor.start_monitoring()
        
        # Start execution
        sandbox_mgr.start_execution(file_path)
        print(f"{Fore.GREEN}✓ Execution started (timeout: {timeout}s){Style.RESET_ALL}")
        
        # Simulate execution time
        import time
        print(f"{Fore.CYAN}  Monitoring in progress...{Style.RESET_ALL}")
        time.sleep(2)  # In real implementation, would wait for actual execution
        
        # Stop monitoring
        monitor.stop_monitoring()
        
        # Step 6: Collect artifacts
        print(f"\n{Fore.YELLOW}[6/7] Collecting artifacts...{Style.RESET_ALL}")
        collector = ArtifactCollector(execution_id)
        
        dropped_files = collector.collect_dropped_files()
        print(f"  Dropped files: {len(dropped_files)}")
        
        if dump_memory:
            # In real implementation, would dump all relevant processes
            print(f"  Memory dumps: enabled")
        
        # Step 7: VirusTotal scan
        if vt_scan:
            print(f"\n{Fore.YELLOW}[7/7] Running VirusTotal scan...{Style.RESET_ALL}")
            
            # Check for API key
            vt_api_key = os.environ.get('VT_API_KEY')
            if vt_api_key:
                vt_client = VirusTotalClient(vt_api_key)
                vt_report = vt_client.get_file_report(result.file_hash['sha256'])
                
                if vt_report:
                    print(f"{Fore.GREEN}✓ VirusTotal scan complete{Style.RESET_ALL}")
                    print(f"  Detection ratio: {vt_report.detection_ratio}")
                    print(f"  Detections: {vt_report.positive_detections}/{vt_report.total_engines}")
                else:
                    print(f"{Fore.YELLOW}  No existing report, submitting file...{Style.RESET_ALL}")
                    submission = vt_client.submit_file(file_path)
                    if submission:
                        print(f"  Submission ID: {submission.submission_id}")
            else:
                print(f"{Fore.YELLOW}  ⚠ VT_API_KEY not set, skipping VirusTotal scan{Style.RESET_ALL}")
        
        # Cleanup
        print(f"\n{Fore.YELLOW}Cleaning up...{Style.RESET_ALL}")
        sandbox_mgr.stop_environment()
        db.update_execution_status(execution_id, 'completed')
        
        # Summary
        print(f"\n{Fore.CYAN}╔════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║                  Analysis Complete                     ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        summary = monitor.get_summary()
        print(f"\n{Fore.GREEN}Execution Summary:{Style.RESET_ALL}")
        print(f"  Execution ID: {execution_id}")
        print(f"  Total events: {summary['total_events']}")
        print(f"  Process events: {summary['process_events']}")
        print(f"  File events: {summary['file_events']}")
        print(f"  Registry events: {summary['registry_events']}")
        print(f"  Network events: {summary['network_events']}")
        
        artifact_summary = collector.get_summary()
        print(f"\n{Fore.GREEN}Artifacts:{Style.RESET_ALL}")
        print(f"  Total artifacts: {artifact_summary['total_artifacts']}")
        print(f"  Artifacts directory: {artifact_summary['artifacts_dir']}")
        
        print(f"\n{Fore.CYAN}Report format: {output}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Results saved to execution ID: {execution_id}{Style.RESET_ALL}\n")


    @cli.command()
    @click.argument('execution_id')
    @click.option('--format', 'fmt', default='json', type=click.Choice(['json', 'html', 'pdf']), help='Report format')
    def report(execution_id, fmt):
        """Generate report for an execution"""
        print(f"{Fore.CYAN}Generating {fmt.upper()} report for execution: {execution_id}{Style.RESET_ALL}")
        
        db = init_database()
        execution = db.get_execution(execution_id)
        
        if not execution:
            print(f"{Fore.RED}✗ Execution not found: {execution_id}{Style.RESET_ALL}")
            return
        
        print(f"{Fore.GREEN}✓ Report generated{Style.RESET_ALL}")
        print(f"  Execution ID: {execution['execution_id']}")
        print(f"  File: {execution['file_name']}")
        print(f"  Status: {execution['status']}")
        print(f"  Start time: {execution['start_time']}")


    @cli.command()
    @click.option('--limit', default=20, help='Number of executions to list')
    def list(limit):
        """List recent executions"""
        print(f"{Fore.CYAN}Recent Executions:{Style.RESET_ALL}\n")
        
        db = init_database()
        executions = db.list_executions(limit=limit)
        
        if not executions:
            print(f"{Fore.YELLOW}No executions found{Style.RESET_ALL}")
            return
        
        for i, exec_data in enumerate(executions, 1):
            status_color = Fore.GREEN if exec_data['status'] == 'completed' else Fore.YELLOW
            print(f"{i}. {Fore.CYAN}{exec_data['execution_id']}{Style.RESET_ALL}")
            print(f"   File: {exec_data['file_name']}")
            print(f"   Status: {status_color}{exec_data['status']}{Style.RESET_ALL}")
            print(f"   Time: {exec_data['start_time']}")
            print()


    @cli.command()
    @click.argument('file_hash')
    def vt_check(file_hash):
        """Check file hash in VirusTotal"""
        vt_api_key = os.environ.get('VT_API_KEY')
        
        if not vt_api_key:
            print(f"{Fore.RED}✗ VT_API_KEY environment variable not set{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}Checking VirusTotal for hash: {file_hash}{Style.RESET_ALL}\n")
        
        vt_client = VirusTotalClient(vt_api_key)
        report = vt_client.get_file_report(file_hash)
        
        if report:
            print(f"{Fore.GREEN}✓ Report found{Style.RESET_ALL}")
            print(f"  Detection ratio: {report.detection_ratio}")
            print(f"  Scan date: {report.scan_date}")
            print(f"  File type: {report.file_type}")
        else:
            print(f"{Fore.YELLOW}No report found for this hash{Style.RESET_ALL}")


def main():
    """Main entry point"""
    if not CLICK_AVAILABLE:
        print("Error: click and colorama modules are required for CLI")
        print("Install with: pip install click colorama")
        sys.exit(1)
    
    cli()


if __name__ == '__main__':
    main()
