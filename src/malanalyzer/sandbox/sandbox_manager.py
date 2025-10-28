"""Sandbox Manager - Manages sandbox environment for safe PE execution"""

import os
import uuid
from typing import Optional, List
from dataclasses import dataclass, field
from enum import Enum


class VMType(Enum):
    """Supported VM types"""
    VIRTUALBOX = "virtualbox"
    VMWARE = "vmware"
    HYPERV = "hyperv"
    WINDOWS_SANDBOX = "windows_sandbox"


@dataclass
class SandboxConfig:
    """Sandbox configuration"""
    vm_type: VMType
    vm_name: str
    snapshot: str
    timeout: int = 300  # seconds
    memory_mb: int = 4096
    cpu_cores: int = 2
    network_mode: str = "isolated"  # isolated, limited, full
    # Hyper-V specific settings
    use_default_switch: bool = True  # Use Hyper-V Default Switch for network
    enable_guest_services: bool = True  # Enable Guest Services for file transfer
    powershell_direct: bool = True  # Use PowerShell Direct for command execution
    time_sync: bool = True  # Enable time synchronization
    # Child process monitoring
    dump_all_child_processes: bool = True  # Dump memory of all child processes
    memory_dump_type: str = "Full"  # Full, Heap, Mini
    # Network capture
    enable_pcap: bool = True  # Enable network packet capture
    pcap_ring_buffer_mb: int = 500  # PCAP ring buffer size in MB


@dataclass
class Environment:
    """Sandbox environment details"""
    environment_id: str
    vm_type: VMType
    vm_name: str
    snapshot: str
    status: str  # preparing, ready, running, stopped, error
    network_isolated: bool
    monitoring_active: bool
    # Hyper-V specific info
    default_switch_enabled: bool = False
    guest_services_enabled: bool = False
    guest_ip_address: Optional[str] = None
    # Process tracking
    tracked_processes: List[int] = field(default_factory=list)  # PIDs of tracked processes


class SandboxManager:
    """Sandbox Environment Manager"""
    
    def __init__(self, config: SandboxConfig):
        self.config = config
        self.vm_type = config.vm_type
        self.vm_name = config.vm_name
        self.snapshot_name = config.snapshot
        self.timeout = config.timeout
        self.current_environment: Optional[Environment] = None
        
    def prepare_environment(self) -> Environment:
        """
        Prepare sandbox environment
        
        Steps:
        - Restore VM snapshot
        - Configure network (Default Switch for Hyper-V)
        - Deploy monitoring agent
        - Enable Guest Services (for Hyper-V)
        - Synchronize time
        """
        env_id = str(uuid.uuid4())
        
        print(f"[SandboxManager] Preparing environment {env_id}")
        print(f"[SandboxManager] VM Type: {self.vm_type.value}")
        print(f"[SandboxManager] VM Name: {self.vm_name}")
        print(f"[SandboxManager] Snapshot: {self.snapshot_name}")
        
        # Hyper-V specific configuration
        default_switch = False
        guest_services = False
        guest_ip = None
        
        if self.vm_type == VMType.HYPERV:
            print("[SandboxManager] Configuring Hyper-V specific settings")
            
            if self.config.use_default_switch:
                print("[SandboxManager] Using Hyper-V Default Switch for network connectivity")
                default_switch = True
                # In a real implementation:
                # - Configure VM to use "Default Switch"
                # - This provides NAT-based internet access
                # - Guest can reach internet for C2 communication testing
            
            if self.config.enable_guest_services:
                print("[SandboxManager] Enabling Hyper-V Guest Services")
                guest_services = True
                # In a real implementation:
                # - Enable-VMIntegrationService -VMName $vm_name -Name "Guest Service Interface"
                # - This allows file transfer via Copy-VMFile
            
            if self.config.powershell_direct:
                print("[SandboxManager] PowerShell Direct enabled for command execution")
                # In a real implementation:
                # - Use Invoke-Command -VMName $vm_name -ScriptBlock { ... }
                # - No network required, works through VM bus
            
            if self.config.time_sync:
                print("[SandboxManager] Time synchronization enabled")
                # In a real implementation:
                # - Enable-VMIntegrationService -VMName $vm_name -Name "Time Synchronization"
        
        # In a real implementation, this would:
        # 1. Restore VM from snapshot: Restore-VMCheckpoint -Name $snapshot -VMName $vm_name
        # 2. Start VM: Start-VM -Name $vm_name
        # 3. Wait for VM to be ready
        # 4. Get guest IP: Get-VMNetworkAdapter -VMName $vm_name | Select -ExpandProperty IPAddresses
        # 5. Configure network isolation/connectivity
        # 6. Deploy monitoring agent via Copy-VMFile
        # 7. Start agent via Invoke-Command
        # 8. Verify environment is ready
        
        environment = Environment(
            environment_id=env_id,
            vm_type=self.vm_type,
            vm_name=self.vm_name,
            snapshot=self.snapshot_name,
            status="ready",
            network_isolated=self.config.network_mode == "isolated",
            monitoring_active=True,
            default_switch_enabled=default_switch,
            guest_services_enabled=guest_services,
            guest_ip_address=guest_ip,
            tracked_processes=[]
        )
        
        self.current_environment = environment
        print(f"[SandboxManager] Environment {env_id} is ready")
        
        return environment
    
    def deploy_sample(self, file_path: str) -> bool:
        """
        Deploy sample to sandbox
        
        Steps:
        - Transfer file to VM (using Guest Services for Hyper-V)
        - Set execution permissions
        - Configure execution trigger
        """
        if not self.current_environment:
            print("[SandboxManager] Error: No environment prepared")
            return False
        
        if not os.path.exists(file_path):
            print(f"[SandboxManager] Error: File not found: {file_path}")
            return False
        
        print(f"[SandboxManager] Deploying sample: {file_path}")
        
        # In a real implementation for Hyper-V with Guest Services:
        # 1. Use PowerShell Copy-VMFile cmdlet:
        #    Copy-VMFile -VMName $vm_name -SourcePath $file_path 
        #                -DestinationPath "C:\Samples\sample.exe" 
        #                -FileSource Host
        # 2. This works without network, directly via VM bus
        # 3. Much faster than network-based transfer
        
        # For other hypervisors:
        # 1. Copy file to VM (using VM tools, shared folder, or network)
        # 2. Set appropriate permissions
        # 3. Prepare execution environment
        
        print(f"[SandboxManager] Sample deployed successfully")
        return True
    
    def execute_command(self, command: str, args: Optional[str] = None) -> dict:
        """
        Execute command in the sandbox using PowerShell Direct (Hyper-V)
        
        Returns execution result with stdout, stderr, exit code
        """
        if not self.current_environment:
            print("[SandboxManager] Error: No environment prepared")
            return {"success": False, "error": "No environment prepared"}
        
        print(f"[SandboxManager] Executing command: {command}")
        if args:
            print(f"[SandboxManager] Arguments: {args}")
        
        # In a real implementation for Hyper-V with PowerShell Direct:
        # $result = Invoke-Command -VMName $vm_name -ScriptBlock {
        #     param($cmd, $args)
        #     & $cmd $args
        # } -ArgumentList $command, $args
        
        # For other hypervisors, use appropriate remote execution method
        
        return {
            "success": True,
            "stdout": "",
            "stderr": "",
            "exit_code": 0
        }
    
    def track_process(self, pid: int) -> bool:
        """Add process to tracking list for child process monitoring"""
        if not self.current_environment:
            return False
        
        if pid not in self.current_environment.tracked_processes:
            self.current_environment.tracked_processes.append(pid)
            print(f"[SandboxManager] Tracking process: {pid}")
        
        return True
    
    def get_tracked_processes(self) -> List[int]:
        """Get list of tracked process IDs"""
        if not self.current_environment:
            return []
        
        return self.current_environment.tracked_processes
    
    def start_execution(self, file_path: str, args: Optional[str] = None) -> bool:
        """Start sample execution in sandbox"""
        if not self.current_environment:
            print("[SandboxManager] Error: No environment prepared")
            return False
        
        print(f"[SandboxManager] Starting execution: {file_path}")
        if args:
            print(f"[SandboxManager] Arguments: {args}")
        
        # In a real implementation, this would execute the sample in the VM
        self.current_environment.status = "running"
        
        return True
    
    def stop_environment(self) -> bool:
        """Stop and cleanup sandbox environment"""
        if not self.current_environment:
            return True
        
        print(f"[SandboxManager] Stopping environment {self.current_environment.environment_id}")
        
        # In a real implementation, this would:
        # 1. Stop any running processes
        # 2. Collect artifacts
        # 3. Stop VM
        # 4. Restore snapshot (cleanup)
        
        self.current_environment.status = "stopped"
        print(f"[SandboxManager] Environment stopped")
        
        return True
    
    def restore_snapshot(self) -> bool:
        """Restore VM to clean snapshot state"""
        print(f"[SandboxManager] Restoring snapshot: {self.snapshot_name}")
        
        # In a real implementation, this would restore the VM snapshot
        # using the appropriate hypervisor API
        
        return True
    
    def get_vm_info(self) -> dict:
        """Get current VM information"""
        if not self.current_environment:
            return {"status": "no_environment"}
        
        return {
            "environment_id": self.current_environment.environment_id,
            "vm_type": self.current_environment.vm_type.value,
            "vm_name": self.current_environment.vm_name,
            "snapshot": self.current_environment.snapshot,
            "status": self.current_environment.status,
            "network_isolated": self.current_environment.network_isolated,
            "monitoring_active": self.current_environment.monitoring_active,
            "default_switch_enabled": self.current_environment.default_switch_enabled,
            "guest_services_enabled": self.current_environment.guest_services_enabled,
            "guest_ip_address": self.current_environment.guest_ip_address,
            "tracked_processes": self.current_environment.tracked_processes
        }
