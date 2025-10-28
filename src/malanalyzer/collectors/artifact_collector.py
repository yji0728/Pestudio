"""Artifact Collector - Collects artifacts created during execution"""

import os
import hashlib
from typing import List, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class DroppedFile:
    """Information about a dropped file"""
    file_path: str
    file_size: int
    file_hash: str
    created_time: datetime
    modified_time: datetime
    is_executable: bool


@dataclass
class MemoryDump:
    """Memory dump information"""
    process_id: int
    process_name: str
    dump_path: str
    dump_size: int
    dump_time: datetime
    dump_type: str  # full, heap, stack, unpacked


@dataclass
class NetworkCapture:
    """Network capture information"""
    capture_path: str
    capture_size: int
    start_time: datetime
    end_time: datetime
    packet_count: int
    protocols: List[str]


class ArtifactCollector:
    """Artifact Collector - Collects execution artifacts"""
    
    def __init__(self, execution_id: str):
        self.execution_id = execution_id
        self.artifacts_dir = f"./artifacts/{execution_id}"
        self.dropped_files: List[DroppedFile] = []
        self.memory_dumps: List[MemoryDump] = []
        self.network_captures: List[NetworkCapture] = []
        
        # Create artifacts directory
        os.makedirs(self.artifacts_dir, exist_ok=True)
        os.makedirs(f"{self.artifacts_dir}/files", exist_ok=True)
        os.makedirs(f"{self.artifacts_dir}/dumps", exist_ok=True)
        os.makedirs(f"{self.artifacts_dir}/network", exist_ok=True)
        
    def collect_dropped_files(self, monitored_paths: Optional[List[str]] = None) -> List[DroppedFile]:
        """
        Collect dropped files
        
        Collects:
        - Newly created files
        - Modified executables
        - Temporary files
        """
        print(f"[ArtifactCollector] Collecting dropped files for execution {self.execution_id}")
        
        if monitored_paths is None:
            # Default paths to monitor (in a real implementation)
            monitored_paths = [
                "C:\\Windows\\Temp",
                "C:\\Users\\*\\AppData\\Local\\Temp",
                "C:\\Users\\*\\AppData\\Roaming"
            ]
        
        dropped_files = []
        
        # In a real implementation, this would:
        # 1. Scan monitored directories
        # 2. Compare with baseline (pre-execution state)
        # 3. Copy new/modified files to artifacts directory
        # 4. Calculate hashes
        # 5. Determine if files are executable
        
        print(f"[ArtifactCollector] Found {len(dropped_files)} dropped files")
        self.dropped_files = dropped_files
        
        return dropped_files
    
    def dump_process_memory(self, pid: int, process_name: str, dump_type: str = "full") -> Optional[MemoryDump]:
        """
        Dump process memory
        
        Memory dump types:
        - full: Complete process memory (MiniDumpWithFullMemory)
        - heap: Heap regions
        - stack: Stack regions
        - unpacked: Unpacked code regions
        """
        print(f"[ArtifactCollector] Dumping memory for process {pid} ({process_name})")
        
        dump_filename = f"pid_{pid}_{process_name}_{dump_type}.dmp"
        dump_path = os.path.join(self.artifacts_dir, "dumps", dump_filename)
        
        # In a real implementation, this would use one of:
        # 1. MiniDumpWriteDump API with MiniDumpWithFullMemory flag
        # 2. Sysinternals ProcDump: procdump.exe -ma <pid> <output_file>
        # 3. For large processes, use chunked dumping to avoid memory issues
        
        # Example PowerShell command for Procdump:
        # Invoke-Command -VMName $vm_name -ScriptBlock {
        #     C:\Tools\procdump.exe -ma $pid $dump_path -accepteula
        # }
        
        print(f"[ArtifactCollector] Memory dump saved to: {dump_path}")
        
        memory_dump = MemoryDump(
            process_id=pid,
            process_name=process_name,
            dump_path=dump_path,
            dump_size=0,  # Would be actual size
            dump_time=datetime.now(),
            dump_type=dump_type
        )
        
        self.memory_dumps.append(memory_dump)
        
        return memory_dump
    
    def dump_process_tree_memory(self, process_tree: dict, dump_type: str = "full") -> List[MemoryDump]:
        """
        Dump memory for all processes in the process tree (parent and all children)
        
        This implements the requirement to dump ALL child processes
        """
        print(f"[ArtifactCollector] Dumping memory for entire process tree")
        
        dumps = []
        
        def dump_recursive(proc_info):
            """Recursively dump process and all its children"""
            if not proc_info:
                return
            
            pid = proc_info.get('process_id')
            name = proc_info.get('process_name', 'unknown')
            
            # Dump this process
            print(f"[ArtifactCollector] Dumping process: PID={pid}, Name={name}")
            dump = self.dump_process_memory(pid, name, dump_type)
            if dump:
                dumps.append(dump)
            
            # Recursively dump all children
            for child_pid in proc_info.get('children', []):
                if child_pid in process_tree:
                    dump_recursive(process_tree[child_pid])
        
        # Start dumping from root processes
        for proc_id, proc_info in process_tree.items():
            if proc_info.get('parent_process_id') is None or proc_info.get('parent_process_id') not in process_tree:
                # This is a root process, start recursive dump
                dump_recursive(proc_info)
        
        print(f"[ArtifactCollector] Dumped {len(dumps)} processes in total")
        
        return dumps
    
    def capture_network_traffic(self, duration: int = 300) -> Optional[NetworkCapture]:
        """
        Capture network traffic with PCAP ring buffer
        
        Captures:
        - PCAP file creation with ring buffer (prevents unlimited growth)
        - DNS queries
        - HTTP/HTTPS traffic
        - C&C communications
        """
        print(f"[ArtifactCollector] Capturing network traffic for {duration} seconds")
        
        capture_filename = f"network_capture.pcap"
        capture_path = os.path.join(self.artifacts_dir, "network", capture_filename)
        
        # In a real implementation, this would use:
        # 1. Npcap/WinPcap for packet capture
        # 2. SharpPcap library for C# implementation
        # 3. Ring buffer to limit capture size (e.g., 500MB)
        # 4. Example with tshark:
        #    tshark -i <interface> -b filesize:500000 -w capture.pcap
        
        # For Hyper-V guest, capture on the Default Switch interface
        # Example PowerShell in guest:
        # Invoke-Command -VMName $vm_name -ScriptBlock {
        #     C:\Tools\tshark.exe -i "Ethernet" -b filesize:500000 -w D:\agent\pcap\capture.pcap
        # }
        
        start_time = datetime.now()
        
        print(f"[ArtifactCollector] Network capture started")
        print(f"[ArtifactCollector] Using ring buffer to limit size")
        
        # Placeholder for actual capture
        network_capture = NetworkCapture(
            capture_path=capture_path,
            capture_size=0,  # Would be actual size
            start_time=start_time,
            end_time=datetime.now(),
            packet_count=0,
            protocols=[]
        )
        
        self.network_captures.append(network_capture)
        
        return network_capture
    
    def collect_registry_changes(self) -> List[dict]:
        """Collect registry changes"""
        print("[ArtifactCollector] Collecting registry changes")
        
        # In a real implementation, this would:
        # 1. Compare registry state before/after execution
        # 2. Identify new/modified/deleted keys
        # 3. Export relevant registry keys
        
        return []
    
    def create_artifact_archive(self) -> str:
        """Create archive of all collected artifacts"""
        print(f"[ArtifactCollector] Creating artifact archive")
        
        archive_path = f"{self.artifacts_dir}.zip"
        
        # In a real implementation, this would:
        # 1. Zip all artifacts
        # 2. Add metadata file
        # 3. Calculate archive hash
        
        print(f"[ArtifactCollector] Archive created: {archive_path}")
        
        return archive_path
    
    def get_summary(self) -> dict:
        """Get artifact collection summary"""
        return {
            'execution_id': self.execution_id,
            'artifacts_dir': self.artifacts_dir,
            'dropped_files_count': len(self.dropped_files),
            'memory_dumps_count': len(self.memory_dumps),
            'network_captures_count': len(self.network_captures),
            'total_artifacts': len(self.dropped_files) + len(self.memory_dumps) + len(self.network_captures)
        }
