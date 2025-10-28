"""Process Monitor - Monitors process behavior during execution"""

from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime
import uuid


@dataclass
class APICall:
    """API Call information"""
    call_id: str
    timestamp: datetime
    process_id: int
    thread_id: int
    api_name: str
    module_name: str
    parameters: Dict[str, any]
    return_value: Optional[str] = None


class ProcessMonitor:
    """Process Behavior Monitoring"""
    
    def __init__(self):
        self.monitored_events = {
            'process_creation': True,
            'process_termination': True,
            'thread_creation': True,
            'image_load': True,
            'registry_access': True,
            'file_system': True,
            'network': True
        }
        self.is_monitoring = False
        self.captured_events: List[Dict] = []
        self.captured_api_calls: List[APICall] = []
        
    def start_monitoring(self) -> None:
        """
        Start monitoring
        
        In a real implementation, this would:
        - Start ETW (Event Tracing for Windows) session
        - Subscribe to WMI events
        - Set up API hooks
        """
        print("[ProcessMonitor] Starting monitoring session")
        self.is_monitoring = True
        self.captured_events = []
        self.captured_api_calls = []
        
        # Start ETW session
        print("[ProcessMonitor] Starting ETW session")
        
        # Subscribe to WMI events
        print("[ProcessMonitor] Subscribing to WMI events")
        
        print("[ProcessMonitor] Monitoring active")
    
    def stop_monitoring(self) -> None:
        """Stop monitoring and finalize data collection"""
        print("[ProcessMonitor] Stopping monitoring session")
        self.is_monitoring = False
        
        # Stop ETW session
        print("[ProcessMonitor] Stopping ETW session")
        
        # Unsubscribe from WMI events
        print("[ProcessMonitor] Unsubscribing from WMI events")
        
        print(f"[ProcessMonitor] Captured {len(self.captured_events)} events")
        print(f"[ProcessMonitor] Captured {len(self.captured_api_calls)} API calls")
    
    def capture_api_calls(self) -> List[APICall]:
        """
        Capture API calls
        
        Monitored APIs:
        - Kernel32.dll (file operations, process management)
        - Ntdll.dll (low-level system calls)
        - Advapi32.dll (registry, security)
        - User32.dll (UI operations)
        - Ws2_32.dll (network operations)
        """
        return self.captured_api_calls
    
    def capture_process_event(self, event_type: str, data: Dict) -> None:
        """Capture a process event"""
        if not self.is_monitoring:
            return
        
        event = {
            'event_id': str(uuid.uuid4()),
            'timestamp': datetime.now(),
            'event_type': event_type,
            'data': data
        }
        self.captured_events.append(event)
    
    def capture_api_call(
        self, 
        process_id: int, 
        thread_id: int,
        api_name: str,
        module_name: str,
        parameters: Dict[str, any],
        return_value: Optional[str] = None
    ) -> None:
        """Capture an API call"""
        if not self.is_monitoring:
            return
        
        api_call = APICall(
            call_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            process_id=process_id,
            thread_id=thread_id,
            api_name=api_name,
            module_name=module_name,
            parameters=parameters,
            return_value=return_value
        )
        self.captured_api_calls.append(api_call)
    
    def get_process_tree(self) -> Dict:
        """Build process tree from captured events"""
        process_tree = {}
        
        for event in self.captured_events:
            if event['event_type'] == 'process_creation':
                data = event['data']
                pid = data.get('process_id')
                parent_pid = data.get('parent_process_id')
                
                if pid not in process_tree:
                    process_tree[pid] = {
                        'process_id': pid,
                        'parent_process_id': parent_pid,
                        'process_name': data.get('process_name'),
                        'command_line': data.get('command_line'),
                        'start_time': event['timestamp'],
                        'children': []
                    }
                
                if parent_pid and parent_pid in process_tree:
                    process_tree[parent_pid]['children'].append(pid)
        
        return process_tree
    
    def get_file_operations(self) -> List[Dict]:
        """Get all file system operations"""
        return [
            event for event in self.captured_events
            if event['event_type'] in ['file_create', 'file_write', 'file_delete', 'file_read']
        ]
    
    def get_registry_operations(self) -> List[Dict]:
        """Get all registry operations"""
        return [
            event for event in self.captured_events
            if event['event_type'] in ['registry_create', 'registry_set', 'registry_delete', 'registry_query']
        ]
    
    def get_network_connections(self) -> List[Dict]:
        """Get all network connections"""
        return [
            event for event in self.captured_events
            if event['event_type'] in ['network_connect', 'network_send', 'network_receive']
        ]
    
    def get_summary(self) -> Dict:
        """Get monitoring summary"""
        return {
            'total_events': len(self.captured_events),
            'total_api_calls': len(self.captured_api_calls),
            'process_events': len([e for e in self.captured_events if 'process' in e['event_type']]),
            'file_events': len(self.get_file_operations()),
            'registry_events': len(self.get_registry_operations()),
            'network_events': len(self.get_network_connections()),
            'is_monitoring': self.is_monitoring
        }
