# Procmon Integration Guide

## Overview

This document describes the integration of Sysinternals Process Monitor (Procmon) for comprehensive behavior monitoring as specified in add spec3.md and add spec4.md.

## Procmon Overview

Process Monitor (Procmon) is a Sysinternals tool that monitors:
- File system activity
- Registry operations
- Process and thread activity
- Network activity (basic)
- Profiling events

## Integration Architecture

### Workflow

```
Host                    Guest VM (Hyper-V)
─────                   ──────────────────
1. Deploy Procmon  →    Copy via Copy-VMFile
2. Deploy config   →    profile.pmc file
3. Start capture   →    Invoke-Command: Procmon.exe /BackingFile ...
                        
                        [Sample Execution]
                        [Event Capture]
                        
4. Stop capture    →    Invoke-Command: Stop procmon
5. Retrieve PML    ←    Copy-VMFile (PML file)
6. Convert PML     →    Procmon /OpenLog ... /SaveAs CSV
7. Parse CSV       →    Import to database
8. Generate report →    Analysis and visualization
```

## Configuration

### Procmon Profile (profile.pmc)

Create a Procmon configuration file to:
- Enable specific event types
- Exclude noisy system paths
- Optimize performance

**Creating a profile:**
1. Run Procmon GUI
2. Configure filters (Filter → Filter...)
3. Configure capture options
4. Save profile: File → Save Configuration

**Example filters to reduce noise:**

```
Process Name is not System        Include
Process Name is not svchost.exe   Include
Path begins with C:\Windows\      Exclude
Path begins with C:\Program Files\ Exclude
```

### Procmon Command Line Options

#### Starting Capture

```powershell
# Start Procmon with backing file
C:\Tools\Procmon\Procmon64.exe `
    /AcceptEula `
    /Quiet `
    /Minimized `
    /BackingFile D:\agent\logs\trace.pml `
    /LoadConfig C:\Tools\Procmon\profile.pmc
```

**Options:**
- `/AcceptEula`: Accept license automatically
- `/Quiet`: No splash screen
- `/Minimized`: Start minimized
- `/BackingFile <path>`: Save to PML file
- `/LoadConfig <path>`: Load filter configuration

#### Stopping Capture

```powershell
# Terminate Procmon
C:\Tools\Procmon\Procmon64.exe /Terminate
```

#### Converting PML to CSV

```powershell
# Convert PML to CSV (offline)
C:\Tools\Procmon\Procmon64.exe `
    /OpenLog D:\agent\logs\trace.pml `
    /SaveAs D:\agent\logs\trace.csv
```

## PowerShell Direct Integration

### Deployment Script

```powershell
# Deploy Procmon to guest VM
$vmName = "Win11_Analysis"
$procmonHost = "C:\Tools\Procmon\Procmon64.exe"
$procmonGuest = "C:\Tools\Procmon\"
$configHost = "C:\Tools\Procmon\profile.pmc"

# Copy Procmon executable
Copy-VMFile -VMName $vmName `
            -SourcePath $procmonHost `
            -DestinationPath $procmonGuest `
            -FileSource Host `
            -Force

# Copy configuration
Copy-VMFile -VMName $vmName `
            -SourcePath $configHost `
            -DestinationPath "C:\Tools\Procmon\profile.pmc" `
            -FileSource Host `
            -Force
```

### Starting Capture via PowerShell Direct

```powershell
# Start Procmon capture in guest
Invoke-Command -VMName $vmName -ScriptBlock {
    # Create output directory
    New-Item -Path "D:\agent\logs" -ItemType Directory -Force | Out-Null
    
    # Start Procmon
    Start-Process -FilePath "C:\Tools\Procmon\Procmon64.exe" `
                  -ArgumentList "/AcceptEula", `
                               "/Quiet", `
                               "/Minimized", `
                               "/BackingFile", "D:\agent\logs\trace.pml", `
                               "/LoadConfig", "C:\Tools\Procmon\profile.pmc" `
                  -NoNewWindow
    
    # Wait for Procmon to initialize
    Start-Sleep -Seconds 2
    
    Write-Output "Procmon capture started"
}
```

### Stopping Capture

```powershell
# Stop Procmon in guest
Invoke-Command -VMName $vmName -ScriptBlock {
    # Terminate Procmon
    & "C:\Tools\Procmon\Procmon64.exe" /Terminate
    
    Write-Output "Procmon capture stopped"
}
```

### Retrieving PML File

```powershell
# Copy PML file back to host
Copy-VMFile -VMName $vmName `
            -SourcePath "D:\agent\logs\trace.pml" `
            -DestinationPath "C:\MalwareAnalyzer\Results\$executionId\" `
            -FileSource Guest
```

## PML File Processing

### Converting to CSV

```python
import subprocess
import os

def convert_pml_to_csv(pml_path, csv_path, procmon_exe):
    """
    Convert PML file to CSV format
    
    Args:
        pml_path: Path to PML file
        csv_path: Output CSV path
        procmon_exe: Path to Procmon executable
    """
    cmd = [
        procmon_exe,
        '/OpenLog', pml_path,
        '/SaveAs', csv_path
    ]
    
    subprocess.run(cmd, check=True)
    
    return csv_path
```

### CSV Format

Procmon CSV columns:
- Time of Day
- Process Name
- PID
- Operation
- Path
- Result
- Detail

**Example CSV:**
```csv
"Time of Day","Process Name","PID","Operation","Path","Result","Detail"
"10:30:15.1234567 AM","sample.exe","1234","CreateFile","C:\Temp\dropped.exe","SUCCESS","Desired Access: Generic Write"
"10:30:15.2345678 AM","sample.exe","1234","RegSetValue","HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Malware","SUCCESS","Type: REG_SZ, Length: 48"
```

## Parsing and Database Import

### CSV Parser

```python
import csv
from datetime import datetime

class ProcmonParser:
    """Parse Procmon CSV file"""
    
    def parse_csv(self, csv_path):
        """
        Parse Procmon CSV into structured events
        
        Returns list of event dictionaries
        """
        events = []
        
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                event = {
                    'timestamp': self._parse_timestamp(row['Time of Day']),
                    'process_name': row['Process Name'],
                    'pid': int(row['PID']),
                    'operation': row['Operation'],
                    'path': row['Path'],
                    'result': row['Result'],
                    'detail': row['Detail']
                }
                
                events.append(event)
        
        return events
    
    def _parse_timestamp(self, time_str):
        """Parse Procmon timestamp"""
        # Format: "10:30:15.1234567 AM"
        dt = datetime.strptime(time_str, "%I:%M:%S.%f %p")
        return dt
```

### Bulk Database Import

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

def bulk_import_events(events, db_connection_string):
    """
    Bulk import events to database
    
    Uses batch insertion for performance
    """
    engine = create_engine(db_connection_string)
    Session = sessionmaker(bind=engine)
    session = Session()
    
    batch_size = 5000
    
    for i in range(0, len(events), batch_size):
        batch = events[i:i+batch_size]
        
        # Categorize by operation type
        file_ops = []
        reg_ops = []
        proc_ops = []
        net_ops = []
        
        for event in batch:
            if event['operation'].startswith('Reg'):
                reg_ops.append(event)
            elif event['operation'] in ['CreateFile', 'WriteFile', 'ReadFile', 'DeleteFile']:
                file_ops.append(event)
            elif event['operation'] in ['Process Create', 'Process Exit', 'Thread Create']:
                proc_ops.append(event)
            elif event['operation'].startswith('TCP') or event['operation'].startswith('UDP'):
                net_ops.append(event)
        
        # Bulk insert by category
        if file_ops:
            session.bulk_insert_mappings(FileOperation, file_ops)
        if reg_ops:
            session.bulk_insert_mappings(RegistryOperation, reg_ops)
        if proc_ops:
            session.bulk_insert_mappings(ProcessEvent, proc_ops)
        if net_ops:
            session.bulk_insert_mappings(NetworkConnection, net_ops)
        
        session.commit()
    
    session.close()
```

## Event Analysis

### Categorizing Events

```python
class ProcmonAnalyzer:
    """Analyze Procmon events for suspicious behavior"""
    
    def analyze_file_operations(self, events):
        """Identify suspicious file operations"""
        suspicious = []
        
        for event in events:
            # Dropped executables
            if (event['operation'] == 'CreateFile' and 
                event['path'].endswith('.exe') and
                event['result'] == 'SUCCESS'):
                suspicious.append({
                    'type': 'dropped_executable',
                    'path': event['path'],
                    'process': event['process_name']
                })
            
            # Modified system files
            if ('C:\\Windows\\System32' in event['path'] and
                event['operation'] == 'WriteFile'):
                suspicious.append({
                    'type': 'system_file_modification',
                    'path': event['path'],
                    'process': event['process_name']
                })
        
        return suspicious
    
    def analyze_registry_operations(self, events):
        """Identify suspicious registry operations"""
        suspicious = []
        
        persistence_keys = [
            'Run',
            'RunOnce',
            'RunServices',
            'Winlogon',
            'BootExecute'
        ]
        
        for event in events:
            if event['operation'] == 'RegSetValue':
                for key in persistence_keys:
                    if key in event['path']:
                        suspicious.append({
                            'type': 'persistence_mechanism',
                            'key': event['path'],
                            'process': event['process_name']
                        })
        
        return suspicious
```

## Performance Optimization

### 1. PML vs CSV

**Use PML format during capture:**
- Binary format, much faster than CSV
- 10x performance improvement
- Smaller file size
- Convert to CSV offline after capture

### 2. Filtering

**Apply filters to reduce noise:**
- Exclude Windows system paths
- Exclude known safe processes
- Focus on user-space activity
- Use /LoadConfig with pre-configured filters

### 3. Backing File

**Use backing file instead of memory:**
```
/BackingFile D:\agent\logs\trace.pml
```
- Prevents memory exhaustion
- Enables longer captures
- Required for production use

### 4. Offline Processing

**Convert and parse offline:**
1. Capture in binary PML format
2. Copy PML to host
3. Convert to CSV on host (powerful machine)
4. Parse and import in batch

## Integration with Monitoring Module

```python
class ProcmonMonitor:
    """Procmon integration for process monitoring"""
    
    def __init__(self, vm_name, procmon_path):
        self.vm_name = vm_name
        self.procmon_path = procmon_path
        self.pml_path = None
        
    def start_capture(self, output_path):
        """Start Procmon capture in guest VM"""
        self.pml_path = output_path
        
        # Deploy Procmon if needed
        self._deploy_procmon()
        
        # Start capture via PowerShell Direct
        self._start_procmon_guest()
        
    def stop_capture(self):
        """Stop Procmon capture"""
        # Stop Procmon
        self._stop_procmon_guest()
        
        # Retrieve PML file
        self._retrieve_pml()
        
    def process_events(self):
        """Convert PML to CSV and import to database"""
        csv_path = self.pml_path.replace('.pml', '.csv')
        
        # Convert
        self._convert_pml_to_csv(self.pml_path, csv_path)
        
        # Parse
        parser = ProcmonParser()
        events = parser.parse_csv(csv_path)
        
        # Import
        bulk_import_events(events, self.db_connection_string)
        
        return len(events)
```

## Troubleshooting

### Common Issues

**1. Procmon not starting:**
- Ensure EULA is accepted: `/AcceptEula`
- Check path is correct
- Verify disk space for backing file

**2. Large PML files:**
- Apply more aggressive filters
- Reduce capture duration
- Use ring buffer (Procmon doesn't support, but can limit by size)

**3. Conversion fails:**
- Check PML file is complete (not corrupted)
- Ensure enough disk space for CSV
- Try smaller batch sizes

**4. Performance issues:**
- Use backing file, not memory
- Enable aggressive filtering
- Convert offline, not during capture

## Best Practices

1. **Always use `/AcceptEula`** - Avoid interactive prompts
2. **Use backing file** - Required for production
3. **Load configuration** - Pre-configured filters
4. **Terminate properly** - Use `/Terminate`, not kill
5. **Convert offline** - Don't convert during analysis
6. **Batch import** - Use bulk inserts to database
7. **Index database** - Create indexes for queries
8. **Clean up** - Delete PML/CSV after import

## References

- Sysinternals Procmon: https://docs.microsoft.com/en-us/sysinternals/downloads/procmon
- Procmon Command Line: https://docs.microsoft.com/en-us/sysinternals/downloads/procmon#command-line
- add spec3.md: Korean specification with Procmon integration
- add spec4.md: English specification with Procmon optimization
