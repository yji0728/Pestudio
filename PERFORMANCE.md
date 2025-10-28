# Performance Optimization Guide

## Overview

This document describes performance optimization strategies implemented in MalwareAnalyzer Pro based on specifications in add spec3.md and add spec4.md.

## Key Performance Requirements

From spec3.md:
- 5-minute analysis should complete end-to-end processing in ≤ 2 minutes (p95)
- UI should maintain 60fps when scrolling through 100,000+ events
- Drop event loss rate < 0.5%

## Optimization Categories

### 1. Hyper-V Sandbox Optimization

#### VM Pooling
Pre-create and maintain a pool of ready VMs to eliminate startup time:

```python
class VMPool:
    """
    Maintains pool of pre-configured VMs for instant analysis
    """
    def __init__(self, pool_size=3):
        self.pool_size = pool_size
        self.available_vms = []
        
    def acquire_vm(self):
        """Get VM from pool, restore snapshot for clean state"""
        # Instant VM availability, just restore snapshot
        pass
```

#### Differential Disks
Use differential (differencing) VHDXs to avoid full VM copy:
- Base VHDX: Clean Windows installation
- Differential VHDX: Per-analysis disk, discarded after use
- PowerShell: `New-VHD -Path diff.vhdx -ParentPath base.vhdx -Differencing`

#### PowerShell Direct
File transfer and command execution without network:
- No network overhead
- Direct VM bus communication
- Commands: `Copy-VMFile`, `Invoke-Command -VMName`

### 2. ETW Monitoring Optimization

#### Selective Event Filtering
Only capture relevant events to reduce overhead:

```json
{
  "ETWProviders": [
    {
      "Name": "Microsoft-Windows-Kernel-Process",
      "Keywords": "0x10",  // Only process creation/exit
      "Level": "Informational"  // Not verbose
    }
  ]
}
```

#### Buffered Event Processing
Use channel-based buffering to batch events:

```python
class BufferedETWProcessor:
    def __init__(self, buffer_size=1000):
        self.buffer = []
        self.buffer_size = buffer_size
        
    def add_event(self, event):
        self.buffer.append(event)
        if len(self.buffer) >= self.buffer_size:
            self.flush_buffer()
            
    def flush_buffer(self):
        # Batch insert to database
        db.bulk_insert(self.buffer)
        self.buffer.clear()
```

### 3. Memory Dump Optimization

#### Concurrent Dump Limiting
Prevent memory exhaustion by limiting concurrent dumps:

```json
{
  "MemoryDumpOptions": {
    "MaxConcurrentDumps": 2,
    "MinLifetimeMs": 3000
  }
}
```

#### Compression
Compress dumps on-the-fly to reduce storage and transfer time:
- Use zstd compression (fast, high ratio)
- Multi-threaded compression
- Typical 10:1 compression ratio for memory dumps

### 4. Procmon Optimization

#### PML Binary Format
Use binary PML format instead of CSV during capture:
- 10x faster than real-time CSV conversion
- Convert to CSV offline after capture completes
- PowerShell: `Procmon.exe /BackingFile trace.pml`

#### Event Filtering
Pre-configure Procmon filters to exclude noise:
- Filter out Windows system paths
- Focus on user-space operations
- Load filter profile: `/LoadConfig profile.pmc`

### 5. Network Capture Optimization

#### Ring Buffer
Limit PCAP size with ring buffer to prevent unlimited growth:
- Configure 500MB ring buffer
- Old packets automatically discarded
- Command: `tshark -b filesize:500000`

#### Snap Length
Capture only packet headers for protocol analysis:
- SnapLen: 256-512 bytes
- Sufficient for DNS/HTTP analysis
- Reduces capture size by 90%

### 6. Database Optimization

#### Bulk Insert
Batch database inserts for 100x performance improvement:

```python
# Bad: Individual inserts
for event in events:
    db.insert(event)  # 1000 inserts = 10 seconds

# Good: Bulk insert  
db.bulk_insert(events)  # 1000 inserts = 0.1 seconds
```

#### Indexing Strategy
Create indexes on frequently queried columns:

```sql
CREATE INDEX idx_execution_timestamp ON events(execution_id, timestamp);
CREATE INDEX idx_process_timestamp ON events(process_id, timestamp);
CREATE INDEX idx_api_name ON api_calls(api_name);
```

#### Partitioning
Partition large tables by execution_id or date:
- Faster queries on recent data
- Easier data retention management

### 7. File Transfer Optimization

#### Compression
Compress artifacts before transfer:
- zstd compression (fast)
- Multi-threaded compression
- Transfer compressed, decompress on host

#### Parallel Transfer
Transfer multiple files concurrently:
- Use async I/O
- Parallel `Copy-VMFile` operations
- Thread pool for concurrent transfers

### 8. UI Optimization (WPF)

#### Virtualization
Enable UI virtualization for large lists:

```xml
<DataGrid VirtualizingStackPanel.IsVirtualizing="True"
          VirtualizingStackPanel.VirtualizationMode="Recycling"
          EnableRowVirtualization="True">
```

#### Async Data Binding
Load data asynchronously to prevent UI freezing:

```csharp
public async Task LoadEventsAsync()
{
    var events = await Task.Run(() => LoadEventsFromDb());
    EventsCollection.Clear();
    foreach (var evt in events)
    {
        EventsCollection.Add(evt);
    }
}
```

#### Level of Detail
Show aggregated data for large time ranges:
- Zoom out: Show event counts per second
- Zoom in: Show individual events
- Prevents rendering 1M+ UI elements

### 9. Caching Strategy

#### VT Report Caching
Cache VirusTotal results to avoid repeated API calls:

```python
class VTCache:
    def __init__(self, cache_duration=86400):  # 24 hours
        self.cache = {}
        self.cache_duration = cache_duration
        
    def get_cached_report(self, file_hash):
        entry = self.cache.get(file_hash)
        if entry and not self.is_expired(entry):
            return entry['report']
        return None
```

#### File Hash Caching
Cache computed hashes to avoid recalculation:
- Store in database
- Key: file path + modification time
- Value: MD5, SHA1, SHA256 hashes

### 10. Pipeline Architecture

#### Event Processing Pipeline
Process events through staged pipeline:

```
Capture → Buffer → Parse → Transform → Batch → Database
   ↓        ↓        ↓         ↓         ↓        ↓
 ETW/PM   Queue   Thread    Format   Queue    Bulk
                   Pool                      Insert
```

Each stage operates independently with queues between them.

## Performance Metrics

### Target Metrics (from spec3.md)

- **End-to-end processing**: ≤ 2 minutes for 5-minute analysis (p95)
- **UI responsiveness**: 60fps scrolling with 100K+ events
- **Event loss**: < 0.5% drop rate
- **Database ingestion**: 200万 events in < 60 seconds
- **Query latency**: p95 < 300ms

### Measurement Tools

1. **Event Processing Rate**: Events per second
2. **Memory Usage**: Peak memory during analysis
3. **CPU Utilization**: Average CPU % during analysis
4. **Disk I/O**: Read/write throughput
5. **Network Transfer**: Transfer time for artifacts
6. **UI Frame Rate**: FPS during scrolling

## Configuration for Optimal Performance

Example configuration emphasizing performance:

```json
{
  "Performance": {
    "EnableCaching": true,
    "CacheSize": 1073741824,
    "ThreadPoolSize": 16,
    "AsyncIOThreads": 8,
    "EnableCompression": true,
    "BufferSize": 65536,
    "BatchInsertSize": 1000,
    "EventQueueSize": 10000
  },
  "Perf": {
    "MaxIngestDegreeOfParallelism": 4,
    "CsvToDbBuffer": 104857600,
    "Compression": "Zstd"
  }
}
```

## Best Practices Summary

1. **Pre-warm VMs** in pool for instant availability
2. **Use differential disks** to avoid VM cloning
3. **Filter events** at source (ETW, Procmon) to reduce volume
4. **Buffer and batch** all database operations
5. **Compress** memory dumps and large files
6. **Parallelize** I/O operations where possible
7. **Cache** expensive computations (hashes, VT results)
8. **Virtualize** UI for large datasets
9. **Index** database tables appropriately
10. **Monitor** performance metrics continuously

## Tuning Guidelines

### For High-Volume Analysis
- Increase buffer sizes
- Increase thread pool size
- Enable aggressive compression
- Use SSD storage

### For Low-Latency Analysis
- Pre-warm VM pool
- Use PowerShell Direct
- Enable caching
- Reduce batch sizes for faster feedback

### For Resource-Constrained Systems
- Reduce concurrent dumps
- Decrease buffer sizes
- Enable aggressive filtering
- Limit VM pool size

## Monitoring Performance

Track these metrics during analysis:

```python
class PerformanceMonitor:
    def track_metrics(self):
        return {
            'events_per_second': self.calculate_event_rate(),
            'memory_usage_mb': self.get_memory_usage(),
            'cpu_percent': self.get_cpu_usage(),
            'disk_io_mbps': self.get_disk_throughput(),
            'processing_latency_ms': self.get_processing_latency()
        }
```

## References

- add spec3.md: Korean specification with Hyper-V, performance requirements
- add spec4.md: English specification with detailed performance optimization strategies
- Hyper-V documentation: PowerShell Direct, Guest Services
- ETW documentation: Event filtering, providers
- Procmon documentation: PML format, filtering
