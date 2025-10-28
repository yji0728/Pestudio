# WPF GUI Specification

## Overview

This document describes the WPF (Windows Presentation Foundation) GUI specification for MalwareAnalyzer Pro based on add spec3.md and add spec4.md requirements.

## Technology Stack

- **Framework**: .NET 6/7/8
- **UI Framework**: WPF (Windows Presentation Foundation)
- **Architecture**: MVVM (Model-View-ViewModel)
- **Language**: C# 11

## Main Window Structure

### Window Layout

```
┌──────────────────────────────────────────────────────────────────────┐
│ MalwareAnalyzer Pro                                     [Settings ⚙] │
├───────────────┬──────────────────────────────────────────────────────┤
│ Projects/Tags │  New Analysis ▶                                   ⓘ │
│ - All         │  Search: [sha256/file/ip/domain] [🔍]                │
│ - Recent      ├──────────────────────────────────────────────────────┤
│ - VT:bad      │ Executions                                           │
│ - Manual      │ ┌────────────────────────────────────────────────┐  │
│               │ │ ☐ Live  ID    Sample        Start     Verdict │  │
│               │ │ ▣ 123  foo.exe       10:21:03  Suspicious     │  │
│               │ │ □ 122  bar.dll       09:58:10  Malicious (23) │  │
│               │ │ ...                                            │  │
│               │ └────────────────────────────────────────────────┘  │
│               ├──────────────────────────────────────────────────────┤
│               │ Summary (selected execution)                         │
│               │ ProcTree: 7 procs | Files: 42 | Reg: 58 | Net: 12   │
│               │ VT: 23/70 | Duration: 04:59                          │
└───────────────┴──────────────────────────────────────────────────────┘
```

## Key Windows and Views

### 1. Dashboard (Main Window)

**Components:**
- Left Panel: Project/Tag Filter Tree
- Center Top: Execution List (DataGrid)
- Center Bottom: Summary Panel
- Top Bar: New Analysis, Search, Settings

**XAML Structure:**
```xml
<Window x:Class="MalwareAnalyzer.MainWindow"
        Title="MalwareAnalyzer Pro" 
        Height="900" Width="1600">
    <DockPanel>
        <Menu DockPanel.Dock="Top">
            <MenuItem Header="File"/>
            <MenuItem Header="Analysis"/>
            <MenuItem Header="View"/>
            <MenuItem Header="Tools"/>
        </Menu>
        
        <Grid>
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="250"/>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>
            
            <!-- Left Panel: Filters -->
            <TreeView Grid.Column="0" 
                     ItemsSource="{Binding Filters}"/>
            
            <!-- Center Panel: Executions -->
            <Grid Grid.Column="1">
                <Grid.RowDefinitions>
                    <RowDefinition Height="*"/>
                    <RowDefinition Height="150"/>
                </Grid.RowDefinitions>
                
                <DataGrid Grid.Row="0"
                         ItemsSource="{Binding Executions}"
                         VirtualizingStackPanel.IsVirtualizing="True"/>
                         
                <Border Grid.Row="1" 
                       Background="#F5F5F5">
                    <!-- Summary Panel -->
                </Border>
            </Grid>
        </Grid>
    </DockPanel>
</Window>
```

### 2. New Analysis Wizard

**Steps:**
1. File Selection (Drag & Drop or Browse)
2. Analysis Options
3. Sandbox Configuration
4. Summary & Start

**Layout:**
```
┌──────────────────── New Analysis ───────────────────────┐
│ File: [ Drag & Drop or Browse... ] [Compute Hash]       │
│ Options: [x] VT Scan (auto-upload)                      │
│          [x] Dump all child processes (Full)            │
│          [x] Capture PCAP (ring buffer 500MB)           │
│ Timeout: [300] sec                                      │
│ Sandbox: VM [Win11_Analysis] Snapshot [clean_2025-10]   │
│ Network: Default Switch (NAT)                           │
│ [Start] [Cancel]                                        │
└─────────────────────────────────────────────────────────┘
```

**Features:**
- Drag & Drop support for PE files
- Hash computation (MD5, SHA1, SHA256)
- Profile selection (Quick/Standard/Deep)
- VM and snapshot selection
- Real-time validation

### 3. Real-time Analysis View

**Layout:**
```
┌───────────────────────────────────────────────────────────────────────┐
│ foo.exe (Running)  02:15 / 05:00  [⏹ Stop][⏸ Pause] [Logs ▼]         │
├───────────────┬───────────────────────────────────────────────────────┤
│ Process Tree  │ Tabs: [Overview][Processes][Files][Registry][Network]│
│ foo.exe       │       [API][VT][Artifacts]                            │
│ ├─ child1.exe │ ┌───────────────────────────────────────────────────┐ │
│ │  └─ dropper │ │ Overview:                                         │ │
│ └─ svchost    │ │ - Suspicious APIs: WriteProcessMemory, NtMap...   │ │
│               │ │ - Files: 12 created | 3 modified                  │ │
│               │ │ - Net: 3 domains | 5 connections                  │ │
│               │ └───────────────────────────────────────────────────┘ │
├───────────────┴───────────────────────────────────────────────────────┤
│ Timeline:  |■■■ Proc |■■ FS |■ Reg |■ Net |  (Zoom ▒▒▒▒▒)             │
└───────────────────────────────────────────────────────────────────────┘
```

**Components:**

#### Process Tree (Left Panel)
- TreeView showing parent-child relationships
- Real-time updates
- Color coding by risk level
- Icons for process types

#### Tab Panels (Center)

**Overview Tab:**
- High-level summary
- Suspicious behavior indicators
- Risk score visualization
- Quick stats

**Processes Tab:**
- DataGrid of all processes
- Columns: PID, Name, Command Line, User, Start Time
- Memory dump status indicator
- Filter and search

**Files Tab:**
- File operations (Create, Write, Delete, Read)
- Dropped files with hashes
- Modified executables
- Grouped by operation type

**Registry Tab:**
- Registry operations
- Key path and value
- Before/after values for modifications
- Persistence indicators

**Network Tab:**
- Connections (TCP/UDP)
- DNS queries
- HTTP/HTTPS requests
- External IP addresses and domains
- Geolocation map (optional)

**API Calls Tab:**
- Suspicious API calls
- Grouped by category (File, Registry, Network, Process, Crypto)
- Call stack (if available)
- Highlights dangerous APIs

**VT Tab:**
- VirusTotal scan results
- Detection ratio visualization
- Engine detections list
- Sandbox reports
- Upload status (if auto-upload)

**Artifacts Tab:**
- Collected artifacts list
- Memory dumps with sizes
- PCAP files
- Screenshots
- Download/export options

#### Timeline (Bottom)
- Interactive timeline showing events over time
- Color-coded by event type
- Zoom and pan controls
- Click to filter events by time range

### 4. Settings Window

**Categories:**
- Hyper-V Configuration
- Analysis Options
- VirusTotal Settings
- Performance Settings
- Network Settings
- Security Settings

**Layout:**
```
┌──────────────────── Settings ───────────────────────┐
│ [Hyper-V] [Analysis] [VirusTotal] [Performance]     │
├──────────────────────────────────────────────────────┤
│ Hyper-V Configuration                                │
│ VM Name: [Win11_Analysis          ] [Browse]         │
│ Snapshot: [clean_2025-10          ] [▼]             │
│ [x] Use Default Switch                               │
│ [x] Enable Guest Services                            │
│ [x] PowerShell Direct                                │
│ [x] Time Synchronization                             │
│                                                      │
│ Memory: [4096] MB                                    │
│ CPU Cores: [2]                                       │
│                                                      │
│ [Save] [Cancel] [Apply]                              │
└──────────────────────────────────────────────────────┘
```

## MVVM Architecture

### ViewModels

```csharp
// MainViewModel
public class MainViewModel : ViewModelBase
{
    public ObservableCollection<ExecutionViewModel> Executions { get; set; }
    public ICommand NewAnalysisCommand { get; }
    public ICommand SearchCommand { get; }
    public ICommand SettingsCommand { get; }
    
    public ExecutionViewModel SelectedExecution { get; set; }
}

// AnalysisViewModel (Real-time view)
public class AnalysisViewModel : ViewModelBase
{
    public string Status { get; set; }
    public int Progress { get; set; }
    public string ElapsedTime { get; set; }
    
    public ObservableCollection<ProcessNode> ProcessTree { get; set; }
    public ObservableCollection<Event> Events { get; set; }
    
    public ICommand StopCommand { get; }
    public ICommand PauseCommand { get; }
}
```

## UI Performance Optimizations

### 1. Virtualization

Enable virtualization for large datasets:

```xml
<DataGrid ItemsSource="{Binding Events}"
          VirtualizingStackPanel.IsVirtualizing="True"
          VirtualizingStackPanel.VirtualizationMode="Recycling"
          EnableRowVirtualization="True"
          EnableColumnVirtualization="True">
</DataGrid>
```

### 2. Async Data Loading

Load data asynchronously to prevent UI freezing:

```csharp
public async Task LoadExecutionsAsync()
{
    IsLoading = true;
    var executions = await Task.Run(() => _repository.GetExecutions());
    
    Application.Current.Dispatcher.Invoke(() =>
    {
        Executions.Clear();
        foreach (var exec in executions)
        {
            Executions.Add(new ExecutionViewModel(exec));
        }
    });
    
    IsLoading = false;
}
```

### 3. Throttled Updates

Throttle real-time updates to prevent UI overload:

```csharp
private readonly TimeSpan _updateInterval = TimeSpan.FromMilliseconds(100);
private DateTime _lastUpdate = DateTime.MinValue;

public void OnEventReceived(Event evt)
{
    _eventBuffer.Add(evt);
    
    if (DateTime.Now - _lastUpdate > _updateInterval)
    {
        FlushEventBuffer();
        _lastUpdate = DateTime.Now;
    }
}
```

### 4. Lazy Loading

Load details only when needed:

```csharp
public class ExecutionViewModel : ViewModelBase
{
    private ObservableCollection<ProcessEvent> _processes;
    
    public ObservableCollection<ProcessEvent> Processes
    {
        get
        {
            if (_processes == null)
            {
                _processes = LoadProcesses();
            }
            return _processes;
        }
    }
}
```

## Styling and Themes

### Color Scheme

- **Background**: #FFFFFF (white)
- **Secondary Background**: #F5F5F5 (light gray)
- **Accent**: #007ACC (blue)
- **Success**: #28A745 (green)
- **Warning**: #FFC107 (yellow)
- **Danger**: #DC3545 (red)
- **Text**: #212529 (dark gray)

### Risk Level Colors

- **High Risk**: #DC3545 (red)
- **Medium Risk**: #FFC107 (orange)
- **Low Risk**: #FFC107 (yellow)
- **Safe**: #28A745 (green)
- **Unknown**: #6C757D (gray)

## Data Binding Examples

### Process Tree Binding

```xml
<TreeView ItemsSource="{Binding ProcessTree}">
    <TreeView.ItemTemplate>
        <HierarchicalDataTemplate ItemsSource="{Binding Children}">
            <StackPanel Orientation="Horizontal">
                <Image Source="{Binding Icon}" Width="16" Height="16"/>
                <TextBlock Text="{Binding ProcessName}" Margin="5,0"/>
                <TextBlock Text="{Binding PID}" 
                          Foreground="Gray" 
                          FontSize="10"/>
            </StackPanel>
        </HierarchicalDataTemplate>
    </TreeView.ItemTemplate>
</TreeView>
```

### Real-time Event Grid

```xml
<DataGrid ItemsSource="{Binding RealtimeEvents}"
          AutoGenerateColumns="False"
          IsReadOnly="True">
    <DataGrid.Columns>
        <DataGridTextColumn Header="Time" 
                           Binding="{Binding Timestamp, StringFormat=HH:mm:ss.fff}"
                           Width="100"/>
        <DataGridTextColumn Header="Type" 
                           Binding="{Binding EventType}"
                           Width="120"/>
        <DataGridTextColumn Header="Process" 
                           Binding="{Binding ProcessName}"
                           Width="150"/>
        <DataGridTextColumn Header="Description" 
                           Binding="{Binding Description}"
                           Width="*"/>
    </DataGrid.Columns>
</DataGrid>
```

## Integration with Backend

The WPF GUI will integrate with the Python backend via:

1. **REST API**: HTTP API for analysis control
2. **WebSockets**: Real-time event streaming
3. **File System**: Shared artifact storage
4. **Database**: Direct SQLite access for reports

### Example Integration

```csharp
public class AnalysisService
{
    private readonly HttpClient _client;
    
    public async Task<Execution> StartAnalysis(AnalysisRequest request)
    {
        var response = await _client.PostAsJsonAsync("/api/analyze", request);
        return await response.Content.ReadFromJsonAsync<Execution>();
    }
    
    public async Task SubscribeToEvents(string executionId, 
                                       Action<Event> onEvent)
    {
        using var ws = new ClientWebSocket();
        await ws.ConnectAsync(new Uri($"ws://localhost:8080/events/{executionId}"), 
                             CancellationToken.None);
        // Receive and process events
    }
}
```

## Building the WPF Application

### Project Structure

```
MalwareAnalyzerWPF/
├── Views/
│   ├── MainWindow.xaml
│   ├── NewAnalysisWindow.xaml
│   ├── AnalysisWindow.xaml
│   └── SettingsWindow.xaml
├── ViewModels/
│   ├── MainViewModel.cs
│   ├── AnalysisViewModel.cs
│   └── SettingsViewModel.cs
├── Models/
│   ├── Execution.cs
│   ├── ProcessNode.cs
│   └── Event.cs
├── Services/
│   ├── AnalysisService.cs
│   ├── DatabaseService.cs
│   └── VTService.cs
└── App.xaml
```

### Dependencies

```xml
<ItemGroup>
  <PackageReference Include="CommunityToolkit.Mvvm" Version="8.2.0" />
  <PackageReference Include="Microsoft.EntityFrameworkCore" Version="7.0.0" />
  <PackageReference Include="Microsoft.EntityFrameworkCore.Sqlite" Version="7.0.0" />
  <PackageReference Include="LiveCharts.Wpf" Version="0.9.7" />
  <PackageReference Include="MaterialDesignThemes" Version="4.9.0" />
</ItemGroup>
```

## Next Steps

To implement the WPF GUI:

1. **Create .NET WPF Project**: Visual Studio 2022
2. **Implement ViewModels**: MVVM architecture
3. **Design XAML Views**: Based on wireframes above
4. **Integrate with Backend**: REST API and WebSockets
5. **Add Real-time Updates**: SignalR or WebSocket
6. **Optimize Performance**: Virtualization, async loading
7. **Add Styling**: Material Design or custom theme
8. **Testing**: Unit tests and UI tests

## References

- add spec3.md: Korean specification with WPF requirements
- add spec4.md: English specification with detailed UI wireframes
- WPF Documentation: https://docs.microsoft.com/en-us/dotnet/desktop/wpf/
- MVVM Pattern: https://docs.microsoft.com/en-us/windows/uwp/data-binding/data-binding-and-mvvm
