"""Configuration management"""

import os
import yaml
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict


@dataclass
class SandboxSettings:
    """Sandbox configuration settings"""
    type: str = "virtualbox"
    vm_name: str = "Windows10_Sandbox"
    snapshot: str = "clean_state"
    memory: int = 4096
    cpu_cores: int = 2


@dataclass
class MonitoringSettings:
    """Monitoring configuration settings"""
    api_hooks: bool = True
    network_capture: bool = True
    screenshot_interval: int = 5
    memory_dump: bool = True


@dataclass
class AnalysisSettings:
    """Analysis configuration settings"""
    timeout: int = 300
    kill_on_timeout: bool = True
    collect_artifacts: bool = True


@dataclass
class VirusTotalSettings:
    """VirusTotal configuration settings"""
    api_key: str = ""
    auto_submit: bool = True
    wait_for_results: bool = True


@dataclass
class OutputSettings:
    """Output configuration settings"""
    directory: str = "./reports"
    format: str = "json"
    include_pcap: bool = True
    include_memory_dump: bool = False


@dataclass
class Config:
    """Main configuration"""
    sandbox: SandboxSettings
    monitoring: MonitoringSettings
    analysis: AnalysisSettings
    virustotal: VirusTotalSettings
    output: OutputSettings


def load_config(config_path: str = "config.yaml") -> Config:
    """Load configuration from YAML file"""
    
    # Default configuration
    default_config = Config(
        sandbox=SandboxSettings(),
        monitoring=MonitoringSettings(),
        analysis=AnalysisSettings(),
        virustotal=VirusTotalSettings(),
        output=OutputSettings()
    )
    
    # If config file doesn't exist, return default
    if not os.path.exists(config_path):
        print(f"[Config] Config file not found: {config_path}, using defaults")
        return default_config
    
    try:
        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f)
        
        # Parse configuration
        sandbox_data = config_data.get('sandbox', {})
        monitoring_data = config_data.get('monitoring', {})
        analysis_data = config_data.get('analysis', {})
        vt_data = config_data.get('virustotal', {})
        output_data = config_data.get('output', {})
        
        config = Config(
            sandbox=SandboxSettings(**sandbox_data),
            monitoring=MonitoringSettings(**monitoring_data),
            analysis=AnalysisSettings(**analysis_data),
            virustotal=VirusTotalSettings(**vt_data),
            output=OutputSettings(**output_data)
        )
        
        print(f"[Config] Loaded configuration from: {config_path}")
        return config
        
    except Exception as e:
        print(f"[Config] Error loading config: {str(e)}, using defaults")
        return default_config


def save_config(config: Config, config_path: str = "config.yaml") -> bool:
    """Save configuration to YAML file"""
    try:
        config_dict = {
            'sandbox': asdict(config.sandbox),
            'monitoring': asdict(config.monitoring),
            'analysis': asdict(config.analysis),
            'virustotal': asdict(config.virustotal),
            'output': asdict(config.output)
        }
        
        with open(config_path, 'w') as f:
            yaml.dump(config_dict, f, default_flow_style=False)
        
        print(f"[Config] Saved configuration to: {config_path}")
        return True
        
    except Exception as e:
        print(f"[Config] Error saving config: {str(e)}")
        return False


def create_default_config(config_path: str = "config.yaml") -> bool:
    """Create default configuration file"""
    default_config = Config(
        sandbox=SandboxSettings(),
        monitoring=MonitoringSettings(),
        analysis=AnalysisSettings(),
        virustotal=VirusTotalSettings(),
        output=OutputSettings()
    )
    
    return save_config(default_config, config_path)
