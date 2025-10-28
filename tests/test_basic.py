"""Basic tests for MalwareAnalyzer modules"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))


def test_imports():
    """Test that all modules can be imported"""
    try:
        from malanalyzer.validators import PEFileValidator, ValidationResult
        from malanalyzer.sandbox import SandboxManager, SandboxConfig, VMType
        from malanalyzer.monitoring import ProcessMonitor
        from malanalyzer.collectors import ArtifactCollector
        from malanalyzer.api import VirusTotalClient
        from malanalyzer.storage import Database
        from malanalyzer.config import load_config
        
        print("✓ All modules imported successfully")
        return True
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False


def test_pe_validator():
    """Test PE validator with a simple file"""
    from malanalyzer.validators import PEFileValidator
    
    validator = PEFileValidator()
    assert validator is not None
    assert validator.supported_formats == ['.exe', '.dll', '.sys', '.scr']
    assert validator.max_file_size == 100 * 1024 * 1024
    
    print("✓ PE Validator initialized correctly")
    return True


def test_sandbox_config():
    """Test sandbox configuration"""
    from malanalyzer.sandbox import SandboxConfig, VMType
    
    config = SandboxConfig(
        vm_type=VMType.VIRTUALBOX,
        vm_name="test_vm",
        snapshot="clean",
        timeout=300
    )
    
    assert config.vm_type == VMType.VIRTUALBOX
    assert config.vm_name == "test_vm"
    assert config.timeout == 300
    
    print("✓ Sandbox configuration works correctly")
    return True


def test_process_monitor():
    """Test process monitor"""
    from malanalyzer.monitoring import ProcessMonitor
    
    monitor = ProcessMonitor()
    assert not monitor.is_monitoring
    
    monitor.start_monitoring()
    assert monitor.is_monitoring
    
    monitor.stop_monitoring()
    assert not monitor.is_monitoring
    
    print("✓ Process monitor works correctly")
    return True


def test_artifact_collector():
    """Test artifact collector"""
    from malanalyzer.collectors import ArtifactCollector
    import tempfile
    import shutil
    
    # Create temporary execution ID
    exec_id = "test_execution_123"
    
    # Create in temp directory
    temp_dir = tempfile.mkdtemp()
    original_dir = os.getcwd()
    os.chdir(temp_dir)
    
    try:
        collector = ArtifactCollector(exec_id)
        assert collector.execution_id == exec_id
        assert os.path.exists(collector.artifacts_dir)
        
        summary = collector.get_summary()
        assert summary['execution_id'] == exec_id
        assert summary['total_artifacts'] == 0
        
        print("✓ Artifact collector works correctly")
        return True
    finally:
        os.chdir(original_dir)
        shutil.rmtree(temp_dir)


def test_vt_client():
    """Test VirusTotal client initialization"""
    from malanalyzer.api import VirusTotalClient
    
    client = VirusTotalClient("test_api_key")
    assert client.api_key == "test_api_key"
    assert client.base_url == "https://www.virustotal.com/api/v3"
    
    print("✓ VirusTotal client initialized correctly")
    return True


def test_config():
    """Test configuration loading"""
    from malanalyzer.config import load_config
    
    config = load_config("nonexistent_config.yaml")
    assert config is not None
    assert config.sandbox.type == "virtualbox"
    assert config.analysis.timeout == 300
    
    print("✓ Configuration system works correctly")
    return True


def run_all_tests():
    """Run all tests"""
    print("\n" + "="*60)
    print("Running MalwareAnalyzer Tests")
    print("="*60 + "\n")
    
    tests = [
        ("Module Imports", test_imports),
        ("PE Validator", test_pe_validator),
        ("Sandbox Config", test_sandbox_config),
        ("Process Monitor", test_process_monitor),
        ("Artifact Collector", test_artifact_collector),
        ("VirusTotal Client", test_vt_client),
        ("Configuration", test_config),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        print(f"\nTest: {test_name}")
        print("-" * 60)
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"✗ Test failed with exception: {e}")
            failed += 1
    
    print("\n" + "="*60)
    print(f"Results: {passed} passed, {failed} failed")
    print("="*60 + "\n")
    
    return failed == 0


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
