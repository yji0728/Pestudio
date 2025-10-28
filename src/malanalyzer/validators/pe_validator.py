"""PE File Validator Module - Validates and extracts metadata from PE files"""

import os
import hashlib
import math
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

try:
    import pefile
except ImportError:
    pefile = None


@dataclass
class ValidationResult:
    """Result of PE file validation"""
    is_valid: bool
    file_path: str
    file_size: int
    file_hash: Dict[str, str]
    is_pe: bool
    is_packed: Optional[bool] = None
    entropy: Optional[float] = None
    has_signature: Optional[bool] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class PEMetadata:
    """PE File Metadata"""
    file_path: str
    file_hash: Dict[str, str]
    file_size: int
    pe_type: str  # exe, dll, sys, scr
    architecture: str  # x86, x64
    subsystem: str
    timestamp: Optional[datetime] = None
    
    # PE Headers
    entry_point: Optional[int] = None
    image_base: Optional[int] = None
    
    # Import/Export Tables
    imports: List[Dict[str, List[str]]] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    
    # Sections
    sections: List[Dict[str, any]] = field(default_factory=list)
    
    # Resources
    resources: List[Dict[str, any]] = field(default_factory=list)
    
    # Version Info
    version_info: Dict[str, str] = field(default_factory=dict)


class PEFileValidator:
    """PE File Validator - Validates PE files and extracts metadata"""
    
    def __init__(self):
        self.supported_formats = ['.exe', '.dll', '.sys', '.scr']
        self.max_file_size = 100 * 1024 * 1024  # 100MB
        
    def validate(self, file_path: str) -> ValidationResult:
        """
        Validate PE file
        
        Validation checks:
        - PE header validation
        - File size check
        - Digital signature verification
        - Entropy analysis
        - Packing detection
        """
        errors = []
        warnings = []
        
        # Check file exists
        if not os.path.exists(file_path):
            return ValidationResult(
                is_valid=False,
                file_path=file_path,
                file_size=0,
                file_hash={},
                is_pe=False,
                errors=[f"File not found: {file_path}"]
            )
        
        # Check file size
        file_size = os.path.getsize(file_path)
        if file_size > self.max_file_size:
            warnings.append(f"File size ({file_size} bytes) exceeds recommended maximum ({self.max_file_size} bytes)")
        
        if file_size == 0:
            return ValidationResult(
                is_valid=False,
                file_path=file_path,
                file_size=file_size,
                file_hash={},
                is_pe=False,
                errors=["File is empty"]
            )
        
        # Calculate file hashes
        file_hash = self._calculate_hashes(file_path)
        
        # Check file extension
        _, ext = os.path.splitext(file_path)
        if ext.lower() not in self.supported_formats:
            warnings.append(f"Unusual file extension: {ext}")
        
        # Validate PE structure
        is_pe = False
        is_packed = None
        entropy = None
        has_signature = None
        
        if pefile:
            try:
                pe = pefile.PE(file_path)
                is_pe = True
                
                # Check if file is packed (high entropy)
                entropy = self._calculate_entropy(file_path)
                is_packed = entropy > 7.0
                
                # Check for digital signature
                has_signature = hasattr(pe, 'OPTIONAL_HEADER') and \
                               hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY') and \
                               len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4 and \
                               pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress != 0
                
                pe.close()
                
            except pefile.PEFormatError as e:
                errors.append(f"Invalid PE format: {str(e)}")
            except Exception as e:
                errors.append(f"Error parsing PE file: {str(e)}")
        else:
            warnings.append("pefile module not available, skipping PE validation")
            # Basic PE header check
            with open(file_path, 'rb') as f:
                header = f.read(2)
                if header == b'MZ':
                    is_pe = True
        
        is_valid = is_pe and len(errors) == 0
        
        return ValidationResult(
            is_valid=is_valid,
            file_path=file_path,
            file_size=file_size,
            file_hash=file_hash,
            is_pe=is_pe,
            is_packed=is_packed,
            entropy=entropy,
            has_signature=has_signature,
            errors=errors,
            warnings=warnings
        )
    
    def extract_metadata(self, file_path: str) -> Optional[PEMetadata]:
        """
        Extract PE metadata
        
        Extracted information:
        - Import Table
        - Export Table
        - Section Information
        - Resource Information
        - Version Information
        """
        if not pefile:
            return None
        
        try:
            pe = pefile.PE(file_path)
            
            # Basic info
            file_size = os.path.getsize(file_path)
            file_hash = self._calculate_hashes(file_path)
            
            # Determine PE type
            _, ext = os.path.splitext(file_path)
            pe_type = ext[1:].lower() if ext else 'exe'
            
            # Architecture
            architecture = 'x64' if pe.FILE_HEADER.Machine == 0x8664 else 'x86'
            
            # Subsystem
            subsystem_map = {
                1: 'NATIVE',
                2: 'WINDOWS_GUI',
                3: 'WINDOWS_CUI',
                5: 'OS2_CUI',
                7: 'POSIX_CUI',
                9: 'WINDOWS_CE_GUI',
                10: 'EFI_APPLICATION',
                11: 'EFI_BOOT_SERVICE_DRIVER',
                12: 'EFI_RUNTIME_DRIVER',
                13: 'EFI_ROM',
                14: 'XBOX',
                16: 'WINDOWS_BOOT_APPLICATION'
            }
            subsystem = subsystem_map.get(
                pe.OPTIONAL_HEADER.Subsystem, 
                f'UNKNOWN_{pe.OPTIONAL_HEADER.Subsystem}'
            )
            
            # Timestamp
            timestamp = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)
            
            # Entry point and image base
            entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            image_base = pe.OPTIONAL_HEADER.ImageBase
            
            # Extract imports
            imports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8') if isinstance(entry.dll, bytes) else entry.dll
                    functions = []
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8') if isinstance(imp.name, bytes) else imp.name
                            functions.append(func_name)
                    imports.append({dll_name: functions})
            
            # Extract exports
            exports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        export_name = exp.name.decode('utf-8') if isinstance(exp.name, bytes) else exp.name
                        exports.append(export_name)
            
            # Extract sections
            sections = []
            for section in pe.sections:
                section_name = section.Name.decode('utf-8').strip('\x00')
                sections.append({
                    'name': section_name,
                    'virtual_address': section.VirtualAddress,
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'entropy': section.get_entropy()
                })
            
            # Extract resources (simplified)
            resources = []
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(resource_type, 'directory'):
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, 'directory'):
                                for resource_lang in resource_id.directory.entries:
                                    resources.append({
                                        'type': resource_type.id,
                                        'id': resource_id.id,
                                        'lang': resource_lang.id,
                                        'size': resource_lang.data.struct.Size
                                    })
            
            # Extract version info
            version_info = {}
            if hasattr(pe, 'VS_VERSIONINFO'):
                if hasattr(pe, 'FileInfo'):
                    for file_info in pe.FileInfo:
                        if hasattr(file_info, 'StringTable'):
                            for st in file_info.StringTable:
                                for entry in st.entries.items():
                                    key = entry[0].decode('utf-8') if isinstance(entry[0], bytes) else entry[0]
                                    val = entry[1].decode('utf-8') if isinstance(entry[1], bytes) else entry[1]
                                    version_info[key] = val
            
            pe.close()
            
            return PEMetadata(
                file_path=file_path,
                file_hash=file_hash,
                file_size=file_size,
                pe_type=pe_type,
                architecture=architecture,
                subsystem=subsystem,
                timestamp=timestamp,
                entry_point=entry_point,
                image_base=image_base,
                imports=imports,
                exports=exports,
                sections=sections,
                resources=resources,
                version_info=version_info
            )
            
        except Exception as e:
            print(f"Error extracting metadata: {str(e)}")
            return None
    
    def _calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate MD5, SHA1, and SHA256 hashes of file"""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        
        return {
            'md5': md5.hexdigest(),
            'sha1': sha1.hexdigest(),
            'sha256': sha256.hexdigest()
        }
    
    def _calculate_entropy(self, file_path: str) -> float:
        """Calculate Shannon entropy of file"""
        with open(file_path, 'rb') as f:
            data = f.read()
        
        if not data:
            return 0.0
        
        # Calculate byte frequency
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
