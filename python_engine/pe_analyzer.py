import pefile
import struct
from typing import Dict, Any

class PEAnalyzer:
    def __init__(self):
        self.pe = None
        
    def analyze_pe_structure(self, file_path: str) -> Dict[str, Any]:
        try:
            self.pe = pefile.PE(file_path)
            
            analysis_result = {
                'basic_info': self.get_basic_info(),
                'sections': self.get_section_info(),
                'imports': self.get_import_info(),
                'exports': self.get_export_info(),
                'security': self.get_security_info()
            }
            
            return analysis_result
            
        except Exception as e:
            return {'error': str(e)}
    
    def get_basic_info(self) -> Dict[str, Any]:
        info = {
            'machine_type': self.pe.FILE_HEADER.Machine,
            'number_of_sections': self.pe.FILE_HEADER.NumberOfSections,
            'timestamp': self.pe.FILE_HEADER.TimeDateStamp,
            'entry_point': self.pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'image_base': self.pe.OPTIONAL_HEADER.ImageBase,
            'subsystem': self.pe.OPTIONAL_HEADER.Subsystem
        }
        return info
    
    def get_section_info(self) -> List[Dict[str, Any]]:
        sections = []
        for section in self.pe.sections:
            section_info = {
                'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                'virtual_address': section.VirtualAddress,
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'characteristics': section.Characteristics,
                'is_executable': bool(section.Characteristics & 0x20000000),
                'is_writable': bool(section.Characteristics & 0x80000000)
            }
            sections.append(section_info)
        return sections
    
    def get_import_info(self) -> List[Dict[str, Any]]:
        imports = []
        try:
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        imports.append({
                            'dll': entry.dll.decode('utf-8', errors='ignore'),
                            'function': imp.name.decode('utf-8', errors='ignore'),
                            'address': imp.address
                        })
        except AttributeError:
            pass
        return imports
    
    def get_export_info(self) -> List[Dict[str, Any]]:
        exports = []
        try:
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.append({
                        'name': exp.name.decode('utf-8', errors='ignore'),
                        'address': exp.address
                    })
        except AttributeError:
            pass
        return exports
    
    def get_security_info(self) -> Dict[str, Any]:
        security = {
            'aslr_enabled': bool(self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040),
            'dep_enabled': bool(self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100),
            'safe_seh': bool(self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x0400),
            'gs_cookie': self.check_gs_cookie()
        }
        return security
    
    def check_gs_cookie(self) -> bool:
        try:
            for section in self.pe.sections:
                if b'__GSHandlerCheck' in section.Data:
                    return True
        except:
            pass
        return False
