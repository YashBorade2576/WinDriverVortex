import os
import json
import pefile
import capstone
from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass
class AnalysisFinding:
    function_name: str
    vulnerability_type: str
    address: int
    severity: int
    description: str
    evidence: str

class DriverAnalysisEngine:
    def __init__(self):
        self.findings = []
        self.pe_object = None
        self.disasm_engine = None
        
        self.risky_functions = [
            'strcpy', 'strcat', 'gets', 'sprintf', 'vsprintf',
            'memcpy', 'memset', 'strncpy', 'wcscpy',
            'ExAllocatePool', 'ExAllocatePoolWithTag'
        ]
        
        self.code_patterns = {
            'buffer_overflow': [
                b'\x83\xc4\x04\xc3',
                b'\xe8....\x83\xc4'
            ],
            'integer_overflow': [
                b'\x0f\xaf....\x83\xc8\xff'
            ],
            'memory_corruption': [
                b'\xff\x15....\x83\xc8\xff'
            ]
        }

    def load_target_file(self, file_path: str) -> bool:
        try:
            self.pe_object = pefile.PE(file_path)
            
            arch = capstone.CS_ARCH_X86
            mode = capstone.CS_MODE_32
            
            if self.pe_object.FILE_HEADER.Machine == 0x8664:
                mode = capstone.CS_MODE_64
                
            self.disasm_engine = capstone.Cs(arch, mode)
            self.disasm_engine.detail = True
            
            return True
            
        except Exception as load_error:
            print(f"Failed to load file: {load_error}")
            return False

    def check_imported_functions(self):
        if not self.pe_object:
            return
            
        try:
            for import_module in self.pe_object.DIRECTORY_ENTRY_IMPORT:
                for imported_function in import_module.imports:
                    if imported_function.name:
                        func_name = imported_function.name.decode('utf-8', errors='ignore')
                        for risky_func in self.risky_functions:
                            if risky_func.lower() in func_name.lower():
                                self.findings.append(AnalysisFinding(
                                    function_name=f"Imported_{func_name}",
                                    vulnerability_type="Risky Function Import",
                                    address=imported_function.address if imported_function.address else 0,
                                    severity=4,
                                    description=f"Potentially dangerous function: {func_name}",
                                    evidence=f"Imported from {import_module.dll.decode('utf-8', errors='ignore')}"
                                ))
        except AttributeError:
            pass

    def analyze_executable_sections(self):
        if not self.pe_object or not self.disasm_engine:
            return
            
        for section in self.pe_object.sections:
            if section.Characteristics & 0x20000000:
                section_data = section.get_data()
                self.scan_section_content(section_data, section.VirtualAddress)

    def scan_section_content(self, data: bytes, base_addr: int):
        for pattern_name, patterns in self.code_patterns.items():
            for pattern in patterns:
                matches = self.find_pattern_matches(data, pattern)
                for match_pos in matches:
                    self.findings.append(AnalysisFinding(
                        function_name="Code Pattern Match",
                        vulnerability_type=pattern_name.replace('_', ' ').title(),
                        address=base_addr + match_pos,
                        severity=3,
                        description=f"Detected {pattern_name} code pattern",
                        evidence=f"Pattern match at offset 0x{match_pos:X}"
                    ))

    def find_pattern_matches(self, data: bytes, pattern: bytes) -> List[int]:
        matches = []
        pattern_len = len(pattern)
        
        for i in range(len(data) - pattern_len + 1):
            match_found = True
            for j in range(pattern_len):
                if pattern[j] != 0x2E and data[i + j] != pattern[j]:
                    match_found = False
                    break
            if match_found:
                matches.append(i)
                
        return matches

    def analyze_driver(self, file_path: str) -> List[AnalysisFinding]:
        if not self.load_target_file(file_path):
            return []
            
        self.check_imported_functions()
        self.analyze_executable_sections()
        
        return self.findings

    def create_report(self) -> Dict[str, Any]:
        report_data = {
            'findings': [],
            'summary_stats': {
                'total_findings': len(self.findings),
                'critical_count': len([f for f in self.findings if f.severity >= 4]),
                'high_count': len([f for f in self.findings if f.severity == 3]),
                'medium_count': len([f for f in self.findings if f.severity == 2]),
                'low_count': len([f for f in self.findings if f.severity <= 1])
            }
        }
        
        for finding in self.findings:
            report_data['findings'].append({
                'function_name': finding.function_name,
                'vulnerability_type': finding.vulnerability_type,
                'address': finding.address,
                'severity': finding.severity,
                'description': finding.description,
                'evidence': finding.evidence
            })
            
        return report_data

def analyze_driver_file(driver_path: str):
    analyzer = DriverAnalysisEngine()
    findings = analyzer.analyze_driver(driver_path)
    report = analyzer.create_report()
    
    return report

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python driver_analyzer.py <driver_file_path>")
        sys.exit(1)
        
    analysis_result = analyze_driver_file(sys.argv[1])
    print(json.dumps(analysis_result, indent=2))
