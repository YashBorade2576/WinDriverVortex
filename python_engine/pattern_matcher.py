import re
from typing import List, Dict, Any

class PatternMatcher:
    def __init__(self):
        self.vulnerability_patterns = {
            'stack_overflow': [
                {
                    'pattern': b'\x83\xc4.\xc3',
                    'description': 'Stack adjustment before return',
                    'severity': 3
                }
            ],
            'heap_overflow': [
                {
                    'pattern': b'\xff\x15....\x83\xc8\xff',
                    'description': 'Heap allocation pattern',
                    'severity': 4
                }
            ],
            'use_after_free': [
                {
                    'pattern': b'\x8b\x08\xff\x51.\x8b\xf0\x85\xf6',
                    'description': 'Potential use after free',
                    'severity': 5
                }
            ]
        }
    
    def scan_for_patterns(self, data: bytes, base_address: int = 0) -> List[Dict[str, Any]]:
        findings = []
        
        for vuln_type, patterns in self.vulnerability_patterns.items():
            for pattern_info in patterns:
                matches = self.find_byte_pattern(data, pattern_info['pattern'])
                for match_offset in matches:
                    findings.append({
                        'type': vuln_type,
                        'address': base_address + match_offset,
                        'severity': pattern_info['severity'],
                        'description': pattern_info['description'],
                        'evidence': f"Pattern match at offset 0x{match_offset:X}"
                    })
        
        return findings
    
    def find_byte_pattern(self, data: bytes, pattern: bytes) -> List[int]:
        matches = []
        pattern_len = len(pattern)
        
        for i in range(len(data) - pattern_len + 1):
            match = True
            for j in range(pattern_len):
                if pattern[j] != 0x2E and data[i + j] != pattern[j]:
                    match = False
                    break
            if match:
                matches.append(i)
        
        return matches
    
    def match_function_names(self, function_names: List[str]) -> List[Dict[str, Any]]:
        risky_patterns = {
            'strcpy': 4,
            'strcat': 4,
            'gets': 5,
            'sprintf': 4,
            'memcpy': 3
        }
        
        findings = []
        for func_name in function_names:
            for risky_func, severity in risky_patterns.items():
                if risky_func in func_name.lower():
                    findings.append({
                        'type': 'dangerous_function',
                        'function_name': func_name,
                        'severity': severity,
                        'description': f'Use of dangerous function: {risky_func}',
                        'evidence': f'Function name: {func_name}'
                    })
        
        return findings
