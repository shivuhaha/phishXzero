# yara_rules.py - YARA Rules for Malware Detection
import re
import hashlib

YARA_RULES = {
    "suspicious_executable_headers": {
        "name": "Suspicious Executable Headers",
        "risk": "CRITICAL",
        "patterns": [
            {"hex": "4d5a", "name": "DOS MZ Header (PE/EXE)", "severity": "HIGH"},
            {"hex": "7f454c46", "name": "ELF Binary Header", "severity": "MEDIUM"},
            {"hex": "cafebabe", "name": "Java Class File", "severity": "MEDIUM"},
        ]
    },
    "suspicious_strings": {
        "name": "Suspicious Strings & Keywords",
        "risk": "HIGH",
        "patterns": [
            "WinExec", "CreateProcessA", "CreateRemoteThread", "VirtualAllocEx",
            "SetWindowsHookEx", "GetProcAddress", "LoadLibrary", "InternetOpen",
            "URLDownloadToFile", "ShellExecute", "cmd.exe /c", "powershell.exe",
            "registry hive", "HKEY_LOCAL_MACHINE", "privilege escalation",
            "ransomware", "botnet", "c2server", "payload"
        ]
    },
    "macro_indicators": {
        "name": "Macro Malware Indicators",
        "risk": "CRITICAL",
        "patterns": [
            "AutoOpen", "AutoExec", "AutoClose", "DocumentOpen",
            "Workbook_Open", "Worksheet_Activate", "Execute", "Shell",
            "ActivateMacro", "Sub Auto_", "Sub Document_Open"
        ]
    },
    "obfuscation": {
        "name": "Obfuscation Techniques",
        "risk": "HIGH",
        "patterns": [
            r"%[0-9a-f]{2}", "chr(", "chr$(", "hex string", "base64 encoded",
            "unescape", "eval(", "exec(", "compile(", "decode("
        ]
    },
    "network_indicators": {
        "name": "Network Communication Indicators",
        "risk": "HIGH",
        "patterns": [
            r"http[s]?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",  # IP URLs
            r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]+",  # IP:Port
            "www.bit.ly", "goo.gl", "ow.ly", "tinyurl"  # URL shorteners
        ]
    },
    "persistence_mechanisms": {
        "name": "Persistence Mechanisms",
        "risk": "CRITICAL",
        "patterns": [
            "Run", "RunOnce", "Services", "Drivers", "StartupFolder",
            "HKEY_CURRENT_USER", "Software\\Microsoft", "CurrentVersion\\Run",
            "NTFS Alternative Data Stream", "Scheduled Task", "WMI Event"
        ]
    },
    "credentials_stealing": {
        "name": "Credential Stealing Indicators",
        "risk": "CRITICAL",
        "patterns": [
            "browser cookie", "keylogger", "password dump", "credential",
            "LSASS", "mimikatz", "hashdump", "pwdump", "registry sam dump",
            "credential provider", "password history"
        ]
    },
    "ransomware_indicators": {
        "name": "Ransomware Indicators",
        "risk": "CRITICAL",
        "patterns": [
            "encrypt", "ransom", "pay bitcoin", ".locked", ".encrypted",
            "file extension change", "shadow copy", "volume shadow copy",
            "wmic delete shadowcopy", "vssadmin delete shadows"
        ]
    }
}

class YARAScanner:
    """YARA-based malware detection engine"""
    
    def __init__(self):
        self.rules = YARA_RULES
        self.file_hashes = {}  # Cache of known malware hashes
    
    def scan_bytes(self, file_bytes, filename=""):
        """Scan file bytes for malware indicators"""
        results = {
            'filename': filename,
            'file_size': len(file_bytes),
            'file_hash': hashlib.sha256(file_bytes).hexdigest(),
            'detections': [],
            'risk_level': 'CLEAN',
            'verdict': 'SAFE',
            'confidence': 0.0
        }
        
        try:
            file_hex = file_bytes.hex()
            file_string = file_bytes.decode('utf-8', errors='ignore')
            file_string_lower = file_string.lower()
            
            # Check executable headers
            detections = 0
            severity_scores = []
            
            for rule_name, rule_data in self.rules.items():
                rule_detections = []
                
                if rule_name == "suspicious_executable_headers":
                    for pattern in rule_data['patterns']:
                        if pattern['hex'] in file_hex:
                            rule_detections.append({
                                'pattern': pattern['name'],
                                'severity': pattern['severity'],
                                'rule': rule_name
                            })
                            severity_scores.append(self._severity_to_score(pattern['severity']))
                
                elif rule_name == "suspicious_strings":
                    for pattern in rule_data['patterns']:
                        if pattern.lower() in file_string_lower:
                            rule_detections.append({
                                'pattern': pattern,
                                'severity': 'HIGH',
                                'rule': rule_name
                            })
                            severity_scores.append(0.7)
                
                elif rule_name == "macro_indicators":
                    for pattern in rule_data['patterns']:
                        if pattern in file_string_lower:
                            rule_detections.append({
                                'pattern': pattern,
                                'severity': 'CRITICAL',
                                'rule': rule_name
                            })
                            severity_scores.append(0.95)
                
                elif rule_name == "obfuscation":
                    for pattern in rule_data['patterns']:
                        try:
                            if re.search(pattern, file_string_lower):
                                rule_detections.append({
                                    'pattern': pattern,
                                    'severity': 'HIGH',
                                    'rule': rule_name
                                })
                                severity_scores.append(0.7)
                        except:
                            pass
                
                elif rule_name == "network_indicators":
                    for pattern in rule_data['patterns']:
                        try:
                            if re.search(pattern, file_string_lower):
                                rule_detections.append({
                                    'pattern': pattern,
                                    'severity': 'MEDIUM',
                                    'rule': rule_name
                                })
                                severity_scores.append(0.6)
                        except:
                            pass
                
                elif rule_name in ["persistence_mechanisms", "credentials_stealing", "ransomware_indicators"]:
                    for pattern in rule_data['patterns']:
                        if pattern.lower() in file_string_lower:
                            rule_detections.append({
                                'pattern': pattern,
                                'severity': 'CRITICAL',
                                'rule': rule_name
                            })
                            severity_scores.append(0.95)
                
                if rule_detections:
                    results['detections'].append({
                        'rule': rule_name,
                        'description': rule_data['name'],
                        'matched_patterns': rule_detections,
                        'count': len(rule_detections)
                    })
                    detections += len(rule_detections)
            
            # Calculate final risk level
            if detections == 0:
                results['risk_level'] = 'CLEAN'
                results['verdict'] = 'SAFE - No malware indicators detected'
                results['confidence'] = 1.0
            elif detections >= 10:
                results['risk_level'] = 'CRITICAL'
                results['verdict'] = 'MALWARE DETECTED'
                results['confidence'] = min(0.99, sum(severity_scores) / len(severity_scores)) if severity_scores else 0.9
            elif detections >= 5:
                results['risk_level'] = 'HIGH'
                results['verdict'] = 'HIGHLY SUSPICIOUS'
                results['confidence'] = 0.75
            elif detections >= 2:
                results['risk_level'] = 'MEDIUM'
                results['verdict'] = 'SUSPICIOUS'
                results['confidence'] = 0.6
            else:
                results['risk_level'] = 'LOW'
                results['verdict'] = 'POTENTIALLY UNWANTED'
                results['confidence'] = 0.4
            
        except Exception as e:
            results['error'] = str(e)
            results['risk_level'] = 'ERROR'
        
        return results
    
    def scan_text(self, text_content):
        """Scan text content for malware indicators"""
        results = {
            'content_type': 'text',
            'detections': [],
            'risk_level': 'CLEAN',
            'verdict': 'SAFE'
        }
        
        text_lower = text_content.lower()
        
        for rule_name, rule_data in self.rules.items():
            if rule_name in ["suspicious_strings", "macro_indicators", "credentials_stealing"]:
                matched = []
                for pattern in rule_data['patterns']:
                    if isinstance(pattern, str):
                        if pattern.lower() in text_lower:
                            matched.append(pattern)
                
                if matched:
                    results['detections'].append({
                        'rule': rule_name,
                        'description': rule_data['name'],
                        'matches': matched,
                        'severity': rule_data['risk']
                    })
        
        if len(results['detections']) > 0:
            results['risk_level'] = 'MEDIUM'
            results['verdict'] = 'SUSPICIOUS CONTENT DETECTED'
        
        return results
    
    def _severity_to_score(self, severity):
        """Convert severity level to numeric score"""
        scores = {
            'CRITICAL': 0.95,
            'HIGH': 0.7,
            'MEDIUM': 0.5,
            'LOW': 0.2
        }
        return scores.get(severity, 0.3)
    
    def get_rule_info(self, rule_name):
        """Get information about a specific YARA rule"""
        return self.rules.get(rule_name, None)
    
    def list_all_rules(self):
        """Get list of all available rules"""
        return {
            name: {
                'description': data['name'],
                'risk': data['risk'],
                'pattern_count': len(data['patterns'])
            }
            for name, data in self.rules.items()
        }
