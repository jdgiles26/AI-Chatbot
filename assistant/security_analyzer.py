"""
Security Analyzer for Mac Mini M2
Analyzes scan results for security risks and vulnerabilities.
"""

import re
from typing import Dict, List
from pathlib import Path


class SecurityAnalyzer:
    """Analyzes file system data for security vulnerabilities and risks."""
    
    def __init__(self):
        self.vulnerability_database = self._load_vulnerability_patterns()
        
    def _load_vulnerability_patterns(self) -> Dict:
        """Load known vulnerability patterns and indicators."""
        return {
            'dangerous_permissions': {
                'patterns': ['777', '666', '776', '767'],
                'severity': 'high',
                'description': 'Overly permissive file permissions detected'
            },
            'suspicious_extensions': {
                'patterns': ['.sh', '.command', '.pkg', '.dmg', '.app'],
                'severity': 'medium',
                'description': 'Executable or package file detected'
            },
            'hidden_executables': {
                'severity': 'high',
                'description': 'Hidden executable file detected'
            },
            'world_writable': {
                'severity': 'critical',
                'description': 'World-writable file or directory detected'
            },
            'suid_sgid': {
                'severity': 'high',
                'description': 'SUID/SGID executable detected'
            },
            'system_modification': {
                'severity': 'critical',
                'description': 'System file modification detected'
            }
        }
    
    def analyze(self, scan_results: Dict) -> Dict:
        """
        Perform comprehensive security analysis on scan results.
        
        Args:
            scan_results: Results from file system scan
            
        Returns:
            Dictionary containing analysis results and findings
        """
        analysis = {
            'timestamp': scan_results.get('scan_time'),
            'platform': scan_results.get('platform'),
            'findings': [],
            'total_issues': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'scan_results': scan_results
        }
        
        # Analyze files
        for file_info in scan_results.get('files', []):
            findings = self._analyze_file(file_info)
            analysis['findings'].extend(findings)
        
        # Analyze directories
        for dir_info in scan_results.get('directories', []):
            findings = self._analyze_directory(dir_info)
            analysis['findings'].extend(findings)
        
        # Analyze suspicious files
        for file_info in scan_results.get('suspicious_files', []):
            finding = {
                'type': 'suspicious_file',
                'severity': 'medium',
                'path': file_info.get('path'),
                'description': 'File flagged as potentially suspicious',
                'details': file_info,
                'mitigation': 'Review file contents and purpose. Remove if unnecessary.'
            }
            analysis['findings'].append(finding)
        
        # Count findings by severity
        for finding in analysis['findings']:
            severity = finding.get('severity', 'low')
            if severity == 'critical':
                analysis['critical'] += 1
            elif severity == 'high':
                analysis['high'] += 1
            elif severity == 'medium':
                analysis['medium'] += 1
            else:
                analysis['low'] += 1
        
        analysis['total_issues'] = len(analysis['findings'])
        
        # Add recommendations
        analysis['recommendations'] = self._generate_recommendations(analysis)
        
        return analysis
    
    def _analyze_file(self, file_info: Dict) -> List[Dict]:
        """Analyze a single file for security issues."""
        findings = []
        
        # Check permissions
        perms = file_info.get('permissions', '000')
        if perms in self.vulnerability_database['dangerous_permissions']['patterns']:
            findings.append({
                'type': 'dangerous_permissions',
                'severity': 'high',
                'path': file_info.get('path'),
                'description': f"File has overly permissive permissions: {perms}",
                'details': {
                    'permissions': perms,
                    'file_info': file_info
                },
                'mitigation': f"Change permissions with: chmod 644 '{file_info.get('path')}'",
                'references': [
                    'https://www.cyberciti.biz/tips/understanding-linux-unix-umask-value-usage.html',
                    'https://support.apple.com/guide/terminal/change-permissions-apdd0bb11c46/mac'
                ]
            })
        
        # Check for world-writable files
        if len(perms) == 3 and perms[2] in ['2', '3', '6', '7']:
            findings.append({
                'type': 'world_writable',
                'severity': 'critical',
                'path': file_info.get('path'),
                'description': 'File is world-writable, allowing any user to modify it',
                'details': {
                    'permissions': perms,
                    'file_info': file_info
                },
                'mitigation': f"Remove world-write permission: chmod o-w '{file_info.get('path')}'",
                'references': [
                    'https://www.sans.org/blog/the-danger-of-world-writable-files/',
                    'https://www.cisecurity.org/benchmark/apple_os'
                ]
            })
        
        # Check for hidden executables
        if file_info.get('name', '').startswith('.') and file_info.get('is_executable'):
            findings.append({
                'type': 'hidden_executable',
                'severity': 'high',
                'path': file_info.get('path'),
                'description': 'Hidden executable file detected - potential security risk',
                'details': file_info,
                'mitigation': 'Review file purpose. If unknown or unnecessary, remove it.',
                'references': [
                    'https://www.malwarebytes.com/blog/news/2020/01/mac-malware-hiding-in-plain-sight',
                    'https://objective-see.com/malware.html'
                ]
            })
        
        # Check for executables owned by root
        if file_info.get('is_executable') and file_info.get('owner_uid') == 0:
            findings.append({
                'type': 'root_executable',
                'severity': 'medium',
                'path': file_info.get('path'),
                'description': 'Executable file owned by root - verify legitimacy',
                'details': file_info,
                'mitigation': 'Verify this is a legitimate system executable. Check with: ls -la',
                'references': [
                    'https://support.apple.com/guide/terminal/about-user-and-group-permissions-apd67e92c11/mac'
                ]
            })
        
        # Check for sensitive file extensions in user directories
        sensitive_extensions = ['.key', '.pem', '.p12', '.keychain', '.password']
        if file_info.get('extension') in sensitive_extensions:
            if '/Users/' in file_info.get('path', ''):
                findings.append({
                    'type': 'sensitive_file',
                    'severity': 'medium',
                    'path': file_info.get('path'),
                    'description': 'Sensitive file detected - ensure proper encryption',
                    'details': file_info,
                    'mitigation': 'Ensure file is properly encrypted and has restricted permissions (600)',
                    'references': [
                        'https://support.apple.com/guide/security/encryption-and-data-protection-sec1c5d9f1c3/web'
                    ]
                })
        
        return findings
    
    def _analyze_directory(self, dir_info: Dict) -> List[Dict]:
        """Analyze a directory for security issues."""
        findings = []
        
        # Check directory permissions
        perms = dir_info.get('permissions', '000')
        if perms in ['777', '776', '767']:
            findings.append({
                'type': 'dangerous_directory_permissions',
                'severity': 'high',
                'path': dir_info.get('path'),
                'description': f"Directory has overly permissive permissions: {perms}",
                'details': dir_info,
                'mitigation': f"Change permissions with: chmod 755 '{dir_info.get('path')}'",
                'references': [
                    'https://www.cyberciti.biz/tips/understanding-linux-unix-umask-value-usage.html'
                ]
            })
        
        # Check for world-writable directories
        if len(perms) == 3 and perms[2] in ['2', '3', '6', '7']:
            findings.append({
                'type': 'world_writable_directory',
                'severity': 'critical',
                'path': dir_info.get('path'),
                'description': 'Directory is world-writable - severe security risk',
                'details': dir_info,
                'mitigation': f"Remove world-write permission: chmod o-w '{dir_info.get('path')}'",
                'references': [
                    'https://www.cisecurity.org/benchmark/apple_os',
                    'https://www.sans.org/blog/the-danger-of-world-writable-files/'
                ]
            })
        
        return findings
    
    def _generate_recommendations(self, analysis: Dict) -> List[Dict]:
        """Generate security recommendations based on analysis."""
        recommendations = []
        
        if analysis['critical'] > 0:
            recommendations.append({
                'priority': 'critical',
                'title': 'Address Critical Security Issues Immediately',
                'description': f"Found {analysis['critical']} critical security issues that require immediate attention.",
                'actions': [
                    'Review all world-writable files and directories',
                    'Remove or restrict permissions on sensitive files',
                    'Scan for malware using Apple\'s built-in tools or third-party security software'
                ]
            })
        
        if analysis['high'] > 0:
            recommendations.append({
                'priority': 'high',
                'title': 'Review High-Severity Security Findings',
                'description': f"Found {analysis['high']} high-severity security issues.",
                'actions': [
                    'Review and correct file permissions',
                    'Verify legitimacy of hidden executables',
                    'Update security policies and access controls'
                ]
            })
        
        # General recommendations
        recommendations.append({
            'priority': 'general',
            'title': 'Security Best Practices',
            'description': 'Follow these best practices to maintain system security',
            'actions': [
                'Keep macOS and all applications up to date',
                'Enable FileVault disk encryption',
                'Use strong passwords and enable two-factor authentication',
                'Regularly backup important data',
                'Be cautious when installing new software',
                'Review and limit application permissions in System Preferences'
            ]
        })
        
        return recommendations
