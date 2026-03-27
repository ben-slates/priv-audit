# json_report.py
"""
JSON report generator.
Creates structured JSON output for automation.
"""

import json
from typing import List, Dict, Any
from datetime import datetime
from checks.base_check import Finding
from core.analyzer import Analyzer
from core.scorer import Scorer
from core.attack_path import AttackPathBuilder
from utils.helpers import SystemHelpers


class JSONReport:
    """Generates JSON report from findings."""
    
    def __init__(self, findings: List[Finding]):
        """
        Initialize JSON report generator.
        
        Args:
            findings: List of findings
        """
        self.findings = findings
        self.analyzer = Analyzer(findings)
        self.scorer = Scorer(findings)
        self.path_builder = AttackPathBuilder(findings)
    
    def generate(self, filename: str = None) -> Dict[str, Any]:
        """
        Generate JSON report.
        
        Args:
            filename: Optional filename to write to
            
        Returns:
            Dictionary containing report data
        """
        report = {
            'tool': 'PrivAudit',
            'version': '1.0.0',
            'timestamp': datetime.now().isoformat(),
            'system': {
                'hostname': self._get_hostname(),
                'user': SystemHelpers.get_current_user(),
                'os': self._get_os_info(),
                'kernel': self._get_kernel_version()
            },
            'summary': self.analyzer.get_summary(),
            'risk': {
                'total_score': self.scorer.get_total_risk_score(),
                'risk_level': self.scorer.get_risk_level(),
                'top_risks': self._format_top_risks()
            },
            'attack_paths': self._format_attack_paths(),
            'quick_wins': self._format_quick_wins(),
            'findings': [self._format_finding(f) for f in self.findings],
            'findings_by_severity': self._group_findings_by_severity()
        }
        
        if filename:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
        
        return report
    
    def _format_finding(self, finding: Finding) -> Dict[str, Any]:
        """Format a single finding for JSON."""
        return {
            'title': finding.title,
            'description': finding.description,
            'severity': finding.severity.name,
            'severity_score': finding.severity.value,
            'exploit_suggestion': finding.exploit_suggestion,
            'remediation': finding.remediation,
            'metadata': finding.metadata
        }
    
    def _format_top_risks(self) -> List[Dict[str, Any]]:
        """Format top risks."""
        top_risks = self.scorer.get_top_risks(5)
        return [{
            'finding': self._format_finding(risk['finding']),
            'score': risk['final_score'],
            'base_score': risk['base_score'],
            'multiplier': risk['multiplier']
        } for risk in top_risks]
    
    def _format_attack_paths(self) -> List[Dict[str, Any]]:
        """Format attack paths."""
        paths = self.path_builder.get_paths()
        return [{
            'name': path['name'],
            'likelihood': path['likelihood'],
            'impact': path['impact'],
            'steps': path['steps'],
            'findings': [self._format_finding(f) for f in path['findings']]
        } for path in paths]
    
    def _format_quick_wins(self) -> List[Dict[str, Any]]:
        """Format quick wins."""
        quick_wins = self.path_builder.get_quick_wins()
        return [self._format_finding(f) for f in quick_wins]
    
    def _group_findings_by_severity(self) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by severity."""
        grouped = {}
        for severity, findings in self.analyzer.by_severity.items():
            grouped[severity.name] = [self._format_finding(f) for f in findings]
        return grouped
    
    def _get_hostname(self) -> str:
        """Get system hostname."""
        import socket
        return socket.gethostname()
    
    def _get_os_info(self) -> str:
        """Get OS information."""
        try:
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if line.startswith('PRETTY_NAME='):
                        return line.split('=')[1].strip().strip('"')
        except:
            pass
        return 'Unknown'
    
    def _get_kernel_version(self) -> str:
        """Get kernel version."""
        try:
            import platform
            return platform.release()
        except:
            return 'Unknown'