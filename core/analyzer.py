# analyzer.py
"""
Analysis engine.
Groups findings and provides insights.
"""

from typing import List, Dict, Any
from collections import defaultdict
from checks.base_check import Finding, Severity


class Analyzer:
    """Analyzes findings and provides grouped insights."""
    
    def __init__(self, findings: List[Finding]):
        """
        Initialize analyzer.
        
        Args:
            findings: List of findings from scanner
        """
        self.findings = findings
        self.by_severity = self._group_by_severity()
        self.by_category = self._group_by_category()
    
    def _group_by_severity(self) -> Dict[Severity, List[Finding]]:
        """Group findings by severity."""
        groups = defaultdict(list)
        for finding in self.findings:
            groups[finding.severity].append(finding)
        return dict(groups)
    
    def _group_by_category(self) -> Dict[str, List[Finding]]:
        """Group findings by category from titles."""
        groups = defaultdict(list)
        for finding in self.findings:
            # Extract category from title
            category = finding.title.split(':')[0] if ':' in finding.title else 'General'
            groups[category].append(finding)
        return dict(groups)
    
    def get_critical_findings(self) -> List[Finding]:
        """Get only critical findings."""
        return self.by_severity.get(Severity.CRITICAL, [])
    
    def get_high_findings(self) -> List[Finding]:
        """Get high severity findings."""
        return self.by_severity.get(Severity.HIGH, [])
    
    def get_priority_findings(self, limit: int = 3) -> List[Finding]:
        """
        Get top priority findings (highest severity).
        
        Args:
            limit: Maximum number of findings to return
            
        Returns:
            List of highest severity findings
        """
        priority = []
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            priority.extend(self.by_severity.get(severity, []))
            if len(priority) >= limit:
                break
        return priority[:limit]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics."""
        return {
            'total_findings': len(self.findings),
            'critical': len(self.by_severity.get(Severity.CRITICAL, [])),
            'high': len(self.by_severity.get(Severity.HIGH, [])),
            'medium': len(self.by_severity.get(Severity.MEDIUM, [])),
            'low': len(self.by_severity.get(Severity.LOW, [])),
            'info': len(self.by_severity.get(Severity.INFO, [])),
            'categories': len(self.by_category)
        }