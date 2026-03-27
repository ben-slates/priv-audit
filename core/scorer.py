"""
Risk scoring system.
Calculates risk scores based on findings.
"""

from typing import List, Dict, Any
from checks.base_check import Finding, Severity


class Scorer:
    """Calculates risk scores for findings."""
    
    # Realistic base weights
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 10,
        Severity.HIGH: 6,
        Severity.MEDIUM: 3,
        Severity.LOW: 1,
        Severity.INFO: 0
    }
    
    # Reliability multipliers (higher = more reliable)
    RELIABILITY_MULTIPLIERS = {
        'high': 1.0,      # 100% - Works reliably
        'medium': 0.7,    # 70% - Usually works
        'conditional': 0.5, # 50% - Requires specific conditions
        'low': 0.3        # 30% - Unreliable, needs manual analysis
    }
    
    # Impact multipliers (what privilege level can be achieved)
    IMPACT_MULTIPLIERS = {
        'root': 1.0,
        'user': 0.5,
        'info': 0.1
    }
    
    def __init__(self, findings: List[Finding]):
        """
        Initialize scorer.
        
        Args:
            findings: List of findings to score
        """
        self.findings = findings
        self.deduplicated = self._deduplicate_findings(findings)
        self.scores = self._calculate_scores()
    
    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Deduplicate findings for accurate scoring."""
        seen = set()
        unique = []
        
        for finding in findings:
            real_path = finding.metadata.get('real_path', finding.metadata.get('path', ''))
            key = f"{finding.title}_{real_path}"
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        
        return unique
    
    def _determine_impact(self, finding: Finding) -> str:
        """Determine the impact level of a finding."""
        title = finding.title.lower()
        
        if any(word in title for word in ['root', 'sudo', 'suid', 'docker', 'kernel']):
            return 'root'
        elif any(word in title for word in ['writable', 'cron', 'service']):
            return 'user'
        else:
            return 'info'
    
    def _calculate_scores(self) -> List[Dict[str, Any]]:
        """Calculate individual scores for each finding."""
        scored = []
        
        for finding in self.deduplicated:
            base_score = self.SEVERITY_WEIGHTS[finding.severity]
            
            # Apply reliability multiplier
            reliability = finding.metadata.get('reliability', 'medium')
            reliability_mult = self.RELIABILITY_MULTIPLIERS.get(reliability, 0.5)
            
            # Apply impact multiplier
            impact = self._determine_impact(finding)
            impact_mult = self.IMPACT_MULTIPLIERS.get(impact, 0.5)
            
            # Final score = base * reliability * impact
            final_score = base_score * reliability_mult * impact_mult
            
            scored.append({
                'finding': finding,
                'base_score': base_score,
                'reliability': reliability,
                'reliability_multiplier': reliability_mult,
                'impact': impact,
                'impact_multiplier': impact_mult,
                'final_score': final_score
            })
        
        # Sort by final score descending
        scored.sort(key=lambda x: x['final_score'], reverse=True)
        return scored
    
    def get_top_risks(self, limit: int = 5) -> List[Dict[str, Any]]:
        """
        Get highest risk findings.
        
        Args:
            limit: Maximum number to return
            
        Returns:
            List of highest risk findings with scores
        """
        return self.scores[:limit]
    
    def get_total_risk_score(self) -> float:
        """Calculate total risk score across all findings."""
        return sum(item['final_score'] for item in self.scores)
    
    def get_risk_level(self) -> str:
        """Get overall risk level based on total score."""
        total = self.get_total_risk_score()
        
        if total > 40:
            return "CRITICAL"
        elif total > 25:
            return "HIGH"
        elif total > 10:
            return "MEDIUM"
        elif total > 3:
            return "LOW"
        else:
            return "INFO"
    
    def get_risk_breakdown(self) -> Dict[str, Any]:
        """Get detailed risk breakdown."""
        return {
            'total_score': self.get_total_risk_score(),
            'risk_level': self.get_risk_level(),
            'by_severity': self._get_score_by_severity(),
            'by_reliability': self._get_score_by_reliability(),
            'top_risks': self.get_top_risks(3)
        }
    
    def _get_score_by_severity(self) -> Dict[str, float]:
        """Get total score grouped by severity."""
        scores = {s.name: 0 for s in Severity}
        for item in self.scores:
            scores[item['finding'].severity.name] += item['final_score']
        return scores
    
    def _get_score_by_reliability(self) -> Dict[str, float]:
        """Get total score grouped by reliability."""
        scores = {'high': 0, 'medium': 0, 'low': 0, 'conditional': 0}
        for item in self.scores:
            reliability = item.get('reliability', 'medium')
            scores[reliability] += item['final_score']
        return scores