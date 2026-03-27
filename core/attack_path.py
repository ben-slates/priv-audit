"""
Attack path builder.
Constructs chains of vulnerabilities that can be combined.
"""

from typing import List, Dict, Any, Set, Tuple
from checks.base_check import Finding, Severity


class AttackPathBuilder:
    """Builds attack paths by chaining findings."""
    
    def __init__(self, findings: List[Finding]):
        """
        Initialize attack path builder.
        
        Args:
            findings: List of findings to analyze
        """
        self.findings = findings
        self.deduplicated_findings = self._deduplicate_findings(findings)
        self.paths = self._build_paths()
    
    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Deduplicate findings by unique key."""
        seen = set()
        unique = []
        
        for finding in findings:
            # Create unique key based on title and normalized path
            real_path = finding.metadata.get('real_path', finding.metadata.get('path', ''))
            key = f"{finding.title}_{real_path}"
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        
        return unique
    
    def _build_paths(self) -> List[Dict[str, Any]]:
        """Build attack paths from findings."""
        paths = []
        
        # Define attack chains with detailed steps
        chains = [
            {
                'name': 'SUID Binary to Root Shell',
                'description': 'Exploit a SUID binary to spawn a root shell',
                'steps': [
                    {'type': 'Exploitable SUID', 'severity': Severity.CRITICAL, 'reliability': 'high'}
                ],
                'impact': 'Root Shell',
                'time_to_exploit': 'Immediate'
            },
            {
                'name': 'PATH Hijack to Root',
                'description': 'Hijack PATH to execute malicious code with elevated privileges',
                'steps': [
                    {'type': 'Writable PATH', 'severity': Severity.HIGH},
                    {'type': 'Sudo', 'severity': Severity.CRITICAL}
                ],
                'impact': 'Root Shell',
                'time_to_exploit': 'Minutes (depends on execution trigger)'
            },
            {
                'name': 'Writable Cron Job to Root',
                'description': 'Modify cron job to execute malicious code as root',
                'steps': [
                    {'type': 'Writable Cron', 'severity': Severity.CRITICAL}
                ],
                'impact': 'Root Execution',
                'time_to_exploit': 'Up to 1 hour (depends on cron schedule)'
            },
            {
                'name': 'Writable System Service to Root',
                'description': 'Modify system service to execute malicious code as root',
                'steps': [
                    {'type': 'Writable Service File', 'severity': Severity.CRITICAL}
                ],
                'impact': 'Root Execution on Restart',
                'time_to_exploit': 'Depends on service restart'
            },
            {
                'name': 'Sudo Misconfiguration to Root',
                'description': 'Use sudo to escalate privileges',
                'steps': [
                    {'type': 'Sudo', 'severity': Severity.CRITICAL}
                ],
                'impact': 'Root Shell',
                'time_to_exploit': 'Immediate'
            },
            {
                'name': 'Docker Group to Root',
                'description': 'Use Docker group membership to escape to root',
                'steps': [
                    {'type': 'Docker', 'severity': Severity.CRITICAL}
                ],
                'impact': 'Root Access',
                'time_to_exploit': 'Immediate'
            },
            {
                'name': 'Kernel Exploit to Root',
                'description': 'Use kernel vulnerability to gain root',
                'steps': [
                    {'type': 'Kernel', 'severity': Severity.CRITICAL}
                ],
                'impact': 'Root Shell',
                'time_to_exploit': 'Variable (requires compilation)'
            },
            {
                'name': 'SUID (Conditional) to Root',
                'description': 'Exploit conditional SUID binary with limited reliability',
                'steps': [
                    {'type': 'SUID', 'severity': Severity.MEDIUM}
                ],
                'impact': 'Possible Root Access',
                'time_to_exploit': 'Variable (requires testing)'
            }
        ]
        
        # Find matching paths
        for chain in chains:
            path_findings = []
            used_findings = set()
            all_steps_matched = True
            
            for step in chain['steps']:
                step_matched = False
                
                # Find unique findings that match this step
                for finding in self.deduplicated_findings:
                    key = f"{finding.title}_{finding.metadata.get('real_path', finding.metadata.get('path', ''))}"
                    if key in used_findings:
                        continue
                    
                    # Check if finding matches step type
                    if step['type'] in finding.title:
                        # Check severity requirement
                        if finding.severity.value >= step['severity'].value:
                            # Check reliability if specified
                            reliability = finding.metadata.get('reliability', 'medium')
                            if 'reliability' in step and reliability != step['reliability']:
                                continue
                            
                            path_findings.append(finding)
                            used_findings.add(key)
                            step_matched = True
                            break
                
                if not step_matched:
                    all_steps_matched = False
                    break
            
            if all_steps_matched and len(path_findings) == len(chain['steps']):
                # Calculate reliability based on findings
                reliability_score = self._calculate_reliability(path_findings)
                likelihood = self._calculate_likelihood(path_findings, reliability_score)
                
                paths.append({
                    'name': chain['name'],
                    'description': chain['description'],
                    'findings': path_findings,
                    'likelihood': likelihood,
                    'reliability_score': reliability_score,
                    'impact': chain['impact'],
                    'time_to_exploit': chain['time_to_exploit'],
                    'steps': len(path_findings)
                })
        
        # Sort by reliability and likelihood
        paths.sort(key=lambda x: (x['reliability_score'], x['likelihood']), reverse=True)
        
        # Remove duplicate paths
        seen_names = set()
        unique_paths = []
        for path in paths:
            if path['name'] not in seen_names:
                seen_names.add(path['name'])
                unique_paths.append(path)
        
        return unique_paths[:5]  # Top 5 unique paths
    
    def _calculate_reliability(self, findings: List[Finding]) -> float:
        """Calculate overall reliability score (0-100)."""
        if not findings:
            return 0
        
        total = 0
        reliability_map = {'high': 100, 'medium': 60, 'low': 30, 'conditional': 40}
        
        for finding in findings:
            reliability = finding.metadata.get('reliability', 'medium')
            total += reliability_map.get(reliability, 50)
        
        return total / len(findings)
    
    def _calculate_likelihood(self, findings: List[Finding], reliability_score: float) -> float:
        """Calculate likelihood score based on findings and reliability."""
        if not findings:
            return 0
        
        # Base likelihood on severity and reliability
        severity_score = sum(finding.severity.value for finding in findings)
        max_possible = len(findings) * 5
        
        # Combine severity and reliability
        likelihood = (severity_score / max_possible) * 100
        likelihood = (likelihood * 0.6) + (reliability_score * 0.4)
        
        return min(likelihood, 100)
    
    def get_paths(self) -> List[Dict[str, Any]]:
        """Get all attack paths."""
        return self.paths
    
    def get_most_likely_path(self) -> Dict[str, Any]:
        """Get the most likely attack path."""
        if self.paths:
            return self.paths[0]
        return {'name': 'No Clear Path', 'findings': [], 'likelihood': 0, 'reliability_score': 0}
    
    def get_fastest_path(self) -> Dict[str, Any]:
        """Get the fastest path to root."""
        if not self.paths:
            return {'name': 'No Clear Path'}
        
        # Prioritize "Immediate" time_to_exploit
        for path in self.paths:
            if path.get('time_to_exploit') == 'Immediate':
                return path
        return self.paths[0] if self.paths else {'name': 'No Clear Path'}
    
    def get_most_reliable_path(self) -> Dict[str, Any]:
        """Get the most reliable path to root."""
        if not self.paths:
            return {'name': 'No Clear Path'}
        
        # Sort by reliability score
        sorted_paths = sorted(self.paths, key=lambda x: x.get('reliability_score', 0), reverse=True)
        return sorted_paths[0]
    
    def get_quick_wins(self) -> List[Dict[str, Any]]:
        """Get findings that are quick wins for attackers."""
        quick_wins = []
        seen = set()
        
        for finding in self.deduplicated_findings:
            # Quick win criteria: high reliability and critical/high severity
            reliability = finding.metadata.get('reliability', 'medium')
            if reliability in ['high', 'conditional'] and finding.severity in [Severity.CRITICAL, Severity.HIGH]:
                key = f"{finding.title}_{finding.metadata.get('real_path', finding.metadata.get('path', ''))}"
                if key not in seen:
                    seen.add(key)
                    quick_wins.append({
                        'finding': finding,
                        'time_to_exploit': 'Immediate' if reliability == 'high' else 'Conditional',
                        'reliability': reliability
                    })
        
        # Sort by reliability
        quick_wins.sort(key=lambda x: 0 if x['reliability'] == 'high' else 1)
        return quick_wins[:3]  # Top 3 quick wins