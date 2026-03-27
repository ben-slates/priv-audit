"""
CLI output formatter.
Provides colored terminal output for findings.
"""

from typing import List
from checks.base_check import Finding, Severity
from core.analyzer import Analyzer
from core.scorer import Scorer
from core.attack_path import AttackPathBuilder


class CLIOutput:
    """Formats findings for CLI display."""
    
    # Color codes
    COLORS = {
        Severity.CRITICAL: '\033[91m',  # Red
        Severity.HIGH: '\033[93m',      # Yellow
        Severity.MEDIUM: '\033[94m',    # Blue
        Severity.LOW: '\033[92m',       # Green
        Severity.INFO: '\033[97m',      # White
        'RESET': '\033[0m',
        'BOLD': '\033[1m',
        'GREEN': '\033[92m',
        'RED': '\033[91m',
        'YELLOW': '\033[93m',
        'CYAN': '\033[96m',
        'MAGENTA': '\033[95m'
    }
    
    def __init__(self, findings: List[Finding]):
        """
        Initialize CLI output.
        
        Args:
            findings: List of findings to display
        """
        self.findings = findings
        self.analyzer = Analyzer(findings)
        self.scorer = Scorer(findings)
        self.path_builder = AttackPathBuilder(findings)
    
    def display(self):
        """Display all findings in CLI."""
        self._print_banner()
        self._print_summary()
        self._print_attack_paths_enhanced()
        self._print_quick_wins_enhanced()
        self._print_findings_by_severity()
        self._print_footer()
    
    def _print_banner(self):
        """Print tool banner."""
        banner = f"""
{self.COLORS['CYAN']}{self.COLORS['BOLD']}
╔══════════════════════════════════════════════════════════╗
║     PrivAudit - Linux Privilege Escalation Auditor      ║
║     Next-Generation Security Assessment Framework       ║
║                v1.1 - PRO Edition                       ║
╚══════════════════════════════════════════════════════════╝
{self.COLORS['RESET']}
"""
        print(banner)
    
    def _print_summary(self):
        """Print summary statistics."""
        summary = self.analyzer.get_summary()
        total_risk = self.scorer.get_total_risk_score()
        risk_level = self.scorer.get_risk_level()
        
        # Color risk level
        risk_color = {
            'CRITICAL': self.COLORS['RED'],
            'HIGH': self.COLORS['YELLOW'],
            'MEDIUM': self.COLORS['CYAN'],
            'LOW': self.COLORS['GREEN'],
            'INFO': self.COLORS['GREEN']
        }.get(risk_level, self.COLORS['RESET'])
        
        print(f"{self.COLORS['BOLD']}📊 SUMMARY{self.COLORS['RESET']}")
        print("=" * 60)
        print(f"  Total Unique Findings: {summary['total_findings']}")
        print(f"  {self.COLORS['RED']}Critical: {summary['critical']}{self.COLORS['RESET']}")
        print(f"  {self.COLORS['YELLOW']}High: {summary['high']}{self.COLORS['RESET']}")
        print(f"  {self.COLORS['CYAN']}Medium: {summary['medium']}{self.COLORS['RESET']}")
        print(f"  {self.COLORS['GREEN']}Low: {summary['low']}{self.COLORS['RESET']}")
        print(f"  Info: {summary['info']}")
        print(f"")
        print(f"  {self.COLORS['BOLD']}Risk Score: {total_risk:.1f}{self.COLORS['RESET']}")
        print(f"  {self.COLORS['BOLD']}Risk Level: {risk_color}{risk_level}{self.COLORS['RESET']}")
        print("=" * 60)
        print()
    
    def _print_attack_paths_enhanced(self):
        """Print enhanced attack paths with ranking."""
        paths = self.path_builder.get_paths()
        
        if not paths:
            print(f"{self.COLORS['YELLOW']}No clear attack paths identified.{self.COLORS['RESET']}\n")
            return
        
        print(f"{self.COLORS['BOLD']}{self.COLORS['RED']}🎯 ATTACK PATHS (Ranked by Reliability){self.COLORS['RESET']}")
        print("=" * 60)
        
        # Get ranked paths
        fastest = self.path_builder.get_fastest_path()
        most_reliable = self.path_builder.get_most_reliable_path()
        
        if fastest and fastest.get('name') != 'No Clear Path':
            print(f"{self.COLORS['GREEN']}⚡ FASTEST PATH:{self.COLORS['RESET']} {fastest['name']}")
            print(f"   Time to exploit: {fastest.get('time_to_exploit', 'Unknown')}")
            print(f"   Reliability: {fastest.get('reliability_score', 0):.0f}%")
            print()
        
        if most_reliable and most_reliable.get('name') != fastest.get('name'):
            print(f"{self.COLORS['CYAN']}🔒 MOST RELIABLE PATH:{self.COLORS['RESET']} {most_reliable['name']}")
            print(f"   Reliability: {most_reliable.get('reliability_score', 0):.0f}%")
            print()
        
        print(f"{self.COLORS['BOLD']}All Attack Paths:{self.COLORS['RESET']}\n")
        
        for i, path in enumerate(paths[:3], 1):
            # Color based on reliability
            if path.get('reliability_score', 0) > 80:
                path_color = self.COLORS['GREEN']
            elif path.get('reliability_score', 0) > 50:
                path_color = self.COLORS['YELLOW']
            else:
                path_color = self.COLORS['RED']
            
            print(f"{path_color}{i}. {path['name']}{self.COLORS['RESET']}")
            print(f"   {path['description']}")
            print(f"   {self.COLORS['CYAN']}→ Impact:{self.COLORS['RESET']} {path['impact']}")
            print(f"   {self.COLORS['CYAN']}→ Likelihood:{self.COLORS['RESET']} {path['likelihood']:.0f}%")
            print(f"   {self.COLORS['CYAN']}→ Reliability:{self.COLORS['RESET']} {path.get('reliability_score', 0):.0f}%")
            print(f"   {self.COLORS['CYAN']}→ Time:{self.COLORS['RESET']} {path.get('time_to_exploit', 'Unknown')}")
            
            if path['findings']:
                print(f"   {self.COLORS['CYAN']}→ Steps:{self.COLORS['RESET']}")
                for finding in path['findings']:
                    reliability = finding.metadata.get('reliability', 'medium')
                    rel_color = self.COLORS['GREEN'] if reliability == 'high' else self.COLORS['YELLOW']
                    print(f"      - {finding.title} [{rel_color}{reliability}{self.COLORS['RESET']}]")
            print()
    
    def _print_quick_wins_enhanced(self):
        """Print enhanced quick wins."""
        quick_wins = self.path_builder.get_quick_wins()
        
        if not quick_wins:
            return
        
        print(f"{self.COLORS['BOLD']}{self.COLORS['GREEN']}⚡ QUICK WINS (Highest Priority){self.COLORS['RESET']}")
        print("=" * 60)
        
        for i, win in enumerate(quick_wins, 1):
            finding = win['finding']
            severity_color = self.COLORS.get(finding.severity, self.COLORS['RESET'])
            
            print(f"{i}. {severity_color}[{finding.severity.name}]{self.COLORS['RESET']} {finding.title}")
            print(f"   {self.COLORS['CYAN']}Time to Exploit:{self.COLORS['RESET']} {win['time_to_exploit']}")
            print(f"   {self.COLORS['CYAN']}Reliability:{self.COLORS['RESET']} {win['reliability'].upper()}")
            
            if finding.exploit_suggestion:
                # Show first line of exploit suggestion
                exploit_preview = finding.exploit_suggestion.split('\n')[0]
                print(f"   {self.COLORS['GREEN']}→ Exploit:{self.COLORS['RESET']} {exploit_preview[:80]}...")
            print()
    
    def _print_findings_by_severity(self):
        """Print findings grouped by severity."""
        print(f"{self.COLORS['BOLD']}🔍 DETAILED FINDINGS{self.COLORS['RESET']}")
        print("=" * 60)
        
        # Display critical findings first
        critical = self.analyzer.get_critical_findings()
        if critical:
            self._print_finding_group("CRITICAL", critical)
        
        high = self.analyzer.get_high_findings()
        if high:
            self._print_finding_group("HIGH", high)
        
        # For other severities, only show if not too many
        all_findings = self.analyzer.by_severity
        for severity in [Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            findings = all_findings.get(severity, [])
            if findings and len(findings) <= 5:
                self._print_finding_group(severity.name, findings)
            elif findings:
                print(f"{self.COLORS['CYAN']}[{severity.name}]{self.COLORS['RESET']} {len(findings)} findings (use JSON for full list)")
                print()
    
    def _print_finding_group(self, severity_name: str, findings: List[Finding]):
        """Print a group of findings with same severity."""
        severity_color = self.COLORS.get(getattr(Severity, severity_name, Severity.INFO), self.COLORS['RESET'])
        print(f"{severity_color}[{severity_name}]{self.COLORS['RESET']}")
        print("-" * 60)
        
        for finding in findings[:5]:  # Limit to 5 per group to avoid noise
            print(f"  {finding.title}")
            # Show short description
            desc_short = finding.description[:100] + "..." if len(finding.description) > 100 else finding.description
            print(f"  {desc_short}")
            
            if finding.exploit_suggestion and severity_name in ['CRITICAL', 'HIGH']:
                # Show first line of exploit
                exploit_line = finding.exploit_suggestion.split('\n')[0]
                print(f"  {self.COLORS['GREEN']}→ {exploit_line[:100]}{self.COLORS['RESET']}")
            print()
    
    def _print_footer(self):
        """Print footer with recommendations."""
        print("=" * 60)
        print(f"{self.COLORS['BOLD']}📝 NEXT STEPS{self.COLORS['RESET']}")
        print("  • Review CRITICAL findings first - these are the most reliable paths")
        print("  • Test quick wins in a controlled environment")
        print("  • Generate JSON report for automation: python3 main.py --json report.json")
        print("  • Generate Markdown report for documentation: python3 main.py --output report.md")
        print("=" * 60)