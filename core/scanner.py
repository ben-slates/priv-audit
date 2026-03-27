# scanner.py
"""
Main scanner engine.
Coordinates all security checks and collects findings.
"""

from typing import List, Dict, Any, Type
from checks.base_check import BaseCheck, Finding
from checks.suid import SUIDCheck
from checks.permissions import PermissionsCheck
from checks.cron import CronCheck
from checks.sudo import SudoCheck
from checks.capabilities import CapabilitiesCheck
from checks.docker import DockerCheck
from checks.kernel import KernelCheck
from utils.logger import Logger


class Scanner:
    """Main scanner that runs all security checks."""
    
    def __init__(self, logger: Logger, quick: bool = False):
        """
        Initialize scanner.
        
        Args:
            logger: Logger instance
            quick: Run only high-priority checks
        """
        self.logger = logger
        self.quick = quick
        self.checks: List[BaseCheck] = []
        self._register_checks()
    
    def _register_checks(self):
        """Register all security checks."""
        # Always run critical checks
        self.checks = [
            SUIDCheck(),
            PermissionsCheck(),
            SudoCheck(),
            KernelCheck(),
        ]
        
        # Add medium priority checks if not quick mode
        if not self.quick:
            self.checks.extend([
                CronCheck(),
                CapabilitiesCheck(),
                DockerCheck(),
            ])
    
    def scan(self) -> List[Finding]:
        """
        Run all registered checks.
        
        Returns:
            List of all findings
        """
        self.logger.info("Starting security audit...")
        self.logger.info("=" * 60)
        
        all_findings = []
        
        for check in self.checks:
            self.logger.highlight(f"Running {check.name}...")
            try:
                findings = check.run()
                all_findings.extend(findings)
                self.logger.success(f"Found {len(findings)} findings in {check.name}")
            except Exception as e:
                self.logger.error(f"Error in {check.name}: {str(e)}")
                if self.logger.verbose:
                    import traceback
                    traceback.print_exc()
        
        self.logger.info("=" * 60)
        self.logger.success(f"Scan complete. Total findings: {len(all_findings)}")
        
        return all_findings