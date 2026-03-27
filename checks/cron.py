"""
Cron job check module.
Identifies writable cron jobs that can be exploited.
"""

import os
import re
from typing import List, Set
from checks.base_check import BaseCheck, Finding, Severity
from utils.helpers import SystemHelpers


class CronCheck(BaseCheck):
    """Check for writable cron jobs and scripts."""
    
    def __init__(self):
        super().__init__()
        self.seen_findings: Set[str] = set()  # Deduplication
    
    def _add_unique_finding(self, finding: Finding) -> bool:
        """Add finding only if not seen before."""
        finding_id = f"{finding.title}_{finding.metadata.get('path', '')}_{finding.metadata.get('binary', '')}"
        if finding_id not in self.seen_findings:
            self.seen_findings.add(finding_id)
            self.findings.append(finding)
            return True
        return False
    
    def run(self, *args, **kwargs) -> List[Finding]:
        """Find writable cron jobs and scripts."""
        self.seen_findings.clear()
        
        # Check system crontab
        if os.path.exists('/etc/crontab') and SystemHelpers.is_readable('/etc/crontab'):
            with open('/etc/crontab', 'r') as f:
                content = f.read()
                for line in content.split('\n'):
                    if line and not line.startswith('#'):
                        parts = line.split()
                        if len(parts) >= 6:
                            command = ' '.join(parts[5:])
                            self._analyze_command(command)
        
        # Check cron directories
        cron_dirs = [
            '/etc/cron.d/',
            '/etc/cron.daily/',
            '/etc/cron.hourly/',
            '/etc/cron.weekly/',
            '/etc/cron.monthly/'
        ]
        
        for cron_dir in cron_dirs:
            if os.path.exists(cron_dir):
                try:
                    for file in os.listdir(cron_dir):
                        file_path = os.path.join(cron_dir, file)
                        if os.path.isfile(file_path):
                            # Check if writable by current user
                            is_writable, reason = SystemHelpers.is_writable_by_user(file_path)
                            if is_writable:
                                self._add_unique_finding(Finding(
                                    title=f"Writable Cron Job: {file}",
                                    description=f"Cron job {file_path} is writable by current user. This can be modified to execute malicious code with the privileges of the cron user.",
                                    severity=Severity.CRITICAL,
                                    exploit_suggestion=f"Add malicious command to {file_path}\nExample: echo '* * * * * root /bin/bash -c \"chmod +s /bin/bash\"' >> {file_path}",
                                    remediation=f"Secure permissions: chmod 644 {file_path}",
                                    metadata={'path': file_path, 'writable_reason': reason}
                                ))
                            elif SystemHelpers.is_readable(file_path):
                                with open(file_path, 'r') as f:
                                    content = f.read()
                                    self._analyze_script(content, file_path)
                except PermissionError:
                    pass
        
        return self.findings
    
    def _analyze_command(self, command: str):
        """Analyze a command for potential issues."""
        if not command:
            return
        
        # Check for wildcard exploitation
        if '*' in command and ('tar' in command or 'rsync' in command or 'chown' in command):
            self._add_unique_finding(Finding(
                title="Wildcard Injection Risk",
                description=f"Cron command uses wildcards with potentially dangerous program: {command[:100]}",
                severity=Severity.HIGH,
                exploit_suggestion="Create a file named '--checkpoint=1' and '--checkpoint-action=exec=sh shell.sh' to exploit",
                remediation="Avoid using wildcards with dangerous programs",
                metadata={'command': command[:200]}
            ))
        
        # Check for relative paths
        if command and not command.startswith('/') and not command.startswith('cd '):
            self._add_unique_finding(Finding(
                title="Relative Path in Cron Command",
                description=f"Cron command uses relative path: {command[:100]}. This could be exploited via PATH manipulation.",
                severity=Severity.MEDIUM,
                exploit_suggestion="Create a malicious script with the same name in a writable directory in PATH",
                remediation="Use absolute paths in cron commands",
                metadata={'command': command[:200]}
            ))
    
    def _analyze_script(self, content: str, script_path: str):
        """Analyze a cron script for potential issues."""
        if not content:
            return
        
        # Check for writable dependencies
        lines = content.split('\n')
        for line in lines:
            if line.strip() and not line.strip().startswith('#'):
                # Look for commands in script
                parts = line.split()
                for part in parts:
                    if part.startswith('/') and SystemHelpers.file_exists(part):
                        # Skip device files
                        if part.startswith('/dev/'):
                            continue
                        
                        # Check if it's a valid binary
                        if SystemHelpers.is_valid_binary(part):
                            is_writable, reason = SystemHelpers.is_writable_by_user(part)
                            if is_writable:
                                self._add_unique_finding(Finding(
                                    title=f"Cron Script Uses Writable Binary",
                                    description=f"Cron script {os.path.basename(script_path)} uses binary {part} which is writable by current user.",
                                    severity=Severity.CRITICAL,
                                    exploit_suggestion=f"Replace {part} with malicious code",
                                    remediation=f"Secure permissions: chmod 755 {part}",
                                    metadata={
                                        'script': script_path,
                                        'binary': part,
                                        'writable_reason': reason
                                    }
                                ))