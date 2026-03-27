# capabilities.py
"""
Linux capabilities check module.
Identifies binaries with dangerous capabilities.
"""

import os
import re
from typing import List
from checks.base_check import BaseCheck, Finding, Severity
from utils.helpers import SystemHelpers


class CapabilitiesCheck(BaseCheck):
    """Check for binaries with dangerous capabilities."""
    
    # Capabilities that can lead to privilege escalation
    DANGEROUS_CAPS = [
        'cap_dac_override',      # Bypass file read/write/execute permission checks
        'cap_dac_read_search',   # Bypass file read permission and directory read/execute
        'cap_setuid',            # Manipulate UIDs
        'cap_setgid',            # Manipulate GIDs
        'cap_sys_admin',         # Perform a range of system administration operations
        'cap_sys_ptrace',        # Trace arbitrary processes
        'cap_sys_module',        # Load and unload kernel modules
        'cap_sys_rawio',         # Perform I/O port operations
        'cap_sys_boot',          # Use reboot()
        'cap_net_admin',         # Perform various network-related operations
        'cap_net_raw',           # Use RAW and PACKET sockets
    ]
    
    # Exploit commands for capabilities
    EXPLOITS = {
        'cap_dac_override': 'Read any file: cat /etc/shadow\nWrite any file: echo "new root" >> /etc/passwd',
        'cap_dac_read_search': 'Read any file: cat /etc/shadow',
        'cap_setuid': 'python3 -c "import os; os.setuid(0); os.system(\'/bin/bash\')"',
        'cap_sys_admin': 'mount -t tmpfs none /tmp && cp /bin/bash /tmp && chmod +s /tmp/bash',
        'cap_sys_ptrace': 'Inject code into running process to escalate privileges',
        'cap_sys_module': 'insmod rootkit.ko',
        'cap_net_raw': 'Capture packets or perform network attacks',
    }
    
    def run(self, *args, **kwargs) -> List[Finding]:
        """Find binaries with dangerous capabilities."""
        findings = []
        
        # Get all binaries with capabilities
        stdout, stderr, code = SystemHelpers.run_shell_cmd('getcap -r / 2>/dev/null')
        
        if stdout:
            lines = stdout.split('\n')
            for line in lines:
                if not line.strip():
                    continue
                
                # Parse getcap output: /path/to/binary = cap_name+ep
                parts = line.split('=')
                if len(parts) == 2:
                    binary_path = parts[0].strip()
                    caps = parts[1].strip()
                    
                    # Check for dangerous capabilities
                    for dangerous_cap in self.DANGEROUS_CAPS:
                        if dangerous_cap in caps:
                            findings.append(Finding(
                                title=f"Dangerous Capability: {dangerous_cap}",
                                description=f"Binary {binary_path} has the {dangerous_cap} capability which can be exploited for privilege escalation.",
                                severity=Severity.CRITICAL,
                                exploit_suggestion=self.EXPLOITS.get(dangerous_cap, f"Research exploitation techniques for {dangerous_cap}"),
                                remediation=f"Remove capability: setcap -r {binary_path}",
                                metadata={
                                    'binary': binary_path,
                                    'capability': dangerous_cap,
                                    'full_caps': caps
                                }
                            ))
        
        # Check for environment capability inheritance
        stdout, stderr, code = SystemHelpers.run_shell_cmd('capsh --print')
        if stdout and 'Current:' in stdout:
            current_caps = re.search(r'Current:\s*=\s*(.+)', stdout)
            if current_caps:
                caps = current_caps.group(1)
                if 'cap_setuid' in caps:
                    findings.append(Finding(
                        title="Process Has setuid Capability",
                        description="Current process has setuid capability which can be used to escalate privileges.",
                        severity=Severity.HIGH,
                        exploit_suggestion="Use python/perl to set UID to 0",
                        remediation="Drop capabilities if not needed",
                        metadata={'caps': caps}
                    ))
        
        return findings