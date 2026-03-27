"""
Kernel vulnerability check module.
Identifies kernel versions with known exploits.
"""

import os
import re
from typing import List, Dict
from checks.base_check import BaseCheck, Finding, Severity
from utils.helpers import SystemHelpers


class KernelCheck(BaseCheck):
    """Check for kernel vulnerabilities and exploit suggestions."""
    
    def run(self, *args, **kwargs) -> List[Finding]:
        """Check kernel version and suggest exploits."""
        findings = []
        
        # Get kernel version
        kernel_version = SystemHelpers.get_kernel_version()
        
        if kernel_version and kernel_version != 'unknown':
            findings.append(Finding(
                title=f"Kernel Version: {kernel_version}",
                description=f"Running kernel version {kernel_version}",
                severity=Severity.INFO,
                exploit_suggestion=f"Search for exploits: searchsploit Linux Kernel {kernel_version}",
                remediation="Update kernel to latest version",
                metadata={'version': kernel_version}
            ))
            
            # Check for known vulnerabilities
            vulns = SystemHelpers.check_kernel_vulnerabilities(kernel_version)
            
            if vulns:
                for vuln in vulns:
                    findings.append(Finding(
                        title=f"Potential Kernel Exploit: {vuln['name']}",
                        description=f"Kernel version {kernel_version} may be vulnerable to {vuln['name']}\n{vuln['description']}",
                        severity=Severity.CRITICAL,
                        exploit_suggestion=f"[RELIABILITY: {vuln['reliability'].upper()}]\n{vuln['cve']}\nDownload: {vuln['exploit']}",
                        remediation="Update kernel immediately: sudo apt update && sudo apt upgrade (Debian/Ubuntu)\nsudo yum update kernel (RHEL/CentOS)",
                        metadata={
                            'exploit': vuln['name'],
                            'cve': vuln['cve'],
                            'reliability': vuln['reliability']
                        }
                    ))
            else:
                findings.append(Finding(
                    title=f"Kernel Version Assessment",
                    description=f"Kernel version {kernel_version} - No known public exploits found in the database.",
                    severity=Severity.INFO,
                    exploit_suggestion="Manual research recommended: https://www.cvedetails.com/product/47/Linux-Linux-Kernel.html",
                    remediation="Keep kernel updated to latest stable version",
                    metadata={'version': kernel_version, 'has_known_exploits': False}
                ))
            
            # Check for LSM status
            if os.path.exists('/sys/kernel/security/lsm'):
                try:
                    with open('/sys/kernel/security/lsm', 'r') as f:
                        lsm = f.read().strip()
                        if not lsm or lsm == 'none':
                            findings.append(Finding(
                                title="No Mandatory Access Control",
                                description="No AppArmor or SELinux detected. System has weaker security controls.",
                                severity=Severity.MEDIUM,
                                exploit_suggestion="Kernel exploits are easier to execute without MAC restrictions",
                                remediation="Enable AppArmor or SELinux",
                                metadata={'lsm': lsm or 'none'}
                            ))
                except:
                    pass
        
        return findings