"""
Helper functions for PrivAudit.
Includes system interaction utilities.
"""

from ast import Dict
import os
import subprocess
import re
import stat
import pwd
import grp
from typing import List, Optional, Tuple, Set
from pathlib import Path


class SystemHelpers:
    """System interaction helper methods."""
    
    @staticmethod
    def normalize_path(path: str) -> str:
        """Get real path resolving symlinks."""
        try:
            return os.path.realpath(path)
        except:
            return path
    
    @staticmethod
    def get_unique_binaries(paths: List[str]) -> Set[str]:
        """Get unique binaries by resolving symlinks."""
        unique = set()
        for path in paths:
            real_path = SystemHelpers.normalize_path(path)
            unique.add(real_path)
        return unique
    
    @staticmethod
    def run_command(cmd: List[str], timeout: int = 10) -> Tuple[str, str, int]:
        """Run a shell command and return output."""
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                shell=False
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", f"Command timed out after {timeout}s", -1
        except Exception as e:
            return "", str(e), -1
    
    @staticmethod
    def run_shell_cmd(cmd: str, timeout: int = 10) -> Tuple[str, str, int]:
        """Run a shell command using shell=True."""
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                shell=True,
                executable='/bin/bash'
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", f"Command timed out after {timeout}s", -1
        except Exception as e:
            return "", str(e), -1
    
    @staticmethod
    def file_exists(path: str) -> bool:
        """Check if a file exists."""
        return os.path.exists(path)
    
    @staticmethod
    def is_readable(path: str) -> bool:
        """Check if a file is readable."""
        return os.access(path, os.R_OK)
    
    @staticmethod
    def is_writable_by_user_real(path: str) -> Tuple[bool, str]:
        """
        CORRECT permission check using REAL path (after resolving symlinks).
        This is the ONLY reliable way to check write permissions.
        """
        # First resolve any symlinks to get the REAL file
        try:
            real_path = os.path.realpath(path)
        except Exception as e:
            return False, f"Cannot resolve path: {str(e)}"
        
        if not os.path.exists(real_path):
            return False, f"Real path does not exist: {real_path}"
        
        # Ignore device files - they're not real writable binaries
        if real_path.startswith('/dev/'):
            return False, f"Skipping device file: {real_path}"
        
        # Special case: /dev/null should never be considered writable for exploitation
        if real_path == '/dev/null':
            return False, "Skipping /dev/null (pseudo-device)"
        
        try:
            st = os.stat(real_path)
            uid = os.geteuid()
            gids = os.getgroups()
            
            # Check owner writable
            if st.st_uid == uid and (st.st_mode & stat.S_IWUSR):
                return True, f"User (UID {uid}) is owner of {real_path} and file has write permission"
            
            # Check group writable
            if st.st_gid in gids and (st.st_mode & stat.S_IWGRP):
                return True, f"User is in group GID {st.st_gid} and {real_path} has group write permission"
            
            # Check world writable
            if st.st_mode & stat.S_IWOTH:
                return True, f"{real_path} is world writable"
            
            return False, f"No write permission on {real_path} (owner:{st.st_uid}, group:{st.st_gid}, mode:{oct(st.st_mode)})"
            
        except Exception as e:
            return False, f"Error checking permissions on {real_path}: {str(e)}"
    
    @staticmethod
    def is_writable_by_user(path: str) -> Tuple[bool, str]:
        """
        Wrapper that ensures we check the REAL file.
        This is the function that should be called by all checks.
        """
        return SystemHelpers.is_writable_by_user_real(path)
    
    @staticmethod
    def is_system_protected_service(path: str) -> bool:
        """Check if this is a system service path that should be protected."""
        protected_paths = [
            '/usr/lib/systemd/system/',
            '/lib/systemd/system/',
            '/etc/systemd/system/',
        ]
        return any(path.startswith(protected) for protected in protected_paths)
    
    @staticmethod
    def is_valid_service_file(path: str) -> Tuple[bool, str]:
        """
        Check if a service file is valid and worth checking.
        Returns (is_valid, reason)
        """
        try:
            # Step 1: Resolve symlink to get the REAL file
            real_path = os.path.realpath(path)
            
            # Step 2: Ignore fake services that point to /dev/null
            if real_path == '/dev/null':
                return False, f"Service symlinks to /dev/null (not a real service)"
            
            # Step 3: Ignore anything in /dev
            if real_path.startswith('/dev/'):
                return False, f"Service points to device file: {real_path}"
            
            # Step 4: Check if the REAL file exists
            if not os.path.exists(real_path):
                return False, f"Real path does not exist: {real_path}"
            
            # Step 5: Check if it's a regular file
            if not os.path.isfile(real_path):
                return False, f"Not a regular file: {real_path}"
            
            return True, f"Valid service file: {real_path}"
            
        except Exception as e:
            return False, f"Error checking service file: {str(e)}"
    
    @staticmethod
    def get_real_path(path: str) -> str:
        """Get the real path (resolve symlinks)."""
        try:
            return os.path.realpath(path)
        except:
            return path
    
    @staticmethod
    def is_executable(path: str) -> bool:
        """Check if a file is executable."""
        return os.access(path, os.X_OK) and os.path.isfile(path)
    
    @staticmethod
    def get_file_owner(path: str) -> Optional[str]:
        """Get file owner username from REAL path."""
        try:
            real_path = os.path.realpath(path)
            stat_info = os.stat(real_path)
            return pwd.getpwuid(stat_info.st_uid).pw_name
        except:
            return None
    
    @staticmethod
    def get_file_owner_uid(path: str) -> Optional[int]:
        """Get file owner UID from REAL path."""
        try:
            real_path = os.path.realpath(path)
            return os.stat(real_path).st_uid
        except:
            return None
    
    @staticmethod
    def get_file_permissions(path: str) -> Optional[str]:
        """Get file permissions as string from REAL path (e.g., 'rw-r--r--')."""
        try:
            real_path = os.path.realpath(path)
            st = os.stat(real_path)
            mode = st.st_mode
            perms = []
            # Owner
            perms.append('r' if mode & stat.S_IRUSR else '-')
            perms.append('w' if mode & stat.S_IWUSR else '-')
            perms.append('x' if mode & stat.S_IXUSR else '-')
            # Group
            perms.append('r' if mode & stat.S_IRGRP else '-')
            perms.append('w' if mode & stat.S_IWGRP else '-')
            perms.append('x' if mode & stat.S_IXGRP else '-')
            # Others
            perms.append('r' if mode & stat.S_IROTH else '-')
            perms.append('w' if mode & stat.S_IWOTH else '-')
            perms.append('x' if mode & stat.S_IXOTH else '-')
            return ''.join(perms)
        except:
            return None
    
    @staticmethod
    def get_current_user() -> str:
        """Get current username."""
        try:
            return pwd.getpwuid(os.getuid()).pw_name
        except:
            return os.environ.get('USER', 'unknown')
    
    @staticmethod
    def get_current_uid() -> int:
        """Get current UID."""
        return os.getuid()
    
    @staticmethod
    def get_current_euid() -> int:
        """Get current effective UID."""
        return os.geteuid()
    
    @staticmethod
    def get_current_gid() -> int:
        """Get current GID."""
        return os.getgid()
    
    @staticmethod
    def get_current_groups() -> List[int]:
        """Get current group IDs."""
        return os.getgroups()
    
    @staticmethod
    def get_user_groups(username: str) -> List[str]:
        """Get groups for a user."""
        try:
            groups = []
            for group in grp.getgrall():
                if username in group.gr_mem:
                    groups.append(group.gr_name)
            return groups
        except:
            return []
    
    @staticmethod
    def is_valid_binary(path: str) -> bool:
        """Check if path is a valid executable binary (not device file)."""
        if not os.path.exists(path):
            return False
        
        # Skip device files
        if path.startswith('/dev/'):
            return False
        
        # Skip special files
        try:
            st = os.stat(path)
            if not stat.S_ISREG(st.st_mode):
                return False
        except:
            return False
        
        return os.access(path, os.X_OK) and os.path.isfile(path)
    
    @staticmethod
    def is_system_service(service_path: str) -> bool:
        """Check if a service is a system-wide service (not user)."""
        system_dirs = ['/etc/systemd/system/', '/usr/lib/systemd/system/', '/lib/systemd/system/']
        return any(service_path.startswith(d) for d in system_dirs)
    
    @staticmethod
    def can_restart_service(service_name: str, is_system: bool = True) -> Tuple[bool, str]:
        """Check if user can restart a service."""
        if is_system:
            # System services typically require root to restart
            if os.geteuid() == 0:
                return True, "Running as root - can restart any service"
            
            # Check if user has sudo rights for systemctl
            stdout, stderr, code = SystemHelpers.run_command(['sudo', '-l', 'systemctl'])
            if 'systemctl' in stdout:
                return True, "User can restart services via sudo"
            return False, "User cannot restart system services (requires root or sudo)"
        else:
            # User services can be restarted by the user
            return True, "User can restart their own services"
    
    @staticmethod
    def find_files(path: str, pattern: str = '*', recursive: bool = True) -> List[str]:
        """Find files matching pattern."""
        matches = []
        try:
            path_obj = Path(path)
            if recursive:
                matches = [str(p) for p in path_obj.rglob(pattern) if p.is_file()]
            else:
                matches = [str(p) for p in path_obj.glob(pattern) if p.is_file()]
        except Exception:
            pass
        return matches
    
    @staticmethod
    def parse_suid_binary(line: str) -> Optional[dict]:
        """Parse ls -l output for SUID binary."""
        # Use raw string to avoid escape sequence warning
        pattern = r'^([-rwxsS]+)\s+\d+\s+(\S+)\s+(\S+)\s+(\d+)\s+(.+)'
        match = re.match(pattern, line.strip())
        
        if match:
            permissions, owner, group, size, path = match.groups()
            if 's' in permissions[:3]:
                return {
                    'path': path.strip(),
                    'owner': owner,
                    'group': group,
                    'size': int(size),
                    'permissions': permissions
                }
        return None
    
    @staticmethod
    def get_linux_distribution() -> str:
        """Detect Linux distribution."""
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read()
                if 'ID=' in content:
                    for line in content.split('\n'):
                        if line.startswith('ID='):
                            return line.split('=')[1].strip('"')
        except:
            pass
        
        try:
            with open('/etc/issue', 'r') as f:
                return f.read().strip().split()[0]
        except:
            pass
        
        return 'unknown'
    
    @staticmethod
    def check_root_privileges() -> Tuple[bool, List[str]]:
        """Check if running as root and what limitations exist."""
        is_root = os.geteuid() == 0
        limitations = []
        
        if not is_root:
            limitations.append("SUID scanning may miss binaries in protected directories")
            limitations.append("Cannot read some cron files in /var/spool/cron")
            limitations.append("Capabilities detection may be incomplete")
            limitations.append("Cannot access some process information in /proc")
        
        return is_root, limitations
    
    @staticmethod
    def get_kernel_version() -> str:
        """Get kernel version."""
        try:
            stdout, _, _ = SystemHelpers.run_command(['uname', '-r'])
            return stdout.strip()
        except:
            return 'unknown'
    
    @staticmethod
    def check_kernel_vulnerabilities(kernel_version: str) -> List[Dict]:
        """Check kernel version against known vulnerabilities."""
        vulnerabilities = []
        
        # Parse kernel version
        parts = kernel_version.split('.')
        if len(parts) >= 2:
            major = parts[0]
            try:
                minor = int(parts[1])
            except:
                minor = 0
            
            # Check for known vulnerabilities
            if major == '5' and minor <= 16:
                vulnerabilities.append({
                    'name': 'Dirty Pipe (CVE-2022-0847)',
                    'cve': 'CVE-2022-0847',
                    'description': 'Local privilege escalation through pipe manipulation',
                    'reliability': 'high',
                    'exploit': 'https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits'
                })
            
            if major == '4' and minor <= 19:
                vulnerabilities.append({
                    'name': 'Dirty Cow (CVE-2016-5195)',
                    'cve': 'CVE-2016-5195',
                    'description': 'Race condition in memory handling',
                    'reliability': 'high',
                    'exploit': 'https://www.exploit-db.com/exploits/40839'
                })
            
            if major == '3' or (major == '4' and minor <= 19):
                vulnerabilities.append({
                    'name': 'OverlayFS (CVE-2015-1328)',
                    'cve': 'CVE-2015-1328',
                    'description': 'Privilege escalation via OverlayFS',
                    'reliability': 'medium',
                    'exploit': 'https://www.exploit-db.com/exploits/37292'
                })
        
        return vulnerabilities