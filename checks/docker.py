"""
Docker security check module.
Identifies Docker misconfigurations and group membership.
"""

import os
from typing import List
from checks.base_check import BaseCheck, Finding, Severity
from utils.helpers import SystemHelpers


class DockerCheck(BaseCheck):
    """Check for Docker-related privilege escalation vectors."""
    
    def run(self, *args, **kwargs) -> List[Finding]:
        """Identify Docker security issues."""
        findings = []
        current_user = SystemHelpers.get_current_user()
        groups = SystemHelpers.get_user_groups(current_user)
        
        # Check if user is in docker group
        if 'docker' in groups:
            findings.append(Finding(
                title="User in Docker Group",
                description=f"User {current_user} is in the docker group. This allows full root access via Docker.",
                severity=Severity.CRITICAL,
                exploit_suggestion="docker run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh\n\nOr:\ndocker run -v /:/mnt -it alpine chroot /mnt sh",
                remediation="Remove user from docker group: gpasswd -d username docker",
                metadata={'user': current_user}
            ))
        
        # Check if docker socket is writable
        docker_socket = '/var/run/docker.sock'
        if os.path.exists(docker_socket):
            if os.access(docker_socket, os.W_OK):
                findings.append(Finding(
                    title="Writable Docker Socket",
                    description=f"Docker socket {docker_socket} is writable. This allows full root access.",
                    severity=Severity.CRITICAL,
                    exploit_suggestion="docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh",
                    remediation="Secure docker socket permissions: chmod 660 /var/run/docker.sock",
                    metadata={'socket': docker_socket}
                ))
        
        # Check for running privileged containers
        stdout, stderr, code = SystemHelpers.run_command(['docker', 'ps'])
        if code == 0:
            stdout, stderr, code = SystemHelpers.run_command(['docker', 'ps', '--format', '{{.Names}} {{.Image}} {{.Command}}'])
            if stdout:
                findings.append(Finding(
                    title="Docker Containers Running",
                    description="Docker containers are running on this system. Check for privileged containers or mounts.",
                    severity=Severity.MEDIUM,
                    exploit_suggestion="Check for containers with: docker inspect <container> | grep -i privileged\n\nBreak out of container if needed",
                    remediation="Run containers without --privileged flag and with limited capabilities",
                    metadata={'containers': stdout}
                ))
        
        # Check for Docker-in-Docker
        if os.path.exists('/.dockerenv'):
            findings.append(Finding(
                title="Running Inside Docker Container",
                description="The audit is running inside a Docker container. Check for container escape opportunities.",
                severity=Severity.HIGH,
                exploit_suggestion="Check for privileged containers, mounted host directories, or kernel vulnerabilities",
                remediation="Run containers with security constraints",
                metadata={'environment': 'docker'}
            ))
        
        return findings