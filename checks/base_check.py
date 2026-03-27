"""
Base class for all security checks.
Defines the interface that all check modules must implement.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    """Severity levels for findings."""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


@dataclass
class Finding:
    """Represents a single security finding."""
    title: str
    description: str
    severity: Severity
    exploit_suggestion: Optional[str] = None
    remediation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            'title': self.title,
            'description': self.description,
            'severity': self.severity.name,
            'severity_score': self.severity.value,
            'exploit_suggestion': self.exploit_suggestion,
            'remediation': self.remediation,
            'metadata': self.metadata
        }


class BaseCheck(ABC):
    """Base class for all security checks."""
    
    def __init__(self):
        """Initialize check."""
        self.findings: List[Finding] = []
        self.name = self.__class__.__name__
    
    @abstractmethod
    def run(self, *args, **kwargs) -> List[Finding]:
        """
        Execute the security check.
        
        Returns:
            List of findings
        """
        pass
    
    def add_finding(self, finding: Finding):
        """Add a finding to the check results."""
        self.findings.append(finding)
    
    def get_results(self) -> List[Finding]:
        """Get all findings from this check."""
        return self.findings
    
    def clear_results(self):
        """Clear all findings."""
        self.findings = []