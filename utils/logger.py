# logger.py
"""
Logging utility for PrivAudit.
Provides structured logging with different verbosity levels.
"""

import logging
import sys
from datetime import datetime
from typing import Optional


class Logger:
    """Custom logger for PrivAudit with color support."""
    
    def __init__(self, verbose: bool = False, log_file: Optional[str] = None):
        """
        Initialize logger.
        
        Args:
            verbose: Enable verbose logging
            log_file: Optional file to write logs to
        """
        self.verbose = verbose
        
        # Configure root logger
        self.logger = logging.getLogger('priv-audit')
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        console_format = logging.Formatter('%(message)s')
        console_handler.setFormatter(console_format)
        self.logger.addHandler(console_handler)
        
        # File handler if specified
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_format = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(file_format)
            self.logger.addHandler(file_handler)
    
    def info(self, message: str):
        """Log info message."""
        self.logger.info(message)
    
    def debug(self, message: str):
        """Log debug message."""
        self.logger.debug(message)
    
    def warning(self, message: str):
        """Log warning message."""
        self.logger.warning(message)
    
    def error(self, message: str):
        """Log error message."""
        self.logger.error(message)
    
    def success(self, message: str):
        """Log success message with green color."""
        self.logger.info(f"\033[92m✓ {message}\033[0m")
    
    def critical(self, message: str):
        """Log critical message with red color."""
        self.logger.info(f"\033[91m⚠ {message}\033[0m")
    
    def highlight(self, message: str):
        """Log highlighted message with yellow color."""
        self.logger.info(f"\033[93m→ {message}\033[0m")