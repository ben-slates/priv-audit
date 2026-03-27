#!/usr/bin/env python3
"""
PrivAudit - Linux Privilege Escalation Auditor
Next-Generation Security Assessment Framework
"""

import sys
import os
import argparse

from core.scanner import Scanner
from core.scorer import Scorer
from core.attack_path import AttackPathBuilder
from output.cli import CLIOutput
from output.json_report import JSONReport
from output.markdown_report import MarkdownReport
from utils.logger import Logger
from utils.helpers import SystemHelpers


def main():
    """Main entry point for PrivAudit."""
    parser = argparse.ArgumentParser(
        description='PrivAudit - Linux Privilege Escalation Auditor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py --full          # Run full audit
  python3 main.py --quick         # Run quick audit (high priority checks only)
  python3 main.py --output report.md  # Generate Markdown report
  python3 main.py --json report.json  # Generate JSON report
  python3 main.py --verbose       # Enable verbose output
        """
    )
    
    parser.add_argument('--full', action='store_true', 
                        help='Run full audit (all checks)')
    parser.add_argument('--quick', action='store_true',
                        help='Run quick audit (critical checks only)')
    parser.add_argument('--output', type=str, metavar='FILE',
                        help='Generate Markdown report to FILE')
    parser.add_argument('--json', type=str, metavar='FILE',
                        help='Generate JSON report to FILE')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Check privileges and show limitations
    is_root, limitations = SystemHelpers.check_root_privileges()
    
    if not is_root:
        print("\033[93m⚠ WARNING: Not running as root\033[0m")
        print("The following checks will be limited:\n")
        for limitation in limitations:
            print(f"  • {limitation}")
        print("\n\033[93mTip: Run with sudo for complete results\033[0m\n")
    
    # Initialize logger
    logger = Logger(verbose=args.verbose)
    
    # Determine scan mode
    quick = args.quick or not args.full
    
    try:
        # Run scanner
        logger.info("Initializing PrivAudit...")
        scanner = Scanner(logger, quick=quick)
        findings = scanner.scan()
        
        # Score findings (deduplicated internally)
        scorer = Scorer(findings)
        path_builder = AttackPathBuilder(findings)
        
        # Generate outputs
        if args.json:
            logger.info(f"Generating JSON report: {args.json}")
            json_report = JSONReport(findings)
            json_report.generate(args.json)
            logger.success(f"JSON report saved to {args.json}")
        
        if args.output:
            logger.info(f"Generating Markdown report: {args.output}")
            md_report = MarkdownReport(findings)
            md_report.generate(args.output)
            logger.success(f"Markdown report saved to {args.output}")
        
        # Always show CLI output
        cli = CLIOutput(findings)
        cli.display()
        
        # If no output format specified, suggest generating reports
        if not args.json and not args.output:
            print("\n💡 Tip: Use --output report.md or --json report.json to generate reports")
        
    except KeyboardInterrupt:
        logger.warning("\n\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()