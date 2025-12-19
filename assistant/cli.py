#!/usr/bin/env python3
"""
Mac Mini M2 Security Assistant CLI
A comprehensive security monitoring and analysis tool optimized for Mac Mini M2.
"""

import argparse
import sys
import json
from datetime import datetime
from pathlib import Path
from scanner import FileSystemScanner
from security_analyzer import SecurityAnalyzer
from reporter import SecurityReporter


class AssistantCLI:
    """Main CLI interface for the security assistant."""
    
    def __init__(self):
        self.scanner = FileSystemScanner()
        self.analyzer = SecurityAnalyzer()
        self.reporter = SecurityReporter()
        
    def scan(self, args):
        """Perform a comprehensive security scan."""
        print(f"[*] Starting security scan of: {args.path}")
        print(f"[*] Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Scan the file system
        scan_results = self.scanner.scan(
            path=args.path,
            recursive=not args.no_recursive,
            follow_symlinks=args.follow_symlinks
        )
        
        print(f"[+] Scanned {scan_results['total_files']} files and {scan_results['total_dirs']} directories")
        
        # Analyze for security risks
        print("[*] Analyzing security risks...")
        analysis_results = self.analyzer.analyze(scan_results)
        
        # Generate report
        if args.output:
            print(f"[*] Generating report: {args.output}")
            self.reporter.generate_report(
                scan_results=scan_results,
                analysis_results=analysis_results,
                output_file=args.output,
                format=args.format
            )
            print(f"[+] Report saved to: {args.output}")
        
        # Display summary
        self._display_summary(analysis_results)
        
        # Return both scan and analysis results
        return {
            'scan_results': scan_results,
            'analysis_results': analysis_results
        }
    
    def monitor(self, args):
        """Start continuous monitoring of file system."""
        print(f"[*] Starting continuous monitoring")
        print(f"[*] Monitoring path: {args.path}")
        print(f"[*] Check interval: {args.interval} seconds")
        print("[*] Press Ctrl+C to stop monitoring")
        
        try:
            self.scanner.monitor(
                path=args.path,
                interval=args.interval,
                callback=self._monitor_callback
            )
        except KeyboardInterrupt:
            print("\n[*] Monitoring stopped by user")
            sys.exit(0)
    
    def report(self, args):
        """Generate a security report from existing data."""
        print(f"[*] Generating security report")
        
        # Check if we have cached scan data
        if not args.input and not hasattr(self, 'last_scan'):
            print("[!] No scan data available. Please run a scan first.")
            sys.exit(1)
        
        if args.input:
            print(f"[*] Loading scan data from: {args.input}")
            with open(args.input, 'r') as f:
                data = json.load(f)
            scan_results = data.get('scan_results', {})
            analysis_results = data.get('analysis_results', {})
        else:
            scan_results = self.last_scan['scan_results']
            analysis_results = self.last_scan['analysis_results']
        
        self.reporter.generate_report(
            scan_results=scan_results,
            analysis_results=analysis_results,
            output_file=args.output,
            format=args.format
        )
        
        print(f"[+] Report saved to: {args.output}")
    
    def _display_summary(self, analysis_results):
        """Display a summary of security findings."""
        print("\n" + "="*60)
        print("SECURITY SCAN SUMMARY")
        print("="*60)
        
        total_issues = analysis_results.get('total_issues', 0)
        critical = analysis_results.get('critical', 0)
        high = analysis_results.get('high', 0)
        medium = analysis_results.get('medium', 0)
        low = analysis_results.get('low', 0)
        
        print(f"\nTotal Security Issues Found: {total_issues}")
        print(f"  - Critical: {critical}")
        print(f"  - High: {high}")
        print(f"  - Medium: {medium}")
        print(f"  - Low: {low}")
        
        if critical > 0 or high > 0:
            print("\n[!] WARNING: Critical or high-severity issues detected!")
            print("[!] Please review the detailed report for mitigation steps.")
        elif total_issues > 0:
            print("\n[*] Some security issues detected. Review recommended.")
        else:
            print("\n[+] No security issues detected. System appears secure.")
        
        print("="*60 + "\n")
    
    def _monitor_callback(self, event):
        """Callback for monitoring events."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] {event['type']}: {event['path']}")
        
        if event.get('risk_level', 'low') in ['critical', 'high']:
            print(f"  [!] ALERT: {event.get('description', 'Security risk detected')}")


def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description='Mac Mini M2 Security Assistant - Comprehensive security monitoring and analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a directory
  %(prog)s scan --path /Users
  
  # Generate a report
  %(prog)s report --output security_report.json
  
  # Start continuous monitoring
  %(prog)s monitor --path /Users --interval 300
  
  # Scan and save detailed report
  %(prog)s scan --path /Applications --output scan_report.html --format html
  
  # Scan non-recursively
  %(prog)s scan --path /Users/username/Downloads --no-recursive
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Perform security scan')
    scan_parser.add_argument('--path', type=str, default='/', 
                            help='Path to scan (default: /)')
    scan_parser.add_argument('--no-recursive', action='store_true',
                            help='Disable recursive scanning (default: recursive enabled)')
    scan_parser.add_argument('--follow-symlinks', action='store_true',
                            help='Follow symbolic links')
    scan_parser.add_argument('--output', type=str,
                            help='Output file for report')
    scan_parser.add_argument('--format', type=str, default='json',
                            choices=['json', 'html', 'pdf'],
                            help='Report format (default: json)')
    
    # Monitor command
    monitor_parser = subparsers.add_parser('monitor', help='Start continuous monitoring')
    monitor_parser.add_argument('--path', type=str, default='/Users',
                               help='Path to monitor (default: /Users)')
    monitor_parser.add_argument('--interval', type=int, default=300,
                               help='Check interval in seconds (default: 300)')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate security report')
    report_parser.add_argument('--input', type=str,
                              help='Input file with scan data')
    report_parser.add_argument('--output', type=str, required=True,
                              help='Output file for report')
    report_parser.add_argument('--format', type=str, default='json',
                              choices=['json', 'html', 'pdf'],
                              help='Report format (default: json)')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Create CLI instance and execute command
    cli = AssistantCLI()
    
    if args.command == 'scan':
        result = cli.scan(args)
        # Store for potential report generation
        cli.last_scan = result
    elif args.command == 'monitor':
        cli.monitor(args)
    elif args.command == 'report':
        cli.report(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
