#!/usr/bin/env python3
import sys
import os
import argparse
from core.scanner import WebGuardian

def main():
    parser = argparse.ArgumentParser(description="WebGuardian - Ethical Vulnerability Scanner")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("-c", "--config", help="Configuration file", default="config.json")
    parser.add_argument("-o", "--output", help="Output file for the report")
    parser.add_argument("--threads", type=int, help="Number of threads to use")
    parser.add_argument("--delay", type=float, help="Delay between requests (seconds)")
    parser.add_argument("--depth", type=int, help="Maximum crawl depth")
    parser.add_argument("--modules", nargs="+", choices=["sql", "xss", "dt", "headers", "ssl", "files"], 
                        help="Specific modules to run (default: all)")
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print("Error: URL must start with http:// or https://")
        sys.exit(1)
    
    # Create scanner
    scanner = WebGuardian(args.url, args.config)
    
    # Override config with command line arguments
    if args.threads:
        scanner.config['threads'] = args.threads
    if args.delay:
        scanner.config['delay'] = args.delay
    if args.depth:
        scanner.config['max_depth'] = args.depth
    
    # Run specific modules if requested
    if args.modules:
        print(f"[*] Running specific modules: {', '.join(args.modules)}")
        
        # First crawl the website
        scanner.crawl(args.url)
        
        # Run selected modules
        if 'sql' in args.modules:
            scanner.scan_sql_injection()
        if 'xss' in args.modules:
            scanner.scan_xss()
        if 'dt' in args.modules:
            scanner.scan_directory_traversal()
        if 'headers' in args.modules:
            scanner.scan_security_headers()
        if 'ssl' in args.modules:
            scanner.scan_ssl_tls()
        if 'files' in args.modules:
            scanner.scan_common_files()
    else:
        # Run full scan
        scanner.run_scan()
    
    # Generate report
    if args.output:
        scanner.generate_report(args.output)
    else:
        scanner.generate_report()

if __name__ == "__main__":
    main()
