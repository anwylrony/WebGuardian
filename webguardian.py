#!/usr/bin/env python3
# webguardian.py

import argparse
import json
import time
import sys
import os

# Add the 'core' directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'core'))

from crawler import Crawler
from utils import setup_session, load_payloads

# --- Vulnerability Check Modules ---

def check_sql_injection(session, target_assets, payloads, signatures):
    """Checks for SQL Injection vulnerabilities."""
    print("\n[*] Starting SQL Injection checks...")
    vulnerabilities = []
    # Logic for testing forms and URL parameters with payloads
    # ... (implementation from the previous response can be adapted here) ...
    # This would iterate through target_assets['forms'] and target_assets['urls']
    # and check responses against signatures['sql_errors'].
    return vulnerabilities

def check_xss(session, target_assets, payloads, signatures):
    """Checks for Cross-Site Scripting vulnerabilities."""
    print("\n[*] Starting XSS checks...")
    vulnerabilities = []
    # Logic for testing forms and URL parameters with XSS payloads
    # ... (implementation from the previous response can be adapted here) ...
    # This checks if the payload is reflected in the response.
    return vulnerabilities

# Add other check modules here (e.g., check_lfi, check_headers)

# --- Main Application Logic ---

def load_config(config_path):
    """Loads configuration from a JSON file."""
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[-] Config file not found: {config_path}. Using defaults.")
        return {
            "threads": 10, "delay": 0.5, "timeout": 10, "max_depth": 3,
            "user_agents": ["WebGuardian/1.0"],
            "payloads_dir": "data/payloads",
            "signatures_file": "data/signatures/vulns.json"
        }

def main():
    parser = argparse.ArgumentParser(description="WebGuardian - Ethical Vulnerability Scanner")
    parser.add_argument("url", help="Target URL to scan (e.g., http://example.com)")
    parser.add_argument("-c", "--config", default="config.json", help="Path to configuration file.")
    parser.add_argument("-o", "--output", help="Path to save the JSON report.")
    parser.add_argument("--modules", nargs='+', default=['sqli', 'xss'], choices=['sqli', 'xss', 'lfi', 'headers'], help="Specify which modules to run.")
    
    args = parser.parse_args()

    if not args.url.startswith(('http://', 'https://')):
        print("[-] Error: URL must start with http:// or https://")
        sys.exit(1)

    config = load_config(args.config)
    session = setup_session()
    
    # 1. CRAWL THE TARGET
    print(f"[*] Initiating crawl on {args.url}")
    crawler = Crawler(args.url, session, config)
    target_assets = crawler.crawl(max_pages=config.get('max_pages', 50))
    
    print(f"\n[+] Crawl Complete.")
    print(f"    - Discovered {len(target_assets['urls'])} unique URLs.")
    print(f"    - Discovered {len(target_assets['forms'])} forms.")

    # 2. LOAD PAYLOADS AND SIGNATURES
    signatures = json.load(open(config['signatures_file']))
    
    # 3. RUN VULNERABILITY MODULES
    all_vulnerabilities = []
    if 'sqli' in args.modules:
        payloads = load_payloads(os.path.join(config['payloads_dir'], 'sqli.txt'))
        all_vulnerabilities.extend(check_sql_injection(session, target_assets, payloads, signatures))
    
    if 'xss' in args.modules:
        payloads = load_payloads(os.path.join(config['payloads_dir'], 'xss.txt'))
        all_vulnerabilities.extend(check_xss(session, target_assets, payloads, signatures))

    # 4. GENERATE REPORT
    report = {
        'scan_info': {
            'target': args.url,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'modules_run': args.modules
        },
        'assets_discovered': target_assets,
        'vulnerabilities_found': all_vulnerabilities
    }
    
    report_path = args.output or f"report_{int(time.time())}.json"
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=4)
        
    print(f"\n[+] Scan finished. Report saved to {report_path}")
    print(f"    - Total vulnerabilities found: {len(all_vulnerabilities)}")


if __name__ == "__main__":
    main()
