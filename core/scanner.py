#!/usr/bin/env python3
import requests
import argparse
import json
import time
import sys
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import re
import random
import string
import subprocess
import os

class WebGuardian:
    def __init__(self, target_url, config_file=None):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WebGuardian/1.0 (Security Scanner)'
        })
        self.results = {
            'target': target_url,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'vulnerabilities': [],
            'info': []
        }
        self.visited_urls = set()
        self.forms = []
        self.endpoints = []
        self.config = self.load_config(config_file)
        
        # Load compiled C++ modules
        self.cpp_modules = self.load_cpp_modules()
        
    def load_config(self, config_file):
        """Load configuration from file or use defaults"""
        default_config = {
            'threads': 10,
            'delay': 0.5,
            'timeout': 10,
            'max_depth': 3,
            'user_agents': [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            ],
            'payloads_file': 'data/payloads/common.txt',
            'signatures_file': 'data/signatures/vulns.json'
        }
        
        if config_file and os.path.exists(config_file):
            with open(config_file, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)
                
        return default_config
    
    def load_cpp_modules(self):
        """Load compiled C++ modules for performance-critical operations"""
        modules = {}
        try:
            # Check if compiled modules exist
            if os.path.exists('cpp/http_parser'):
                modules['http_parser'] = 'cpp/http_parser'
            if os.path.exists('cpp/pattern_matcher'):
                modules['pattern_matcher'] = 'cpp/pattern_matcher'
        except Exception as e:
            print(f"Warning: Could not load C++ modules: {e}")
            
        return modules
    
    def random_user_agent(self):
        """Return a random user agent from the config"""
        return random.choice(self.config['user_agents'])
    
    def crawl(self, url, depth=0):
        """Crawl the website to discover endpoints and forms"""
        if depth > self.config['max_depth'] or url in self.visited_urls:
            return
            
        self.visited_urls.add(url)
        print(f"[+] Crawling: {url} (depth: {depth})")
        
        try:
            # Randomize user agent
            self.session.headers.update({'User-Agent': self.random_user_agent()})
            response = self.session.get(url, timeout=self.config['timeout'])
            
            # Use C++ parser if available, otherwise fallback to Python
            if 'http_parser' in self.cpp_modules:
                parsed = self.parse_with_cpp(response.text)
            else:
                parsed = self.parse_with_python(response.text)
                
            # Extract forms
            self.extract_forms(url, response.text)
            
            # Extract links and continue crawling
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(url, href)
                
                # Only follow links to the same domain
                if urlparse(full_url).netloc == urlparse(self.target_url).netloc:
                    self.endpoints.append(full_url)
                    time.sleep(self.config['delay'])
                    self.crawl(full_url, depth + 1)
                    
        except Exception as e:
            print(f"[-] Error crawling {url}: {e}")
    
    def parse_with_cpp(self, html):
        """Parse HTML using C++ module for better performance"""
        try:
            process = subprocess.run(
                [self.cpp_modules['http_parser']],
                input=html.encode('utf-8'),
                capture_output=True,
                check=True
            )
            return json.loads(process.stdout.decode('utf-8'))
        except Exception as e:
            print(f"[-] C++ parser error, falling back to Python: {e}")
            return self.parse_with_python(html)
    
    def parse_with_python(self, html):
        """Parse HTML using Python (fallback method)"""
        soup = BeautifulSoup(html, 'html.parser')
        return {
            'title': soup.title.string if soup.title else '',
            'forms': len(soup.find_all('form')),
            'links': len(soup.find_all('a', href=True)),
            'scripts': len(soup.find_all('script')),
            'inputs': len(soup.find_all('input'))
        }
    
    def extract_forms(self, url, html):
        """Extract forms from the page"""
        soup = BeautifulSoup(html, 'html.parser')
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            full_url = urljoin(url, action)
            
            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_type = input_tag.get('type', 'text')
                input_name = input_tag.get('name', '')
                inputs.append({'type': input_type, 'name': input_name})
            
            self.forms.append({
                'url': full_url,
                'method': method,
                'inputs': inputs
            })
    
    def scan_sql_injection(self):
        """Check for SQL injection vulnerabilities"""
        print("[*] Testing for SQL Injection...")
        
        # Load SQL injection payloads
        with open(self.config['payloads_file'], 'r') as f:
            payloads = [line.strip() for line in f if 'sql' in line.lower()]
        
        # Test forms
        for form in self.forms:
            for payload in payloads:
                data = {}
                for input_field in form['inputs']:
                    if input_field['type'] in ['text', 'search', 'password', 'email']:
                        data[input_field['name']] = payload
                
                try:
                    if form['method'] == 'get':
                        response = self.session.get(form['url'], params=data, timeout=self.config['timeout'])
                    else:
                        response = self.session.post(form['url'], data=data, timeout=self.config['timeout'])
                    
                    # Check for SQL error patterns
                    sql_errors = [
                        "you have an error in your sql syntax",
                        "warning: mysql",
                        "unclosed quotation mark",
                        "microsoft ole db provider for odbc drivers error"
                    ]
                    
                    for error in sql_errors:
                        if error.lower() in response.text.lower():
                            self.results['vulnerabilities'].append({
                                'type': 'SQL Injection',
                                'url': form['url'],
                                'method': form['method'],
                                'payload': payload,
                                'evidence': error
                            })
                            print(f"[!] SQL Injection found at {form['url']} with payload: {payload}")
                            break
                            
                except Exception as e:
                    print(f"[-] Error testing SQL injection: {e}")
                
                time.sleep(self.config['delay'])
        
        # Test URL parameters
        for url in self.endpoints:
            parsed = urlparse(url)
            if parsed.query:
                params = dict(param.split('=') for param in parsed.query.split('&') if '=' in param)
                
                for param_name in params:
                    for payload in payloads:
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        try:
                            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?" + '&'.join([f"{k}={v}" for k, v in test_params.items()])
                            response = self.session.get(test_url, timeout=self.config['timeout'])
                            
                            # Check for SQL error patterns
                            for error in sql_errors:
                                if error.lower() in response.text.lower():
                                    self.results['vulnerabilities'].append({
                                        'type': 'SQL Injection',
                                        'url': test_url,
                                        'method': 'GET',
                                        'payload': payload,
                                        'evidence': error
                                    })
                                    print(f"[!] SQL Injection found at {test_url} with payload: {payload}")
                                    break
                                    
                        except Exception as e:
                            print(f"[-] Error testing SQL injection in URL: {e}")
                        
                        time.sleep(self.config['delay'])
    
    def scan_xss(self):
        """Check for Cross-Site Scripting vulnerabilities"""
        print("[*] Testing for XSS...")
        
        # Load XSS payloads
        with open(self.config['payloads_file'], 'r') as f:
            payloads = [line.strip() for line in f if 'xss' in line.lower()]
        
        # Test forms
        for form in self.forms:
            for payload in payloads:
                data = {}
                for input_field in form['inputs']:
                    if input_field['type'] in ['text', 'search', 'password', 'email', 'textarea']:
                        data[input_field['name']] = payload
                
                try:
                    if form['method'] == 'get':
                        response = self.session.get(form['url'], params=data, timeout=self.config['timeout'])
                    else:
                        response = self.session.post(form['url'], data=data, timeout=self.config['timeout'])
                    
                    # Check if payload is reflected in the response
                    if payload in response.text:
                        self.results['vulnerabilities'].append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'url': form['url'],
                            'method': form['method'],
                            'payload': payload,
                            'evidence': 'Payload reflected in response'
                        })
                        print(f"[!] XSS found at {form['url']} with payload: {payload}")
                        
                except Exception as e:
                    print(f"[-] Error testing XSS: {e}")
                
                time.sleep(self.config['delay'])
    
    def scan_directory_traversal(self):
        """Check for directory traversal vulnerabilities"""
        print("[*] Testing for Directory Traversal...")
        
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        # Test forms
        for form in self.forms:
            for payload in payloads:
                data = {}
                for input_field in form['inputs']:
                    if input_field['type'] in ['text', 'search', 'file']:
                        data[input_field['name']] = payload
                
                try:
                    if form['method'] == 'get':
                        response = self.session.get(form['url'], params=data, timeout=self.config['timeout'])
                    else:
                        response = self.session.post(form['url'], data=data, timeout=self.config['timeout'])
                    
                    # Check for file content patterns
                    if "root:x:0:0" in response.text or "# localhost" in response.text:
                        self.results['vulnerabilities'].append({
                            'type': 'Directory Traversal',
                            'url': form['url'],
                            'method': form['method'],
                            'payload': payload,
                            'evidence': 'File content exposed'
                        })
                        print(f"[!] Directory Traversal found at {form['url']} with payload: {payload}")
                        
                except Exception as e:
                    print(f"[-] Error testing Directory Traversal: {e}")
                
                time.sleep(self.config['delay'])
    
    def scan_security_headers(self):
        """Check for missing security headers"""
        print("[*] Checking Security Headers...")
        
        try:
            response = self.session.get(self.target_url, timeout=self.config['timeout'])
            
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-XSS-Protection': 'XSS filter',
                'X-Content-Type-Options': 'MIME type sniffing protection',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'Content injection protection',
                'X-Content-Security-Policy': 'Legacy CSP',
                'Referrer-Policy': 'Referrer information control'
            }
            
            for header, description in security_headers.items():
                if header not in response.headers:
                    self.results['vulnerabilities'].append({
                        'type': 'Missing Security Header',
                        'url': self.target_url,
                        'header': header,
                        'description': description
                    })
                    print(f"[!] Missing security header: {header} - {description}")
                    
        except Exception as e:
            print(f"[-] Error checking security headers: {e}")
    
    def scan_ssl_tls(self):
        """Check SSL/TLS configuration"""
        print("[*] Checking SSL/TLS Configuration...")
        
        try:
            # Use OpenSSL command to check SSL/TLS
            domain = urlparse(self.target_url).netloc
            result = subprocess.run(
                ["openssl", "s_client", "-connect", f"{domain}:443", "-servername", domain],
                input="", 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True,
                timeout=10
            )
            
            # Parse the output for SSL/TLS information
            if "no peer certificate available" in result.stderr:
                self.results['vulnerabilities'].append({
                    'type': 'SSL/TLS Issue',
                    'url': self.target_url,
                    'issue': 'No SSL certificate available'
                })
                print(f"[!] SSL/TLS issue: No certificate available for {domain}")
                return
                
            # Check for weak ciphers
            if "DES-CBC3-SHA" in result.stdout or "RC4" in result.stdout:
                self.results['vulnerabilities'].append({
                    'type': 'SSL/TLS Issue',
                    'url': self.target_url,
                    'issue': 'Weak cipher suites detected'
                })
                print(f"[!] SSL/TLS issue: Weak cipher suites detected for {domain}")
                
            # Check certificate expiration
            cert_info = subprocess.run(
                ["openssl", "x509", "-noout", "-dates"],
                input=result.stdout.encode(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            if cert_info.returncode == 0:
                dates = cert_info.stdout.decode()
                if "notAfter" in dates:
                    expire_date = dates.split("notAfter=")[1].strip()
                    print(f"[+] SSL Certificate expires: {expire_date}")
                    
        except Exception as e:
            print(f"[-] Error checking SSL/TLS: {e}")
    
    def scan_common_files(self):
        """Check for exposed sensitive files"""
        print("[*] Checking for common sensitive files...")
        
        common_files = [
            ".env",
            ".git/config",
            "config.php",
            "web.config",
            "database.yml",
            ".htaccess",
            "wp-config.php",
            "composer.json",
            "package.json",
            "robots.txt",
            "sitemap.xml",
            ".DS_Store",
            "Thumbs.db"
        ]
        
        for file in common_files:
            url = urljoin(self.target_url, file)
            try:
                response = self.session.get(url, timeout=self.config['timeout'])
                if response.status_code == 200:
                    self.results['vulnerabilities'].append({
                        'type': 'Exposed Sensitive File',
                        'url': url,
                        'status_code': response.status_code
                    })
                    print(f"[!] Exposed sensitive file: {url}")
                    
            except Exception as e:
                print(f"[-] Error checking {file}: {e}")
            
            time.sleep(self.config['delay'])
    
    def run_scan(self):
        """Run the complete vulnerability scan"""
        print(f"[*] Starting scan on {self.target_url}")
        
        # First, crawl the website
        self.crawl(self.target_url)
        
        # Run vulnerability checks
        self.scan_sql_injection()
        self.scan_xss()
        self.scan_directory_traversal()
        self.scan_security_headers()
        self.scan_ssl_tls()
        self.scan_common_files()
        
        # Generate report
        self.generate_report()
    
    def generate_report(self):
        """Generate a report of the scan results"""
        report_file = f"report_{urlparse(self.target_url).netloc}_{int(time.time())}.json"
        
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=4)
            
        print(f"\n[*] Scan completed. Report saved to {report_file}")
        print(f"[*] Found {len(self.results['vulnerabilities'])} potential vulnerabilities")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WebGuardian - Ethical Vulnerability Scanner")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("-c", "--config", help="Configuration file")
    parser.add_argument("-o", "--output", help="Output file for the report")
    
    args = parser.parse_args()
    
    scanner = WebGuardian(args.url, args.config)
    scanner.run_scan()
