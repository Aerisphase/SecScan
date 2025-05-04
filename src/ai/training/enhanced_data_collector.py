import json
import logging
import logging.config
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import os
import re
import requests
import time
import random
import sys
import site

# Add user site-packages to path (where pandas and other packages are installed)
user_site_packages = site.getusersitepackages()
if user_site_packages not in sys.path:
    sys.path.append(user_site_packages)

# Import required libraries with error handling
try:
    from bs4 import BeautifulSoup
except ImportError:
    print("Error: BeautifulSoup not found. Please install with 'pip install beautifulsoup4'")
    sys.exit(1)

try:
    import pandas as pd
except ImportError:
    print("Error: pandas not found. Please install with 'pip install pandas'")
    print("Python path:", sys.path)
    sys.exit(1)

try:
    import numpy as np
except ImportError:
    print("Error: numpy not found. Please install with 'pip install numpy'")
    sys.exit(1)
from config import (
    BASE_DIR,
    CVE_API_URL,
    LOGGING_CONFIG,
    OWASP_RESOURCES,
    PEN_TEST_REPORT_PATHS,
    TRAINING_DATA_DIR,
    WAF_LOG_PATHS,
    SAMPLE_DATA_DIR
)

# Configure logging
logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger(__name__)

class EnhancedDataCollector:
    """Enhanced data collector with multiple sources for AI training"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecScan/1.0 (Training Pipeline)'
        })
        # Ensure training data directory exists
        TRAINING_DATA_DIR.mkdir(parents=True, exist_ok=True)
        
        # Create additional directories
        self.github_data_dir = TRAINING_DATA_DIR / "github"
        self.cve_data_dir = TRAINING_DATA_DIR / "cve"
        self.owasp_data_dir = TRAINING_DATA_DIR / "owasp"
        self.capec_data_dir = TRAINING_DATA_DIR / "capec"
        self.synthetic_data_dir = TRAINING_DATA_DIR / "synthetic"
        
        for directory in [self.github_data_dir, self.cve_data_dir, self.owasp_data_dir, 
                         self.capec_data_dir, self.synthetic_data_dir]:
            directory.mkdir(parents=True, exist_ok=True)
    
    def collect_all(self) -> Dict[str, List[Dict[str, Any]]]:
        """Collect all data from various sources"""
        logger.info("Starting enhanced data collection...")
        
        data = {
            'cve_data': self.collect_cve_data(),
            'waf_logs': self.collect_waf_logs(),
            'pen_test_findings': self.collect_pen_test_reports(),
            'owasp_resources': self.collect_owasp_resources(),
            'github_security_data': self.collect_github_security_data(),
            'capec_attack_patterns': self.collect_capec_data(),
            'cwe_weaknesses': self.collect_cwe_data(),
            'synthetic_data': self.generate_synthetic_data()
        }
        
        # Save combined data
        output_file = TRAINING_DATA_DIR / "enhanced_combined_data.json"
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
            
        logger.info(f"Enhanced data collection completed. Data saved to {output_file}")
        return data
    
    def collect_cve_data(self) -> List[Dict[str, Any]]:
        """Collect CVE data from NVD with enhanced filtering"""
        try:
            all_cves = []
            
            # Collect CVEs from multiple time periods for better coverage
            time_periods = [
                (30, "recent"),   # Last 30 days
                (90, "quarter"),  # Last quarter
                (365, "annual")   # Last year
            ]
            
            for days, period_name in time_periods:
                end_date = datetime.now()
                start_date = end_date - timedelta(days=days)
                
                params = {
                    'pubStartDate': start_date.strftime('%Y-%m-%dT00:00:00.000'),
                    'pubEndDate': end_date.strftime('%Y-%m-%dT00:00:00.000'),
                    'resultsPerPage': 2000
                }
                
                # Add keyword filters for web vulnerabilities
                keywords = ["web", "injection", "xss", "csrf", "ssrf", "sql", "command", "path traversal", "xxe"]
                for keyword in keywords:
                    try:
                        # Create a copy of params with the keyword
                        keyword_params = params.copy()
                        keyword_params['keywordSearch'] = keyword
                        
                        response = self.session.get(CVE_API_URL, params=keyword_params)
                        response.raise_for_status()
                        
                        data = response.json()
                        cves = data.get('vulnerabilities', [])
                        logger.info(f"Collected {len(cves)} CVEs for keyword '{keyword}' in {period_name} period")
                        
                        # Add only if not already in the list (avoid duplicates)
                        for cve in cves:
                            if not any(existing['cve']['id'] == cve['cve']['id'] for existing in all_cves):
                                all_cves.append(cve)
                        
                        # Rate limiting to avoid API restrictions
                        time.sleep(1)
                    except Exception as e:
                        logger.error(f"Error collecting CVEs for keyword '{keyword}': {e}")
            
            # Save to file
            output_file = self.cve_data_dir / "collected_cves.json"
            with open(output_file, 'w') as f:
                json.dump(all_cves, f, indent=2)
                
            logger.info(f"Collected {len(all_cves)} unique CVEs")
            return all_cves
            
        except Exception as e:
            logger.error(f"Error in CVE collection: {e}")
            return self._get_sample_cve_data()
    
    def collect_github_security_data(self) -> List[Dict[str, Any]]:
        """Collect security data from GitHub repositories"""
        security_data = []
        
        # List of GitHub repositories with security advisories and examples
        security_repos = [
            "OWASP/CheatSheetSeries",
            "OWASP/wstg",
            "swisskyrepo/PayloadsAllTheThings",
            "payloadbox/sql-injection-payload-list",
            "payloadbox/xss-payload-list"
        ]
        
        for repo in security_repos:
            try:
                # Get repository content
                url = f"https://api.github.com/repos/{repo}/contents"
                response = self.session.get(url)
                response.raise_for_status()
                
                contents = response.json()
                
                # Process markdown files which often contain security information
                for item in contents:
                    if item['type'] == 'file' and item['name'].endswith('.md'):
                        file_url = item['download_url']
                        file_response = self.session.get(file_url)
                        file_response.raise_for_status()
                        
                        content = file_response.text
                        
                        # Extract security patterns, payloads, and examples
                        security_data.append({
                            'repo': repo,
                            'file': item['name'],
                            'content': content,
                            'url': file_url
                        })
                        
                        # Rate limiting
                        time.sleep(1)
                
                logger.info(f"Collected security data from GitHub repo: {repo}")
                
            except Exception as e:
                logger.error(f"Error collecting data from GitHub repo {repo}: {e}")
        
        # Save to file
        output_file = self.github_data_dir / "github_security_data.json"
        with open(output_file, 'w') as f:
            json.dump(security_data, f, indent=2)
            
        return security_data
    
    def collect_capec_data(self) -> List[Dict[str, Any]]:
        """Collect CAPEC (Common Attack Pattern Enumeration and Classification) data"""
        try:
            # CAPEC XML data URL
            url = "https://capec.mitre.org/data/xml/capec_latest.xml"
            response = self.session.get(url)
            response.raise_for_status()
            
            # Parse XML
            soup = BeautifulSoup(response.text, 'xml')
            attack_patterns = []
            
            # Extract attack patterns
            for pattern in soup.find_all('Attack_Pattern'):
                try:
                    pattern_id = pattern.get('ID', '')
                    pattern_name = pattern.find('Name').text if pattern.find('Name') else ''
                    description = pattern.find('Description').text if pattern.find('Description') else ''
                    
                    # Extract examples
                    examples = []
                    for example in pattern.find_all('Example'):
                        examples.append(example.text)
                    
                    # Extract related weaknesses (CWEs)
                    related_weaknesses = []
                    for related in pattern.find_all('Related_Weakness'):
                        related_weaknesses.append(related.get('CWE_ID', ''))
                    
                    attack_patterns.append({
                        'id': pattern_id,
                        'name': pattern_name,
                        'description': description,
                        'examples': examples,
                        'related_weaknesses': related_weaknesses
                    })
                except Exception as e:
                    logger.error(f"Error processing CAPEC pattern: {e}")
            
            # Save to file
            output_file = self.capec_data_dir / "capec_patterns.json"
            with open(output_file, 'w') as f:
                json.dump(attack_patterns, f, indent=2)
                
            logger.info(f"Collected {len(attack_patterns)} CAPEC attack patterns")
            return attack_patterns
            
        except Exception as e:
            logger.error(f"Error collecting CAPEC data: {e}")
            return []
    
    def collect_cwe_data(self) -> List[Dict[str, Any]]:
        """Collect CWE (Common Weakness Enumeration) data"""
        try:
            # CWE XML data URL
            url = "https://cwe.mitre.org/data/xml/cwec_latest.xml"
            response = self.session.get(url)
            response.raise_for_status()
            
            # Parse XML
            soup = BeautifulSoup(response.text, 'xml')
            weaknesses = []
            
            # Extract weaknesses
            for weakness in soup.find_all('Weakness'):
                try:
                    weakness_id = weakness.get('ID', '')
                    weakness_name = weakness.get('Name', '')
                    
                    # Get description
                    description = ""
                    desc_summary = weakness.find('Description_Summary')
                    if desc_summary:
                        description = desc_summary.text
                    
                    # Get examples
                    examples = []
                    for example in weakness.find_all('Example'):
                        examples.append(example.text)
                    
                    # Filter to include only web-relevant weaknesses
                    web_keywords = ['web', 'http', 'html', 'input', 'validation', 'injection', 'xss', 'csrf', 
                                   'authentication', 'authorization', 'session', 'cookie']
                    
                    if any(keyword in description.lower() or keyword in weakness_name.lower() for keyword in web_keywords):
                        weaknesses.append({
                            'id': weakness_id,
                            'name': weakness_name,
                            'description': description,
                            'examples': examples
                        })
                except Exception as e:
                    logger.error(f"Error processing CWE: {e}")
            
            # Save to file
            output_file = self.capec_data_dir / "cwe_weaknesses.json"
            with open(output_file, 'w') as f:
                json.dump(weaknesses, f, indent=2)
                
            logger.info(f"Collected {len(weaknesses)} CWE weaknesses")
            return weaknesses
            
        except Exception as e:
            logger.error(f"Error collecting CWE data: {e}")
            return []
    
    def generate_synthetic_data(self) -> List[Dict[str, Any]]:
        """Generate synthetic training data for better coverage"""
        synthetic_data = []
        
        # Vulnerability types to generate data for
        vuln_types = [
            "SQL Injection", "XSS", "CSRF", "SSRF", "XXE", 
            "Command Injection", "Path Traversal", "SSTI",
            "Open Redirect", "IDOR"
        ]
        
        # Templates for different vulnerability types
        templates = {
            "SQL Injection": [
                "User input '{payload}' was injected into SQL query without proper sanitization",
                "SQL query vulnerable to injection at parameter '{param}'",
                "Database query constructed with user-controlled input '{payload}'",
                "Unsanitized user input in SQL query: '{payload}'",
                "SQL injection vulnerability in login form with payload '{payload}'"
            ],
            "XSS": [
                "Cross-site scripting vulnerability with payload '{payload}'",
                "Reflected XSS via parameter '{param}'",
                "Stored XSS in comment field with payload '{payload}'",
                "DOM-based XSS in client-side JavaScript handling '{param}'",
                "XSS vulnerability in search function with payload '{payload}'"
            ],
            "CSRF": [
                "Cross-site request forgery vulnerability in '{endpoint}' endpoint",
                "Missing CSRF token in form submission to '{endpoint}'",
                "CSRF vulnerability allowing unauthorized '{action}'",
                "Form submission without CSRF protection at '{endpoint}'",
                "CSRF vulnerability in user profile update function"
            ],
            # Templates for other vulnerability types...
        }
        
        # Payloads for different vulnerability types
        payloads = {
            "SQL Injection": [
                "' OR 1=1 --", "1' OR '1'='1", "admin'--", 
                "'; DROP TABLE users; --", "1' UNION SELECT username,password FROM users --"
            ],
            "XSS": [
                "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>", "javascript:alert(1)", "<iframe src=javascript:alert(1)>"
            ],
            "CSRF": ["N/A"],  # CSRF doesn't use payloads in the same way
            # Payloads for other vulnerability types...
        }
        
        # Parameters commonly vulnerable
        parameters = ["id", "username", "search", "q", "query", "redirect", "file", "path", "cmd", "action"]
        
        # Endpoints commonly vulnerable
        endpoints = ["/login", "/profile", "/admin", "/search", "/upload", "/download", "/api/users", "/settings"]
        
        # Actions commonly vulnerable to CSRF
        actions = ["password change", "email update", "fund transfer", "account deletion", "role modification"]
        
        # Generate synthetic data
        for vuln_type in vuln_types:
            # Get templates for this vulnerability type
            type_templates = templates.get(vuln_type, ["Generic {vuln_type} vulnerability with payload '{payload}'"])
            
            # Get payloads for this vulnerability type
            type_payloads = payloads.get(vuln_type, ["generic_payload"])
            
            # Generate multiple examples for each vulnerability type
            for i in range(20):  # Generate 20 examples per type
                template = random.choice(type_templates)
                payload = random.choice(type_payloads)
                param = random.choice(parameters)
                endpoint = random.choice(endpoints)
                action = random.choice(actions)
                
                # Format the template
                description = template.format(
                    payload=payload, 
                    param=param,
                    endpoint=endpoint,
                    action=action,
                    vuln_type=vuln_type
                )
                
                # Create synthetic vulnerability entry
                synthetic_data.append({
                    "type": vuln_type,
                    "description": description,
                    "payload": payload if payload != "N/A" else None,
                    "parameter": param if "{param}" in template else None,
                    "endpoint": endpoint if "{endpoint}" in template else None,
                    "severity": random.choice(["Low", "Medium", "High", "Critical"]),
                    "synthetic": True
                })
        
        # Save to file
        output_file = self.synthetic_data_dir / "synthetic_vulnerabilities.json"
        with open(output_file, 'w') as f:
            json.dump(synthetic_data, f, indent=2)
            
        logger.info(f"Generated {len(synthetic_data)} synthetic vulnerability examples")
        return synthetic_data
    
    # Include original methods from DataCollector
    def collect_waf_logs(self) -> List[Dict[str, Any]]:
        """Collect WAF logs from configured paths with enhanced processing"""
        logs = []
        
        for path in WAF_LOG_PATHS:
            try:
                with open(path, 'r') as f:
                    for line in f:
                        try:
                            log_entry = json.loads(line)
                            logs.append(log_entry)
                        except json.JSONDecodeError:
                            # Try to parse non-JSON log formats
                            parsed_log = self._parse_log_line(line)
                            if parsed_log:
                                logs.append(parsed_log)
            except FileNotFoundError:
                logger.warning(f"WAF log file not found: {path}")
                continue
                
        if not logs:
            logger.warning("No WAF logs found, using sample data")
            return self._get_sample_waf_logs()
            
        return logs
    
    def _parse_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a log line in various formats"""
        # Try to parse ModSecurity format
        modsec_pattern = r'\[([^\]]+)\] \[([^\]]+)\] \[([^\]]+)\] \[([^\]]+)\] \[([^\]]+)\] (.*)'
        match = re.match(modsec_pattern, line)
        if match:
            return {
                'timestamp': match.group(1),
                'client_ip': match.group(2),
                'rule_id': match.group(3),
                'severity': match.group(4),
                'rule_message': match.group(6)
            }
        
        # Try to parse Nginx format
        nginx_pattern = r'(\d+\.\d+\.\d+\.\d+) - .* \[([^\]]+)\] "([^"]+)" (\d+) (\d+) "([^"]*)" "([^"]*)"'
        match = re.match(nginx_pattern, line)
        if match:
            return {
                'client_ip': match.group(1),
                'timestamp': match.group(2),
                'request': match.group(3),
                'status_code': match.group(4),
                'user_agent': match.group(7)
            }
        
        return None
    
    def collect_pen_test_reports(self) -> List[Dict[str, Any]]:
        """Collect penetration test reports"""
        findings = []
        
        for path in PEN_TEST_REPORT_PATHS:
            try:
                with open(path, 'r') as f:
                    report = json.load(f)
                    findings.extend(report.get('findings', []))
            except (FileNotFoundError, json.JSONDecodeError) as e:
                logger.warning(f"Error reading pen test report {path}: {e}")
                continue
                
        if not findings:
            logger.warning("No pen test findings found, using sample data")
            return self._get_sample_pen_test_findings()
            
        return findings
    
    def collect_owasp_resources(self) -> List[Dict[str, Any]]:
        """Collect OWASP resources with enhanced processing"""
        resources = []
        
        # Expanded OWASP resources
        owasp_urls = OWASP_RESOURCES + [
            # OWASP API Security Top 10
            "https://raw.githubusercontent.com/OWASP/API-Security/master/editions/2023/en/0x00-header.md",
            # OWASP Mobile Top 10
            "https://raw.githubusercontent.com/OWASP/owasp-mstg/master/Document/0x04-Mobile-App-Security-Testing.md",
            # OWASP Testing Guide
            "https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/README.md"
        ]
        
        for url in owasp_urls:
            try:
                response = self.session.get(url)
                response.raise_for_status()
                
                # Process based on content type
                if url.endswith('.json'):
                    resources.append(response.json())
                elif url.endswith('.md'):
                    # Process markdown content
                    content = response.text
                    # Extract sections and headers
                    sections = self._parse_markdown(content)
                    resources.append({
                        'url': url,
                        'type': 'markdown',
                        'sections': sections
                    })
                else:
                    resources.append({
                        'url': url,
                        'content': response.text
                    })
                    
                # Rate limiting
                time.sleep(1)
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Error collecting OWASP resource {url}: {e}")
                continue
                
        if not resources:
            logger.warning("No OWASP resources found, using sample data")
            return self._get_sample_owasp_resources()
            
        # Save to file
        output_file = self.owasp_data_dir / "owasp_resources.json"
        with open(output_file, 'w') as f:
            json.dump(resources, f, indent=2)
            
        return resources
    
    def _parse_markdown(self, content: str) -> List[Dict[str, str]]:
        """Parse markdown content into sections"""
        sections = []
        current_section = {'title': '', 'content': ''}
        
        for line in content.split('\n'):
            if line.startswith('# '):
                # Save previous section if it exists
                if current_section['title']:
                    sections.append(current_section)
                # Start new section
                current_section = {'title': line[2:], 'content': ''}
            elif line.startswith('## '):
                # Save previous section if it exists
                if current_section['title']:
                    sections.append(current_section)
                # Start new subsection
                current_section = {'title': line[3:], 'content': ''}
            else:
                # Add to current section content
                current_section['content'] += line + '\n'
        
        # Add the last section
        if current_section['title']:
            sections.append(current_section)
            
        return sections
    
    # Sample data methods (fallbacks)
    def _get_sample_cve_data(self) -> List[Dict[str, Any]]:
        """Get sample CVE data"""
        sample_path = SAMPLE_DATA_DIR / "cve" / "sample_cves.json"
        try:
            with open(sample_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return [
                {
                    "cve": {
                        "id": "CVE-2024-1234",
                        "descriptions": [{"value": "Sample SQL injection vulnerability"}],
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]}
                    }
                }
            ]
            
    def _get_sample_waf_logs(self) -> List[Dict[str, Any]]:
        """Get sample WAF logs"""
        sample_path = SAMPLE_DATA_DIR / "waf" / "sample_logs.json"
        try:
            with open(sample_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return [
                {
                    "timestamp": "2024-04-28T12:00:00Z",
                    "client_ip": "192.168.1.1",
                    "request_method": "GET",
                    "request_uri": "/admin.php",
                    "rule_id": "941100",
                    "rule_message": "SQL Injection Attack Detected",
                    "severity": "CRITICAL"
                }
            ]
            
    def _get_sample_pen_test_findings(self) -> List[Dict[str, Any]]:
        """Get sample pen test findings"""
        sample_path = SAMPLE_DATA_DIR / "reports" / "sample_findings.json"
        try:
            with open(sample_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return [
                {
                    "title": "SQL Injection in Login Form",
                    "description": "Login form vulnerable to SQL injection",
                    "severity": "High",
                    "impact": "Full database access",
                    "recommendation": "Use parameterized queries"
                }
            ]
            
    def _get_sample_owasp_resources(self) -> List[Dict[str, Any]]:
        """Get sample OWASP resources"""
        return [
            {
                "url": "sample_owasp_resource",
                "type": "markdown",
                "sections": [
                    {
                        "title": "A1:2021-Broken Access Control",
                        "content": "Access control enforces policy such that users cannot act outside of their intended permissions."
                    },
                    {
                        "title": "A2:2021-Cryptographic Failures",
                        "content": "Failures related to cryptography which often lead to sensitive data exposure or system compromise."
                    }
                ]
            }
        ]

# If run directly, collect data
if __name__ == "__main__":
    collector = EnhancedDataCollector()
    collector.collect_all()
