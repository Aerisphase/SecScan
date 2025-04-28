import json
import logging
import logging.config
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import os

import requests
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

class DataCollector:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecScan/1.0 (Training Pipeline)'
        })
        # Ensure training data directory exists
        TRAINING_DATA_DIR.mkdir(parents=True, exist_ok=True)
        
    def collect_scan_results(self) -> List[Dict]:
        """Collect scan results from the database."""
        try:
            # TODO: Implement database connection and query
            logger.warning("Scan results collection not implemented yet")
            return []
        except Exception as e:
            logger.error(f"Error collecting scan results: {e}")
            return []

    def collect_cve_data(self) -> List[Dict[str, Any]]:
        """Collect recent CVE data from NVD"""
        try:
            # Get CVEs from last 30 days
            end_date = datetime.now()
            start_date = end_date - timedelta(days=30)
            
            params = {
                'pubStartDate': start_date.strftime('%Y-%m-%dT00:00:00.000'),
                'pubEndDate': end_date.strftime('%Y-%m-%dT00:00:00.000'),
                'resultsPerPage': 2000,
                'noRejected': True
            }
            
            response = self.session.get(CVE_API_URL, params=params)
            response.raise_for_status()
            
            data = response.json()
            return data.get('vulnerabilities', [])
            
        except requests.exceptions.RequestException as e:
            logger.error(f"HTTP error collecting CVE data: {e}")
            # Return sample CVE data if API fails
            return self._get_sample_cve_data()
            
    def collect_waf_logs(self) -> List[Dict[str, Any]]:
        """Collect WAF logs from configured paths"""
        logs = []
        
        for path in WAF_LOG_PATHS:
            try:
                with open(path, 'r') as f:
                    for line in f:
                        try:
                            log_entry = json.loads(line)
                            logs.append(log_entry)
                        except json.JSONDecodeError:
                            continue
            except FileNotFoundError:
                logger.warning(f"WAF log file not found: {path}")
                continue
                
        if not logs:
            logger.warning("No WAF logs found, using sample data")
            return self._get_sample_waf_logs()
            
        return logs
        
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
        """Collect OWASP resources"""
        resources = []
        
        for url in OWASP_RESOURCES:
            try:
                response = self.session.get(url)
                response.raise_for_status()
                resources.append(response.json())
            except requests.exceptions.RequestException as e:
                logger.error(f"Error collecting OWASP resource {url}: {e}")
                continue
                
        if not resources:
            logger.warning("No OWASP resources found, using sample data")
            return self._get_sample_owasp_resources()
            
        return resources
        
    def collect_all(self) -> Dict[str, List[Dict[str, Any]]]:
        """Collect all data"""
        logger.info("Starting data collection...")
        
        data = {
            'cve_data': self.collect_cve_data(),
            'waf_logs': self.collect_waf_logs(),
            'pen_test_findings': self.collect_pen_test_reports(),
            'owasp_resources': self.collect_owasp_resources()
        }
        
        # Save combined data
        output_file = TRAINING_DATA_DIR / "combined_data.json"
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
            
        logger.info("Data collection completed")
        return data
        
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
        sample_path = SAMPLE_DATA_DIR / "owasp" / "sample_resources.json"
        try:
            with open(sample_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return [
                {
                    "title": "OWASP Top 10 2023",
                    "categories": [
                        {
                            "id": "A01",
                            "name": "Broken Access Control",
                            "description": "Access control vulnerabilities"
                        }
                    ]
                }
            ] 