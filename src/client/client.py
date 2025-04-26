import sys
import os
from pathlib import Path

# Add the project root directory to Python path
project_root = str(Path(__file__).parent.parent.parent)
sys.path.append(project_root)

import requests
import argparse
import logging
from typing import Optional, Dict
import json
import os
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('client.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('Client')

class SecScanClient:
    def __init__(self, server_url: str, api_key: str):
        self.server_url = server_url.rstrip('/')
        self.api_key = api_key
        self.headers = {
            'X-API-Key': api_key,
            'Content-Type': 'application/json'
        }
        
    def start_scan(self, target_url: str, scan_type: str = "fast", 
                  delay: float = 1.0, max_pages: int = 20, 
                  user_agent: Optional[str] = None) -> Optional[str]:
        """Start a new scan and return the scan ID"""
        try:
            payload = {
                'target_url': target_url,
                'scan_type': scan_type,
                'delay': delay,
                'max_pages': max_pages
            }
            if user_agent:
                payload['user_agent'] = user_agent
                
            response = requests.post(
                f"{self.server_url}/scan",
                headers=self.headers,
                json=payload,
                verify=True  # Verify SSL certificate
            )
            
            if response.status_code == 200:
                result = response.json()
                return result['scan_id']
            else:
                logger.error(f"Failed to start scan: {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error: {str(e)}")
            return None
            
    def get_scan_results(self, scan_id: str) -> Optional[Dict]:
        """Retrieve scan results by scan ID"""
        try:
            response = requests.get(
                f"{self.server_url}/scan/{scan_id}",
                headers=self.headers,
                verify=True
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to get scan results: {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error: {str(e)}")
            return None
            
    def print_results(self, results: Dict):
        """Print scan results in a formatted way"""
        if not results:
            logger.error("No results to display")
            return
            
        # Print statistics
        stats = results.get('stats', {})
        logger.info(
            f"\nScan completed\n"
            f"Pages crawled: {stats.get('pages_crawled', 0)}\n"
            f"Links found: {stats.get('links_found', 0)}\n"
            f"Forms found: {stats.get('forms_found', 0)}"
        )
        
        # Print vulnerabilities
        vulnerabilities = results.get('vulnerabilities', [])
        if vulnerabilities:
            logger.critical(f"\nFound {len(vulnerabilities)} vulnerabilities:")
            for i, vuln in enumerate(vulnerabilities, 1):
                logger.critical(
                    f"\n[{i}] {vuln['type'].upper()} at {vuln['url']}\n"
                    f"Parameter: {vuln.get('param', 'N/A')}\n"
                    f"Payload: {vuln.get('payload', 'N/A')}\n"
                    f"Evidence: {vuln.get('evidence', 'N/A')}\n"
                    f"Severity: {vuln.get('severity', 'medium')}"
                )
        else:
            logger.info("No vulnerabilities found")

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='SecScan Client')
    parser.add_argument('--target', required=True, help='URL to scan')
    parser.add_argument('--server', default='https://localhost:8000',
                      help='Server URL')
    parser.add_argument('--api-key', required=True, help='API Key')
    parser.add_argument('--scan-type', choices=['fast', 'full'], default='fast',
                      help='Scan intensity level')
    parser.add_argument('--delay', type=float, default=1.0,
                      help='Delay between requests in seconds')
    parser.add_argument('--max-pages', type=int, default=20,
                      help='Maximum pages to crawl')
    parser.add_argument('--user-agent', 
                      default='SecScan/1.0 (+https://github.com/Aerisphase/SecScan)',
                      help='Custom User-Agent string')
    return parser.parse_args()

def main():
    """Main entry point"""
    args = parse_args()
    
    try:
        client = SecScanClient(args.server, args.api_key)
        
        logger.info(f"Starting scan for {args.target} (mode: {args.scan_type})")
        scan_id = client.start_scan(
            target_url=args.target,
            scan_type=args.scan_type,
            delay=args.delay,
            max_pages=args.max_pages,
            user_agent=args.user_agent
        )
        
        if scan_id:
            logger.info(f"Scan started with ID: {scan_id}")
            results = client.get_scan_results(scan_id)
            client.print_results(results)
        else:
            logger.error("Failed to start scan")
            
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
    except Exception as e:
        logger.error(f"Critical error: {str(e)}", exc_info=True)

if __name__ == "__main__":
    main() 