#!/usr/bin/env python3
import argparse
import logging
from core.crawler import AdvancedCrawler
from core.scanners import SQLiScanner, XSSScanner
from typing import List, Dict, Optional

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('scan.log'),
            logging.StreamHandler()
        ]
    )

def parse_args():
    parser = argparse.ArgumentParser(description='SecScan - Web Vulnerability Scanner')
    parser.add_argument('--target', required=True, help='URL to scan')
    parser.add_argument('--scan-type', choices=['fast', 'full'], default='fast')
    parser.add_argument('--delay', type=float, default=1.0, help='Delay between requests')
    parser.add_argument('--max-pages', type=int, default=20, help='Max pages to crawl')
    parser.add_argument('--user-agent', default='SecScan/1.0 (+https://github.com/Aerisphase/SecScan)')
    parser.add_argument('--output', choices=['console', 'json', 'html'], default='console')
    return parser.parse_args()

def main():
    args = parse_args()
    setup_logging()
    
    try:
        # Initialize crawler with custom settings
        crawler = AdvancedCrawler(
            base_url=args.target,
            max_pages=args.max_pages,
            delay=args.delay,
            user_agent=args.user_agent
        )
        
        # Start crawling
        logger = logging.getLogger('Main')
        logger.info(f"Starting scan for {args.target} (mode: {args.scan_type})")
        
        crawl_results = crawler.crawl()
        logger.info(f"Crawling completed. Pages: {len(crawl_results['urls'])}")
        
        # Run scanners
        scanners = [
            SQLiScanner(crawler.session),
            XSSScanner(crawler.session)
        ]
        
        vulnerabilities = []
        for url in crawl_results['urls']:
            for scanner in scanners:
                try:
                    vulns = scanner.scan(url)
                    if vulns:
                        vulnerabilities.extend(vulns)
                except Exception as e:
                    logger.error(f"Scanner failed on {url}: {str(e)}")
        
        # Generate report
        logger.info(f"Found {len(vulnerabilities)} potential vulnerabilities")
        if args.output != 'console':
            generate_report(vulnerabilities, args.output)
        else:
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"\nVulnerability #{i}:")
                print(f"Type: {vuln.get('type')}")
                print(f"URL: {vuln.get('url')}")
                print(f"Confidence: {vuln.get('confidence', 0)*100:.1f}%")
                print(f"Payload: {vuln.get('payload')}")
                print(f"Solution: {vuln.get('solution', 'Not specified')}")
                
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
    except Exception as e:
        logger.error(f"Critical error: {str(e)}", exc_info=True)

def generate_report(vulns: List[Dict], format: str):
    # Implement JSON/HTML report generation
    pass

if __name__ == "__main__":
    main()