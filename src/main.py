import asyncio
import logging
from typing import Dict, Any
from core.scanner import Scanner
from core.crawler import AdvancedCrawler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('Main')

async def main():
    # Configuration
    config: Dict[str, Any] = {
        'client': {
            'timeout': 30,
            'verify_ssl': True,
            'user_agent': 'SecScan/1.0',
            'max_retries': 3,
            'delay': 1.0
        },
        'crawler': {
            'max_pages': 20,
            'delay': 1.0,
            'user_agent': 'SecScan/1.0',
            'verify_ssl': True,
            'max_retries': 3
        }
    }
    
    # Initialize crawler and scanner
    crawler = AdvancedCrawler(config['crawler'])
    scanner = Scanner(config)
    
    # Target URL
    target_url = "https://example.com"
    
    try:
        # Crawl the target
        logger.info(f"Starting crawl of {target_url}")
        pages = await crawler.crawl(target_url)
        
        # Scan each page
        all_vulnerabilities = []
        for page in pages:
            logger.info(f"Scanning page: {page['url']}")
            vulnerabilities = await scanner.scan_page(page['url'])
            all_vulnerabilities.extend(vulnerabilities)
            
        # Print results
        logger.info(f"Found {len(all_vulnerabilities)} vulnerabilities")
        for vuln in all_vulnerabilities:
            logger.info(f"Vulnerability: {vuln['type']} at {vuln['url']}")
            logger.info(f"Severity: {vuln['severity']}")
            logger.info(f"Description: {vuln['description']}")
            
    except Exception as e:
        logger.error(f"Error during scanning: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main()) 