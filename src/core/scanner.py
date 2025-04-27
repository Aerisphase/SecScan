import sys
import io
import argparse
import logging
import asyncio
from typing import Dict, Optional, List, Any
from .crawler import AdvancedCrawler
from .scanners import (
    XSSScanner,
    SQLInjectionScanner,
    CSRFScanner,
    SSRFScanner,
    XXEScanner,
    IDORScanner,
    BrokenAuthScanner,
    SensitiveDataScanner,
    SecurityMisconfigScanner
)
from .http_client_adapter import AiohttpClientAdapter

# Настройка кодировки для Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

logger = logging.getLogger('Scanner')

def setup_logging():
    """Настройка системы логирования"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('scan.log', encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger('Main')

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='SecScan - Web Vulnerability Scanner')
    parser.add_argument('--target', required=True, help='URL to scan')
    parser.add_argument('--scan-type', choices=['fast', 'full'], default='fast',
                      help='Scan intensity level')
    parser.add_argument('--delay', type=float, default=1.0,
                      help='Delay between requests in seconds')
    parser.add_argument('--max-pages', type=int, default=20,
                      help='Maximum pages to crawl')
    parser.add_argument('--user-agent', 
                      default='SecScan/1.0 (+https://github.com/Aerisphase/SecScan)',
                      help='Custom User-Agent string')
    parser.add_argument('--verify-ssl', action='store_true',
                      help='Verify SSL certificates')
    parser.add_argument('--proxy', help='Proxy server URL (e.g., http://proxy:8080)')
    parser.add_argument('--auth', help='Basic auth credentials (user:pass)')
    parser.add_argument('--max-retries', type=int, default=3,
                      help='Maximum number of retries for failed requests')
    return parser.parse_args()

def analyze_security_headers(headers: Dict[str, str]) -> List[str]:
    """Analyze security headers and return recommendations"""
    recommendations = []
    
    # Check X-Frame-Options
    if not headers.get('x-frame-options'):
        recommendations.append("Missing X-Frame-Options header - Consider adding to prevent clickjacking")
    
    # Check X-Content-Type-Options
    if not headers.get('x-content-type-options'):
        recommendations.append("Missing X-Content-Type-Options header - Consider adding 'nosniff'")
    
    # Check X-XSS-Protection
    if not headers.get('x-xss-protection'):
        recommendations.append("Missing X-XSS-Protection header - Consider adding '1; mode=block'")
    
    # Check Content-Security-Policy
    if not headers.get('content-security-policy'):
        recommendations.append("Missing Content-Security-Policy header - Consider implementing CSP")
    
    # Check Strict-Transport-Security
    if not headers.get('strict-transport-security'):
        recommendations.append("Missing Strict-Transport-Security header - Consider adding HSTS")
    
    return recommendations

class Scanner:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        # Create adapter for aiohttp client
        self.client = AiohttpClientAdapter(config['client'])
        
    async def scan_page(self, url: str) -> List[Dict[str, Any]]:
        """Scan a single page for vulnerabilities"""
        vulnerabilities = []
        
        # Initialize enabled scanners
        scanners = []
        logger.info("Initializing scanners...")
        
        if self.config['scanners'].get('xss', True):
            logger.info("Initializing XSS scanner")
            scanners.append(XSSScanner(self.client))
        if self.config['scanners'].get('sql_injection', True):
            logger.info("Initializing SQL Injection scanner")
            scanners.append(SQLInjectionScanner(self.client))
        if self.config['scanners'].get('csrf', True):
            logger.info("Initializing CSRF scanner")
            scanners.append(CSRFScanner(self.client))
        if self.config['scanners'].get('ssrf', True):
            logger.info("Initializing SSRF scanner")
            scanners.append(SSRFScanner(self.client))
        if self.config['scanners'].get('xxe', True):
            logger.info("Initializing XXE scanner")
            scanners.append(XXEScanner(self.client))
        if self.config['scanners'].get('idor', True):
            logger.info("Initializing IDOR scanner")
            scanners.append(IDORScanner(self.client))
        if self.config['scanners'].get('broken_auth', True):
            logger.info("Initializing Broken Auth scanner")
            scanners.append(BrokenAuthScanner(self.client))
        if self.config['scanners'].get('sensitive_data', True):
            logger.info("Initializing Sensitive Data scanner")
            scanners.append(SensitiveDataScanner(self.client))
        if self.config['scanners'].get('security_misconfig', True):
            logger.info("Initializing Security Misconfig scanner")
            scanners.append(SecurityMisconfigScanner(self.client))
            
        logger.info(f"Total scanners initialized: {len(scanners)}")
        
        # Run all scanners concurrently
        tasks = []
        for scanner in scanners:
            try:
                logger.info(f"Starting {scanner.__class__.__name__} on {url}")
                task = asyncio.create_task(scanner.scan(url))
                tasks.append(task)
            except Exception as e:
                logger.error(f"Error initializing {scanner.__class__.__name__}: {str(e)}")
                logger.error(f"Error details: {type(e).__name__}: {str(e)}", exc_info=True)
                
        # Wait for all scanners to complete
        logger.info(f"Waiting for {len(tasks)} scanner tasks to complete...")
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Scanner {scanners[i].__class__.__name__} failed: {str(result)}")
                logger.error(f"Error details: {type(result).__name__}: {str(result)}", exc_info=True)
            elif isinstance(result, list):
                vulnerabilities.extend(result)
                logger.info(f"Scanner {scanners[i].__class__.__name__} found {len(result)} vulnerabilities")
                
        return vulnerabilities

    async def scan(self, target_url: str) -> Dict[str, Any]:
        """Main scanning method"""
        try:
            # Initialize crawler
            crawler = AdvancedCrawler(self.config['crawler'])
            
            # Crawl the target
            logger.info(f"Starting crawl of {target_url}")
            pages = await crawler.crawl(target_url)
            logger.info(f"Crawling completed. Found {len(pages)} pages")
            
            # Scan each page
            all_vulnerabilities = []
            for i, page in enumerate(pages, 1):
                logger.info(f"Scanning page {i}/{len(pages)}: {page['url']}")
                page_vulns = await self.scan_page(page['url'])
                if page_vulns:
                    all_vulnerabilities.extend(page_vulns)
                    logger.info(f"Found {len(page_vulns)} vulnerabilities on {page['url']}")
            
            # Prepare results
            results = {
                'target_url': target_url,
                'pages_crawled': len(pages),
                'vulnerabilities_found': len(all_vulnerabilities),
                'vulnerabilities': all_vulnerabilities,
                'scan_type': self.config.get('scan_type', 'fast'),
                'scanners_used': [k for k, v in self.config['scanners'].items() if v]
            }
            
            return results
            
        except Exception as e:
            logger.error(f"Scan error: {str(e)}")
            raise

def print_results(results: Dict):
    """Вывод результатов в консоль"""
    logger = logging.getLogger('Reporter')
    
    if not results:
        logger.error("No results to display")
        return

    # Вывод статистики
    stats = results.get('stats', {})
    logger.info(
        f"\nScan completed\n"
        f"Pages crawled: {stats.get('pages_crawled', 0)}\n"
        f"Links found: {stats.get('links_found', 0)}\n"
        f"Forms found: {stats.get('forms_found', 0)}"
    )

    # Вывод рекомендаций по безопасности
    recommendations = results.get('security_recommendations', [])
    if recommendations:
        logger.warning("\nSecurity Recommendations:")
        for i, rec in enumerate(recommendations, 1):
            logger.warning(f"[{i}] {rec}")

    # Вывод уязвимостей
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

def main():
    """Program entry point"""
    logger = setup_logging()
    args = parse_args()

    try:
        logger.info(f"Starting scan for {args.target} (mode: {args.scan_type})")
        
        config = {
            'scan_type': args.scan_type,
            'delay': args.delay,
            'max_pages': args.max_pages,
            'user_agent': args.user_agent,
            'verify_ssl': args.verify_ssl,
            'proxy': args.proxy,
            'auth': args.auth,
            'max_retries': args.max_retries
        }

        scanner = Scanner(config)
        results = scanner.scan(args.target)
        print_results(results)

    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
    except Exception as e:
        logger.error(f"Critical error: {str(e)}", exc_info=True)
    finally:
        logging.shutdown()

if __name__ == "__main__":
    main()