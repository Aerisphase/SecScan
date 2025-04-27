import sys
import io
import argparse
import logging
import asyncio
import json
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
        try:
            logger.info("Initializing Scanner with configuration")
            logger.debug(f"Configuration received: {json.dumps(config, indent=2)}")
            
            # Validate configuration structure
            if not isinstance(config, dict):
                raise ValueError("Configuration must be a dictionary")
                
            if 'client' not in config:
                logger.error("Configuration missing 'client' section")
                raise ValueError("Configuration must contain 'client' section")
                
            if 'scanners' not in config:
                logger.error("Configuration missing 'scanners' section")
                raise ValueError("Configuration must contain 'scanners' section")
                
            if 'crawler' not in config:
                logger.error("Configuration missing 'crawler' section")
                raise ValueError("Configuration must contain 'crawler' section")
                
            # Validate client configuration
            client_config = config['client']
            if not isinstance(client_config, dict):
                logger.error("Client configuration is not a dictionary")
                raise ValueError("Client configuration must be a dictionary")
                
            required_client_fields = ['timeout', 'max_retries', 'delay', 'user_agent', 'verify_ssl']
            for field in required_client_fields:
                if field not in client_config:
                    logger.error(f"Client configuration missing required field: {field}")
                    raise ValueError(f"Client configuration missing required field: {field}")
                    
            # Validate crawler configuration
            crawler_config = config['crawler']
            if not isinstance(crawler_config, dict):
                logger.error("Crawler configuration is not a dictionary")
                raise ValueError("Crawler configuration must be a dictionary")
                
            required_crawler_fields = ['max_pages', 'delay', 'client']
            for field in required_crawler_fields:
                if field not in crawler_config:
                    logger.error(f"Crawler configuration missing required field: {field}")
                    raise ValueError(f"Crawler configuration missing required field: {field}")
                    
            # Validate client configuration in crawler
            crawler_client_config = crawler_config['client']
            if not isinstance(crawler_client_config, dict):
                logger.error("Crawler client configuration is not a dictionary")
                raise ValueError("Crawler client configuration must be a dictionary")
                
            for field in required_client_fields:
                if field not in crawler_client_config:
                    logger.error(f"Crawler client configuration missing required field: {field}")
                    raise ValueError(f"Crawler client configuration missing required field: {field}")
                    
            # Validate scanners configuration
            scanners_config = config['scanners']
            if not isinstance(scanners_config, dict):
                logger.error("Scanners configuration is not a dictionary")
                raise ValueError("Scanners configuration must be a dictionary")
                
            if not any(scanners_config.values()):
                logger.error("No scanners are enabled")
                raise ValueError("At least one scanner must be enabled")
                
            self.config = config
            logger.info("Creating AiohttpClientAdapter")
            self.client = AiohttpClientAdapter(config['client'])
            logger.info("Scanner initialized successfully")
            
        except ValueError as e:
            logger.error(f"Scanner configuration validation failed: {str(e)}")
            logger.error(f"Configuration structure: {json.dumps(config, indent=2)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during scanner initialization: {str(e)}")
            logger.error(f"Configuration structure: {json.dumps(config, indent=2)}")
            raise
        
    async def scan_page(self, url: str) -> List[Dict[str, Any]]:
        """Scan a single page for vulnerabilities"""
        try:
            vulnerabilities = []
            scanners = []
            logger.info("Initializing scanners...")
            
            # Map of scanner names to their classes
            scanner_classes = {
                'xss': XSSScanner,
                'sql_injection': SQLInjectionScanner,
                'csrf': CSRFScanner,
                'ssrf': SSRFScanner,
                'xxe': XXEScanner,
                'idor': IDORScanner,
                'broken_auth': BrokenAuthScanner,
                'sensitive_data': SensitiveDataScanner,
                'security_misconfig': SecurityMisconfigScanner
            }
            
            # Initialize all enabled scanners
            for scanner_name, enabled in self.config['scanners'].items():
                if enabled:
                    try:
                        scanner_class = scanner_classes.get(scanner_name)
                        if scanner_class:
                            logger.info(f"Initializing {scanner_name} scanner")
                            scanner = scanner_class(self.client)
                            scanners.append(scanner)
                        else:
                            logger.warning(f"Unknown scanner type: {scanner_name}")
                    except Exception as e:
                        logger.error(f"Failed to initialize {scanner_name} scanner: {str(e)}")
                        logger.error(f"Error details: {type(e).__name__}: {str(e)}", exc_info=True)
            
            if not scanners:
                raise ValueError("No valid scanners were initialized")
                
            logger.info(f"Total scanners initialized: {len(scanners)}")
            
            # Run all scanners concurrently
            tasks = []
            for scanner in scanners:
                try:
                    task = asyncio.create_task(scanner.scan(url))
                    tasks.append(task)
                except Exception as e:
                    logger.error(f"Failed to create task for scanner: {str(e)}")
            
            if not tasks:
                raise ValueError("No scanner tasks were created")
                
            # Wait for all scanners to complete
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Scanner error: {str(result)}")
                elif isinstance(result, list):
                    vulnerabilities.extend(result)
            
            return vulnerabilities
            
        except ValueError as e:
            logger.error(f"Scan page validation error: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during page scan: {str(e)}")
            raise

    async def scan(self, target_url: str) -> Dict[str, Any]:
        """Main scanning method"""
        try:
            # Initialize crawler with crawler configuration
            crawler_config = {
                'crawler': {
                    'max_pages': self.config['crawler']['max_pages'],
                    'delay': self.config['crawler']['delay'],
                    'client': {
                        'timeout': self.config['client']['timeout'],
                        'max_retries': self.config['client']['max_retries'],
                        'delay': self.config['client']['delay'],
                        'user_agent': self.config['client']['user_agent'],
                        'verify_ssl': self.config['client']['verify_ssl']
                    }
                }
            }
            logger.info(f"Initializing crawler with configuration: {json.dumps(crawler_config, indent=2)}")
            crawler = AdvancedCrawler(crawler_config)
            
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