import sys
import io
import argparse
import logging
import asyncio
from typing import List, Dict, Optional, Any, Type
from .scanner_base import BaseScannerPlugin

from .scanner_base import ScannerRegistry

# Set up encoding for Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

def setup_logging():
    """Set up logging system"""
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
    def __init__(self, pages: List[Dict[str, Any]], scanner_classes: Optional[List[Type[BaseScannerPlugin]]] = None):
        self.pages = pages
        self.registry = ScannerRegistry()
        self.logger = logging.getLogger('Scanner')
        self.scanners = scanner_classes or self.registry.get_all_scanners()

    def scan_page(self, page_data: Dict) -> List[Dict]:
        """Scan a single page for vulnerabilities"""
        try:
            vulnerabilities = []
            url = page_data.get('url', '')
            forms = page_data.get('forms', [])
            
            # Initialize scanners
            scanners = {
                'xss': XSSScanner(),
                'sqli': SQLiScanner()
            }
            
            # Run each scanner on the page
            for scanner_name, scanner in scanners.items():
                try:
                    self.logger.info(f"Running {scanner_name.upper()} scanner on {url}")
                    vulns = scanner.scan(page_data)
                    if vulns:
                        vulnerabilities.extend(vulns)
                except Exception as e:
                    self.logger.error(f"{scanner_name} scanner failed on {url}: {str(e)}")
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Error scanning page {url}: {str(e)}")
            return []

    async def scan(self, scan_type: Optional[str] = None) -> List[Dict]:
        """Perform vulnerability scanning.
        
        Args:
            scan_type (Optional[str]): Type of scan to perform.
        
        Returns:
            List of detected vulnerabilities
        """
        # Determine available scanners
        scanner_registry = ScannerRegistry()
        available_scanners = scanner_registry.list_scanners()
        self.logger.info(f"Available scanners: {available_scanners}")
        
        # Determine which scanners to use
        if scan_type:
            # If a specific scan type is provided, validate it
            if scan_type not in available_scanners:
                self.logger.error(f"Invalid scan type: {scan_type}. Available: {available_scanners}")
                raise ValueError(f"Invalid scan type: {scan_type}. Available: {available_scanners}")
            
            # Get the scanner class directly
            scanner_class = scanner_registry._scanners.get(scan_type)
            
            # If no scanner found, log a warning and return empty list
            if not scanner_class:
                self.logger.warning(f"No scanner found for type: {scan_type}")
                return []
            
            # Create scanner instance
            self.logger.info(f"Initializing scanner: {scanner_class.__name__}")
            scanner = scanner_class()
        else:
            # Default to all registered scanners
            scanner_classes = list(scanner_registry._scanners.values())
            
            # If no scanners found, return empty list
            if not scanner_classes:
                self.logger.warning("No scanners registered")
                return []
            
            # Create scanner instances
            scanners = []
            for scanner_class in scanner_classes:
                self.logger.info(f"Initializing scanner: {scanner_class.__name__}")
                scanners.append(scanner_class())
        
        # Prepare scanning tasks
        tasks = []
        
        # Use single scanner or multiple scanners based on previous logic
        target_scanners = [scanner] if scan_type else scanners
        
        # Log scanning details
        self.logger.info(f"Scanning with {len(target_scanners)} scanner(s) on {len(self.pages)} pages")
        
        for target_scanner in target_scanners:
            for page in self.pages:
                tasks.append(
                    asyncio.create_task(
                        target_scanner.scan(page)
                    )
                )
        
        # Wait for all scanning tasks to complete
        results = await asyncio.gather(*tasks)
        
        # Flatten and filter results
        vulnerabilities = []
        for result in results:
            if result:
                vulnerabilities.extend(result)
        
        self.logger.info(f"Scan completed. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities

    def _validate_scan_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate scan configuration.
        
        Args:
            config (Dict[str, Any]): Scan configuration dictionary.
        
        Returns:
            Dict[str, Any]: Validated configuration.
        
        Raises:
            ValueError: If required configuration keys are missing.
        """
        required_keys = ['target_url', 'max_pages']
        for key in required_keys:
            if key not in config:
                raise ValueError(f"Missing required configuration key: {key}")
        
        return config

def print_results(results: Dict):
    """Print results to console"""
    logger = logging.getLogger('Reporter')
    
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

    # Print security recommendations
    recommendations = results.get('security_recommendations', [])
    if recommendations:
        logger.warning("\nSecurity Recommendations:")
        for i, rec in enumerate(recommendations, 1):
            logger.warning(f"[{i}] {rec}")

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