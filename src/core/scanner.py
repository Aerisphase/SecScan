import sys
import io
import argparse
import logging
from typing import Dict, Optional, List
from .crawler import AdvancedCrawler
from .js_crawler import JSCrawler
from .http_client import HttpClient
from .enhanced_http_client import EnhancedHttpClient
from .scanners import SQLiScanner, XSSScanner, SSRFScanner, CSRFScanner, SSTIScanner, CommandInjectionScanner, XXEScanner, PathTraversalScanner

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
    parser.add_argument('--js-enabled', action='store_true',
                      help='Enable JavaScript rendering for crawling')
    parser.add_argument('--waf-evasion', action='store_true',
                      help='Enable WAF evasion techniques')
    parser.add_argument('--rotate-user-agent', action='store_true',
                      help='Rotate user agents to avoid detection')
    parser.add_argument('--randomize-headers', action='store_true',
                      help='Randomize HTTP headers to avoid detection')
    parser.add_argument('--maintain-session', action='store_true',
                      help='Maintain session cookies across requests')
    parser.add_argument('--handle-csrf', action='store_true',
                      help='Automatically handle CSRF tokens in forms')
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
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.logger = logging.getLogger('Scanner')
        
    def scan(self, target_url: str) -> Optional[Dict]:
        """Main scanning function"""
        try:
            import time
            from datetime import datetime
            import re
            from urllib.parse import urlparse
            
            start_time = time.time()
            self.logger.info(f"Starting scan for {target_url}")
            
            # Ensure correct types in config
            validated_config = {
                'max_pages': int(self.config.get('max_pages', 20)),
                'delay': float(self.config.get('delay', 1.0)),
                'user_agent': str(self.config.get('user_agent', '')),
                'scan_type': str(self.config.get('scan_type', 'fast')),
                'verify_ssl': bool(self.config.get('verify_ssl', True)),
                'proxy': self.config.get('proxy'),
                'auth': self.config.get('auth'),
                'max_retries': int(self.config.get('max_retries', 3)),
                'js_enabled': bool(self.config.get('js_enabled', False)),
                'waf_evasion': bool(self.config.get('waf_evasion', True)),  # Default to True for WAF evasion
                'rotate_user_agent': bool(self.config.get('rotate_user_agent', True)),  # Default to True
                'randomize_headers': bool(self.config.get('randomize_headers', True)),  # Default to True
                'maintain_session': bool(self.config.get('maintain_session', True)),
                'handle_csrf': bool(self.config.get('handle_csrf', True))
            }
            
            # Initialize results
            results = {
                'target_url': target_url,
                'scan_type': validated_config['scan_type'],
                'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'end_time': '',
                'duration': 0,
                'vulnerabilities': [],
                'stats': {
                    'pages_crawled': 0,
                    'links_found': 0,
                    'forms_found': 0,
                    'injection_points': 0
                },
                'security_recommendations': []
            }
            
            # Create crawler configuration
            crawler_config = {
                'max_pages': validated_config['max_pages'],
                'delay': validated_config['delay'],
                'user_agent': validated_config['user_agent'],
                'scan_type': validated_config['scan_type'],
                'verify_ssl': validated_config['verify_ssl'],
                'proxy': validated_config['proxy'],
                'auth': validated_config['auth'],
                'max_retries': validated_config['max_retries']
            }
            
            # Crawl the website
            self.logger.info("Starting crawler...")
            crawler = AdvancedCrawler(target_url, **crawler_config)
            pages = crawler.crawl()
            
            if not pages:
                self.logger.error("No pages found during crawl")
                return results
                
            # Update stats
            results['stats']['pages_crawled'] = len(pages)
            results['stats']['links_found'] = sum(len(page.get('links', [])) for page in pages)
            results['stats']['forms_found'] = sum(len(page.get('forms', [])) for page in pages)
            results['stats']['injection_points'] = sum(len(page.get('potential_injection_points', [])) for page in pages)
            
            # If JavaScript rendering is enabled, process with headless browser
            if validated_config['js_enabled']:
                self.logger.info("Starting JavaScript crawler...")
                js_crawler = JSCrawler(target_url, max_pages=validated_config['max_pages'])
                js_pages = js_crawler.crawl()
                
                if js_pages:
                    # Add unique pages from JS crawler
                    js_urls = {page['url'] for page in js_pages}
                    existing_urls = {page['url'] for page in pages}
                    
                    for js_page in js_pages:
                        if js_page['url'] not in existing_urls:
                            pages.append(js_page)
                            
                    # Update stats
                    results['stats']['pages_crawled'] = len(pages)
                    results['stats']['links_found'] = sum(len(page.get('links', [])) for page in pages)
                    results['stats']['forms_found'] = sum(len(page.get('forms', [])) for page in pages)
            
            # Check security headers
            self.logger.info("Checking security headers...")
            try:
                # Use EnhancedHttpClient for better WAF handling
                client = EnhancedHttpClient(
                    verify_ssl=validated_config['verify_ssl'],
                    waf_evasion=validated_config['waf_evasion'],
                    rotate_user_agent=validated_config['rotate_user_agent']
                )
                response = client.get(target_url)
                if response and response.headers:
                    security_recommendations = analyze_security_headers(response.headers)
                    results['security_recommendations'] = security_recommendations
                    
                    # Check if WAF was detected
                    waf_detected = False
                    for waf_name, pattern in client.waf_signatures:
                        headers_str = str(response.headers)
                        if re.search(pattern, headers_str, re.IGNORECASE):
                            waf_detected = True
                            self.logger.warning(f"WAF detected: {waf_name} - Enabling advanced evasion techniques")
                            results['security_recommendations'].append(f"WAF detected: {waf_name} - Using advanced evasion techniques")
                            break
            except Exception as e:
                self.logger.error(f"Error checking security headers: {str(e)}")
            
            # Scan each page for vulnerabilities
            self.logger.info("Scanning pages for vulnerabilities...")
            vulnerabilities = []
            
            # Get selected scanners from config
            selected_scanners = self.config.get('selected_scanners')
            
            # Process pages with potential injection points first
            pages.sort(key=lambda p: len(p.get('potential_injection_points', [])), reverse=True)
            
            for page in pages:
                # Check if the page has potential injection points
                injection_points = page.get('potential_injection_points', [])
                if injection_points:
                    self.logger.info(f"Found {len(injection_points)} potential injection points in {page['url']}")
                
                # Scan the page for vulnerabilities
                page_vulns = self.scan_page(page, selected_scanners)
                if page_vulns:
                    vulnerabilities.extend(page_vulns)
                    
                # If we're in fast scan mode and already found vulnerabilities, stop scanning
                if validated_config['scan_type'] == 'fast' and vulnerabilities and len(vulnerabilities) >= 5:
                    self.logger.info("Fast scan mode: Found vulnerabilities, stopping scan")
                    break
                    
            # Remove duplicates
            unique_vulns = []
            vuln_signatures = set()
            
            for vuln in vulnerabilities:
                # Create a signature for the vulnerability
                signature = f"{vuln['type']}:{vuln['url']}:{vuln.get('param', '')}:{vuln.get('evidence', '')}:{vuln.get('severity', '')}"  
                
                if signature not in vuln_signatures:
                    vuln_signatures.add(signature)
                    unique_vulns.append(vuln)
                    
            results['vulnerabilities'] = unique_vulns
            
            # Calculate scan duration
            end_time = time.time()
            duration = end_time - start_time
            results['end_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            results['duration'] = round(duration, 2)
            
            self.logger.info(f"Scan completed in {duration:.2f} seconds")
            self.logger.info(f"Found {len(unique_vulns)} vulnerabilities")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Scan error: {str(e)}", exc_info=True)
            return None

    def scan_page(self, page_data: Dict, selected_scanners: List[str] = None) -> List[Dict]:
        """Scan a single page for vulnerabilities"""
        try:
            vulnerabilities = []
            url = page_data.get('url', '')
            forms = page_data.get('forms', [])
            
            # Create an enhanced HTTP client with WAF evasion capabilities
            enhanced_client = EnhancedHttpClient(
                verify_ssl=False,
                timeout=15,
                max_retries=3,
                rate_limit_min=0.2,
                rate_limit_max=1.0,
                rotate_user_agent=True,
                rotate_request_pattern=True,
                waf_evasion=True,
                handle_csrf=True,
                maintain_session=True
            )
            
            # Initialize all available scanners
            all_scanners = {}
            
            # Only initialize scanners that are selected
            if selected_scanners is None or 'xss' in selected_scanners:
                all_scanners['xss'] = XSSScanner(enhanced_client)
                
            if selected_scanners is None or 'sqli' in selected_scanners:
                all_scanners['sqli'] = SQLiScanner(enhanced_client)
                
            if selected_scanners is None or 'ssrf' in selected_scanners:
                all_scanners['ssrf'] = SSRFScanner(enhanced_client)
                
            # Add new scanners if available and selected
            if CSRFScanner is not None and (selected_scanners is None or 'csrf' in selected_scanners):
                all_scanners['csrf'] = CSRFScanner(enhanced_client)
                
            if SSTIScanner is not None and (selected_scanners is None or 'ssti' in selected_scanners):
                all_scanners['ssti'] = SSTIScanner(enhanced_client)
                
            if CommandInjectionScanner is not None and (selected_scanners is None or 'cmdInjection' in selected_scanners):
                all_scanners['cmd_injection'] = CommandInjectionScanner(enhanced_client)
                
            if PathTraversalScanner is not None and (selected_scanners is None or 'pathTraversal' in selected_scanners):
                all_scanners['path_traversal'] = PathTraversalScanner(enhanced_client)
                
            if XXEScanner is not None and (selected_scanners is None or 'xxe' in selected_scanners):
                all_scanners['xxe'] = XXEScanner(enhanced_client)
            
            # Run each selected scanner on the page
            for scanner_name, scanner in all_scanners.items():
                try:
                    self.logger.info(f"Running {scanner_name.upper()} scanner on {url}")
                    vulns = scanner.scan(url, forms)
                    if vulns:
                        vulnerabilities.extend(vulns)
                except Exception as e:
                    self.logger.error(f"{scanner_name} scanner failed on {url}: {str(e)}")
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Error scanning page {url}: {str(e)}")
            return []

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
            'target_url': args.target,
            'scan_type': args.scan_type,
            'delay': args.delay,
            'max_pages': args.max_pages,
            'user_agent': args.user_agent,
            'verify_ssl': args.verify_ssl,
            'proxy': args.proxy,
            'auth': args.auth,
            'max_retries': args.max_retries,
            'js_enabled': args.js_enabled,
            'waf_evasion': args.waf_evasion,
            'rotate_user_agent': args.rotate_user_agent,
            'maintain_session': args.maintain_session,
            'handle_csrf': args.handle_csrf
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