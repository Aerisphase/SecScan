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
                'waf_evasion': bool(self.config.get('waf_evasion', False)),
                'rotate_user_agent': bool(self.config.get('rotate_user_agent', False)),
                'randomize_headers': bool(self.config.get('randomize_headers', False)),
                'maintain_session': bool(self.config.get('maintain_session', True)),
                'handle_csrf': bool(self.config.get('handle_csrf', True))
            }

            self.logger.debug(f"Using config: {validated_config}")
            
            # Create HTTP client based on configuration
            if validated_config.get('waf_evasion', False) or validated_config.get('rotate_user_agent', False) or \
               validated_config.get('maintain_session', True) or validated_config.get('handle_csrf', True):
                self.logger.info("Using enhanced HTTP client with WAF evasion and session management")
                http_client = EnhancedHttpClient(
                    verify_ssl=validated_config.get('verify_ssl', True),
                    timeout=10,
                    max_retries=validated_config.get('max_retries', 3),
                    rate_limit_min=validated_config.get('delay', 1.0),
                    rate_limit_max=validated_config.get('delay', 1.0) * 2,
                    proxy=validated_config.get('proxy'),
                    auth=validated_config.get('auth'),
                    rotate_user_agent=validated_config.get('rotate_user_agent', False),
                    rotate_request_pattern=validated_config.get('randomize_headers', False) or validated_config.get('waf_evasion', False),
                    waf_evasion=validated_config.get('waf_evasion', False),
                    handle_csrf=validated_config.get('handle_csrf', True),
                    maintain_session=validated_config.get('maintain_session', True)
                )
                
                if validated_config.get('user_agent'):
                    http_client.session.headers['User-Agent'] = validated_config.get('user_agent')
            else:
                self.logger.info("Using standard HTTP client")
                http_client = HttpClient(
                    verify_ssl=validated_config.get('verify_ssl', True),
                    timeout=10,
                    max_retries=validated_config.get('max_retries', 3),
                    rate_limit=validated_config.get('delay', 1.0),
                    proxy=validated_config.get('proxy'),
                    auth=validated_config.get('auth')
                )
                
                if validated_config.get('user_agent'):
                    http_client.session.headers['User-Agent'] = validated_config.get('user_agent')
            
            # Use JSCrawler if JavaScript is enabled, otherwise use AdvancedCrawler
            if validated_config.get('js_enabled', False):
                self.logger.info("Using JavaScript-enabled crawler")
                async def run_js_crawler():
                    async with JSCrawler(target_url, validated_config) as crawler:
                        return await crawler.crawl()
                        
                import asyncio
                crawl_data = asyncio.run(run_js_crawler())
            else:
                self.logger.info("Using standard crawler")
                # Pass the HTTP client to the crawler
                crawler = AdvancedCrawler(target_url, validated_config)
                crawler.client = http_client
                crawl_data = crawler.crawl()
            # Crawl data is already obtained above
            
            if not crawl_data:
                self.logger.error("No data collected during crawling")
                return None

            # Analyze security headers
            security_recommendations = analyze_security_headers(crawl_data.get('security_headers', {}))

            # Initialize scanners with the HTTP client
            scanners = {
                'xss': XSSScanner(http_client),
                'sqli': SQLiScanner(http_client),
                'ssrf': SSRFScanner(http_client)
            }
            
            # Add additional scanners if configured
            if validated_config.get('scan_type', 'fast') == 'full':
                scanners.update({
                    'csrf': CSRFScanner(http_client),
                    'ssti': SSTIScanner(http_client),
                    'cmdInjection': CommandInjectionScanner(http_client),
                    'xxe': XXEScanner(http_client),
                    'pathTraversal': PathTraversalScanner(http_client)
                })

            # Collect vulnerabilities
            vulnerabilities = []
            
            # Extract forms from crawl data
            forms = []
            if validated_config.get('js_enabled', False):
                # For JSCrawler, forms are in the pages array
                for page in crawl_data.get('pages', []):
                    page_forms = page.get('forms', [])
                    # Add page URL to each form for context
                    for form in page_forms:
                        form['page_url'] = page.get('url', '')
                    forms.extend(page_forms)
            else:
                # For AdvancedCrawler, forms are directly in crawl_data
                forms = crawl_data.get('forms', [])
            
            for scanner_name, scanner in scanners.items():
                try:
                    self.logger.info(f"Running {scanner_name.upper()} scanner...")
                    vulns = scanner.scan(target_url, forms)
                    if vulns:
                        vulnerabilities.extend(vulns)
                except Exception as e:
                    self.logger.error(f"{scanner_name} scanner failed: {str(e)}")

            # Get form analysis for JavaScript-rendered forms
            form_analysis = []
            if validated_config.get('js_enabled', False):
                for page in crawl_data.get('pages', []):
                    for form in page.get('forms', []):
                        if form.get('has_submit_handler', False) or not form.get('action'):
                            form_analysis.append({
                                'url': page.get('url', ''),
                                'form_id': form.get('form_id', ''),
                                'form_class': form.get('form_class', ''),
                                'submission_type': 'javascript' if form.get('has_submit_handler') else 'unknown',
                                'action': form.get('action', 'JavaScript event handler')
                            })

            return {
                'stats': {
                    'pages_crawled': crawl_data.get('pages_crawled', 0) if not validated_config.get('js_enabled', False) 
                                   else len(crawl_data.get('pages', [])),
                    'links_found': crawl_data.get('links_found', 0) if not validated_config.get('js_enabled', False)
                                 else crawl_data.get('links_found', 0),
                    'forms_found': len(forms),
                    'js_enabled': validated_config.get('js_enabled', False)
                },
                'form_analysis': form_analysis,
                'vulnerabilities': vulnerabilities,
                'security_recommendations': security_recommendations,
                'security_headers': crawl_data.get('security_headers', {})
            }

        except Exception as e:
            self.logger.error(f"Scanning error: {str(e)}", exc_info=True)
            return None

    def scan_page(self, page_data: Dict, selected_scanners: List[str] = None) -> List[Dict]:
        """Scan a single page for vulnerabilities"""
        try:
            vulnerabilities = []
            url = page_data.get('url', '')
            forms = page_data.get('forms', [])
            
            # Initialize all available scanners
            all_scanners = {}
            
            # Only initialize scanners that are selected
            if selected_scanners is None or 'xss' in selected_scanners:
                all_scanners['xss'] = XSSScanner(None)
                
            if selected_scanners is None or 'sqli' in selected_scanners:
                all_scanners['sqli'] = SQLiScanner(None)
                
            if selected_scanners is None or 'ssrf' in selected_scanners:
                all_scanners['ssrf'] = SSRFScanner(None)
                
            # Add new scanners if available and selected
            if CSRFScanner is not None and (selected_scanners is None or 'csrf' in selected_scanners):
                all_scanners['csrf'] = CSRFScanner(None)
                
            if SSTIScanner is not None and (selected_scanners is None or 'ssti' in selected_scanners):
                all_scanners['ssti'] = SSTIScanner(None)
                
            if CommandInjectionScanner is not None and (selected_scanners is None or 'cmdInjection' in selected_scanners):
                all_scanners['cmd_injection'] = CommandInjectionScanner(None)
                
            if PathTraversalScanner is not None and (selected_scanners is None or 'pathTraversal' in selected_scanners):
                all_scanners['path_traversal'] = PathTraversalScanner(None)
                
            if XXEScanner is not None and (selected_scanners is None or 'xxe' in selected_scanners):
                all_scanners['xxe'] = XXEScanner(None)
            
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