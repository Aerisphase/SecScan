import sys
import io
import argparse
import logging
from typing import Dict, Optional, List
from core.crawler import AdvancedCrawler
from core.scanners import SQLiScanner, XSSScanner

# Настройка кодировки для Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

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

def scan_website(target_url: str, config: Dict) -> Optional[Dict]:
    """Main scanning function"""
    logger = logging.getLogger('Scanner')
    
    try:
        # Ensure correct types in config
        validated_config = {
            'max_pages': int(config.get('max_pages', 20)),
            'delay': float(config.get('delay', 1.0)),
            'user_agent': str(config.get('user_agent', '')),
            'scan_type': str(config.get('scan_type', 'fast')),
            'verify_ssl': bool(config.get('verify_ssl', True)),
            'proxy': config.get('proxy'),
            'auth': config.get('auth'),
            'max_retries': int(config.get('max_retries', 3))
        }

        logger.debug(f"Using config: {validated_config}")
        crawler = AdvancedCrawler(target_url, validated_config)
        crawl_data = crawler.crawl()
        
        if not crawl_data:
            logger.error("No data collected during crawling")
            return None

        # Analyze security headers
        security_recommendations = analyze_security_headers(crawl_data.get('security_headers', {}))

        # Initialize scanners
        scanners = {
            'xss': XSSScanner(crawler.client),
            'sqli': SQLiScanner(crawler.client)
        }

        # Collect vulnerabilities
        vulnerabilities = []
        for scanner_name, scanner in scanners.items():
            try:
                logger.info(f"Running {scanner_name.upper()} scanner...")
                vulns = scanner.scan(target_url, crawl_data.get('forms', []))
                if vulns:
                    vulnerabilities.extend(vulns)
            except Exception as e:
                logger.error(f"{scanner_name} scanner failed: {str(e)}")

        return {
            'stats': {
                'pages_crawled': crawl_data.get('pages_crawled', 0),
                'links_found': crawl_data.get('links_found', 0),
                'forms_found': crawl_data.get('forms_found', 0)
            },
            'vulnerabilities': vulnerabilities,
            'security_recommendations': security_recommendations,
            'security_headers': crawl_data.get('security_headers', {})
        }

    except Exception as e:
        logger.error(f"Scanning error: {str(e)}", exc_info=True)
        return None

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

        results = scan_website(args.target, config)
        print_results(results)

    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
    except Exception as e:
        logger.error(f"Critical error: {str(e)}", exc_info=True)
    finally:
        logging.shutdown()

if __name__ == "__main__":
    main()