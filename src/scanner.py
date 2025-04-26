import sys
import io
import argparse
import logging
from typing import Dict, Optional
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
    """Разбор аргументов командной строки"""
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
    return parser.parse_args()

def scan_website(target_url: str, config: Dict) -> Optional[Dict]:
    """Основная функция сканирования"""
    logger = logging.getLogger('Scanner')
    
    try:
        # Гарантируем правильные типы в конфиге
        validated_config = {
            'max_pages': int(config.get('max_pages', 20)),
            'delay': float(config.get('delay', 1.0)),
            'user_agent': str(config.get('user_agent', '')),
            'scan_type': str(config.get('scan_type', 'fast'))
        }

        logger.debug(f"Using config: {validated_config}")
        crawler = AdvancedCrawler(target_url, validated_config)
        crawl_data = crawler.crawl()
        
        if not crawl_data:
            logger.error("No data collected during crawling")
            return None

        # Инициализация сканеров
        scanners = {
            'xss': XSSScanner(crawler.session),
            'sqli': SQLiScanner(crawler.session)
        }

        # Сбор уязвимостей
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
            'vulnerabilities': vulnerabilities
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
    """Точка входа в программу"""
    logger = setup_logging()
    args = parse_args()

    try:
        logger.info(f"Starting scan for {args.target} (mode: {args.scan_type})")
        
        config = {
            'scan_type': args.scan_type,
            'delay': args.delay,
            'max_pages': args.max_pages,
            'user_agent': args.user_agent
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