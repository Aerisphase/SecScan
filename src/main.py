from core.crawler import AdvancedCrawler
from core.scanners.sqli import SQLiScanner
from ai.fp_filter import FalsePositiveFilter
import logging

def main():
    logging.basicConfig(level=logging.INFO)
    
    # 1. Инициализация краулера
    crawler = AdvancedCrawler("https://example.com", max_pages=20)
    results = crawler.crawl()
    
    # 2. Сканирование на уязвимости
    scanner = SQLiScanner(crawler.session)
    vulnerabilities = []
    
    for url in results['urls']:
        vulns = scanner.scan(url, {'id': 'test'})  # Пример параметров
        vulnerabilities.extend(vulns['vulnerabilities'])
    
    # 3. Фильтрация ложных срабатываний
    fp_filter = FalsePositiveFilter()
    real_vulns = [v for v in vulnerabilities if fp_filter.predict(v)]
    
    print(f"Found {len(real_vulns)} real vulnerabilities")

if __name__ == "__main__":
    main()