import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import re
import time
from collections import deque
import tldextract
import logging
from typing import Set, Dict, List, Optional

class AdvancedCrawler:
    def __init__(self, base_url: str, max_pages: int = 50, delay: float = 1.0):
        """
        Инициализация краулера
        
        :param base_url: Базовый URL для сканирования
        :param max_pages: Максимальное количество страниц для посещения
        :param delay: Задержка между запросами (в секундах)
        """
        self.base_url = base_url
        self.max_pages = max_pages
        self.delay = delay
        self.visited_urls: Set[str] = set()
        self.queue = deque()
        self.session = requests.Session()
        self.session.headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) VulnScanner/1.0'}
        
        # Извлекаем домен для проверки "внешних" ссылок
        parsed = urlparse(base_url)
        self.base_domain = parsed.netloc
        self.scheme = parsed.scheme
        
        # Настройка логгера
        self.logger = logging.getLogger('VulnScanner.Crawler')
        logging.basicConfig(level=logging.INFO)
        
        # Статистика
        self.stats = {
            'pages_crawled': 0,
            'links_found': 0,
            'forms_found': 0,
            'api_endpoints': 0
        }

    def is_valid_url(self, url: str) -> bool:
        """
        Проверяет, является ли URL валидным для сканирования
        """
        # Игнорируем почту, телефон и javascript
        if url.startswith(('mailto:', 'tel:', 'javascript:', '#')):
            return False
            
        parsed = urlparse(url)
        if not parsed.scheme in ('http', 'https'):
            return False
            
        # Извлекаем домен с помощью tldextract для точного сравнения
        ext = tldextract.extract(url)
        base_ext = tldextract.extract(self.base_url)
        
        return ext.domain == base_ext.domain and ext.suffix == base_ext.suffix

    def normalize_url(self, url: str) -> str:
        """
        Нормализует URL, убирая якоря и параметры сортировки
        """
        url = url.split('#')[0]  # Удаляем якорь
        url = url.split('?')[0]  # Удаляем параметры запроса
        return url.rstrip('/')

    def extract_links(self, html: str, base_url: str) -> Set[str]:
        """
        Извлекает все ссылки со страницы
        """
        soup = BeautifulSoup(html, 'html.parser')
        links = set()
        
        # Находим все теги с ссылками
        for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe']):
            url = tag.get('href', '') or tag.get('src', '')
            if url:
                absolute_url = urljoin(base_url, url)
                if self.is_valid_url(absolute_url):
                    links.add(self.normalize_url(absolute_url))
                    
        # Находим API endpoints в JavaScript
        script_tags = soup.find_all('script')
        for script in script_tags:
            if script.string:
                # Ищем AJAX-запросы (упрощенный вариант)
                api_calls = re.findall(r'fetch\(["\'](.*?)["\']', script.string)
                api_calls += re.findall(r'\.get\(["\'](.*?)["\']', script.string)
                for api in api_calls:
                    absolute_api = urljoin(base_url, api)
                    if self.is_valid_url(absolute_api):
                        links.add(self.normalize_url(absolute_api))
                        self.stats['api_endpoints'] += 1
        
        return links

    def extract_forms(self, html: str, base_url: str) -> List[Dict]:
        """
        Извлекает все формы со страницы
        """
        soup = BeautifulSoup(html, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            form_details = {
                'action': urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'get').lower(),
                'inputs': []
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_details = {
                    'type': input_tag.get('type', 'text'),
                    'name': input_tag.get('name'),
                    'value': input_tag.get('value', '')
                }
                form_details['inputs'].append(input_details)
                
            if self.is_valid_url(form_details['action']):
                forms.append(form_details)
                self.stats['forms_found'] += 1
                
        return forms

    def crawl(self) -> Dict[str, List]:
        """
        Основной метод запуска краулинга
        Возвращает словарь с найденными URL и формами
        """
        self.queue.append(self.base_url)
        results = {
            'urls': [],
            'forms': [],
            'api_endpoints': []
        }

        while self.queue and len(self.visited_urls) < self.max_pages:
            current_url = self.queue.popleft()
            
            if current_url in self.visited_urls:
                continue
                
            try:
                self.logger.info(f"Crawling: {current_url}")
                time.sleep(self.delay)  # Уважаем robots.txt
                
                response = self.session.get(current_url, timeout=10)
                if response.status_code != 200:
                    continue
                    
                # Добавляем в посещенные
                self.visited_urls.add(current_url)
                results['urls'].append(current_url)
                self.stats['pages_crawled'] += 1
                
                # Извлекаем контент
                content_type = response.headers.get('content-type', '')
                if 'text/html' not in content_type:
                    continue
                    
                html = response.text
                
                # Извлекаем ссылки
                new_links = self.extract_links(html, current_url)
                for link in new_links:
                    if link not in self.visited_urls and link not in self.queue:
                        self.queue.append(link)
                        self.stats['links_found'] += 1
                
                # Извлекаем формы
                forms = self.extract_forms(html, current_url)
                results['forms'].extend(forms)
                
            except Exception as e:
                self.logger.error(f"Error crawling {current_url}: {str(e)}")
                continue
                
        self.logger.info(f"Crawling completed. Stats: {self.stats}")
        return results

    def save_to_sitemap(self, file_path: str):
        """
        Сохраняет результаты в файл sitemap.xml
        """
        with open(file_path, 'w') as f:
            f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
            f.write('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n')
            
            for url in self.visited_urls:
                f.write(f'  <url><loc>{url}</loc></url>\n')
                
            f.write('</urlset>\n')

# Пример использования
if __name__ == "__main__":
    crawler = AdvancedCrawler("https://example.com", max_pages=20)
    results = crawler.crawl()
    
    print(f"Found {len(results['urls'])} URLs:")
    for url in results['urls']:
        print(f" - {url}")
        
    print(f"\nFound {len(results['forms'])} forms:")
    for form in results['forms']:
        print(f" - {form['action']} ({form['method']})")