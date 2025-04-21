import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging
from typing import Dict, List, Set

class AdvancedCrawler:
    def __init__(self, base_url: str, config: dict):
        self.base_url = base_url
        self.max_pages = int(config['max_pages'])
        self.delay = float(config.get('delay', 1.0))
        self.user_agent = config.get('user_agent', 'SecScan/1.0')
        
        # Инициализация структур данных
        self.queue = []
        self.visited_urls = set()
        self.discovered_links = set()
        self.discovered_forms = []
        
        # Настройка сессии
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.user_agent})
        self.logger = logging.getLogger('Crawler')

    def _normalize_url(self, url: str) -> str:
        """Приводит URL к стандартному виду"""
        url = url.strip().lower()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.replace('www.', '', 1)

    def _extract_links(self, soup, base_url: str) -> List[str]:
        """Извлекает только валидные HTTP/HTTPS ссылки"""
        links = []
        for a in soup.find_all('a', href=True):
            href = a['href'].strip()
            try:
                # Пропускаем не-HTTP ссылки и onion домены
                if href.startswith(('javascript:', 'mailto:', 'tel:', '#')) or '.onion' in href:
                    continue
                    
                # Преобразуем относительные ссылки
                full_url = urljoin(base_url, href)
                normalized_url = self._normalize_url(full_url)
                
                # Проверяем что URL валидный
                parsed = urlparse(normalized_url)
                if parsed.scheme and parsed.netloc:
                    links.append(normalized_url)
            except Exception as e:
                self.logger.debug(f"Invalid URL {href}: {str(e)}")
        return links

    def _extract_forms(self, soup, base_url: str) -> List[Dict]:
        """Извлекает все формы со страницы"""
        forms = []
        for form in soup.find_all('form'):
            try:
                action = form.get('action', '')
                form_data = {
                    'action': self._normalize_url(urljoin(base_url, action)),
                    'method': form.get('method', 'get').lower(),
                    'inputs': [],
                    'data': {}
                }
                
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    if input_tag.get('name'):
                        form_data['inputs'].append(input_tag['name'])
                        form_data['data'][input_tag['name']] = input_tag.get('value', '')
                
                forms.append(form_data)
            except Exception as e:
                self.logger.error(f"Error parsing form: {str(e)}")
        return forms

    def _process_page(self, url: str) -> Dict:
        """Обрабатывает одну страницу"""
        try:
            response = self.session.get(url, timeout=10, verify=False)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            return {
                'links': self._extract_links(soup, url),
                'forms': self._extract_forms(soup, url)
            }
            
        except Exception as e:
            self.logger.error(f"Error processing {url}: {str(e)}")
            return {'links': [], 'forms': []}

    def crawl(self) -> Dict:
        """Основной метод краулинга"""
        try:
            self.queue = [self._normalize_url(self.base_url)]
            self.visited_urls = set()
            self.discovered_links = set()
            self.discovered_forms = []
            pages_crawled = 0
            
            while self.queue and pages_crawled < self.max_pages:
                current_url = self.queue.pop(0)
                
                if current_url in self.visited_urls:
                    continue
                    
                self.logger.info(f"Crawling: {current_url}")
                page_data = self._process_page(current_url)
                self.visited_urls.add(current_url)
                pages_crawled += 1
                
                # Добавляем новые ссылки в очередь
                new_links = [link for link in page_data.get('links', []) 
                           if link not in self.visited_urls]
                self.queue.extend(new_links)
                self.discovered_links.update(new_links)
                
                # Сохраняем формы
                self.discovered_forms.extend(page_data.get('forms', []))
                
                # Задержка между запросами
                if self.delay > 0:
                    time.sleep(self.delay)
            
            return {
                'pages_crawled': pages_crawled,
                'links_found': len(self.discovered_links),
                'forms_found': len(self.discovered_forms),
                'urls': list(self.visited_urls),
                'forms': self.discovered_forms
            }
            
        except Exception as e:
            self.logger.error(f"Crawling failed: {str(e)}", exc_info=True)
            return {}