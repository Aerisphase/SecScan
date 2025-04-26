import time
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Dict, List, Set, Optional
from .http_client import HttpClient
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
import threading

class AdvancedCrawler:
    def __init__(self, base_url: str, config: dict):
        self.base_url = base_url
        self.max_pages = int(config['max_pages'])
        self.delay = float(config.get('delay', 0.5))  # Задержка по умолчанию между запросами
        self.user_agent = config.get('user_agent', 'SecScan/1.0')
        
        # Настройки безопасности
        self.verify_ssl = config.get('verify_ssl', True)
        self.max_retries = config.get('max_retries', 2)
        self.proxy = config.get('proxy')
        self.auth = config.get('auth')
        
        # Ограничения по доменам
        self.base_domain = urlparse(base_url).netloc
        self.allowed_domains = {self.base_domain}
        
        # Инициализация HTTP клиента с оптимизированными настройками
        self.client = HttpClient(
            verify_ssl=self.verify_ssl,
            timeout=5,
            max_retries=self.max_retries,
            rate_limit=self.delay,
            proxy=self.proxy,
            auth=self.auth
        )
        
        # Инициализация структур данных
        self.queue = Queue()
        self.visited_urls = set()
        self.discovered_links = set()
        self.discovered_forms = []
        self.logger = logging.getLogger('Crawler')
        
        # Пул потоков для параллельной обработки
        self.max_workers = min(5, self.max_pages)  # Ограничение количества параллельных воркеров
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        
        # Ограничение частоты запросов
        self.last_request_time = 0
        self.request_lock = threading.Lock()

    def _normalize_url(self, url: str) -> str:
        """Нормализация URL к стандартному формату"""
        url = url.strip().lower()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.replace('www.', '', 1)

    def _is_valid_url(self, url: str) -> bool:
        """Расширенная валидация URL с проверками безопасности"""
        try:
            parsed = urlparse(url)
            
            # Пропуск не-HTTP(S) URL
            if parsed.scheme not in ('http', 'https'):
                return False
                
            # Пропуск URL с распространенными расширениями файлов
            if any(ext in url.lower() for ext in ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.zip', '.rar', '.tar', '.gz']):
                return False
                
            # Пропуск URL с потенциально опасными параметрами
            dangerous_params = ['cmd=', 'exec=', 'system=', 'eval=', 'php://', 'file://', 'expect://']
            if '?' in url and any(param in url.lower() for param in dangerous_params):
                return False
                
            # Пропуск URL с избыточным количеством сегментов пути
            if len(parsed.path.split('/')) > 10:
                return False
                
            # Пропуск URL с избыточным количеством параметров запроса
            if len(parse_qs(parsed.query)) > 20:
                return False
                
            # Проверка на подозрительные паттерны в пути
            suspicious_patterns = ['/admin/', '/config/', '/backup/', '/database/']
            if any(pattern in parsed.path.lower() for pattern in suspicious_patterns):
                return False
                
            # Ограничение по домену
            if parsed.netloc not in self.allowed_domains:
                return False
                
            return True
        except Exception:
            return False

    def _extract_links(self, soup, base_url: str) -> List[str]:
        """Извлечение валидных HTTP/HTTPS ссылок с расширенными проверками безопасности"""
        links = []
        
        # Извлечение ссылок из различных HTML-элементов
        elements = {
            'a': 'href',
            'link': 'href',
            'script': 'src',
            'img': 'src',
            'iframe': 'src',
            'form': 'action',
            'meta': 'content'  # Для URL обновления страницы
        }
        
        for tag, attr in elements.items():
            for element in soup.find_all(tag):
                try:
                    url = element.get(attr, '').strip()
                    if not url:
                        continue
                        
                    # Обработка URL обновления страницы в meta-тегах
                    if tag == 'meta' and element.get('http-equiv', '').lower() == 'refresh':
                        content = element.get('content', '')
                        if 'url=' in content.lower():
                            url = content.split('url=', 1)[1].strip()
                    
                    # Пропуск потенциально опасных ссылок
                    if any(url.startswith(prefix) for prefix in ['javascript:', 'mailto:', 'tel:', '#', 'data:', 'file:']):
                        continue
                        
                    # Пропуск специальных TLD
                    if any(tld in url.lower() for tld in ['.onion', '.local', '.internal']):
                        continue
                        
                    # Преобразование относительных URL в абсолютные
                    full_url = urljoin(base_url, url)
                    normalized_url = self._normalize_url(full_url)
                    
                    # Валидация URL
                    if self._is_valid_url(normalized_url):
                        links.append(normalized_url)
                except Exception as e:
                    self.logger.debug(f"Невалидный URL в теге {tag}: {str(e)}")
        
        return list(set(links))  # Удаление дубликатов

    def _extract_forms(self, soup, base_url: str) -> List[Dict]:
        """Извлечение форм с учетом мер безопасности"""
        forms = []
        for form in soup.find_all('form'):
            try:
                action = form.get('action', '')
                form_data = {
                    'action': self._normalize_url(urljoin(base_url, action)),
                    'method': form.get('method', 'get').lower(),
                    'fields': [],
                    'security': {
                        'has_csrf': False,
                        'has_captcha': False,
                        'has_honeypot': False,
                        'has_autocomplete': False
                    }
                }
                
                # Извлечение полей формы
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    if input_tag.get('name'):
                        field_data = {
                            'name': input_tag['name'],
                            'type': input_tag.get('type', 'text'),
                            'required': input_tag.get('required') is not None,
                            'autocomplete': input_tag.get('autocomplete', 'on')
                        }
                        
                        # Проверка паттернов безопасности
                        name_lower = input_tag['name'].lower()
                        if any(pattern in name_lower for pattern in ['csrf', 'token', 'nonce']):
                            form_data['security']['has_csrf'] = True
                        elif any(pattern in name_lower for pattern in ['captcha', 'recaptcha']):
                            form_data['security']['has_captcha'] = True
                        elif any(pattern in name_lower for pattern in ['honeypot', 'spam', 'bot']):
                            form_data['security']['has_honeypot'] = True
                        
                        # Проверка настроек автозаполнения
                        if field_data['autocomplete'].lower() == 'off':
                            form_data['security']['has_autocomplete'] = True
                        
                        form_data['fields'].append(field_data)
                
                # Пропуск форм с мерами безопасности
                if not any(form_data['security'].values()):
                    forms.append(form_data)
            except Exception as e:
                self.logger.error(f"Ошибка при разборе формы: {str(e)}")
        return forms

    def _process_page(self, url: str) -> Dict:
        """Обработка отдельной страницы с параллельным разбором HTML"""
        try:
            # Ограничение частоты запросов
            with self.request_lock:
                current_time = time.time()
                time_since_last = current_time - self.last_request_time
                if time_since_last < self.delay:
                    time.sleep(self.delay - time_since_last)
                self.last_request_time = time.time()

            response = self.client.get(url)
            if not response:
                return {'links': [], 'forms': [], 'security_headers': {}}
            
            # Обработка заголовков безопасности
            security_headers = {
                'x-frame-options': response.headers.get('X-Frame-Options'),
                'x-content-type-options': response.headers.get('X-Content-Type-Options'),
                'x-xss-protection': response.headers.get('X-XSS-Protection'),
                'content-security-policy': response.headers.get('Content-Security-Policy'),
                'strict-transport-security': response.headers.get('Strict-Transport-Security'),
                'referrer-policy': response.headers.get('Referrer-Policy'),
                'permissions-policy': response.headers.get('Permissions-Policy')
            }
            
            # Разбор HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Параллельное извлечение ссылок и форм
            links_task = self.executor.submit(self._extract_links, soup, url)
            forms_task = self.executor.submit(self._extract_forms, soup, url)
            
            links = links_task.result()
            forms = forms_task.result()
            
            return {
                'links': links,
                'forms': forms,
                'security_headers': security_headers
            }
            
        except Exception as e:
            self.logger.error(f"Ошибка при обработке {url}: {str(e)}")
            return {'links': [], 'forms': [], 'security_headers': {}}

    def crawl(self) -> Dict:
        """Основной метод сканирования с параллельной обработкой страниц"""
        try:
            self.queue.put(self._normalize_url(self.base_url))
            self.visited_urls = set()
            self.discovered_links = set()
            self.discovered_forms = []
            pages_crawled = 0
            
            while not self.queue.empty() and pages_crawled < self.max_pages:
                # Параллельная обработка нескольких URL
                current_batch = []
                while not self.queue.empty() and len(current_batch) < self.max_workers:
                    url = self.queue.get()
                    if url not in self.visited_urls:
                        current_batch.append(url)
                
                # Отправка задач в пул потоков
                future_to_url = {
                    self.executor.submit(self._process_page, url): url 
                    for url in current_batch
                }
                
                # Обработка завершенных задач
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        result = future.result()
                        if url not in self.visited_urls:
                            self.visited_urls.add(url)
                            pages_crawled += 1
                            
                            # Добавление новых ссылок в очередь
                            new_links = [link for link in result['links'] 
                                       if link not in self.visited_urls and link not in self.queue.queue]
                            for link in new_links:
                                self.queue.put(link)
                            
                            # Добавление форм
                            self.discovered_forms.extend(result['forms'])
                            
                            self.logger.info(f"Обработана страница {url} ({pages_crawled}/{self.max_pages})")
                    except Exception as e:
                        self.logger.error(f"Ошибка при обработке {url}: {str(e)}")
            
            return {
                'pages_crawled': pages_crawled,
                'links_found': len(self.discovered_links),
                'forms_found': len(self.discovered_forms),
                'forms': self.discovered_forms
            }
            
        except Exception as e:
            self.logger.error(f"Ошибка сканирования: {str(e)}")
            return {
                'pages_crawled': pages_crawled,
                'links_found': len(self.discovered_links),
                'forms_found': len(self.discovered_forms),
                'forms': self.discovered_forms
            }
        finally:
            self.executor.shutdown(wait=True)