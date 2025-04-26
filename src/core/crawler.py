import time
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Dict, List, Set, Optional
from .http_client import HttpClient
import re

class AdvancedCrawler:
    def __init__(self, base_url: str, config: dict):
        self.base_url = base_url
        self.max_pages = int(config['max_pages'])
        self.delay = float(config.get('delay', 1.0))
        self.user_agent = config.get('user_agent', 'SecScan/1.0')
        
        # Настройки безопасности
        self.verify_ssl = config.get('verify_ssl', True)
        self.max_retries = config.get('max_retries', 3)
        self.proxy = config.get('proxy')
        self.auth = config.get('auth')
        
        # Инициализация HTTP-клиента с настройками безопасности
        self.client = HttpClient(
            verify_ssl=self.verify_ssl,
            timeout=10,
            max_retries=self.max_retries,
            rate_limit=self.delay,
            proxy=self.proxy,
            auth=self.auth
        )
        
        # Инициализация структуры данных
        self.queue = []
        self.visited_urls = set()
        self.discovered_links = set()
        self.discovered_forms = []
        self.logger = logging.getLogger('Crawler')

    def _normalize_url(self, url: str) -> str:
        """Normalize URL to standard form"""
        url = url.strip().lower()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.replace('www.', '', 1)

    def _is_valid_url(self, url: str) -> bool:
        """Advanced URL validation with security checks"""
        try:
            parsed = urlparse(url)
            
            # Пропуск не-HTTP(S) URL-адресов
            if parsed.scheme not in ('http', 'https'):
                return False
                
            # Пропуск общих URL-адресов
            if any(ext in url.lower() for ext in ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.zip', '.rar', '.tar', '.gz']):
                return False
                
            # Пропуск URL-адресов с потенциально опасными параметрами
            dangerous_params = ['cmd=', 'exec=', 'system=', 'eval=', 'php://', 'file://', 'expect://']
            if '?' in url and any(param in url.lower() for param in dangerous_params):
                return False
                
            # Пропуск URL-адресов с избыточными сегментами пути
            if len(parsed.path.split('/')) > 10:
                return False
                
            # Пропуск URL-адресов с избыточными параметрами запроса
            if len(parse_qs(parsed.query)) > 20:
                return False
                
            # Проверка наличия подозрительных шаблонов в пути
            suspicious_patterns = ['/admin/', '/config/', '/backup/', '/database/']
            if any(pattern in parsed.path.lower() for pattern in suspicious_patterns):
                return False
                
            return True
        except Exception:
            return False

    def _extract_links(self, soup, base_url: str) -> List[str]:
        """Extract valid HTTP/HTTPS links with advanced security checks"""
        links = []
        
        # Извлечение ссылок из различных HTML-элементов
        elements = {
            'a': 'href',
            'link': 'href',
            'script': 'src',
            'img': 'src',
            'iframe': 'src',
            'form': 'action',
            'meta': 'content'  # Для обновления URL-адресов
        }
        
        for tag, attr in elements.items():
            for element in soup.find_all(tag):
                try:
                    url = element.get(attr, '').strip()
                    if not url:
                        continue
                        
                    # Обработка мета-обновляемых URL-адресов
                    if tag == 'meta' and element.get('http-equiv', '').lower() == 'refresh':
                        content = element.get('content', '')
                        if 'url=' in content.lower():
                            url = content.split('url=', 1)[1].strip()
                    
                    # Пропуск потенциально опасные ссылки
                    if any(url.startswith(prefix) for prefix in ['javascript:', 'mailto:', 'tel:', '#', 'data:', 'file:']):
                        continue
                        
                    # Пропуск  onion-домены и другие специальные TLD
                    if any(tld in url.lower() for tld in ['.onion', '.local', '.internal']):
                        continue
                        
                    # Преобразование относительные URL-адреса в абсолютные
                    full_url = urljoin(base_url, url)
                    normalized_url = self._normalize_url(full_url)
                    
                    # Подтверждение URL-адреса
                    if self._is_valid_url(normalized_url):
                        links.append(normalized_url)
                except Exception as e:
                    self.logger.debug(f"Invalid URL in {tag} tag: {str(e)}")
        
        return list(set(links))  # Удалить дубликаты

    def _extract_forms(self, soup, base_url: str) -> List[Dict]:
        """Extract forms with advanced security considerations"""
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
                
                # Извлечение полуй формы
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    if input_tag.get('name'):
                        field_data = {
                            'name': input_tag['name'],
                            'type': input_tag.get('type', 'text'),
                            'required': input_tag.get('required') is not None,
                            'autocomplete': input_tag.get('autocomplete', 'on')
                        }
                        
                        # Проверка шаблонов безопасности
                        name_lower = input_tag['name'].lower()
                        if any(pattern in name_lower for pattern in ['csrf', 'token', 'nonce']):
                            form_data['security']['has_csrf'] = True
                        elif any(pattern in name_lower for pattern in ['captcha', 'recaptcha']):
                            form_data['security']['has_captcha'] = True
                        elif any(pattern in name_lower for pattern in ['honeypot', 'spam', 'bot']):
                            form_data['security']['has_honeypot'] = True
                        
                        # Проверкае настройки автозаполнения
                        if field_data['autocomplete'].lower() == 'off':
                            form_data['security']['has_autocomplete'] = True
                        
                        form_data['fields'].append(field_data)
                
                # Пропуск формы с мерами безопасности
                if not any(form_data['security'].values()):
                    forms.append(form_data)
            except Exception as e:
                self.logger.error(f"Error parsing form: {str(e)}")
        return forms

    def _process_page(self, url: str) -> Dict:
        """Process a single page with advanced security checks"""
        try:
            response = self.client.get(url)
            if not response:
                return {'links': [], 'forms': [], 'security_headers': {}}
            
            # Проверка заголовков безопасности
            security_headers = {
                'x-frame-options': response.headers.get('X-Frame-Options'),
                'x-content-type-options': response.headers.get('X-Content-Type-Options'),
                'x-xss-protection': response.headers.get('X-XSS-Protection'),
                'content-security-policy': response.headers.get('Content-Security-Policy'),
                'strict-transport-security': response.headers.get('Strict-Transport-Security'),
                'referrer-policy': response.headers.get('Referrer-Policy'),
                'permissions-policy': response.headers.get('Permissions-Policy')
            }
            
            # Проверка наличия распространенных проблем безопасности
            security_issues = {
                'missing_security_headers': [],
                'insecure_cookies': [],
                'server_info_disclosure': False
            }
            
            # Проверка наличия отсутствующих заголовков безопасности
            required_headers = ['x-frame-options', 'x-content-type-options', 'content-security-policy']
            for header in required_headers:
                if not security_headers.get(header):
                    security_issues['missing_security_headers'].append(header)
            
            # Проверка на предмет раскрытия информации о сервере
            server_info = response.headers.get('Server', '')
            if server_info and not server_info.startswith('cloudflare'):
                security_issues['server_info_disclosure'] = True
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            return {
                'links': self._extract_links(soup, url),
                'forms': self._extract_forms(soup, url),
                'security_headers': security_headers,
                'security_issues': security_issues
            }
            
        except Exception as e:
            self.logger.error(f"Error processing {url}: {str(e)}")
            return {'links': [], 'forms': [], 'security_headers': {}, 'security_issues': {}}

    def crawl(self) -> Dict:
        """Main crawling method with security enhancements"""
        try:
            self.queue = [self._normalize_url(self.base_url)]
            self.visited_urls = set()
            self.discovered_links = set()
            self.discovered_forms = []
            pages_crawled = 0
            security_headers = {}
            
            while self.queue and pages_crawled < self.max_pages:
                current_url = self.queue.pop(0)
                
                if current_url in self.visited_urls:
                    continue
                    
                self.logger.info(f"Crawling: {current_url}")
                page_data = self._process_page(current_url)
                self.visited_urls.add(current_url)
                pages_crawled += 1
                
                
                security_headers.update(page_data.get('security_headers', {}))
                
            
                new_links = [link for link in page_data.get('links', []) 
                           if link not in self.visited_urls]
                self.queue.extend(new_links)
                self.discovered_links.update(new_links)
                
                
                self.discovered_forms.extend(page_data.get('forms', []))
            
            return {
                'pages_crawled': pages_crawled,
                'links_found': len(self.discovered_links),
                'forms_found': len(self.discovered_forms),
                'urls': list(self.visited_urls),
                'forms': self.discovered_forms,
                'security_headers': security_headers
            }
            
        except Exception as e:
            self.logger.error(f"Crawling failed: {str(e)}", exc_info=True)
            return {}