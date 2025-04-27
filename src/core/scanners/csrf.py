import logging
from ..http_client import HttpClient
from typing import List, Dict, Optional
import re
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)

class CSRFScanner:
    def __init__(self, client=None):
        # Инициализация HTTP клиента
        self.client = client if client else HttpClient()
        
        # Список заголовков, которые могут указывать на защиту от CSRF
        self.csrf_headers = [
            'X-CSRF-Token',
            'X-CSRFToken',
            'X-XSRF-Token',
            'X-Requested-With',
            'X-CSRF-Protection',
            'X-CSRF-Header',
            'X-CSRF-Key'
        ]
        
        # Список параметров, которые могут содержать CSRF-токены
        self.csrf_params = [
            'csrf_token',
            'csrf-token',
            'csrf',
            'token',
            'authenticity_token',
            'request_token',
            'security_token'
        ]
        
        # Паттерны для поиска CSRF-токенов в HTML
        self.csrf_patterns = [
            r'<input[^>]*name=["\']csrf_token["\'][^>]*>',
            r'<input[^>]*name=["\']csrf-token["\'][^>]*>',
            r'<input[^>]*name=["\']_csrf["\'][^>]*>',
            r'<input[^>]*name=["\']authenticity_token["\'][^>]*>',
            r'<meta[^>]*name=["\']csrf-token["\'][^>]*>',
            r'<meta[^>]*name=["\']csrf["\'][^>]*>'
        ]
        
        # Паттерны для поиска форм, которые могут быть уязвимы к CSRF
        self.form_patterns = [
            r'<form[^>]*method=["\']post["\'][^>]*>',
            r'<form[^>]*method=["\']put["\'][^>]*>',
            r'<form[^>]*method=["\']delete["\'][^>]*>',
            r'<form[^>]*method=["\']patch["\'][^>]*>'
        ]

    def scan(self, url: str, forms: Optional[List[Dict]] = None) -> List[Dict]:
        # Основной метод сканирования, который проверяет CSRF уязвимости
        vulnerabilities = []
        
        try:
            # Проверка заголовков ответа
            header_vulns = self._check_headers(url)
            vulnerabilities.extend(header_vulns)
            
            # Проверка форм
            if forms:
                form_vulns = self._check_forms(url, forms)
                vulnerabilities.extend(form_vulns)
            
            # Проверка HTML-страницы
            html_vulns = self._check_html(url)
            vulnerabilities.extend(html_vulns)
            
        except Exception as e:
            logger.error(f"CSRF scan error: {str(e)}")
        
        return vulnerabilities

    def _check_headers(self, url: str) -> List[Dict]:
        # Проверка заголовков ответа на наличие защиты от CSRF
        vulnerabilities = []
        try:
            # Отправка запроса
            response = self.client.get(url, timeout=10)
            if not response:
                return vulnerabilities
            
            # Проверка наличия CSRF-заголовков
            csrf_headers_found = []
            for header in self.csrf_headers:
                if header in response.headers:
                    csrf_headers_found.append(header)
            
            if not csrf_headers_found:
                vulnerabilities.append({
                    'type': 'CSRF',
                    'url': url,
                    'payload': 'Missing CSRF headers',
                    'evidence': 'No CSRF protection headers found in response',
                    'severity': 'medium',
                    'param': 'Headers',
                    'method': 'GET'
                })
        
        except Exception as e:
            logger.error(f"Headers check error: {str(e)}")
        
        return vulnerabilities

    def _check_forms(self, url: str, forms: List[Dict]) -> List[Dict]:
        # Проверка форм на уязвимость к CSRF
        vulnerabilities = []
        try:
            for form in forms:
                # Получение метода и действия формы
                method = form.get('method', 'GET').upper()
                action = form.get('action', url)
                
                # Проверка только форм с методами, изменяющими состояние
                if method not in ['POST', 'PUT', 'DELETE', 'PATCH']:
                    continue
                
                # Проверка наличия CSRF-токена в форме
                has_csrf_token = False
                for field in form.get('fields', []):
                    field_name = field.get('name', '').lower()
                    if any(param in field_name for param in self.csrf_params):
                        has_csrf_token = True
                        break
                
                if not has_csrf_token:
                    vulnerabilities.append({
                        'type': 'CSRF',
                        'url': action,
                        'payload': 'Missing CSRF token',
                        'evidence': f'Form with method {method} does not contain CSRF token',
                        'severity': 'high',
                        'param': 'Form Fields',
                        'method': method
                    })
        
        except Exception as e:
            logger.error(f"Forms check error: {str(e)}")
        
        return vulnerabilities

    def _check_html(self, url: str) -> List[Dict]:
        # Проверка HTML-страницы на уязвимость к CSRF
        vulnerabilities = []
        try:
            # Отправка запроса
            response = self.client.get(url, timeout=10)
            if not response:
                return vulnerabilities
            
            # Поиск форм, изменяющих состояние
            form_matches = re.finditer('|'.join(self.form_patterns), response.text, re.IGNORECASE)
            for match in form_matches:
                form_html = match.group(0)
                
                # Проверка наличия CSRF-токена в форме
                has_csrf_token = False
                for pattern in self.csrf_patterns:
                    if re.search(pattern, form_html, re.IGNORECASE):
                        has_csrf_token = True
                        break
                
                if not has_csrf_token:
                    vulnerabilities.append({
                        'type': 'CSRF',
                        'url': url,
                        'payload': 'Missing CSRF token in form',
                        'evidence': 'Form that modifies state does not contain CSRF token',
                        'severity': 'high',
                        'param': 'HTML Form',
                        'method': 'GET'
                    })
        
        except Exception as e:
            logger.error(f"HTML check error: {str(e)}")
        
        return vulnerabilities