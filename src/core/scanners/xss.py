import logging
from ..http_client import HttpClient
from typing import List, Dict, Optional
import re
from urllib.parse import urlparse, parse_qs, urlencode

logger = logging.getLogger(__name__)

class XSSScanner:
    def __init__(self, client=None):
        # Инициализация HTTP клиента
        self.client = client if client else HttpClient()
        
        # Список полезных нагрузок для тестирования XSS уязвимостей
        self.payloads = [
            # Базовые полезные нагрузки
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '<input autofocus onfocus=alert(1)>',
            
            # Полезные нагрузки с кодировкой
            '<script>alert(1)</script>'.encode('utf-8').hex(),
            '<img src=x onerror=alert(1)>'.encode('utf-8').hex(),
            
            # Полезные нагрузки с обходом фильтров
            '<scr<script>ipt>alert(1)</scr</script>ipt>',
            '<img src=x onerror=alert(1)//',
            '<svg><script>alert(1)</script></svg>',
            
            # Полезные нагрузки с событиями
            '<img src=x onmouseover=alert(1)>',
            '<div onmouseover=alert(1)>XSS</div>',
            '<a onmouseover=alert(1)>XSS</a>',
            
            # Полезные нагрузки с атрибутами
            '<img src=x onerror=alert(1) x=>',
            '<img src=x onerror=alert(1) x=',
            '<img src=x onerror=alert(1) x',
            
            # Полезные нагрузки с JavaScript
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'vbscript:msgbox(1)'
        ]
        
        # Паттерны для поиска отраженных полезных нагрузок
        self.reflection_patterns = [
            r'<script[^>]*>.*?</script>',
            r'<img[^>]*>',
            r'<svg[^>]*>',
            r'<body[^>]*>',
            r'<input[^>]*>',
            r'<div[^>]*>',
            r'<a[^>]*>',
            r'javascript:',
            r'data:text/html',
            r'vbscript:'
        ]

    def scan(self, url: str, forms: Optional[List[Dict]] = None) -> List[Dict]:
        # Основной метод сканирования, который проверяет XSS уязвимости
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
            logger.error(f"XSS scan error: {str(e)}")
        
        return vulnerabilities

    def _check_url_params(self, url: str) -> List[Dict]:
        # Проверка параметров URL на XSS уязвимости
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
                                    'type': 'XSS',
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
        # Проверка форм на XSS уязвимости
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
                    
                    # Пропуск полей, не подходящих для XSS
                    if field_type not in ['text', 'textarea', 'hidden', 'search', 'email', 'url']:
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
                                    'type': 'XSS',
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
        # Проверка, является ли ответ уязвимым к XSS
        try:
            # Проверка отражения полезной нагрузки
            if payload in response_text:
                return True
            
            # Проверка отражения с кодировкой
            encoded_payload = payload.encode('utf-8').hex()
            if encoded_payload in response_text:
                return True
            
            # Проверка паттернов отражения
            for pattern in self.reflection_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True
            
            return False
        
        except Exception as e:
            logger.error(f"Vulnerability check error: {str(e)}")
            return False

    def _get_evidence(self, response_text: str, payload: str) -> str:
        # Получение доказательства уязвимости
        try:
            # Поиск отраженной полезной нагрузки
            if payload in response_text:
                return f"Payload '{payload}' was reflected in the response"
            
            # Поиск отражения с кодировкой
            encoded_payload = payload.encode('utf-8').hex()
            if encoded_payload in response_text:
                return f"Encoded payload '{encoded_payload}' was reflected in the response"
            
            # Поиск паттернов отражения
            for pattern in self.reflection_patterns:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    return f"XSS pattern '{match.group(0)}' was found in the response"
            
            return "No direct evidence found"
        
        except Exception as e:
            logger.error(f"Evidence collection error: {str(e)}")
            return "Error collecting evidence"