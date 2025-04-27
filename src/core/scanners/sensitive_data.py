import logging
from ..http_client import HttpClient
from typing import List, Dict, Optional
import re
import json
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

logger = logging.getLogger(__name__)

class SensitiveDataScanner:
    def __init__(self, client=None):
        # Инициализация HTTP клиента
        self.client = client if client else HttpClient()
        
        # Паттерны для определения конфиденциальных данных
        self.sensitive_patterns = {
            # Кредитные карты
            'credit_card': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b',
            
            # Номера социального страхования (SSN)
            'ssn': r'\b\d{3}[-]?\d{2}[-]?\d{4}\b',
            
            # Email адреса
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            
            # Номера телефонов
            'phone': r'\b(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})(?: *x\d+)?\b',
            
            # API ключи
            'api_key': r'\b(?:[A-Za-z0-9+/]{32,}|[A-Za-z0-9]{32,})\b',
            
            # Пароли
            'password': r'\b(?:password|passwd|pwd)[:=]\s*[\'"]?[^\s\'"]+[\'"]?\b',
            
            # JWT токены
            'jwt': r'\b(?:eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)\b',
            
            # Приватные ключи
            'private_key': r'-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----',
            
            # AWS учетные данные
            'aws_credentials': r'\b(?:aws_access_key_id|aws_secret_access_key)[:=]\s*[\'"]?[^\s\'"]+[\'"]?\b',
            
            # Учетные данные базы данных
            'db_credentials': r'\b(?:database|db|mysql|postgresql|mongodb)[:=]\s*[\'"]?[^\s\'"]+[\'"]?\b'
        }
        
        # Список конфиденциальных заголовков
        self.sensitive_headers = [
            'authorization',
            'cookie',
            'set-cookie',
            'x-api-key',
            'x-auth-token',
            'x-csrf-token',
            'x-access-token',
            'x-secret-key',
            'x-password',
            'x-credentials'
        ]

    def scan(self, url: str, forms: Optional[List[Dict]] = None) -> List[Dict]:
        # Основной метод сканирования, который проверяет уязвимости конфиденциальных данных
        vulnerabilities = []
        
        try:
            # Проверка заголовков ответа
            header_vulns = self._check_headers(url)
            vulnerabilities.extend(header_vulns)
            
            # Проверка тела ответа
            body_vulns = self._check_response_body(url)
            vulnerabilities.extend(body_vulns)
            
            # Проверка JavaScript файлов
            js_vulns = self._check_javascript_files(url)
            vulnerabilities.extend(js_vulns)
            
            # Проверка форм
            if forms:
                form_vulns = self._check_forms(url, forms)
                vulnerabilities.extend(form_vulns)
            
            # Проверка JSON данных
            json_vulns = self._check_json_data(url)
            vulnerabilities.extend(json_vulns)
            
        except Exception as e:
            logger.error(f"Sensitive Data scan error: {str(e)}")
        
        return vulnerabilities

    def _check_headers(self, url: str) -> List[Dict]:
        # Проверка заголовков ответа на наличие конфиденциальных данных
        vulnerabilities = []
        try:
            # Отправка запроса
            response = self.client.get(url, timeout=10)
            if not response:
                return vulnerabilities
            
            # Проверка каждого заголовка
            for header, value in response.headers.items():
                header_lower = header.lower()
                
                # Проверка, является ли заголовок конфиденциальным
                if header_lower in self.sensitive_headers:
                    vulnerabilities.append({
                        'type': 'Sensitive Data Exposure',
                        'url': url,
                        'payload': f'Header: {header}',
                        'evidence': f'Sensitive header "{header}" found with value: {self._mask_sensitive_data(value)}',
                        'severity': 'high',
                        'param': header,
                        'method': 'GET'
                    })
                
                # Проверка значения заголовка на наличие конфиденциальных данных
                for pattern_name, pattern in self.sensitive_patterns.items():
                    if re.search(pattern, value, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': 'Sensitive Data Exposure',
                            'url': url,
                            'payload': f'Header: {header}',
                            'evidence': f'{pattern_name} found in header "{header}": {self._mask_sensitive_data(value)}',
                            'severity': 'high',
                            'param': header,
                            'method': 'GET'
                        })
        
        except Exception as e:
            logger.error(f"Headers check error: {str(e)}")
        
        return vulnerabilities

    def _check_response_body(self, url: str) -> List[Dict]:
        # Проверка тела ответа на наличие конфиденциальных данных
        vulnerabilities = []
        try:
            # Отправка запроса
            response = self.client.get(url, timeout=10)
            if not response:
                return vulnerabilities
            
            # Проверка тела ответа на наличие конфиденциальных данных
            for pattern_name, pattern in self.sensitive_patterns.items():
                matches = re.finditer(pattern, response.text, re.IGNORECASE)
                for match in matches:
                    vulnerabilities.append({
                        'type': 'Sensitive Data Exposure',
                        'url': url,
                        'payload': 'Response body',
                        'evidence': f'{pattern_name} found in response body: {self._mask_sensitive_data(match.group(0))}',
                        'severity': 'high',
                        'param': 'Response Body',
                        'method': 'GET'
                    })
        
        except Exception as e:
            logger.error(f"Response body check error: {str(e)}")
        
        return vulnerabilities

    def _check_javascript_files(self, url: str) -> List[Dict]:
        # Проверка JavaScript файлов на наличие конфиденциальных данных
        vulnerabilities = []
        try:
            # Отправка запроса
            response = self.client.get(url, timeout=10)
            if not response:
                return vulnerabilities
            
            # Поиск JavaScript файлов
            js_pattern = r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>'
            js_files = re.findall(js_pattern, response.text)
            
            # Проверка каждого JavaScript файла
            for js_file in js_files:
                try:
                    # Получение полного URL JavaScript файла
                    js_url = urljoin(url, js_file)
                    
                    # Загрузка JavaScript файла
                    js_response = self.client.get(js_url, timeout=10)
                    if not js_response:
                        continue
                    
                    # Проверка JavaScript файла на наличие конфиденциальных данных
                    for pattern_name, pattern in self.sensitive_patterns.items():
                        matches = re.finditer(pattern, js_response.text, re.IGNORECASE)
                        for match in matches:
                            vulnerabilities.append({
                                'type': 'Sensitive Data Exposure',
                                'url': js_url,
                                'payload': 'JavaScript file',
                                'evidence': f'{pattern_name} found in JavaScript file: {self._mask_sensitive_data(match.group(0))}',
                                'severity': 'high',
                                'param': 'JavaScript',
                                'method': 'GET'
                            })
                
                except Exception as e:
                    logger.error(f"JavaScript file check error for {js_file}: {str(e)}")
        
        except Exception as e:
            logger.error(f"JavaScript files check error: {str(e)}")
        
        return vulnerabilities

    def _check_forms(self, url: str, forms: List[Dict]) -> List[Dict]:
        # Проверка форм на наличие конфиденциальных данных
        vulnerabilities = []
        try:
            for form in forms:
                # Получение метода и действия формы
                method = form.get('method', 'GET').upper()
                action = form.get('action', url)
                
                # Проверка каждого поля формы
                for field in form.get('fields', []):
                    field_name = field.get('name', '').lower()
                    field_value = field.get('value', '')
                    
                    # Проверка, является ли поле конфиденциальным
                    for pattern_name, pattern in self.sensitive_patterns.items():
                        if re.search(pattern, field_value, re.IGNORECASE):
                            vulnerabilities.append({
                                'type': 'Sensitive Data Exposure',
                                'url': action,
                                'payload': f'Form field: {field_name}',
                                'evidence': f'{pattern_name} found in form field "{field_name}": {self._mask_sensitive_data(field_value)}',
                                'severity': 'high',
                                'param': field_name,
                                'method': method
                            })
        
        except Exception as e:
            logger.error(f"Forms check error: {str(e)}")
        
        return vulnerabilities

    def _check_json_data(self, url: str) -> List[Dict]:
        # Проверка JSON данных на наличие конфиденциальных данных
        vulnerabilities = []
        try:
            # Отправка запроса
            response = self.client.get(url, timeout=10)
            if not response:
                return vulnerabilities
            
            # Попытка разбора JSON
            try:
                json_data = json.loads(response.text)
                
                # Рекурсивный поиск конфиденциальных данных в JSON
                def check_json_value(value, path=''):
                    if isinstance(value, dict):
                        for k, v in value.items():
                            check_json_value(v, f"{path}.{k}" if path else k)
                    elif isinstance(value, list):
                        for i, v in enumerate(value):
                            check_json_value(v, f"{path}[{i}]")
                    elif isinstance(value, str):
                        for pattern_name, pattern in self.sensitive_patterns.items():
                            if re.search(pattern, value, re.IGNORECASE):
                                vulnerabilities.append({
                                    'type': 'Sensitive Data Exposure',
                                    'url': url,
                                    'payload': 'JSON data',
                                    'evidence': f'{pattern_name} found in JSON path "{path}": {self._mask_sensitive_data(value)}',
                                    'severity': 'high',
                                    'param': path,
                                    'method': 'GET'
                                })
                
                check_json_value(json_data)
            
            except json.JSONDecodeError:
                pass
        
        except Exception as e:
            logger.error(f"JSON data check error: {str(e)}")
        
        return vulnerabilities

    def _mask_sensitive_data(self, data: str) -> str:
        # Маскирование конфиденциальных данных
        try:
            # Маскирование кредитных карт
            data = re.sub(self.sensitive_patterns['credit_card'], lambda m: '*' * len(m.group(0)), data)
            
            # Маскирование SSN
            data = re.sub(self.sensitive_patterns['ssn'], lambda m: '*' * len(m.group(0)), data)
            
            # Маскирование API ключей
            data = re.sub(self.sensitive_patterns['api_key'], lambda m: '*' * len(m.group(0)), data)
            
            # Маскирование JWT токенов
            data = re.sub(self.sensitive_patterns['jwt'], lambda m: '*' * len(m.group(0)), data)
            
            # Маскирование приватных ключей
            data = re.sub(self.sensitive_patterns['private_key'], lambda m: '*' * len(m.group(0)), data)
            
            # Маскирование учетных данных
            data = re.sub(self.sensitive_patterns['aws_credentials'], lambda m: '*' * len(m.group(0)), data)
            data = re.sub(self.sensitive_patterns['db_credentials'], lambda m: '*' * len(m.group(0)), data)
            
            return data
        
        except Exception as e:
            logger.error(f"Sensitive data masking error: {str(e)}")
            return data 