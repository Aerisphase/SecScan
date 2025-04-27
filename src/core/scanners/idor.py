import logging
from ..http_client import HttpClient
from typing import List, Dict, Optional
import re
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

logger = logging.getLogger(__name__)

class IDORScanner:
    def __init__(self, client=None):
        # Инициализация HTTP клиента
        self.client = client if client else HttpClient()
        
        # Паттерны для определения ID в URL и параметрах
        self.id_patterns = [
            # Числовые ID
            r'\bid\b',
            r'\buser_id\b',
            r'\baccount_id\b',
            r'\bcustomer_id\b',
            r'\border_id\b',
            r'\bproduct_id\b',
            r'\bpost_id\b',
            r'\bcomment_id\b',
            r'\bmessage_id\b',
            r'\btransaction_id\b',
            
            # UUID и хеши
            r'\buuid\b',
            r'\bguid\b',
            r'\bhash\b',
            r'\btoken\b',
            r'\breference\b',
            r'\bcode\b',
            
            # Имена файлов и путей
            r'\bfile\b',
            r'\bpath\b',
            r'\bname\b',
            r'\bfilename\b',
            r'\bdocument\b',
            r'\battachment\b'
        ]
        
        # Паттерны для определения конфиденциальных данных
        self.sensitive_patterns = [
            # Личные данные
            r'\bemail\b',
            r'\bphone\b',
            r'\baddress\b',
            r'\bssn\b',
            r'\bcredit\b',
            r'\bcard\b',
            r'\bpassword\b',
            
            # Финансовая информация
            r'\baccount\b',
            r'\bbalance\b',
            r'\btransaction\b',
            r'\bpayment\b',
            r'\binvoice\b',
            
            # Конфиденциальные документы
            r'\bcontract\b',
            r'\bagreement\b',
            r'\breport\b',
            r'\bconfidential\b',
            r'\bsecret\b'
        ]
        
        # Значения для тестирования ID
        self.test_values = [
            '1',  # Первая запись
            '2',  # Вторая запись
            '100',  # Большой номер
            '999',  # Максимальный номер
            'admin',  # Администратор
            'root',  # Суперпользователь
            'test',  # Тестовая запись
            'demo'  # Демонстрационная запись
        ]

    def scan(self, url: str, forms: Optional[List[Dict]] = None) -> List[Dict]:
        # Основной метод сканирования, который проверяет IDOR уязвимости
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
            logger.error(f"IDOR scan error: {str(e)}")
        
        return vulnerabilities

    def _check_url_params(self, url: str) -> List[Dict]:
        # Проверка параметров URL на IDOR уязвимости
        vulnerabilities = []
        try:
            # Парсинг URL для получения параметров
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            
            # Проверка каждого параметра
            for param, values in params.items():
                # Проверка, является ли параметр ID
                if not any(re.search(pattern, param, re.IGNORECASE) for pattern in self.id_patterns):
                    continue
                
                for value in values:
                    for test_value in self.test_values:
                        try:
                            # Создание URL с тестовым значением
                            modified_params = params.copy()
                            modified_params[param] = [test_value]
                            modified_query = urlencode(modified_params, doseq=True)
                            modified_url = parsed_url._replace(query=modified_query).geturl()
                            
                            # Отправка запроса
                            response = self.client.get(modified_url, timeout=10)
                            if not response:
                                continue
                            
                            # Проверка на уязвимость
                            if self._is_vulnerable(response.text, value, test_value):
                                vulnerabilities.append({
                                    'type': 'IDOR',
                                    'url': modified_url,
                                    'payload': test_value,
                                    'evidence': self._get_evidence(response.text, value, test_value),
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
        # Проверка форм на IDOR уязвимости
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
                    
                    # Проверка, является ли поле ID
                    if not any(re.search(pattern, field_name, re.IGNORECASE) for pattern in self.id_patterns):
                        continue
                    
                    # Пропуск полей, не подходящих для IDOR
                    if field_type not in ['text', 'hidden', 'number']:
                        continue
                    
                    for test_value in self.test_values:
                        try:
                            # Подготовка данных формы
                            form_data = {}
                            for f in form.get('fields', []):
                                if f.get('name') == field_name:
                                    form_data[f.get('name')] = test_value
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
                            if self._is_vulnerable(response.text, field.get('value', ''), test_value):
                                vulnerabilities.append({
                                    'type': 'IDOR',
                                    'url': action,
                                    'payload': test_value,
                                    'evidence': self._get_evidence(response.text, field.get('value', ''), test_value),
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

    def _is_vulnerable(self, response_text: str, original_value: str, test_value: str) -> bool:
        # Проверка, является ли ответ уязвимым к IDOR
        try:
            # Проверка наличия конфиденциальных данных
            for pattern in self.sensitive_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True
            
            # Проверка отражения тестового значения
            if test_value in response_text:
                return True
            
            return False
        
        except Exception as e:
            logger.error(f"Vulnerability check error: {str(e)}")
            return False

    def _get_evidence(self, response_text: str, original_value: str, test_value: str) -> str:
        # Получение доказательства уязвимости
        try:
            # Поиск конфиденциальных данных
            for pattern in self.sensitive_patterns:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    return f"Sensitive data found: {match.group(0)}"
            
            # Поиск отражения тестового значения
            if test_value in response_text:
                return f"Test value '{test_value}' was reflected in the response"
            
            return "IDOR vulnerability detected"
        
        except Exception as e:
            logger.error(f"Evidence collection error: {str(e)}")
            return "Error collecting evidence" 