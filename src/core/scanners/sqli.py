from typing import List, Dict

class SQLiScanner:
    def __init__(self, session):
        self.session = session

    def scan(self, url: str, params: Dict = None) -> List[Dict]:
        """Сканирование URL на SQL-инъекции"""
        if params is None:
            params = {'id': '1'}  # Параметры по умолчанию
            
        test_payloads = ["'", "\"", "1' OR '1'='1"]
        results = []
        
        for param, value in params.items():
            for payload in test_payloads:
                try:
                    test_params = params.copy()
                    test_params[param] = value + payload
                    response = self.session.get(url, params=test_params)
                    
                    if self._is_sqli_vulnerable(response.text):
                        results.append({
                            'type': 'SQLi',
                            'url': response.url,
                            'param': param,
                            'payload': payload,
                            'confidence': 0.9
                        })
                except Exception:
                    continue
        return results

    def _is_sqli_vulnerable(self, response_text: str) -> bool:
        """Проверяет признаки SQL-инъекции в ответе"""
        patterns = [
            r"SQL (syntax|query) error",
            r"MySQL server version",
            r"Unclosed quotation mark"
        ]
        return any(re.search(p, response_text, re.I) for p in patterns)