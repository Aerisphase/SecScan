import re
from typing import Dict

class SQLiScanner:
    def __init__(self, session):
        self.session = session
        self.error_patterns = [
            r"SQL (syntax|query) error",
            r"MySQL (server|database) error",
            r"Unclosed quotation mark",
            r"Warning: mysql_"
        ]

    def scan(self, url: str, params: Dict) -> Dict:
        payloads = ["'", "\"", "1' OR '1'='1", "1 AND 1=1"]
        results = []
        
        for param, value in params.items():
            for payload in payloads:
                test_params = params.copy()
                test_params[param] = value + payload
                
                response = self.session.get(url, params=test_params)
                if any(re.search(pattern, response.text) for pattern in self.error_patterns):
                    results.append({
                        'type': 'SQLi',
                        'param': param,
                        'payload': payload,
                        'confidence': 'high'
                    })
                    
        return {'vulnerabilities': results}