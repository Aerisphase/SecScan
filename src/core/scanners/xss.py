from typing import List, Dict

class XSSScanner:
    def __init__(self, session):
        self.session = session

    def scan(self, url: str, params: Dict = None) -> List[Dict]:
        """Сканирование на XSS-уязвимости"""
        if params is None:
            params = {'q': 'test'}  # Параметры по умолчанию
            
        payloads = [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>"
        ]
        results = []
        
        for param, value in params.items():
            for payload in payloads:
                try:
                    test_params = params.copy()
                    test_params[param] = payload
                    response = self.session.get(url, params=test_params)
                    
                    if payload in response.text:
                        results.append({
                            'type': 'XSS',
                            'url': response.url,
                            'param': param,
                            'payload': payload,
                            'confidence': 0.8
                        })
                except Exception:
                    continue
        return results