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
    
def scan(self, url, form_data=None):
    vulnerabilities = []
    
    payloads = [
        "<script>alert(1)</script>",
        "'\"><img src=x onerror=alert(1)>"
    ]
    
    for payload in payloads:
        try:
            response = requests.post(url, data={**form_data, 'field': payload})
            if payload in response.text:
                vulnerabilities.append({
                    'type': 'XSS',
                    'url': url,
                    'payload': payload,
                    'evidence': 'Payload reflected in response',
                    'severity': 'high'
                })
        except Exception as e:
            logger.error(f"XSS scan error for {url}: {str(e)}")
    
    return vulnerabilities