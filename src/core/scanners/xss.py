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
    
def scan(self, url: str, forms: List[Dict]) -> List[Dict]:
    vulnerabilities = []
    
    for form in forms:
        try:
            # Проверяем что form - словарь
            if not isinstance(form, dict):
                continue
                
            # Основная логика сканирования
            for payload in self.payloads:
                test_data = form.get('data', {}).copy()
                for field in form.get('inputs', []):
                    test_data[field] = payload
                
                response = self.session.post(
                    form.get('action', url),
                    data=test_data,
                    timeout=5,
                    verify=False
                )
                
                if payload in response.text:
                    vulnerabilities.append({
                        'type': 'XSS',
                        'url': url,
                        'form_action': form.get('action'),
                        'payload': payload,
                        'evidence': 'Payload reflected in response',
                        'severity': 'high'
                    })
        except Exception as e:
            self.logger.error(f"XSS scan error for {url}: {str(e)}")
    
    return vulnerabilities