from typing import Dict, Optional
from requests import Session

class CSRFScanner:
    def __init__(self, session: Session):
        self.session = session
        
    def scan(self, url: str) -> Dict[str, Optional[bool]]:
        """
        Checks for CSRF protection
        
        :param url: URL to check
        :return: Results in format {'csrf_protected': bool, 'token_found': bool}
        """
        try:
            response = self.session.get(url)
            html = response.text.lower()
            
            # Check for CSRF token presence
            token_found = any(
                'csrf_token' in html or
                'csrfmiddlewaretoken' in html or
                'authenticity_token' in html
            )
            
            # Check protection headers
            protected = (
                response.headers.get('X-CSRF-Protection') == '1' or
                'SameSite=Strict' in response.headers.get('Set-Cookie', '')
            )
            
            return {
                'csrf_protected': protected,
                'token_found': token_found
            }
            
        except Exception as e:
            return {
                'csrf_protected': None,
                'token_found': None,
                'error': str(e)
            }