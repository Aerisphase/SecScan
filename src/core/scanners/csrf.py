import logging
from typing import Dict, List, Optional
from urllib.parse import urlparse
from ..http_client import HttpClient
from .base_scanner import BaseScanner
import re

logger = logging.getLogger(__name__)

class CSRFScanner(BaseScanner):
    def __init__(self, client=None):
        super().__init__(client)
        
    def scan(self, url: str, forms: Optional[List[Dict]] = None) -> List[Dict]:
        """
        Checks for CSRF protection
        
        :param url: URL to check
        :param forms: List of forms to check
        :return: List of vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            # Check the main page
            response = self.client.get(url)
            if not response:
                return vulnerabilities
                
            html = response.text.lower()
            headers = response.headers
            
            # Check for CSRF token presence
            token_found = any([
                'csrf_token' in html,
                'csrfmiddlewaretoken' in html,
                'authenticity_token' in html,
                '_token' in html
            ])
            
            # Check protection headers
            header_protection = (
                headers.get('X-CSRF-Protection') == '1' or
                'SameSite=Strict' in headers.get('Set-Cookie', '') or
                'SameSite=Lax' in headers.get('Set-Cookie', '')
            )
            
            # If no CSRF protection found, report vulnerability
            if not token_found and not header_protection and forms:
                # Only report CSRF for forms that might change state
                for form in forms:
                    method = form.get('method', '').upper()
                    if method == 'POST':
                        action = form.get('action', url)
                        vulnerabilities.append({
                            'type': 'CSRF',
                            'url': action,
                            'payload': None,
                            'evidence': 'No CSRF token or protection headers found',
                            'severity': 'medium',
                            'param': None,
                            'method': method
                        })
            
        except Exception as e:
            logger.error(f"CSRF scan error: {str(e)}")
            
        return vulnerabilities