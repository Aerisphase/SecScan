import logging
import random
import string
import re
from typing import List, Dict, Optional, Union, Tuple
import urllib.parse
import base64
import html

logger = logging.getLogger(__name__)

class WAFBypass:
    """
    WAF Bypass techniques for SecScan
    
    This class implements various techniques to bypass Web Application Firewalls (WAFs)
    when performing security scans. It includes methods for payload obfuscation,
    request manipulation, and evasion techniques.
    """
    
    def __init__(self):
        # Common WAF bypass techniques
        self.techniques = {
            "headers": self._randomize_headers,
            "encoding": self._apply_encoding,
            "obfuscation": self._obfuscate_payload,
            "case_switching": self._case_switching,
            "delay": self._add_delay_parameter,
            "comment_injection": self._add_comments,
            "whitespace": self._add_whitespace
        }
        
        # Headers that can be used to bypass WAF
        self.bypass_headers = {
            "X-Forwarded-For": self._generate_random_ip,
            "X-Originating-IP": self._generate_random_ip,
            "X-Remote-IP": self._generate_random_ip,
            "X-Remote-Addr": self._generate_random_ip,
            "X-Client-IP": self._generate_random_ip,
            "X-Host": lambda: "localhost",
            "X-Forwarded-Host": lambda: "localhost",
            "User-Agent": self._generate_random_user_agent,
            "Referer": lambda: "https://www.google.com/",
            "X-Custom-IP-Authorization": self._generate_random_ip,
            "True-Client-IP": self._generate_random_ip,
            "X-WAF-Bypass": lambda: "true"
        }
        
        # User agents that are less likely to be blocked
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59"
        ]
        
        # SQL injection evasion techniques
        self.sql_evasion_techniques = [
            self._sql_case_switching,
            self._sql_comment_injection,
            self._sql_whitespace_manipulation,
            self._sql_string_concatenation,
            self._sql_hex_encoding,
            self._sql_char_encoding,
            self._sql_alternative_operators
        ]
        
        # XSS evasion techniques
        self.xss_evasion_techniques = [
            self._xss_case_switching,
            self._xss_html_encoding,
            self._xss_unicode_encoding,
            self._xss_attribute_obfuscation,
            self._xss_event_handler_obfuscation,
            self._xss_script_obfuscation,
            self._xss_protocol_obfuscation
        ]
    
    def apply_bypass_techniques(self, payload: str, technique_types: List[str], 
                               vulnerability_type: str) -> str:
        """
        Apply multiple bypass techniques to a payload
        
        Args:
            payload: The original payload
            technique_types: List of technique types to apply
            vulnerability_type: Type of vulnerability (e.g., 'sql', 'xss')
            
        Returns:
            Modified payload with bypass techniques applied
        """
        modified_payload = payload
        
        for technique in technique_types:
            if technique in self.techniques:
                modified_payload = self.techniques[technique](modified_payload, vulnerability_type)
                
        return modified_payload
    
    def get_bypass_headers(self, num_headers: int = 3) -> Dict[str, str]:
        """
        Get a dictionary of random headers that can help bypass WAF
        
        Args:
            num_headers: Number of headers to include
            
        Returns:
            Dictionary of header name to header value
        """
        headers = {}
        header_keys = list(self.bypass_headers.keys())
        selected_headers = random.sample(header_keys, min(num_headers, len(header_keys)))
        
        for header in selected_headers:
            headers[header] = self.bypass_headers[header]()
            
        return headers
    
    def generate_sql_bypass_payloads(self, base_payload: str, num_variants: int = 3) -> List[str]:
        """
        Generate SQL injection payloads designed to bypass WAF
        
        Args:
            base_payload: Base SQL injection payload
            num_variants: Number of variants to generate
            
        Returns:
            List of WAF-bypass SQL injection payloads
        """
        variants = []
        
        for _ in range(num_variants):
            # Apply random SQL evasion techniques
            variant = base_payload
            techniques = random.sample(self.sql_evasion_techniques, 
                                      min(3, len(self.sql_evasion_techniques)))
            
            for technique in techniques:
                variant = technique(variant)
                
            variants.append(variant)
            
        return variants
    
    def generate_xss_bypass_payloads(self, base_payload: str, num_variants: int = 3) -> List[str]:
        """
        Generate XSS payloads designed to bypass WAF
        
        Args:
            base_payload: Base XSS payload
            num_variants: Number of variants to generate
            
        Returns:
            List of WAF-bypass XSS payloads
        """
        variants = []
        
        for _ in range(num_variants):
            # Apply random XSS evasion techniques
            variant = base_payload
            techniques = random.sample(self.xss_evasion_techniques, 
                                      min(3, len(self.xss_evasion_techniques)))
            
            for technique in techniques:
                variant = technique(variant)
                
            variants.append(variant)
            
        return variants
    
    # Helper methods for generating random values
    def _generate_random_ip(self) -> str:
        """Generate a random IP address"""
        return f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    
    def _generate_random_user_agent(self) -> str:
        """Get a random user agent"""
        return random.choice(self.user_agents)
    
    # WAF bypass technique implementations
    def _randomize_headers(self, payload: str, vuln_type: str) -> str:
        """This technique doesn't modify the payload but should be used with get_bypass_headers()"""
        return payload
    
    def _apply_encoding(self, payload: str, vuln_type: str) -> str:
        """Apply URL encoding to the payload"""
        # Double URL encoding can bypass some WAFs
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    def _obfuscate_payload(self, payload: str, vuln_type: str) -> str:
        """Apply obfuscation based on vulnerability type"""
        if vuln_type.lower() == 'sql':
            return random.choice(self.sql_evasion_techniques)(payload)
        elif vuln_type.lower() == 'xss':
            return random.choice(self.xss_evasion_techniques)(payload)
        return payload
    
    def _case_switching(self, payload: str, vuln_type: str) -> str:
        """Randomly switch case of characters in the payload"""
        return ''.join(c.upper() if random.choice([True, False]) else c.lower() 
                      for c in payload)
    
    def _add_delay_parameter(self, payload: str, vuln_type: str) -> str:
        """Add a random parameter to potentially bypass rate limiting"""
        param = ''.join(random.choices(string.ascii_lowercase, k=8))
        value = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
        
        if '?' in payload:
            return f"{payload}&{param}={value}"
        else:
            return f"{payload}?{param}={value}"
    
    def _add_comments(self, payload: str, vuln_type: str) -> str:
        """Add comments based on vulnerability type"""
        if vuln_type.lower() == 'sql':
            return self._sql_comment_injection(payload)
        elif vuln_type.lower() == 'xss':
            return payload.replace('<', '<!--random--><')
        return payload
    
    def _add_whitespace(self, payload: str, vuln_type: str) -> str:
        """Add random whitespace based on vulnerability type"""
        if vuln_type.lower() == 'sql':
            return self._sql_whitespace_manipulation(payload)
        elif vuln_type.lower() == 'xss':
            # Add random whitespace in XSS tags
            return re.sub(r'(<[^>]*>)', lambda m: m.group(0).replace(' ', ' ' * random.randint(1, 3)), payload)
        return payload
    
    # SQL injection evasion techniques
    def _sql_case_switching(self, payload: str) -> str:
        """Randomly switch case of SQL keywords"""
        keywords = ['SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'FROM', 'WHERE', 
                   'AND', 'OR', 'ORDER BY', 'GROUP BY', 'HAVING', 'JOIN']
        
        result = payload
        for keyword in keywords:
            if keyword.lower() in payload.lower():
                # Create a case-switched version of the keyword
                switched = ''.join(c.upper() if random.choice([True, False]) else c.lower() 
                                  for c in keyword)
                # Replace ignoring case
                pattern = re.compile(re.escape(keyword), re.IGNORECASE)
                result = pattern.sub(switched, result)
                
        return result
    
    def _sql_comment_injection(self, payload: str) -> str:
        """Add SQL comments to the payload"""
        comments = ['/**/', '-- ', '#', '/*! */', '/**/']
        comment = random.choice(comments)
        
        # Insert comments between SQL keywords and other parts
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'ORDER', 'GROUP', 'HAVING']
        result = payload
        
        for keyword in keywords:
            if keyword.lower() in result.lower():
                pattern = re.compile(f"({re.escape(keyword)})", re.IGNORECASE)
                result = pattern.sub(f"\\1{comment}", result)
                
        return result
    
    def _sql_whitespace_manipulation(self, payload: str) -> str:
        """Manipulate whitespace in SQL queries"""
        # Replace spaces with various whitespace characters
        whitespaces = [' ', '\t', '\n', '\r', '\v', '\f']
        result = re.sub(r'\s+', lambda _: random.choice(whitespaces) * random.randint(1, 3), payload)
        return result
    
    def _sql_string_concatenation(self, payload: str) -> str:
        """Use string concatenation to obfuscate SQL strings"""
        if "'" not in payload and '"' not in payload:
            return payload
            
        # Find strings in quotes and replace with concatenated versions
        def replace_string(match):
            quote = match.group(1)
            content = match.group(2)
            
            # For MySQL/PostgreSQL style concatenation
            if random.choice([True, False]):
                parts = []
                for char in content:
                    parts.append(f"{quote}{char}{quote}")
                return '||'.join(parts)
            # For SQL Server/Oracle style
            else:
                parts = []
                for char in content:
                    parts.append(f"{quote}{char}{quote}")
                return '+'.join(parts)
                
        return re.sub(r"(['\"])(.*?)(\1)", replace_string, payload)
    
    def _sql_hex_encoding(self, payload: str) -> str:
        """Encode strings as hexadecimal in SQL queries"""
        if "'" not in payload and '"' not in payload:
            return payload
            
        def hex_encode(match):
            content = match.group(2)
            hex_str = ''.join([hex(ord(c))[2:] for c in content])
            return f"0x{hex_str}"
            
        return re.sub(r"(['\"])(.*?)(\1)", hex_encode, payload)
    
    def _sql_char_encoding(self, payload: str) -> str:
        """Encode strings using CHAR() function in SQL"""
        if "'" not in payload and '"' not in payload:
            return payload
            
        def char_encode(match):
            content = match.group(2)
            chars = [str(ord(c)) for c in content]
            return f"CHAR({','.join(chars)})"
            
        return re.sub(r"(['\"])(.*?)(\1)", char_encode, payload)
    
    def _sql_alternative_operators(self, payload: str) -> str:
        """Replace operators with alternative representations"""
        replacements = {
            '=': ['=', 'LIKE', 'IN (', 'IS'],
            '>': ['>', '!<', 'NOT BETWEEN 0 AND'],
            '<': ['<', '!>', 'NOT BETWEEN 0 AND'],
            '>=': ['>=', '!<', 'NOT BETWEEN 0 AND'],
            '<=': ['<=', '!>', 'NOT BETWEEN 0 AND'],
            'AND': ['AND', '&&'],
            'OR': ['OR', '||']
        }
        
        result = payload
        for op, alternatives in replacements.items():
            if op in result:
                result = result.replace(op, random.choice(alternatives))
                
        return result
    
    # XSS evasion techniques
    def _xss_case_switching(self, payload: str) -> str:
        """Switch case of XSS tags and attributes"""
        tags = ['script', 'img', 'svg', 'body', 'iframe', 'a']
        attrs = ['src', 'onerror', 'onload', 'href', 'onclick']
        
        result = payload
        for tag in tags:
            if tag in result.lower():
                switched_tag = ''.join(c.upper() if random.choice([True, False]) else c.lower() 
                                      for c in tag)
                result = re.sub(f"<{tag}", f"<{switched_tag}", result, flags=re.IGNORECASE)
                result = re.sub(f"</{tag}>", f"</{switched_tag}>", result, flags=re.IGNORECASE)
                
        for attr in attrs:
            if attr in result.lower():
                switched_attr = ''.join(c.upper() if random.choice([True, False]) else c.lower() 
                                       for c in attr)
                result = re.sub(f"{attr}=", f"{switched_attr}=", result, flags=re.IGNORECASE)
                
        return result
    
    def _xss_html_encoding(self, payload: str) -> str:
        """Encode parts of the payload using HTML encoding"""
        # Encode random characters
        result = ""
        for char in payload:
            if random.random() < 0.3 and char.isalpha():
                result += f"&#{ord(char)};"
            else:
                result += char
        return result
    
    def _xss_unicode_encoding(self, payload: str) -> str:
        """Encode parts of the payload using Unicode encoding"""
        # Encode random characters
        result = ""
        for char in payload:
            if random.random() < 0.3 and char.isalpha():
                result += f"\\u{ord(char):04x}"
            else:
                result += char
        return result
    
    def _xss_attribute_obfuscation(self, payload: str) -> str:
        """Obfuscate HTML attributes in XSS payloads"""
        # Replace attribute="value" with attribute=value or attribute='value'
        def replace_attr(match):
            attr = match.group(1)
            value = match.group(3)
            quote = random.choice(["'", '"']) if random.random() < 0.5 else ""
            return f"{attr}={quote}{value}{quote}"
            
        return re.sub(r'(\w+)=(["\'])(.*?)(\2)', replace_attr, payload)
    
    def _xss_event_handler_obfuscation(self, payload: str) -> str:
        """Obfuscate event handlers in XSS payloads"""
        handlers = ['onload', 'onerror', 'onclick', 'onmouseover', 'onfocus']
        
        result = payload
        for handler in handlers:
            if handler in result.lower():
                # Create obfuscated versions like "on\x6Coad"
                chars = []
                for char in handler:
                    if random.random() < 0.3:
                        chars.append(f"\\x{ord(char):02x}")
                    else:
                        chars.append(char)
                obfuscated = ''.join(chars)
                result = re.sub(handler, obfuscated, result, flags=re.IGNORECASE)
                
        return result
    
    def _xss_script_obfuscation(self, payload: str) -> str:
        """Obfuscate script content in XSS payloads"""
        if "<script>" not in payload.lower():
            return payload
            
        # Find script content and obfuscate it
        def obfuscate_script(match):
            script_content = match.group(1)
            
            # Simple obfuscation: add spaces, use string concatenation
            obfuscated = script_content
            obfuscated = obfuscated.replace("alert", "al" + "ert")
            obfuscated = obfuscated.replace("(", "( ")
            obfuscated = obfuscated.replace(")", " )")
            
            return f"<script>{obfuscated}</script>"
            
        return re.sub(r"<script>(.*?)</script>", obfuscate_script, payload, flags=re.IGNORECASE | re.DOTALL)
    
    def _xss_protocol_obfuscation(self, payload: str) -> str:
        """Obfuscate javascript: protocol in XSS payloads"""
        if "javascript:" not in payload.lower():
            return payload
            
        # Obfuscate javascript: protocol
        obfuscations = [
            "javascript:",
            "javascript&#58;",
            "javascript&#x3A;",
            "java&#09;script:",
            "java\tscript:",
            "java script:",
            "java%09script:",
            "java%0Ascript:",
            "java%0Dscript:",
            "\u006A\u0061\u0076\u0061\u0073\u0063\u0072\u0069\u0070\u0074\u003A"
        ]
        
        return payload.replace("javascript:", random.choice(obfuscations))
