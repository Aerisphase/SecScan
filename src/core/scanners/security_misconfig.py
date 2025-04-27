import logging
from ..http_client import HttpClient
from typing import List, Dict, Optional
import re
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)

class SecurityMisconfigScanner:
    def __init__(self, client=None):
        # Инициализация HTTP клиента
        self.client = client if client else HttpClient()
        
        # Список общих директорий, которые могут содержать конфиденциальную информацию
        self.common_dirs = [
            'admin', 'administrator', 'backup', 'config', 'database',
            'db', 'debug', 'dev', 'development', 'docs', 'documentation',
            'git', 'logs', 'old', 'phpmyadmin', 'server-status',
            'sql', 'test', 'tmp', 'upload', 'uploads', 'var', 'www'
        ]
        
        # Список общих файлов, которые могут содержать конфиденциальную информацию
        self.common_files = [
            '.env', '.git/config', '.htaccess', 'config.php', 'config.json',
            'config.yml', 'config.yaml', 'database.yml', 'db.php', 'debug.log',
            'error.log', 'phpinfo.php', 'server-status', 'web.config'
        ]
        
        # Заголовки, которые могут раскрывать информацию о сервере
        self.server_headers = [
            'Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version'
        ]
        
        # Паттерны для поиска отладочной информации
        self.debug_patterns = [
            r'debug\s*=\s*true',
            r'display_errors\s*=\s*on',
            r'error_reporting\s*=\s*E_ALL',
            r'development\s*=\s*true',
            r'DEBUG\s*=\s*True'
        ]

    def scan(self, url: str, forms: Optional[List[Dict]] = None) -> List[Dict]:
        # Основной метод сканирования, который проверяет различные типы уязвимостей
        vulnerabilities = []
        
        try:
            # Проверка включенного листинга директорий
            dir_vulns = self._check_directory_listing(url)
            vulnerabilities.extend(dir_vulns)
            
            # Проверка общих файлов и директорий
            common_vulns = self._check_common_files_dirs(url)
            vulnerabilities.extend(common_vulns)
            
            # Проверка раскрытия информации о сервере
            server_vulns = self._check_server_info(url)
            vulnerabilities.extend(server_vulns)
            
            # Проверка отладочной информации
            debug_vulns = self._check_debug_info(url)
            vulnerabilities.extend(debug_vulns)
            
            # Проверка учетных данных по умолчанию
            default_vulns = self._check_default_credentials(url)
            vulnerabilities.extend(default_vulns)
            
            # Проверка настроек CORS
            cors_vulns = self._check_cors(url)
            vulnerabilities.extend(cors_vulns)
            
        except Exception as e:
            logger.error(f"Security Misconfiguration scan error: {str(e)}")
        
        return vulnerabilities

    def _check_directory_listing(self, url: str) -> List[Dict]:
        # Проверка включенного листинга директорий
        vulnerabilities = []
        try:
            # Проверка корневой директории
            response = self.client.get(url, timeout=10)
            if not response:
                return vulnerabilities
            
            # Индикаторы включенного листинга директорий
            indicators = [
                '<title>Index of /',
                '<h1>Index of /',
                'Directory listing for /',
                'Parent Directory',
                'Last modified',
                'Size'
            ]
            
            # Проверка наличия индикаторов в ответе
            if any(indicator in response.text for indicator in indicators):
                vulnerabilities.append({
                    'type': 'Security Misconfiguration',
                    'url': url,
                    'payload': 'Directory listing enabled',
                    'evidence': 'Directory listing is enabled, exposing file structure',
                    'severity': 'medium',
                    'param': 'Directory Listing',
                    'method': 'GET'
                })
            
            # Проверка общих директорий
            for directory in self.common_dirs:
                dir_url = urljoin(url, directory)
                dir_response = self.client.get(dir_url, timeout=10)
                if dir_response and any(indicator in dir_response.text for indicator in indicators):
                    vulnerabilities.append({
                        'type': 'Security Misconfiguration',
                        'url': dir_url,
                        'payload': f'Directory listing enabled for {directory}',
                        'evidence': f'Directory listing is enabled for {directory}, exposing file structure',
                        'severity': 'medium',
                        'param': 'Directory Listing',
                        'method': 'GET'
                    })
        
        except Exception as e:
            logger.error(f"Directory listing check error: {str(e)}")
        
        return vulnerabilities

    def _check_common_files_dirs(self, url: str) -> List[Dict]:
        # Проверка доступности общих файлов и директорий
        vulnerabilities = []
        try:
            # Проверка общих файлов
            for file in self.common_files:
                file_url = urljoin(url, file)
                response = self.client.get(file_url, timeout=10)
                if response and response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Security Misconfiguration',
                        'url': file_url,
                        'payload': f'Exposed file: {file}',
                        'evidence': f'Sensitive file {file} is publicly accessible',
                        'severity': 'high',
                        'param': 'File Access',
                        'method': 'GET'
                    })
            
            # Проверка общих директорий
            for directory in self.common_dirs:
                dir_url = urljoin(url, directory)
                response = self.client.get(dir_url, timeout=10)
                if response and response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Security Misconfiguration',
                        'url': dir_url,
                        'payload': f'Exposed directory: {directory}',
                        'evidence': f'Sensitive directory {directory} is publicly accessible',
                        'severity': 'medium',
                        'param': 'Directory Access',
                        'method': 'GET'
                    })
        
        except Exception as e:
            logger.error(f"Common files/dirs check error: {str(e)}")
        
        return vulnerabilities

    def _check_server_info(self, url: str) -> List[Dict]:
        # Проверка раскрытия информации о сервере
        vulnerabilities = []
        try:
            response = self.client.get(url, timeout=10)
            if not response:
                return vulnerabilities
            
            # Проверка заголовков сервера
            for header in self.server_headers:
                if header in response.headers:
                    vulnerabilities.append({
                        'type': 'Security Misconfiguration',
                        'url': url,
                        'payload': f'Server information in {header} header',
                        'evidence': f'Server information exposed in {header} header: {response.headers[header]}',
                        'severity': 'low',
                        'param': header,
                        'method': 'GET'
                    })
            
            # Паттерны для поиска информации о сервере в теле ответа
            server_info_patterns = [
                r'Apache/\d+\.\d+\.\d+',
                r'nginx/\d+\.\d+\.\d+',
                r'PHP/\d+\.\d+\.\d+',
                r'ASP\.NET \d+\.\d+\.\d+',
                r'Microsoft-IIS/\d+\.\d+'
            ]
            
            # Поиск информации о сервере в теле ответа
            for pattern in server_info_patterns:
                matches = re.finditer(pattern, response.text, re.IGNORECASE)
                for match in matches:
                    vulnerabilities.append({
                        'type': 'Security Misconfiguration',
                        'url': url,
                        'payload': 'Server information in response body',
                        'evidence': f'Server information exposed in response body: {match.group(0)}',
                        'severity': 'low',
                        'param': 'Response Body',
                        'method': 'GET'
                    })
        
        except Exception as e:
            logger.error(f"Server info check error: {str(e)}")
        
        return vulnerabilities

    def _check_debug_info(self, url: str) -> List[Dict]:
        # Проверка отладочной информации
        vulnerabilities = []
        try:
            response = self.client.get(url, timeout=10)
            if not response:
                return vulnerabilities
            
            # Поиск отладочных паттернов в ответе
            for pattern in self.debug_patterns:
                matches = re.finditer(pattern, response.text, re.IGNORECASE)
                for match in matches:
                    vulnerabilities.append({
                        'type': 'Security Misconfiguration',
                        'url': url,
                        'payload': 'Debug information exposed',
                        'evidence': f'Debug configuration found: {match.group(0)}',
                        'severity': 'high',
                        'param': 'Debug Configuration',
                        'method': 'GET'
                    })
            
            # Проверка общих отладочных эндпоинтов
            debug_endpoints = [
                'debug', 'debugger', 'phpinfo', 'status', 'trace',
                'error', 'errors', 'log', 'logs'
            ]
            
            for endpoint in debug_endpoints:
                debug_url = urljoin(url, endpoint)
                debug_response = self.client.get(debug_url, timeout=10)
                if debug_response and debug_response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Security Misconfiguration',
                        'url': debug_url,
                        'payload': f'Debug endpoint exposed: {endpoint}',
                        'evidence': f'Debug endpoint {endpoint} is publicly accessible',
                        'severity': 'high',
                        'param': 'Debug Endpoint',
                        'method': 'GET'
                    })
        
        except Exception as e:
            logger.error(f"Debug info check error: {str(e)}")
        
        return vulnerabilities

    def _check_default_credentials(self, url: str) -> List[Dict]:
        # Проверка учетных данных по умолчанию
        vulnerabilities = []
        try:
            # Проверка общих путей администрирования
            admin_paths = ['admin', 'administrator', 'manager', 'login']
            default_creds = [
                ('admin', 'admin'),
                ('admin', 'password'),
                ('root', 'root'),
                ('root', 'password'),
                ('administrator', 'administrator'),
                ('administrator', 'password')
            ]
            
            for path in admin_paths:
                login_url = urljoin(url, path)
                response = self.client.get(login_url, timeout=10)
                if response and response.status_code == 200:
                    for username, password in default_creds:
                        try:
                            # Попытка входа с учетными данными по умолчанию
                            login_response = self.client.post(
                                login_url,
                                data={'username': username, 'password': password},
                                timeout=10
                            )
                            if login_response and login_response.status_code == 200:
                                vulnerabilities.append({
                                    'type': 'Security Misconfiguration',
                                    'url': login_url,
                                    'payload': f'Default credentials: {username}/{password}',
                                    'evidence': f'Default credentials {username}/{password} are accepted',
                                    'severity': 'high',
                                    'param': 'Default Credentials',
                                    'method': 'POST'
                                })
                        except Exception as e:
                            logger.error(f"Default credentials check error for {login_url}: {str(e)}")
        
        except Exception as e:
            logger.error(f"Default credentials check error: {str(e)}")
        
        return vulnerabilities

    def _check_cors(self, url: str) -> List[Dict]:
        # Проверка настроек CORS
        vulnerabilities = []
        try:
            response = self.client.get(url, timeout=10)
            if not response:
                return vulnerabilities
            
            # Проверка заголовков CORS
            if 'Access-Control-Allow-Origin' in response.headers:
                origin = response.headers['Access-Control-Allow-Origin']
                if origin == '*':
                    vulnerabilities.append({
                        'type': 'Security Misconfiguration',
                        'url': url,
                        'payload': 'CORS misconfiguration',
                        'evidence': 'CORS is configured to allow all origins (*)',
                        'severity': 'medium',
                        'param': 'CORS',
                        'method': 'GET'
                    })
                elif 'Access-Control-Allow-Credentials' in response.headers and \
                     response.headers['Access-Control-Allow-Credentials'].lower() == 'true':
                    vulnerabilities.append({
                        'type': 'Security Misconfiguration',
                        'url': url,
                        'payload': 'CORS misconfiguration',
                        'evidence': 'CORS is configured to allow credentials with wildcard origin',
                        'severity': 'high',
                        'param': 'CORS',
                        'method': 'GET'
                    })
        
        except Exception as e:
            logger.error(f"CORS check error: {str(e)}")
        
        return vulnerabilities 