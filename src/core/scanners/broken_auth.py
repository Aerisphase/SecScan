import logging
from ..http_client import HttpClient
from typing import List, Dict, Optional
import re
from urllib.parse import urlparse, parse_qs, urlencode

logger = logging.getLogger(__name__)

class BrokenAuthScanner:
    def __init__(self, client=None):
        # Инициализация HTTP клиента
        self.client = client if client else HttpClient()
        
        # Список распространенных паролей
        self.common_passwords = [
            'password',
            '123456',
            'qwerty',
            'admin',
            'letmein',
            'welcome',
            'monkey',
            'dragon',
            'baseball',
            'football',
            'mustang',
            'access',
            'master',
            'superman',
            'batman',
            'trustno1'
        ]
        
        # Список распространенных имен пользователей
        self.common_usernames = [
            'admin',
            'root',
            'administrator',
            'user',
            'test',
            'guest',
            'demo',
            'support',
            'webmaster',
            'system'
        ]
        
        # Паттерны для определения сессионных куки
        self.session_patterns = [
            r'session',
            r'sessid',
            r'jsessionid',
            r'phpsessid',
            r'aspsessionid',
            r'sid',
            r'token',
            r'auth',
            r'login',
            r'user'
        ]
        
        # Паттерны для определения слабой криптографии
        self.weak_crypto_patterns = [
            r'md5',
            r'sha1',
            r'base64',
            r'des',
            r'rc4',
            r'3des',
            r'blowfish',
            r'plaintext',
            r'cleartext',
            r'unsafe'
        ]
        
        # Паттерны для определения токенов сброса пароля
        self.reset_token_patterns = [
            r'reset',
            r'password',
            r'token',
            r'key',
            r'code',
            r'verify',
            r'confirm',
            r'validate',
            r'activation',
            r'secret'
        ]

    def scan(self, url: str, forms: Optional[List[Dict]] = None) -> List[Dict]:
        # Основной метод сканирования, который проверяет уязвимости аутентификации
        vulnerabilities = []
        
        try:
            # Проверка фиксации сессии
            session_vulns = self._check_session_fixation(url)
            vulnerabilities.extend(session_vulns)
            
            # Проверка слабой политики паролей
            if forms:
                password_vulns = self._check_weak_password_policy(url, forms)
                vulnerabilities.extend(password_vulns)
            
            # Проверка сброса пароля
            reset_vulns = self._check_password_reset(url)
            vulnerabilities.extend(reset_vulns)
            
            # Проверка слабой криптографии
            crypto_vulns = self._check_weak_crypto(url)
            vulnerabilities.extend(crypto_vulns)
            
        except Exception as e:
            logger.error(f"Broken Authentication scan error: {str(e)}")
        
        return vulnerabilities

    def _check_session_fixation(self, url: str) -> List[Dict]:
        # Проверка уязвимости фиксации сессии
        vulnerabilities = []
        try:
            # Отправка запроса
            response = self.client.get(url, timeout=10)
            if not response:
                return vulnerabilities
            
            # Проверка куки
            for cookie in response.cookies:
                cookie_name = cookie.name.lower()
                
                # Проверка, является ли кука сессионной
                if any(pattern in cookie_name for pattern in self.session_patterns):
                    # Проверка атрибутов безопасности куки
                    if not cookie.secure:
                        vulnerabilities.append({
                            'type': 'Broken Authentication',
                            'url': url,
                            'payload': 'Session cookie without secure flag',
                            'evidence': f'Session cookie "{cookie_name}" is not secure',
                            'severity': 'high',
                            'param': 'Cookie',
                            'method': 'GET'
                        })
                    
                    if not cookie.has_nonstandard_attr('HttpOnly'):
                        vulnerabilities.append({
                            'type': 'Broken Authentication',
                            'url': url,
                            'payload': 'Session cookie without HttpOnly flag',
                            'evidence': f'Session cookie "{cookie_name}" is not HttpOnly',
                            'severity': 'high',
                            'param': 'Cookie',
                            'method': 'GET'
                        })
        
        except Exception as e:
            logger.error(f"Session fixation check error: {str(e)}")
        
        return vulnerabilities

    def _check_weak_password_policy(self, url: str, forms: List[Dict]) -> List[Dict]:
        # Проверка слабой политики паролей
        vulnerabilities = []
        try:
            for form in forms:
                # Получение метода и действия формы
                method = form.get('method', 'GET').upper()
                action = form.get('action', url)
                
                # Проверка каждого поля формы
                for field in form.get('fields', []):
                    field_name = field.get('name', '').lower()
                    field_type = field.get('type', 'text')
                    
                    # Проверка, является ли поле паролем
                    if field_type != 'password':
                        continue
                    
                    # Проверка с распространенными паролями
                    for password in self.common_passwords:
                        try:
                            # Подготовка данных формы
                            form_data = {}
                            for f in form.get('fields', []):
                                if f.get('name') == field_name:
                                    form_data[f.get('name')] = password
                                else:
                                    form_data[f.get('name')] = f.get('value', '')
                            
                            # Отправка запроса
                            if method == 'GET':
                                response = self.client.get(action, params=form_data, timeout=10)
                            else:
                                response = self.client.post(action, data=form_data, timeout=10)
                            
                            if not response:
                                continue
                            
                            # Проверка успешной аутентификации
                            if self._is_authenticated(response.text):
                                vulnerabilities.append({
                                    'type': 'Broken Authentication',
                                    'url': action,
                                    'payload': f'Common password "{password}" accepted',
                                    'evidence': f'Authentication successful with common password "{password}"',
                                    'severity': 'high',
                                    'param': field_name,
                                    'method': method
                                })
                                break
                        
                        except Exception as e:
                            logger.error(f"Password check error for {field_name}: {str(e)}")
        
        except Exception as e:
            logger.error(f"Weak password policy check error: {str(e)}")
        
        return vulnerabilities

    def _check_password_reset(self, url: str) -> List[Dict]:
        # Проверка уязвимостей сброса пароля
        vulnerabilities = []
        try:
            # Отправка запроса
            response = self.client.get(url, timeout=10)
            if not response:
                return vulnerabilities
            
            # Поиск токенов сброса пароля в URL
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            
            for param, values in params.items():
                if any(pattern in param.lower() for pattern in self.reset_token_patterns):
                    vulnerabilities.append({
                        'type': 'Broken Authentication',
                        'url': url,
                        'payload': 'Password reset token in URL',
                        'evidence': f'Password reset token found in URL parameter "{param}"',
                        'severity': 'high',
                        'param': param,
                        'method': 'GET'
                    })
            
            # Поиск токенов сброса пароля в ответе
            for pattern in self.reset_token_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': 'Broken Authentication',
                        'url': url,
                        'payload': 'Password reset token in response',
                        'evidence': f'Password reset token found in response matching pattern "{pattern}"',
                        'severity': 'high',
                        'param': 'Response',
                        'method': 'GET'
                    })
        
        except Exception as e:
            logger.error(f"Password reset check error: {str(e)}")
        
        return vulnerabilities

    def _check_weak_crypto(self, url: str) -> List[Dict]:
        # Проверка слабой криптографии
        vulnerabilities = []
        try:
            # Отправка запроса
            response = self.client.get(url, timeout=10)
            if not response:
                return vulnerabilities
            
            # Поиск слабой криптографии в ответе
            for pattern in self.weak_crypto_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': 'Broken Authentication',
                        'url': url,
                        'payload': 'Weak cryptography detected',
                        'evidence': f'Weak cryptography pattern "{pattern}" found in response',
                        'severity': 'high',
                        'param': 'Response',
                        'method': 'GET'
                    })
        
        except Exception as e:
            logger.error(f"Weak crypto check error: {str(e)}")
        
        return vulnerabilities

    def _is_authenticated(self, response_text: str) -> bool:
        # Проверка успешной аутентификации
        try:
            # Проверка наличия индикаторов успешной аутентификации
            auth_indicators = [
                'logout',
                'sign out',
                'my account',
                'profile',
                'dashboard',
                'welcome',
                'success',
                'authenticated',
                'logged in'
            ]
            
            return any(indicator in response_text.lower() for indicator in auth_indicators)
        
        except Exception as e:
            logger.error(f"Authentication check error: {str(e)}")
            return False 