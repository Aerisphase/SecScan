import time
import random
import logging
import requests
import re
import json
from requests.adapters import HTTPAdapter
from requests.cookies import RequestsCookieJar
from urllib3.util.retry import Retry
from typing import Optional, Dict, Any, List, Tuple, Union
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

class EnhancedHttpClient:
    """
    Enhanced HTTP client with WAF evasion techniques and session management.
    
    """
    
    # Common user agents for rotation
    USER_AGENTS = [
        # Chrome
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
        # Firefox
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0',
        # Safari
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
        # Edge
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59',
        # Mobile
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/88.0'
    ]
    
    # Request patterns for randomization
    REQUEST_PATTERNS = [
        {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
         'Accept-Language': 'en-US,en;q=0.5',
         'Accept-Encoding': 'gzip, deflate, br',
         'Connection': 'keep-alive',
         'Upgrade-Insecure-Requests': '1'},
        {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
         'Accept-Language': 'en-US,en;q=0.9',
         'Accept-Encoding': 'gzip, deflate',
         'Connection': 'keep-alive',
         'Upgrade-Insecure-Requests': '1'},
        {'Accept': 'application/json, text/plain, */*',
         'Accept-Language': 'en-US,en;q=0.7',
         'Accept-Encoding': 'gzip, deflate, br',
         'Connection': 'keep-alive',
         'X-Requested-With': 'XMLHttpRequest'}
    ]
    
    def __init__(self, 
                 verify_ssl: bool = True,
                 timeout: int = 10,
                 max_retries: int = 3,
                 rate_limit_min: float = 0.5,
                 rate_limit_max: float = 2.0,
                 proxy: Optional[Union[str, List[str]]] = None,
                 auth: Optional[Dict[str, str]] = None,
                 rotate_user_agent: bool = True,
                 rotate_request_pattern: bool = True,
                 waf_evasion: bool = True,
                 handle_csrf: bool = True,
                 maintain_session: bool = True):
        """
        Initialize the enhanced HTTP client.
        
        """
        # Suppress SSL warnings if verify_ssl is False
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.max_retries = max_retries
        self.rate_limit_min = rate_limit_min
        self.rate_limit_max = rate_limit_max
        self.proxies = self._setup_proxies(proxy)
        self.auth = auth
        self.rotate_user_agent = rotate_user_agent
        self.rotate_request_pattern = rotate_request_pattern
        self.waf_evasion = waf_evasion
        self.handle_csrf = handle_csrf
        self.maintain_session = maintain_session
        
        self.last_request_time = 0
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Session and cookie management
        self.session = requests.Session()
        self.cookie_jar = RequestsCookieJar()
        self.session.cookies = self.cookie_jar
        
        # CSRF token cache
        self.csrf_tokens = {}
        
        # Track domains where we've already detected WAFs to reduce log noise
        self._detected_wafs = set()
        
        # WAF detection patterns
        self.waf_signatures = [
            ('Cloudflare', r'cloudflare|cf-ray|cf-chl-bypass|__cf_bm'),
            ('Akamai', r'akamai|ak_bmsc|bm_sv'),
            ('AWS WAF', r'aws-waf|awselb'),
            ('ModSecurity', r'mod_security|modsecurity'),
            ('Imperva', r'incap_ses|visid_incap'),
            ('F5 BIG-IP', r'BIGipServer|TS01'),
            ('Sucuri', r'sucuri'),
            ('Barracuda', r'barracuda_'),
            ('Wordfence', r'wordfence|wfvt_'),
            ('Generic WAF', r'waf|firewall|security|blocked|forbidden|captcha|challenge')
        ]
        
        # Configure session with retry strategy
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Initialize headers attribute that scanners can access directly
        self.headers = {}
        
        # Set initial headers
        self._rotate_headers()

    def _setup_proxies(self, proxy: Optional[Union[str, List[str]]]) -> List[Dict[str, str]]:
        """Set up proxy configuration"""
        if not proxy:
            return [None]
            
        if isinstance(proxy, str):
            return [{'http': proxy, 'https': proxy}]
            
        if isinstance(proxy, list):
            return [{'http': p, 'https': p} for p in proxy]
            
        return [None]

    def _rotate_headers(self):
        """Rotate headers to avoid pattern detection"""
        headers = {}
        
        # Rotate user agent if enabled
        if self.rotate_user_agent:
            headers['User-Agent'] = random.choice(self.USER_AGENTS)
        else:
            headers['User-Agent'] = 'SecScan/1.0'
            
        # Rotate request pattern if enabled
        if self.rotate_request_pattern:
            headers.update(random.choice(self.REQUEST_PATTERNS))
        else:
            headers.update(self.REQUEST_PATTERNS[0])
            
        # Add randomized headers for WAF evasion if enabled
        if self.waf_evasion:
            # Add random Accept header variations
            if random.random() > 0.5:
                accept_values = ['text/html', 'application/xhtml+xml', 'application/xml', 'image/webp', '*/*']
                random.shuffle(accept_values)
                q_values = [f"q={round(random.uniform(0.1, 1.0), 1)}" for _ in range(len(accept_values)-1)]
                q_values.append('')
                accept_header = ','.join(f"{val};{q}" if q else val for val, q in zip(accept_values, q_values))
                headers['Accept'] = accept_header
                
            # Add random order of standard headers
            if random.random() > 0.7:
                headers['Accept-Charset'] = 'utf-8, iso-8859-1;q=0.5, *;q=0.1'
                
            # Add cache control variations
            if random.random() > 0.6:
                cache_options = ['no-cache', 'max-age=0', 'no-store, max-age=0', 'no-transform']
                headers['Cache-Control'] = random.choice(cache_options)
                
        # Add random custom headers occasionally
        if random.random() > 0.8:
            headers['X-Forwarded-For'] = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            
        # Add random DNT (Do Not Track) header
        if random.random() > 0.7:
            headers['DNT'] = '1'
            
        # Update both the session headers and the headers attribute
        self.session.headers.update(headers)
        # Make a copy of the headers for scanners to access directly
        self.headers = self.session.headers.copy()

    def _rate_limit(self) -> None:
        """Implement randomized rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        # Calculate random delay within range
        delay = random.uniform(self.rate_limit_min, self.rate_limit_max)
        
        # Apply delay if needed
        if time_since_last < delay:
            time.sleep(delay - time_since_last)
            
        self.last_request_time = time.time()

    def _get_random_headers(self):
        """Generate random headers to bypass WAF fingerprinting"""
        headers = {}
        
        # Randomize User-Agent
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0) Gecko/20100101 Firefox/94.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Mobile/15E148 Safari/604.1"
        ]
        
        # Randomize Accept headers
        accept_variations = [
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
        ]
        
        headers["User-Agent"] = random.choice(user_agents)
        headers["Accept"] = random.choice(accept_variations)
        headers["Accept-Language"] = random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.8", "en-CA,en;q=0.7,fr-CA;q=0.6"])
        
        # Add random innocuous headers to vary fingerprint
        if random.random() > 0.5:
            headers["Upgrade-Insecure-Requests"] = "1"
        
        if random.random() > 0.7:
            headers["Accept-Encoding"] = random.choice(["gzip, deflate", "gzip, deflate, br", "br, gzip, deflate"])
            
        if random.random() > 0.8:
            headers["DNT"] = "1"
            
        if random.random() > 0.9:
            headers["Connection"] = random.choice(["keep-alive", "close"])
            
        return headers
        
    def _adaptive_rate_limit(self, url):
        """Adjust request timing based on WAF detection"""
        domain = urlparse(url).netloc
        
        if domain in self._detected_wafs:
            # More random delays for WAF domains
            delay = random.uniform(2.0, 5.0)
        else:
            # Standard delay
            delay = random.uniform(0.5, 1.5)
            
        time.sleep(delay)
    
    def _detect_waf(self, response: requests.Response) -> Optional[str]:
        """Detect if a WAF is present based on response headers and content"""
        if not response:
            return None
            
        # Skip WAF detection for most requests to reduce noise
        # Only detect WAF on suspicious responses
        if response.status_code not in [403, 406, 429, 401, 418, 444]:
            return None
            
        # Check headers for WAF signatures
        headers_str = str(response.headers).lower()
        content = response.text.lower() if hasattr(response, 'text') else ''
        
        for waf_name, pattern in self.waf_signatures:
            if re.search(pattern, headers_str, re.IGNORECASE) or re.search(pattern, content, re.IGNORECASE):
                # Only log WAF detection once per domain to reduce noise
                domain = urlparse(response.url).netloc
                if domain not in self._detected_wafs:
                    self.logger.warning(f"Detected {waf_name} WAF on {domain}")
                    self._detected_wafs.add(domain)
                return waf_name
                
        # Check for common WAF response patterns in content
        waf_content_patterns = [
            r'blocked|protection|security|firewall|waf|challenge|captcha|forbidden|access denied',
            r'your (ip|browser|request) (was|has been) (blocked|flagged|rejected)',
            r'automated request|bot detected|security check|unusual traffic'
        ]
        
        for pattern in waf_content_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                domain = urlparse(response.url).netloc
                if domain not in self._detected_wafs:
                    self.logger.warning(f"Detected generic WAF on {domain}")
                    self._detected_wafs.add(domain)
                return "Generic WAF"
                
        return None

    def _extract_csrf_token(self, response: requests.Response, url: str) -> Optional[str]:
        """Extract CSRF token from response"""
        if not response or not hasattr(response, 'text'):
            return None
            
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Check for common CSRF token patterns
        csrf_patterns = [
            # Meta tag
            {'element': 'meta', 'attrs': {'name': re.compile(r'csrf[-_]?token', re.I)}},
            # Input field
            {'element': 'input', 'attrs': {'name': re.compile(r'csrf[-_]?token', re.I)}},
            {'element': 'input', 'attrs': {'name': re.compile(r'_token', re.I)}},
            # Form with data attribute
            {'element': 'form', 'attrs': {'data-csrf': True}},
            # Hidden input with various names
            {'element': 'input', 'attrs': {'name': '_csrf'}},
            {'element': 'input', 'attrs': {'name': 'csrfmiddlewaretoken'}},
            {'element': 'input', 'attrs': {'name': '_csrftoken'}},
            {'element': 'input', 'attrs': {'name': 'authenticity_token'}}
        ]
        
        for pattern in csrf_patterns:
            element = soup.find(pattern['element'], pattern['attrs'])
            if element:
                if element.name == 'meta':
                    token = element.get('content')
                elif element.name == 'input':
                    token = element.get('value')
                elif element.name == 'form':
                    token = element.get('data-csrf')
                    
                if token:
                    self.logger.debug(f"Found CSRF token: {token[:10]}...")
                    return token
                    
        # Check for CSRF token in cookies
        for cookie_name in response.cookies:
            if re.search(r'csrf|xsrf|token', cookie_name, re.I):
                token = response.cookies[cookie_name]
                self.logger.debug(f"Found CSRF token in cookie: {token[:10]}...")
                return token
                
        # Check for token in response headers
        for header, value in response.headers.items():
            if re.search(r'csrf|xsrf|token', header, re.I):
                self.logger.debug(f"Found CSRF token in header: {value[:10]}...")
                return value
                
        return None

    def _apply_waf_evasion(self, url: str, method: str, detected_waf: Optional[str] = None) -> Dict[str, Any]:
        """Apply WAF evasion techniques based on detected WAF"""
        evasion_params = {}
        
        if not self.waf_evasion:
            return evasion_params
            
        # Apply general evasion techniques
        self._rotate_headers()
        
        # Add random delay
        time.sleep(random.uniform(1.0, 3.0))
        
        # Apply improved general WAF evasion techniques
        # Use a more realistic browser profile
        evasion_params['headers'] = {
            # Use a standard browser user agent
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            # Set referer to the site itself to appear as normal navigation
            'Referer': urlparse(url).scheme + "://" + urlparse(url).netloc,
            # Standard browser headers
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        # Add some randomization to appear more human-like
        if random.random() > 0.7:
            # Sometimes add a random delay to simulate human behavior
            time.sleep(random.uniform(1.0, 3.0))
        
        # WAF-specific evasion techniques
        if detected_waf:
            if detected_waf == "Cloudflare":
                # Cloudflare-specific evasion
                evasion_params['headers'] = {
                    'CF-IPCountry': random.choice(['US', 'GB', 'CA', 'AU', 'DE', 'FR']),
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Referer': url
                }
                
            elif detected_waf == "Akamai":
                # Akamai-specific evasion
                evasion_params['headers'] = {
                    'Referer': url,
                    'Origin': urlparse(url).scheme + "://" + urlparse(url).netloc
                }
                
            elif detected_waf in ["AWS WAF", "Generic WAF"]:
                # General WAF evasion
                evasion_params['headers'] = {
                    'Referer': random.choice([
                        'https://www.google.com/',
                        'https://www.bing.com/',
                        'https://search.yahoo.com/'
                    ]),
                    'Accept-Language': random.choice([
                        'en-US,en;q=0.9',
                        'en-GB,en;q=0.8,en-US;q=0.6',
                        'en-CA,en;q=0.7,fr-CA;q=0.3'
                    ])
                }
                
        return evasion_params

    def _handle_response(self, response: requests.Response, url: str) -> requests.Response:
        """Process response, handle cookies, CSRF tokens, and detect WAFs"""
        if not response:
            return response
            
        # Store cookies if session maintenance is enabled
        if self.maintain_session and response.cookies:
            for cookie in response.cookies:
                self.logger.debug(f"Received cookie: {cookie.name}")
                
        # Extract and store CSRF token if enabled
        if self.handle_csrf:
            csrf_token = self._extract_csrf_token(response, url)
            if csrf_token:
                domain = urlparse(url).netloc
                self.csrf_tokens[domain] = csrf_token
                
        # Detect WAF
        detected_waf = self._detect_waf(response)
        if detected_waf:
            self.logger.warning(f"WAF detected: {detected_waf} at {url}")
            
        return response

    def _prepare_request_params(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        """Prepare request parameters with all enhancements"""
        # Set default parameters
        params = kwargs.copy()
        params.setdefault('timeout', self.timeout)
        params.setdefault('verify', self.verify_ssl)
        
        # Select a proxy if multiple are available
        if self.proxies and len(self.proxies) > 0:
            current_proxy = random.choice(self.proxies)
            if current_proxy:
                params.setdefault('proxies', current_proxy)
                
        # Add authentication if provided
        if self.auth:
            params.setdefault('auth', (self.auth.get('username'), self.auth.get('password')))
            
        # Add CSRF token if available for this domain
        if self.handle_csrf and method.upper() in ['POST', 'PUT', 'DELETE', 'PATCH']:
            domain = urlparse(url).netloc
            if domain in self.csrf_tokens:
                # If data is a dict, add the token
                if 'data' in params and isinstance(params['data'], dict):
                    csrf_data = params['data'].copy()
                    csrf_data['csrf_token'] = self.csrf_tokens[domain]
                    params['data'] = csrf_data
                    
                # Also add as a header
                headers = params.get('headers', {})
                headers['X-CSRF-Token'] = self.csrf_tokens[domain]
                params['headers'] = headers
                
        # Apply WAF evasion if enabled
        if self.waf_evasion:
            evasion_params = self._apply_waf_evasion(url, method)
            # Merge headers
            if 'headers' in evasion_params:
                headers = params.get('headers', {})
                headers.update(evasion_params['headers'])
                params['headers'] = headers
                
        return params

    def _make_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Make an HTTP request with all enhancements"""
        try:
            # Apply rate limiting
            self._rate_limit()
            
            # Prepare request parameters
            params = self._prepare_request_params(method, url, **kwargs)
            
            # Make the request
            response = self.session.request(method, url, **params)
            
            # Process the response
            processed_response = self._handle_response(response, url)
            
            # Check for WAF and retry with evasion if needed
            detected_waf = self._detect_waf(response)
            if detected_waf and response.status_code in [403, 406, 429]:
                self.logger.warning(f"Detected {detected_waf} blocking request to {url}. Retrying with evasion...")
                
                # Wait longer before retry
                time.sleep(random.uniform(2.0, 5.0))
                
                # Apply specific evasion techniques
                evasion_params = self._apply_waf_evasion(url, method, detected_waf)
                params.update(evasion_params)
                
                # Retry the request
                response = self.session.request(method, url, **params)
                processed_response = self._handle_response(response, url)
            
            # Raise for status but return the response even if it's an error
            response.raise_for_status()
            return processed_response
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed for {url}: {str(e)}")
            return getattr(e, 'response', None)

    def get(self, url: str, headers: Optional[Dict[str, str]] = None, 
             params: Optional[Dict[str, Any]] = None, 
             timeout: int = 30, 
             verify_ssl: bool = False,
             allow_redirects: bool = True,
             cookies: Optional[Dict[str, str]] = None) -> Optional[requests.Response]:
        """
        Perform a GET request with rate limiting and WAF detection.
        """
        try:
            # Use adaptive rate limiting based on WAF detection
            domain = urlparse(url).netloc
            if domain in self._detected_wafs:
                self._adaptive_rate_limit(url)
            else:
                self._rate_limit()
            
            # Get random headers for WAF evasion
            random_headers = self._get_random_headers()
            
            # Merge headers with default headers and random headers
            merged_headers = self.headers.copy()
            merged_headers.update(random_headers)
            if headers:
                merged_headers.update(headers)
                
            # Create session if needed
            if not self.session:
                self._create_session()
                
            # Perform request
            response = self.session.get(
                url, 
                headers=merged_headers,
                params=params,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=allow_redirects,
                cookies=cookies
            )
            
            # Update the headers attribute with the merged headers
            self.headers = merged_headers.copy()
            
            # Check for WAF
            waf = self._detect_waf(response)
            if waf:
                self.logger.debug(f"WAF detected: {waf} at {url}")
                
            return response
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed for {url}: {str(e)}")
            return getattr(e, 'response', None)

    def post(self, url: str, data: Optional[Dict[str, Any]] = None, 
             headers: Optional[Dict[str, str]] = None, 
             params: Optional[Dict[str, Any]] = None, 
             timeout: int = 30, 
             verify_ssl: bool = False,
             allow_redirects: bool = True,
             cookies: Optional[Dict[str, str]] = None) -> Optional[requests.Response]:
        """
        Perform a POST request with rate limiting and WAF detection.
        """
        try:
            # Use adaptive rate limiting based on WAF detection
            domain = urlparse(url).netloc
            if domain in self._detected_wafs:
                self._adaptive_rate_limit(url)
            else:
                self._rate_limit()
            
            # Get random headers for WAF evasion
            random_headers = self._get_random_headers()
            
            # Merge headers with default headers and random headers
            merged_headers = self.headers.copy()
            merged_headers.update(random_headers)
            if headers:
                merged_headers.update(headers)
                
            # Create session if needed
            if not self.session:
                self._create_session()
                
            # Perform request
            response = self.session.post(
                url, 
                headers=merged_headers,
                data=data,
                params=params,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=allow_redirects,
                cookies=cookies
            )
            
            # Update the headers attribute with the merged headers
            self.headers = merged_headers.copy()
            
            # Check for WAF
            waf = self._detect_waf(response)
            if waf:
                self.logger.debug(f"WAF detected: {waf} at {url}")
                
            return response
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed for {url}: {str(e)}")
            return getattr(e, 'response', None)
        
    def put(self, url: str, data: Optional[Dict[str, Any]] = None, **kwargs) -> Optional[requests.Response]:
        """Make a PUT request with enhancements"""
        return self._make_request('PUT', url, data=data, **kwargs)
        
    def delete(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make a DELETE request with enhancements"""
        return self._make_request('DELETE', url, **kwargs)
        
    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make a HEAD request with enhancements"""
        return self._make_request('HEAD', url, **kwargs)
        
    def options(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make an OPTIONS request with enhancements"""
        return self._make_request('OPTIONS', url, **kwargs)
        
    def get_csrf_token(self, url: str) -> Optional[str]:
        """Get CSRF token for a specific URL"""
        domain = urlparse(url).netloc
        
        # Check if we already have a token
        if domain in self.csrf_tokens:
            return self.csrf_tokens[domain]
            
        # Otherwise, make a GET request to extract the token
        response = self.get(url)
        if response:
            return self.csrf_tokens.get(domain)
            
        return None
        
    def clear_cookies(self) -> None:
        """Clear all cookies"""
        self.session.cookies.clear()
        
    def get_cookies(self) -> Dict[str, str]:
        """Get all cookies as a dictionary"""
        return {cookie.name: cookie.value for cookie in self.session.cookies}
        
    def set_cookie(self, name: str, value: str, domain: str = None) -> None:
        """Set a specific cookie"""
        self.session.cookies.set(name, value, domain=domain)
        
    def save_cookies(self, filename: str) -> None:
        """Save cookies to a file"""
        with open(filename, 'w') as f:
            json.dump(self.get_cookies(), f)
            
    def load_cookies(self, filename: str) -> None:
        """Load cookies from a file"""
        try:
            with open(filename, 'r') as f:
                cookies = json.load(f)
                for name, value in cookies.items():
                    self.session.cookies.set(name, value)
        except (IOError, json.JSONDecodeError) as e:
            self.logger.error(f"Error loading cookies from {filename}: {str(e)}")
