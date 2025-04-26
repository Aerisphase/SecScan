import time
import logging
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Optional, Dict, Any

class HttpClient:
    def __init__(self, 
                 verify_ssl: bool = True,
                 timeout: int = 5,
                 max_retries: int = 2,
                 rate_limit: float = 0.5,
                 proxy: Optional[str] = None,
                 auth: Optional[Dict[str, str]] = None):
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.max_retries = max_retries
        self.rate_limit = rate_limit
        self.proxy = proxy
        self.auth = auth
        self.last_request_time = 0
        self.logger = logging.getLogger('HttpClient')
        
        # Configure session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set default headers
        self.session.headers.update({
            'User-Agent': 'SecScan/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })

    def _rate_limit(self):
        """Implement rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.rate_limit:
            time.sleep(self.rate_limit - time_since_last)
        self.last_request_time = time.time()

    def _make_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Make an HTTP request with error handling"""
        try:
            self._rate_limit()
            
            # Set default parameters
            kwargs.setdefault('timeout', self.timeout)
            kwargs.setdefault('verify', self.verify_ssl)
            if self.proxy:
                kwargs.setdefault('proxies', {'http': self.proxy, 'https': self.proxy})
            if self.auth:
                kwargs.setdefault('auth', (self.auth.get('username'), self.auth.get('password')))
            
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed for {url}: {str(e)}")
            return None

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make a GET request"""
        return self._make_request('GET', url, **kwargs)

    def post(self, url: str, data: Optional[Dict[str, Any]] = None, **kwargs) -> Optional[requests.Response]:
        """Make a POST request"""
        return self._make_request('POST', url, data=data, **kwargs)