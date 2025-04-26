import requests
import logging
import time
from typing import Optional, Dict, Any
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning
import warnings

# Suppress SSL warnings when verify=False
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

class HttpClient:
    def __init__(
        self,
        verify_ssl: bool = True,
        timeout: int = 10,
        max_retries: int = 3,
        rate_limit: float = 1.0,  # seconds between requests
        proxy: Optional[Dict[str, str]] = None,
        auth: Optional[tuple] = None
    ):
        self.verify = verify_ssl
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.last_request_time = 0
        self.proxy = proxy
        self.auth = auth
        
        # Configure session with retry strategy
        self.session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504]
        )
        
        # Mount the adapter with retry strategy
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set default headers
        self.session.headers.update({
            'User-Agent': 'SecScan/1.0 (+https://github.com/Aerisphase/SecScan)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        })

    def _enforce_rate_limit(self):
        """Enforce rate limiting between requests"""
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        if time_since_last_request < self.rate_limit:
            time.sleep(self.rate_limit - time_since_last_request)
        self.last_request_time = time.time()

    def _make_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Make an HTTP request with rate limiting and error handling"""
        try:
            self._enforce_rate_limit()
            
            # Merge proxy and auth settings with request kwargs
            request_kwargs = {
                'verify': self.verify,
                'timeout': self.timeout,
                'proxies': self.proxy,
                'auth': self.auth,
                **kwargs
            }
            
            response = self.session.request(method, url, **request_kwargs)
            response.raise_for_status()
            return response
            
        except requests.exceptions.Timeout:
            logging.error(f"Timeout occurred for {url}")
        except requests.exceptions.SSLError:
            logging.error(f"SSL error occurred for {url}")
        except requests.exceptions.ConnectionError:
            logging.error(f"Connection error for {url}")
        except requests.exceptions.HTTPError as e:
            logging.error(f"HTTP error occurred for {url}: {e}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed for {url}: {e}")
        return None

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make a GET request"""
        return self._make_request('GET', url, **kwargs)

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make a POST request"""
        return self._make_request('POST', url, **kwargs)