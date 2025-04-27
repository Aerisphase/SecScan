import aiohttp
from typing import Optional, Dict, Any
import logging
import asyncio

logger = logging.getLogger('HttpClientAdapter')

class AiohttpClientAdapter:
    """Adapter to make aiohttp work with our HttpClient interface"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.session = None
        self.timeout = aiohttp.ClientTimeout(total=config.get('timeout', 30))
        self.headers = {'User-Agent': config.get('user_agent', 'SecScan/1.0')}
        self.verify_ssl = config.get('verify_ssl', True)
        self.max_retries = config.get('max_retries', 3)
        self.retry_delay = config.get('retry_delay', 1.0)
        
    async def __aenter__(self):
        """Create a new session when entering async context"""
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=self.timeout,
                headers=self.headers,
                connector=aiohttp.TCPConnector(ssl=self.verify_ssl)
            )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Close the session when exiting async context"""
        if self.session:
            await self.session.close()
            self.session = None
            
    async def _make_request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        """Internal method to make HTTP requests with retry logic"""
        for attempt in range(self.max_retries):
            try:
                if not self.session:
                    await self.__aenter__()
                    
                # Handle request-specific timeout
                if 'timeout' in kwargs:
                    timeout = aiohttp.ClientTimeout(total=kwargs.pop('timeout'))
                else:
                    timeout = self.timeout
                    
                # Merge headers
                request_headers = self.headers.copy()
                if 'headers' in kwargs:
                    request_headers.update(kwargs.pop('headers'))
                    
                async with self.session.request(
                    method,
                    url,
                    headers=request_headers,
                    ssl=self.verify_ssl,
                    timeout=timeout,
                    **kwargs
                ) as response:
                    return {
                        'status_code': response.status,
                        'headers': dict(response.headers),
                        'text': await response.text(),
                        'url': str(response.url)
                    }
                    
            except Exception as e:
                if attempt == self.max_retries - 1:
                    logger.error(f"{method} request failed for {url}: {str(e)}")
                    return {
                        'status_code': 0,
                        'headers': {},
                        'text': '',
                        'url': url
                    }
                await asyncio.sleep(self.retry_delay)
                
    async def get(self, url: str, params: Optional[Dict] = None, headers: Optional[Dict] = None, **kwargs) -> Dict[str, Any]:
        """Make a GET request"""
        return await self._make_request('GET', url, params=params, headers=headers, **kwargs)
            
    async def post(self, url: str, data: Optional[Dict] = None, headers: Optional[Dict] = None, **kwargs) -> Dict[str, Any]:
        """Make a POST request"""
        return await self._make_request('POST', url, data=data, headers=headers, **kwargs)
            
    async def request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        """Make a custom request"""
        return await self._make_request(method, url, **kwargs) 