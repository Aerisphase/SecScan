import aiohttp
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger('HttpClientAdapter')

class AiohttpClientAdapter:
    """Adapter to make aiohttp work with our HttpClient interface"""
    
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session
        
    async def get(self, url: str, params: Optional[Dict] = None, headers: Optional[Dict] = None) -> Dict[str, Any]:
        """Make a GET request"""
        try:
            async with self.session.get(url, params=params, headers=headers) as response:
                return {
                    'status_code': response.status,
                    'headers': dict(response.headers),
                    'text': await response.text(),
                    'url': str(response.url)
                }
        except Exception as e:
            logger.error(f"GET request failed for {url}: {str(e)}")
            return {
                'status_code': 0,
                'headers': {},
                'text': '',
                'url': url
            }
            
    async def post(self, url: str, data: Optional[Dict] = None, headers: Optional[Dict] = None) -> Dict[str, Any]:
        """Make a POST request"""
        try:
            async with self.session.post(url, data=data, headers=headers) as response:
                return {
                    'status_code': response.status,
                    'headers': dict(response.headers),
                    'text': await response.text(),
                    'url': str(response.url)
                }
        except Exception as e:
            logger.error(f"POST request failed for {url}: {str(e)}")
            return {
                'status_code': 0,
                'headers': {},
                'text': '',
                'url': url
            }
            
    async def request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        """Make a custom request"""
        try:
            async with self.session.request(method, url, **kwargs) as response:
                return {
                    'status_code': response.status,
                    'headers': dict(response.headers),
                    'text': await response.text(),
                    'url': str(response.url)
                }
        except Exception as e:
            logger.error(f"{method} request failed for {url}: {str(e)}")
            return {
                'status_code': 0,
                'headers': {},
                'text': '',
                'url': url
            } 