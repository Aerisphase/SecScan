import time
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Dict, List, Set, Optional, Any
from .http_client import HttpClient
import re
import aiohttp
import asyncio
from datetime import datetime
from asyncio import Semaphore
from .http_client_adapter import AiohttpClientAdapter

# Настройка системы логирования
logger = logging.getLogger('Crawler')

class AdvancedCrawler:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.client = AiohttpClientAdapter(config)
        self.visited_urls = set()
        self.pages = []
        
    async def crawl(self, start_url: str) -> List[Dict[str, Any]]:
        """Crawl the website starting from the given URL"""
        try:
            await self._crawl_url(start_url)
            return self.pages
        except Exception as e:
            logger.error(f"Error during crawling: {str(e)}")
            return []
            
    async def _crawl_url(self, url: str) -> None:
        """Crawl a single URL and its links"""
        if len(self.visited_urls) >= self.config.get('max_pages', 20):
            return
            
        if url in self.visited_urls:
            return
            
        self.visited_urls.add(url)
        
        try:
            # Make request
            response = await self.client.get(url)
            if response['status_code'] != 200:
                return
                
            # Parse page
            soup = BeautifulSoup(response['text'], 'html.parser')
            
            # Extract forms
            forms = []
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }
                
                for input_tag in form.find_all('input'):
                    form_data['inputs'].append({
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    })
                    
                forms.append(form_data)
                
            # Store page data
            self.pages.append({
                'url': url,
                'forms': forms,
                'content': response['text']
            })
            
            # Find and crawl links
            tasks = []
            for link in soup.find_all('a'):
                href = link.get('href')
                if not href:
                    continue
                    
                # Convert relative URLs to absolute
                absolute_url = urljoin(url, href)
                
                # Check if URL is within the same domain
                if urlparse(absolute_url).netloc == urlparse(url).netloc:
                    tasks.append(self._crawl_url(absolute_url))
                    
            # Wait for all tasks to complete
            if tasks:
                await asyncio.gather(*tasks)
                
        except Exception as e:
            logger.error(f"Error crawling {url}: {str(e)}")
            
        # Respect delay between requests
        await asyncio.sleep(self.config.get('delay', 1.0))

def scan_website(target_url: str, config: Dict) -> Optional[Dict]:
    """Сканирование веб-сайта на наличие уязвимостей"""
    validated_config = {
        'max_pages': int(config.get('max_pages', 20)),
        'delay': float(config.get('delay', 1.0)),
        'user_agent': str(config.get('user_agent', '')),
        'scan_type': str(config.get('scan_type', 'fast')),
        'verify_ssl': bool(config.get('verify_ssl', True)),
        'proxy': config.get('proxy'),
        'auth': config.get('auth'),
        'max_retries': int(config.get('max_retries', 3))
    }
    crawler = AdvancedCrawler(validated_config)
    crawl_data = crawler.crawl(target_url)