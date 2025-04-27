import time
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Dict, List, Set, Optional
from .http_client import HttpClient
import re
import aiohttp
import asyncio
from datetime import datetime
from asyncio import Semaphore

# Настройка системы логирования
logger = logging.getLogger('Crawler')

class AdvancedCrawler:
    def __init__(self, base_url: str, max_pages: int = 20, delay: float = 0.1, user_agent: Optional[str] = None):
        self.base_url = base_url
        self.max_pages = max_pages
        self.delay = delay
        self.user_agent = user_agent or "SecScan/1.0"
        self.visited_urls = set()
        self.pages = []
        self.session = None
        self.connector = None
        self.semaphore = Semaphore(10)  # Limit concurrent requests
        self.queue = asyncio.Queue()  # Queue for URLs to process
        
    async def __aenter__(self):
        # Create a TCP connector with connection pooling
        self.connector = aiohttp.TCPConnector(
            limit=20,  # Increased concurrent connections
            ttl_dns_cache=300,
            force_close=False,
            ssl=False  # Disable SSL verification for speed
        )
        self.session = aiohttp.ClientSession(
            headers={'User-Agent': self.user_agent},
            connector=self.connector,
            timeout=aiohttp.ClientTimeout(total=30)  # Set timeout
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
        if self.connector:
            await self.connector.close()
            
    async def crawl(self) -> List[Dict]:
        """Crawl the website and return discovered pages"""
        try:
            if not self.session:
                self.connector = aiohttp.TCPConnector(
                    limit=20,
                    ttl_dns_cache=300,
                    force_close=False,
                    ssl=False
                )
                self.session = aiohttp.ClientSession(
                    headers={'User-Agent': self.user_agent},
                    connector=self.connector,
                    timeout=aiohttp.ClientTimeout(total=30)
                )
                
            start_time = time.time()
            
            # Start with the base URL
            await self.queue.put(self.base_url)
            
            # Create worker tasks
            workers = [
                asyncio.create_task(self._worker())
                for _ in range(10)  # Number of concurrent workers
            ]
            
            # Wait for all workers to complete
            await self.queue.join()
            for worker in workers:
                worker.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            
            logger.info(f"Crawling completed in {time.time() - start_time:.2f} seconds")
            logger.info(f"Found {len(self.pages)} pages")
            
            return self.pages
            
        except Exception as e:
            logger.error(f"Crawling error: {str(e)}")
            raise
        finally:
            if self.session:
                await self.session.close()
            if self.connector:
                await self.connector.close()
                
    async def _worker(self):
        """Worker task for concurrent crawling"""
        while True:
            try:
                url = await self.queue.get()
                await self._crawl_page(url)
                self.queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Worker error: {str(e)}")
                self.queue.task_done()
            
    async def _crawl_page(self, url: str):
        """Crawl a single page and its links"""
        if len(self.visited_urls) >= self.max_pages:
            return
            
        if url in self.visited_urls:
            return
            
        async with self.semaphore:  # Limit concurrent requests
            self.visited_urls.add(url)
            
            try:
                async with self.session.get(url) as response:
                    if response.status == 200:
                        content = await response.text()
                        soup = BeautifulSoup(content, 'html.parser')
                        
                        # Extract page data
                        page_data = {
                            'url': url,
                            'title': soup.title.string if soup.title else '',
                            'forms': self._extract_forms(soup),
                            'links': self._extract_links(soup, url),
                            'content': content
                        }
                        
                        self.pages.append(page_data)
                        logger.info(f"Processed page {url} ({len(self.visited_urls)}/{self.max_pages})")
                        
                        # Add discovered links to queue
                        for link in page_data['links']:
                            if len(self.visited_urls) < self.max_pages and link not in self.visited_urls:
                                await self.queue.put(link)
                                
            except Exception as e:
                logger.error(f"Error crawling {url}: {str(e)}")
                
    def _extract_forms(self, soup: BeautifulSoup) -> List[Dict]:
        """Extract form data from the page"""
        forms = []
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }
            
            for input_tag in form.find_all('input'):
                form_data['inputs'].append({
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                })
                
            forms.append(form_data)
        return forms
        
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract and normalize links from the page"""
        links = set()
        base_domain = urlparse(base_url).netloc
        
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            if href.startswith(('http://', 'https://')):
                if urlparse(href).netloc == base_domain:
                    links.add(href)
            else:
                absolute_url = urljoin(base_url, href)
                if urlparse(absolute_url).netloc == base_domain:
                    links.add(absolute_url)
                    
        return list(links)

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
    crawler = AdvancedCrawler(target_url, **validated_config)
    crawl_data = crawler.crawl()