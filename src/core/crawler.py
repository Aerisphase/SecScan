import re
import time
import asyncio
import logging
import aiohttp
from bs4 import BeautifulSoup
from typing import Dict, List, Optional, Set, Union
from urllib.parse import urljoin, urlparse, parse_qs
from .http_client import HttpClient
from datetime import datetime
from asyncio import Semaphore

# Set up logging system
logger = logging.getLogger('Crawler')

class AdvancedCrawler:
    """Advanced web crawler with JavaScript rendering support"""
    
    def __init__(self, base_url: str, max_pages: int = 20, delay: float = 0.1, user_agent: Optional[str] = None, log_manager=None):
        self.base_url = base_url
        self.max_pages = max_pages
        self.delay = delay
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        self.visited_urls = set()
        self.pages = []
        self.session = None
        self.connector = None
        self.semaphore = Semaphore(10)  # Limit concurrent requests
        self.queue = asyncio.Queue()  # Queue for URLs to process
        self.log_manager = log_manager  # WebSocket log manager for real-time updates
        
        # Normalize the base URL to ensure it ends with a slash if it's a domain root
        parsed = urlparse(self.base_url)
        if not parsed.path or parsed.path == '/':
            self.base_url = f"{parsed.scheme}://{parsed.netloc}/"
        
    async def __aenter__(self):
        # Create a TCP connector with connection pooling
        self.connector = aiohttp.TCPConnector(
            limit=20,  # Increased concurrent connections
            ttl_dns_cache=300,
            force_close=False,
            ssl=False  # Disable SSL verification for speed
        )
        self.session = aiohttp.ClientSession(
            headers={
                'User-Agent': self.user_agent,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            },
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
            
        # Use consistent retry settings for all sites
        max_retries = 3
        retry_delay = self.delay
        
        async with self.semaphore:  # Limit concurrent requests
            self.visited_urls.add(url)
            
            success = False
            for attempt in range(max_retries):
                try:
                    # Use standard browser-like headers for all sites
                    headers = {
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.5',
                        'Connection': 'keep-alive',
                        'Upgrade-Insecure-Requests': '1',
                        'Cache-Control': 'max-age=0'
                    }
                    
                    async with self.session.get(url, headers=headers if headers else None, timeout=aiohttp.ClientTimeout(total=30)) as response:
                        if response.status == 200:
                            # Check content type to avoid processing binary files
                            content_type = response.headers.get('Content-Type', '').lower()
                            
                            # Skip binary files like images, videos, etc.
                            if any(binary_type in content_type for binary_type in ['image/', 'video/', 'audio/', 'application/octet-stream', 'application/pdf', 'application/zip', 'application/x-zip']) or url.lower().endswith(('.zip', '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.mp3', '.mp4')):
                                logger.info(f"Skipping binary file: {url} (Content-Type: {content_type})")
                                success = True
                                break
                                
                            try:
                                                # First check content-type header for obvious binary files
                                content_type = response.headers.get('Content-Type', '').lower()
                                
                                # Try to get text content directly
                                try:
                                    content = await response.text()
                                    
                                    # Skip empty or very short content
                                    if not content or len(content.strip()) < 10:
                                        logger.info(f"Empty or very short content from {url}")
                                        success = True
                                        break
                                    
                                    # Additional check: if content is short and contains mostly non-text chars,
                                    # it might be binary despite successful decoding
                                    if len(content) < 100 and sum(c.isalnum() or c.isspace() for c in content) / len(content) < 0.3:
                                        logger.info(f"Content appears to be binary despite successful decoding: {url}")
                                        success = True
                                        break
                                        
                                except UnicodeDecodeError as e:
                                    # It's binary data
                                    logger.info(f"Cannot decode content from {url}: {str(e)}")
                                    success = True
                                    break
                                    
                                soup = BeautifulSoup(content, 'html.parser')
                                
                                # Extract page data
                                forms = self._extract_forms(soup)
                                links = self._extract_links(soup, url)
                                
                                # Extract URL parameters for testing
                                url_params = []
                                parsed_url = urlparse(url)
                                if parsed_url.query:
                                    query_params = parse_qs(parsed_url.query)
                                    for param, values in query_params.items():
                                        url_params.append({
                                            'name': param,
                                            'value': values[0] if values else ''
                                        })
                                
                                # Look for potential injection points in the HTML
                                potential_injection_points = []
                                
                                # Check for reflected parameters
                                for param in url_params:
                                    param_name = param['name']
                                    param_value = param['value']
                                    if param_value and param_value in content:
                                        potential_injection_points.append({
                                            'type': 'reflected_parameter',
                                            'name': param_name,
                                            'value': param_value
                                        })
                                
                                # Check for input fields that might be vulnerable
                                for input_tag in soup.find_all('input'):
                                    input_type = input_tag.get('type', '').lower()
                                    input_name = input_tag.get('name', '')
                                    if input_type in ['text', 'search', 'hidden'] and input_name:
                                        potential_injection_points.append({
                                            'type': 'input_field',
                                            'name': input_name,
                                            'element': str(input_tag)
                                        })
                                
                                # Look for JavaScript event handlers
                                for tag in soup.find_all(lambda tag: any(attr.startswith('on') for attr in tag.attrs)):
                                    for attr, value in tag.attrs.items():
                                        if attr.startswith('on'):
                                            potential_injection_points.append({
                                                'type': 'event_handler',
                                                'event': attr,
                                                'value': value,
                                                'element': str(tag)
                                            })
                                
                                # Look for inline JavaScript
                                for script in soup.find_all('script'):
                                    if script.string and len(script.string.strip()) > 0:
                                        potential_injection_points.append({
                                            'type': 'inline_script',
                                            'content': script.string[:100] + '...' if len(script.string) > 100 else script.string
                                        })
                                
                                # Create enhanced page data
                                page_data = {
                                    'url': url,
                                    'title': soup.title.string if soup.title else '',
                                    'forms': forms,
                                    'links': links,
                                    'url_params': url_params,
                                    'potential_injection_points': potential_injection_points,
                                    'content': content
                                }
                                
                                self.pages.append(page_data)
                                progress_message = f"Processed page {url} ({len(self.visited_urls)}/{self.max_pages})"
                                logger.info(progress_message)
                
                                # Broadcast progress to WebSocket if log_manager is available
                                if self.log_manager:
                                    try:
                                        await self.log_manager.broadcast(f"[CRAWLER] {progress_message}")
                                    except Exception as e:
                                        logger.error(f"Failed to broadcast crawler progress: {str(e)}")
                                
                                # Add discovered links to queue
                                for link in page_data['links']:
                                    if len(self.visited_urls) < self.max_pages and link not in self.visited_urls:
                                        await self.queue.put(link)
                                
                                # Success, no need to retry
                                success = True
                                break
                                
                            except UnicodeDecodeError as e:
                                logger.info(f"Cannot decode content from {url}: {str(e)}")
                                # Mark as visited but don't process further
                                success = True
                                break
                        elif response.status == 429:  # Too Many Requests
                            logger.warning(f"Rate limited on {url}, attempt {attempt+1}/{max_retries}")
                            if attempt < max_retries - 1:
                                await asyncio.sleep(retry_delay * (attempt + 1))  # Exponential backoff
                        elif response.status == 404:  # Not Found
                            # Handle 404 errors gracefully - mark as visited but don't retry
                            logger.info(f"Resource not found (404): {url}")
                            success = True
                            break
                        else:
                            logger.warning(f"Received status {response.status} for {url}, attempt {attempt+1}/{max_retries}")
                            if attempt < max_retries - 1:
                                await asyncio.sleep(retry_delay)
                except aiohttp.ClientConnectorError as e:
                    logger.error(f"Connection error while crawling {url}: {str(e)}")
                    if attempt < max_retries - 1:
                        logger.info(f"Retrying {url}, attempt {attempt+1}/{max_retries}")
                        await asyncio.sleep(retry_delay * (attempt + 1))
                    else:
                        break
                except aiohttp.ClientError as e:
                    logger.error(f"Client error while crawling {url}: {str(e)}")
                    if attempt < max_retries - 1:
                        logger.info(f"Retrying {url}, attempt {attempt+1}/{max_retries}")
                        await asyncio.sleep(retry_delay * (attempt + 1))
                    else:
                        break
                except asyncio.TimeoutError:
                    logger.error(f"Timeout while crawling {url}")
                    if attempt < max_retries - 1:
                        logger.info(f"Retrying {url} after timeout, attempt {attempt+1}/{max_retries}")
                        await asyncio.sleep(retry_delay * (attempt + 1))
                    else:
                        break
                except ConnectionResetError as e:
                    logger.error(f"Connection reset while crawling {url}: {str(e)}")
                    if attempt < max_retries - 1:
                        logger.info(f"Retrying {url} after connection reset, attempt {attempt+1}/{max_retries}")
                        await asyncio.sleep(retry_delay * (attempt + 2))  # Longer delay for connection resets
                    else:
                        break
                except OSError as e:
                    # Handle "The specified network name is no longer available" and similar OS-level errors
                    logger.error(f"OS error while crawling {url}: {str(e)}")
                    if attempt < max_retries - 1:
                        logger.info(f"Retrying {url} after OS error, attempt {attempt+1}/{max_retries}")
                        await asyncio.sleep(retry_delay * (attempt + 2))  # Longer delay for OS errors
                    else:
                        break
                except Exception as e:
                    logger.error(f"Error crawling {url}: {str(e)}")
                    break
                    
            # Add a delay after processing this URL regardless of success
            await asyncio.sleep(self.delay)
                
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
            
            # Skip empty hrefs, javascript: links, and anchors
            if not href or href.startswith(('javascript:', '#')) or href == '/':
                continue
                
            # Handle absolute URLs
            if href.startswith(('http://', 'https://')):
                if urlparse(href).netloc == base_domain:
                    links.add(href)
            # Handle relative URLs
            else:
                # Special case for Google Gruyere which uses fragment identifiers as paths
                if href.startswith('/#'):
                    # Convert fragment identifier to a real path
                    clean_href = href.replace('/#', '/')
                    absolute_url = urljoin(base_url, clean_href)
                    links.add(absolute_url)
                else:
                    absolute_url = urljoin(base_url, href)
                    if urlparse(absolute_url).netloc == base_domain:
                        links.add(absolute_url)
                    
        return list(links)

def scan_website(target_url: str, config: Dict) -> Optional[Dict]:
    """Scan website for vulnerabilities"""
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