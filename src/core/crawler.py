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
import json

# Настройка системы логирования
logger = logging.getLogger('Crawler')

class AdvancedCrawler:
    def __init__(self, config: Dict[str, Any]):
        """Initialize the crawler with configuration."""
        self.logger = logging.getLogger(__name__)
        self.logger.info("Initializing AdvancedCrawler")
        self.logger.debug(f"Received configuration: {json.dumps(config, indent=2)}")
        
        if not isinstance(config, dict):
            error_msg = "Configuration must be a dictionary"
            self.logger.error(f"{error_msg}. Got: {type(config)}")
            raise ValueError(error_msg)
            
        # Validate configuration structure
        if 'crawler' not in config:
            error_msg = "Configuration must contain 'crawler' section"
            self.logger.error(f"{error_msg}. Got keys: {list(config.keys())}")
            raise ValueError(error_msg)
            
        crawler_config = config['crawler']
        
        # Validate required fields
        required_fields = ['max_pages', 'delay', 'client']
        for field in required_fields:
            if field not in crawler_config:
                error_msg = f"Missing required field in crawler config: {field}"
                self.logger.error(f"{error_msg}. Got fields: {list(crawler_config.keys())}")
                raise ValueError(error_msg)
                
        # Validate max_pages
        if not isinstance(crawler_config['max_pages'], (int, float)) or crawler_config['max_pages'] < 1:
            error_msg = f"max_pages must be a positive number, got: {crawler_config['max_pages']}"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
            
        # Validate delay
        if not isinstance(crawler_config['delay'], (int, float)) or crawler_config['delay'] < 0.1:
            error_msg = f"delay must be at least 0.1 seconds, got: {crawler_config['delay']}"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
            
        # Validate client configuration
        client_config = crawler_config['client']
        if not isinstance(client_config, dict):
            error_msg = "Client configuration must be a dictionary"
            self.logger.error(f"{error_msg}. Got: {type(client_config)}")
            raise ValueError(error_msg)
            
        required_client_fields = ['timeout', 'max_retries', 'delay', 'user_agent', 'verify_ssl']
        for field in required_client_fields:
            if field not in client_config:
                error_msg = f"Client configuration missing required field: {field}"
                self.logger.error(f"{error_msg}. Got fields: {list(client_config.keys())}")
                raise ValueError(error_msg)
            
        # Initialize HTTP client with client config
        self.client = AiohttpClientAdapter(client_config)
        self.max_pages = crawler_config['max_pages']
        self.delay = crawler_config['delay']
        self.visited_urls = set()
        self.pages = []
        self.logger.info("AdvancedCrawler initialized successfully")
            
    async def crawl(self, start_url: str) -> List[Dict[str, Any]]:
        """Crawl the website starting from the given URL"""
        try:
            if not start_url.startswith(('http://', 'https://')):
                raise ValueError("URL must start with http:// or https://")
                
            await self._crawl_url(start_url)
            return self.pages
            
        except ValueError as e:
            logger.error(f"Crawl validation error: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error during crawling: {str(e)}")
            return []
            
    async def _crawl_url(self, url: str) -> None:
        """Crawl a single URL and its links"""
        try:
            if len(self.visited_urls) >= self.max_pages:
                logger.info(f"Reached maximum pages limit ({self.max_pages})")
                return
                
            if url in self.visited_urls:
                return
                
            self.visited_urls.add(url)
            
            # Make request
            response = await self.client.get(url)
            if response['status_code'] != 200:
                logger.warning(f"Failed to fetch {url}: Status {response['status_code']}")
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
        await asyncio.sleep(self.delay)

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