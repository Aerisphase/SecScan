import time
import logging
import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Dict, List, Set, Optional, Any, Union
import re
import aiohttp
from datetime import datetime
from asyncio import Semaphore

# For JavaScript rendering
try:
    from playwright.async_api import async_playwright, Page, Browser
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logging.warning("Playwright not available. JavaScript rendering will be disabled.")
    logging.warning("To enable JavaScript rendering, please run: pip install playwright && python -m playwright install chromium")
except Exception as e:
    PLAYWRIGHT_AVAILABLE = False
    logging.error(f"Error loading Playwright: {str(e)}")
    logging.warning("To enable JavaScript rendering, please run: pip install playwright && python -m playwright install chromium")

# Set up logging system
logger = logging.getLogger('JSCrawler')

class JSCrawler:
    """
    Enhanced crawler with JavaScript rendering support using Playwright.
    Handles JavaScript-heavy websites, AJAX forms, and dynamic content.
    """
    def __init__(self, base_url: str, config: Optional[Dict] = None):
        self.base_url = base_url
        self.config = config or {}
        
        # Configuration with defaults
        self.max_pages = int(self.config.get('max_pages', 20))
        self.delay = float(self.config.get('delay', 1.0))
        self.user_agent = self.config.get('user_agent', "SecScan/1.0")
        self.verify_ssl = bool(self.config.get('verify_ssl', True))
        self.proxy = self.config.get('proxy')
        self.auth = self.config.get('auth')
        self.max_retries = int(self.config.get('max_retries', 3))
        self.js_enabled = bool(self.config.get('js_enabled', True)) and PLAYWRIGHT_AVAILABLE
        self.browser_timeout = int(self.config.get('browser_timeout', 30000))
        self.wait_for_idle = bool(self.config.get('wait_for_idle', True))
        self.idle_timeout = int(self.config.get('idle_timeout', 5000))
        
        # State variables
        self.visited_urls = set()
        self.pages = []
        self.session = None
        self.connector = None
        self.semaphore = Semaphore(10)  # Limit concurrent requests
        self.queue = asyncio.Queue()  # Queue for URLs to process
        
        # Playwright objects
        self.playwright = None
        self.browser = None
        
    async def __aenter__(self):
        # Create a TCP connector with connection pooling
        self.connector = aiohttp.TCPConnector(
            limit=20,  # Increased concurrent connections
            ttl_dns_cache=300,
            force_close=False,
            ssl=self.verify_ssl
        )
        
        # Set up headers
        headers = {'User-Agent': self.user_agent}
        
        # Set up authentication if provided
        auth = None
        if self.auth:
            if ':' in self.auth:
                username, password = self.auth.split(':', 1)
                auth = aiohttp.BasicAuth(username, password)
        
        # Create session
        self.session = aiohttp.ClientSession(
            headers=headers,
            connector=self.connector,
            timeout=aiohttp.ClientTimeout(total=30),
            auth=auth
        )
        
        # Initialize Playwright if JavaScript is enabled
        if self.js_enabled:
            if not PLAYWRIGHT_AVAILABLE:
                logger.error("JavaScript rendering requested but Playwright is not available")
                logger.warning("To enable JavaScript rendering, install Playwright and browser binaries:")
                logger.warning("1. pip install playwright")
                logger.warning("2. python -m playwright install chromium")
                self.js_enabled = False
            else:
                try:
                    logger.info("Initializing Playwright for JavaScript rendering...")
                    self.playwright = await async_playwright().start()
                    browser_args = []
                    
                    # Add proxy if configured
                    if self.proxy:
                        browser_args.append(f'--proxy-server={self.proxy}')
                    
                    # Add additional browser arguments for stability
                    browser_args.extend([
                        '--disable-dev-shm-usage',
                        '--no-sandbox',
                        '--disable-setuid-sandbox',
                        '--disable-gpu',
                        '--disable-web-security',
                        '--disable-features=IsolateOrigins,site-per-process'
                    ])
                    
                    self.browser = await self.playwright.chromium.launch(
                        headless=True,
                        args=browser_args
                    )
                    logger.info("Playwright browser initialized successfully for JavaScript rendering")
                except Exception as e:
                    logger.error(f"Failed to initialize Playwright: {str(e)}")
                    logger.warning("JavaScript rendering will be disabled due to browser initialization failure")
                    logger.warning("If this problem persists, try reinstalling Playwright: python -m playwright install --force chromium")
                    self.js_enabled = False
        
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
        if self.connector:
            await self.connector.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
            
    async def crawl(self) -> Dict:
        """Crawl the website and return discovered pages and security information"""
        try:
            if not self.session:
                await self.__aenter__()
                
            start_time = time.time()
            
            # Start with the base URL
            await self.queue.put(self.base_url)
            
            # Create worker tasks
            workers = [
                asyncio.create_task(self._worker())
                for _ in range(min(10, self.max_pages))  # Number of concurrent workers
            ]
            
            # Wait for all workers to complete
            await self.queue.join()
            for worker in workers:
                worker.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            
            # Collect security headers from the base URL
            security_headers = await self._get_security_headers(self.base_url)
            
            logger.info(f"Crawling completed in {time.time() - start_time:.2f} seconds")
            logger.info(f"Found {len(self.pages)} pages")
            
            # Prepare and return crawl results
            return {
                'pages': self.pages,
                'pages_crawled': len(self.pages),
                'links_found': sum(len(page.get('links', [])) for page in self.pages),
                'forms_found': sum(len(page.get('forms', [])) for page in self.pages),
                'security_headers': security_headers,
                'js_enabled': self.js_enabled
            }
            
        except Exception as e:
            logger.error(f"Crawling error: {str(e)}")
            raise
        finally:
            await self.__aexit__(None, None, None)
                
    async def _worker(self):
        """Worker task for concurrent crawling"""
        while True:
            try:
                url = await self.queue.get()
                await self._crawl_page(url)
                self.queue.task_done()
                # Respect the delay between requests
                await asyncio.sleep(self.delay)
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
                # Determine if we should use Playwright for this page
                if self.js_enabled:
                    page_data = await self._crawl_with_js(url)
                else:
                    page_data = await self._crawl_without_js(url)
                
                if page_data:
                    self.pages.append(page_data)
                    logger.info(f"Processed page {url} ({len(self.visited_urls)}/{self.max_pages})")
                    
                    # Add discovered links to queue
                    for link in page_data.get('links', []):
                        if len(self.visited_urls) < self.max_pages and link not in self.visited_urls:
                            await self.queue.put(link)
                            
            except Exception as e:
                logger.error(f"Error crawling {url}: {str(e)}")
                
    async def _crawl_with_js(self, url: str) -> Optional[Dict]:
        """Crawl a page with JavaScript rendering using Playwright"""
        try:
            page = await self.browser.new_page()
            
            # Set user agent
            await page.set_extra_http_headers({'User-Agent': self.user_agent})
            
            # Set authentication if needed
            if self.auth and ':' in self.auth:
                username, password = self.auth.split(':', 1)
                await page.authenticate({'username': username, 'password': password})
            
            # Navigate to the page with timeout
            response = await page.goto(url, timeout=self.browser_timeout, wait_until='networkidle' if self.wait_for_idle else 'load')
            
            if not response:
                logger.error(f"Failed to load {url} with Playwright")
                await page.close()
                return None
                
            if response.status >= 400:
                logger.warning(f"Received status code {response.status} for {url}")
                
            # Wait for page to be fully loaded
            if self.wait_for_idle:
                try:
                    await page.wait_for_load_state('networkidle', timeout=self.idle_timeout)
                except Exception as e:
                    logger.warning(f"Timeout waiting for networkidle on {url}: {str(e)}")
            
            # Extract page content
            content = await page.content()
            
            # Extract page title
            title = await page.title()
            
            # Extract forms using JavaScript
            forms = await self._extract_forms_with_js(page)
            
            # Extract links using JavaScript
            links = await self._extract_links_with_js(page, url)
            
            # Take a screenshot for debugging (optional)
            # await page.screenshot(path=f"screenshot_{urlparse(url).netloc.replace('.', '_')}.png")
            
            # Close the page
            await page.close()
            
            return {
                'url': url,
                'title': title,
                'forms': forms,
                'links': links,
                'content': content,
                'js_rendered': True
            }
            
        except Exception as e:
            logger.error(f"Error in JavaScript crawling for {url}: {str(e)}")
            return None
            
    async def _crawl_without_js(self, url: str) -> Optional[Dict]:
        """Crawl a page without JavaScript rendering using aiohttp"""
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    # Extract page data
                    return {
                        'url': url,
                        'title': soup.title.string if soup.title else '',
                        'forms': self._extract_forms(soup),
                        'links': self._extract_links(soup, url),
                        'content': content,
                        'js_rendered': False
                    }
                else:
                    logger.warning(f"Received status code {response.status} for {url}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error in HTTP crawling for {url}: {str(e)}")
            return None
            
    async def _extract_forms_with_js(self, page: 'Page') -> List[Dict]:
        """Extract form data from the page using JavaScript"""
        try:
            # Execute JavaScript to extract all forms including those created by JS
            forms_data = await page.evaluate("""() => {
                const forms = Array.from(document.querySelectorAll('form'));
                return forms.map(form => {
                    // Get form action - try to handle dynamic actions
                    let action = form.getAttribute('action') || '';
                    if (!action && form.action) {
                        action = form.action;
                    }
                    
                    // Get form method
                    let method = form.getAttribute('method') || 'get';
                    
                    // Extract all inputs
                    const inputs = Array.from(form.querySelectorAll('input, select, textarea, button'))
                        .filter(el => el.name || el.id)
                        .map(el => {
                            return {
                                name: el.name || el.id || '',
                                type: el.type || el.tagName.toLowerCase(),
                                value: el.value || '',
                                required: el.required || false,
                                id: el.id || '',
                                events: getElementEvents(el)
                            };
                        });
                    
                    // Look for event handlers on the form
                    const formEvents = getElementEvents(form);
                    
                    // Check for submit button with click handlers
                    const submitButton = form.querySelector('button[type="submit"], input[type="submit"]');
                    const submitEvents = submitButton ? getElementEvents(submitButton) : [];
                    
                    return {
                        action: action,
                        method: method.toUpperCase(),
                        inputs: inputs,
                        has_submit_handler: formEvents.includes('submit') || 
                                           (submitButton && submitEvents.includes('click')),
                        form_id: form.id || '',
                        form_class: form.className || ''
                    };
                });
                
                // Helper function to get all events attached to an element
                function getElementEvents(element) {
                    const events = [];
                    const possibleEvents = ['submit', 'click', 'change', 'input'];
                    
                    // Check for attributes like onclick, onsubmit
                    for (const event of possibleEvents) {
                        const attr = element.getAttribute('on' + event);
                        if (attr) {
                            events.push(event);
                        }
                    }
                    
                    // Look for elements with event listeners (limited detection)
                    // Note: We can't reliably detect all event listeners in JS
                    if (element.tagName === 'BUTTON' || 
                        (element.tagName === 'INPUT' && element.type === 'submit')) {
                        events.push('click');
                    }
                    
                    return events;
                }
            }""")
            
            # Process form data
            processed_forms = []
            for form in forms_data:
                # Try to determine the full action URL
                action = form.get('action', '')
                if action and not (action.startswith('http://') or action.startswith('https://')):
                    action = urljoin(page.url, action)
                
                processed_form = {
                    'action': action,
                    'method': form.get('method', 'GET'),
                    'inputs': form.get('inputs', []),
                    'has_submit_handler': form.get('has_submit_handler', False),
                    'form_id': form.get('form_id', ''),
                    'form_class': form.get('form_class', '')
                }
                
                # If no action but has submit handler, it's likely using AJAX
                if not action and form.get('has_submit_handler', False):
                    processed_form['is_ajax'] = True
                    processed_form['action'] = page.url  # Use current URL as fallback
                
                processed_forms.append(processed_form)
            
            return processed_forms
            
        except Exception as e:
            logger.error(f"Error extracting forms with JavaScript: {str(e)}")
            return []
            
    async def _extract_links_with_js(self, page: 'Page', base_url: str) -> List[str]:
        """Extract and normalize links from the page using JavaScript"""
        try:
            # Execute JavaScript to extract all links including those created by JS
            links_data = await page.evaluate("""(baseUrl) => {
                // Get all anchor elements
                const anchors = Array.from(document.querySelectorAll('a[href]'));
                
                // Extract href attributes
                const links = anchors.map(a => a.href);
                
                // Get base domain for filtering
                const baseUrlObj = new URL(baseUrl);
                const baseDomain = baseUrlObj.hostname;
                
                // Filter links to same domain and normalize
                return links.filter(link => {
                    try {
                        const url = new URL(link);
                        return url.hostname === baseDomain;
                    } catch {
                        return false;
                    }
                });
            }""", base_url)
            
            # Return unique links
            return list(set(links_data))
            
        except Exception as e:
            logger.error(f"Error extracting links with JavaScript: {str(e)}")
            return []
            
    def _extract_forms(self, soup: BeautifulSoup) -> List[Dict]:
        """Extract form data from the page using BeautifulSoup (fallback method)"""
        forms = []
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').upper(),
                'inputs': [],
                'has_submit_handler': bool(form.get('onsubmit')),
                'form_id': form.get('id', ''),
                'form_class': form.get('class', '')
            }
            
            # Extract all input elements
            for input_tag in form.find_all(['input', 'select', 'textarea', 'button']):
                if input_tag.get('name') or input_tag.get('id'):
                    form_data['inputs'].append({
                        'name': input_tag.get('name', input_tag.get('id', '')),
                        'type': input_tag.get('type', input_tag.name),
                        'value': input_tag.get('value', ''),
                        'required': input_tag.has_attr('required'),
                        'id': input_tag.get('id', ''),
                        'events': self._get_element_events(input_tag)
                    })
            
            # Check for submit button with click handler
            submit_button = form.find(['button[type="submit"]', 'input[type="submit"]'])
            if submit_button and submit_button.get('onclick'):
                form_data['has_submit_handler'] = True
                
            forms.append(form_data)
            
        return forms
        
    def _get_element_events(self, element) -> List[str]:
        """Extract event handlers from an element"""
        events = []
        possible_events = ['submit', 'click', 'change', 'input']
        
        for event in possible_events:
            if element.get(f'on{event}'):
                events.append(event)
                
        return events
        
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract and normalize links from the page using BeautifulSoup (fallback method)"""
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
        
    async def _get_security_headers(self, url: str) -> Dict[str, str]:
        """Get security headers from the target URL"""
        try:
            async with self.session.get(url) as response:
                return {k.lower(): v for k, v in response.headers.items()}
        except Exception as e:
            logger.error(f"Error getting security headers: {str(e)}")
            return {}
            
    async def analyze_form(self, form_data: Dict) -> Dict:
        """Analyze a form to determine its submission method and potential vulnerabilities"""
        result = {
            'submission_type': 'unknown',
            'potential_issues': []
        }
        
        # Check if form has an action
        if not form_data.get('action'):
            if form_data.get('has_submit_handler', False):
                result['submission_type'] = 'javascript'
                result['potential_issues'].append('Form uses JavaScript for submission')
            else:
                result['submission_type'] = 'none'
                result['potential_issues'].append('Form has no submission method')
        else:
            result['submission_type'] = form_data.get('method', 'GET').upper()
        
        # Check for sensitive input types
        for input_field in form_data.get('inputs', []):
            if input_field.get('type') in ['password', 'file', 'hidden']:
                if form_data.get('method', '').upper() != 'POST':
                    result['potential_issues'].append(f"Sensitive input type '{input_field.get('type')}' used with non-POST method")
            
        return result
