import sys
import logging
import argparse
from pathlib import Path

# Add project root to the Python path
project_root = str(Path(__file__).parent.parent.parent)
sys.path.append(project_root)

from src.core.enhanced_http_client import EnhancedHttpClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('TestEnhancedClient')

def test_waf_evasion(url):
    """Test WAF evasion techniques"""
    logger.info(f"Testing WAF evasion on {url}")
    
    # Create client with WAF evasion enabled
    client = EnhancedHttpClient(
        verify_ssl=True,
        timeout=10,
        max_retries=3,
        rate_limit_min=1.0,
        rate_limit_max=3.0,
        rotate_user_agent=True,
        rotate_request_pattern=True,
        waf_evasion=True
    )
    
    # First attempt - might trigger WAF
    logger.info("First attempt...")
    response1 = client.get(url)
    
    if response1:
        logger.info(f"First attempt status code: {response1.status_code}")
        if response1.status_code == 403:
            logger.warning("Detected possible WAF block (403 Forbidden)")
    else:
        logger.error("First attempt failed")
    
    # Second attempt with WAF evasion
    logger.info("Second attempt with WAF evasion...")
    response2 = client.get(url)
    
    if response2:
        logger.info(f"Second attempt status code: {response2.status_code}")
        if response2.status_code == 200:
            logger.info("WAF evasion successful!")
    else:
        logger.error("Second attempt failed")
    
    return response1, response2

def test_session_management(url):
    """Test session management and CSRF token handling"""
    logger.info(f"Testing session management on {url}")
    
    # Create client with session management enabled
    client = EnhancedHttpClient(
        verify_ssl=True,
        timeout=10,
        max_retries=3,
        handle_csrf=True,
        maintain_session=True
    )
    
    # First request to get cookies and CSRF token
    logger.info("Making initial request to establish session...")
    response = client.get(url)
    
    if response:
        logger.info(f"Initial request status code: {response.status_code}")
        
        # Display cookies
        cookies = client.get_cookies()
        logger.info(f"Cookies received: {len(cookies)}")
        for name, value in cookies.items():
            logger.info(f"Cookie: {name} = {value[:10]}..." if len(str(value)) > 10 else f"Cookie: {name} = {value}")
        
        # Check for CSRF token
        domain = url.split('//', 1)[1].split('/', 1)[0]
        csrf_token = client.csrf_tokens.get(domain)
        if csrf_token:
            logger.info(f"CSRF token found: {csrf_token[:10]}...")
        else:
            logger.info("No CSRF token found")
        
        # Make a second request with session cookies
        logger.info("Making second request with session cookies...")
        response2 = client.get(url)
        
        if response2:
            logger.info(f"Second request status code: {response2.status_code}")
            logger.info("Session maintained successfully")
    else:
        logger.error("Initial request failed")
    
    return response

def test_form_submission(url, form_data=None):
    """Test form submission with CSRF token handling"""
    logger.info(f"Testing form submission on {url}")
    
    if form_data is None:
        form_data = {
            'username': 'test_user',
            'password': 'test_password'
        }
    
    # Create client with CSRF handling enabled
    client = EnhancedHttpClient(
        verify_ssl=True,
        timeout=10,
        max_retries=3,
        handle_csrf=True,
        maintain_session=True
    )
    
    # First request to get CSRF token
    logger.info("Making initial request to get CSRF token...")
    response = client.get(url)
    
    if response:
        logger.info(f"Initial request status code: {response.status_code}")
        
        # Check for CSRF token
        domain = url.split('//', 1)[1].split('/', 1)[0]
        csrf_token = client.csrf_tokens.get(domain)
        if csrf_token:
            logger.info(f"CSRF token found: {csrf_token[:10]}...")
            
            # Submit form with CSRF token
            logger.info("Submitting form with CSRF token...")
            response2 = client.post(url, data=form_data)
            
            if response2:
                logger.info(f"Form submission status code: {response2.status_code}")
                if response2.status_code in [200, 302]:
                    logger.info("Form submission successful")
                else:
                    logger.warning("Form submission failed")
        else:
            logger.info("No CSRF token found, submitting form without token...")
            response2 = client.post(url, data=form_data)
            
            if response2:
                logger.info(f"Form submission status code: {response2.status_code}")
    else:
        logger.error("Initial request failed")
    
    return response

def main():
    parser = argparse.ArgumentParser(description='Test Enhanced HTTP Client')
    parser.add_argument('--url', required=True, help='URL to test')
    parser.add_argument('--test', choices=['waf', 'session', 'form'], default='waf', help='Test to run')
    args = parser.parse_args()
    
    if args.test == 'waf':
        test_waf_evasion(args.url)
    elif args.test == 'session':
        test_session_management(args.url)
    elif args.test == 'form':
        test_form_submission(args.url)

if __name__ == "__main__":
    main()
