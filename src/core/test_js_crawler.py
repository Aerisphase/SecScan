import asyncio
import logging
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.parent.parent)
sys.path.append(project_root)

from src.core.js_crawler import JSCrawler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('TestJSCrawler')

async def test_js_crawler():
    """Test the JavaScript-enabled crawler on a sample website"""
    # Target URL - use a site known to have JavaScript forms
    target_url = "https://example.com"  # Replace with an actual test site
    
    # Configuration
    config = {
        'max_pages': 5,
        'delay': 1.0,
        'user_agent': 'SecScan/1.0 (Test Script)',
        'js_enabled': True,
        'browser_timeout': 30000,
        'wait_for_idle': True,
        'verify_ssl': True
    }
    
    logger.info(f"Testing JSCrawler on {target_url}")
    
    try:
        # Create and use the crawler
        async with JSCrawler(target_url, config) as crawler:
            results = await crawler.crawl()
            
            # Log results
            logger.info(f"Crawling completed. Found {len(results.get('pages', []))} pages")
            logger.info(f"Links found: {results.get('links_found', 0)}")
            logger.info(f"Forms found: {results.get('forms_found', 0)}")
            
            # Print form details
            for i, page in enumerate(results.get('pages', [])):
                logger.info(f"\nPage {i+1}: {page.get('url')}")
                
                # Print forms on this page
                forms = page.get('forms', [])
                if forms:
                    logger.info(f"Found {len(forms)} forms on this page")
                    for j, form in enumerate(forms):
                        logger.info(f"  Form {j+1}:")
                        logger.info(f"    Action: {form.get('action', 'No action')}")
                        logger.info(f"    Method: {form.get('method', 'GET')}")
                        logger.info(f"    Has submit handler: {form.get('has_submit_handler', False)}")
                        logger.info(f"    Form ID: {form.get('form_id', 'No ID')}")
                        logger.info(f"    Form Class: {form.get('form_class', 'No class')}")
                        logger.info(f"    Inputs: {len(form.get('inputs', []))}")
                else:
                    logger.info("No forms found on this page")
            
            return results
            
    except Exception as e:
        logger.error(f"Error testing JSCrawler: {str(e)}")
        raise

if __name__ == "__main__":
    # Run the test
    asyncio.run(test_js_crawler())
