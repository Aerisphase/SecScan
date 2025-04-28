import pytest
from unittest.mock import Mock, patch
from core.crawler import AdvancedCrawler
from bs4 import BeautifulSoup
import requests
from urllib.parse import urljoin

# Test fixtures
@pytest.fixture
def mock_response():
    """Fixture for mocking HTTP responses"""
    def _create_mock(content="", status_code=200, content_type="text/html"):
        mock = Mock()
        mock.status_code = status_code
        mock.text = content
        mock.headers = {'Content-Type': content_type}
        return mock
    return _create_mock

@pytest.fixture
def test_crawler():
    """Fixture for creating a test crawler"""
    return AdvancedCrawler("http://test.com", max_pages=10, delay=0)

# Test data
SIMPLE_HTML = """
<html>
    <body>
        <a href="/page1">Link 1</a>
        <a href="http://external.com">External</a>
        <form action="/submit" method="post">
            <input name="username" type="text">
        </form>
    </body>
</html>
"""

# 1. Initialization tests
def test_crawler_initialization(test_crawler):
    assert test_crawler.base_url == "http://test.com"
    assert test_crawler.max_pages == 10
    assert test_crawler.delay == 0
    assert len(test_crawler.visited_urls) == 0
    assert "Mozilla/5.0" in test_crawler.session.headers['User-Agent']

# 2. URL validation tests
@pytest.mark.parametrize("url,expected", [
    ("http://test.com/page", True),
    ("https://test.com/page", True),
    ("/relative/page", False),
    ("javascript:alert(1)", False),
    ("mailto:test@test.com", False),
    ("http://external.com/page", False),
])
def test_is_valid_url(test_crawler, url, expected):
    assert test_crawler.is_valid_url(url) == expected

# 3. URL normalization tests
def test_normalize_url(test_crawler):
    test_cases = [
        ("http://test.com/page#anchor", "http://test.com/page"),
        ("http://test.com/page?param=1", "http://test.com/page"),
        ("http://test.com/page/", "http://test.com/page"),
    ]
    
    for url, expected in test_cases:
        assert test_crawler.normalize_url(url) == expected

# 4. Link extraction tests
def test_extract_links(test_crawler):
    html = """
    <html>
        <a href="/page1">Link 1</a>
        <img src="/image.png">
        <script src="/script.js"></script>
    </html>
    """
    links = test_crawler.extract_links(html, "http://test.com")
    
    assert len(links) == 3
    assert "http://test.com/page1" in links
    assert "http://test.com/image.png" in links
    assert "http://test.com/script.js" in links

# 5. Form extraction tests
def test_extract_forms(test_crawler):
    html = """
    <form action="/login" method="post">
        <input type="text" name="username">
        <input type="password" name="password">
    </form>
    """
    forms = test_crawler.extract_forms(html, "http://test.com")
    
    assert len(forms) == 1
    assert forms[0]['action'] == "http://test.com/login"
    assert forms[0]['method'] == "post"
    assert len(forms[0]['inputs']) == 2
    assert forms[0]['inputs'][0]['name'] == "username"

# 6. API endpoints in JavaScript tests
def test_extract_api_endpoints(test_crawler):
    html = """
    <script>
        fetch('/api/data').then(...);
        $.get('/api/users', ...);
    </script>
    """
    links = test_crawler.extract_links(html, "http://test.com")
    
    assert "http://test.com/api/data" in links
    assert "http://test.com/api/users" in links
    assert test_crawler.stats['api_endpoints'] == 2

# 7. Integration test with mocks
@patch('core.crawler.requests.Session.get')
def test_crawl_integration(mock_get, test_crawler):
    # Mock setup
    mock_responses = {
        "http://test.com": mock_response(SIMPLE_HTML),
        "http://test.com/page1": mock_response("<html>Page 1</html>"),
        "http://test.com/submit": mock_response("", 200, "text/html")
    }
    
    def side_effect(url, *args, **kwargs):
        return mock_responses.get(url, mock_response("Not found", 404))
    
    mock_get.side_effect = side_effect
    
    # Start crawler
    results = test_crawler.crawl()
    
    # Assertions
    assert len(results['urls']) == 3  # Home page + page1 + submit
    assert len(results['forms']) == 1
    assert test_crawler.stats['pages_crawled'] == 3
    assert test_crawler.stats['links_found'] >= 2

# 8. Error handling test
@patch('core.crawler.requests.Session.get')
def test_error_handling(mock_get, test_crawler):
    mock_get.side_effect = requests.exceptions.ConnectionError("Failed to connect")
    
    results = test_crawler.crawl()
    
    assert len(results['urls']) == 0
    assert len(test_crawler.visited_urls) == 0

# 9. Statistics collection test
def test_stats_collection(test_crawler, mock_response):
    with patch('core.crawler.requests.Session.get', 
               return_value=mock_response(SIMPLE_HTML)):
        test_crawler.crawl()
        
        assert test_crawler.stats['pages_crawled'] > 0
        assert test_crawler.stats['forms_found'] == 1
        assert test_crawler.stats['api_endpoints'] == 0

# 10. max_pages limit test
@patch('core.crawler.requests.Session.get')
def test_max_pages_limit(mock_get, mock_response):
    crawler = AdvancedCrawler("http://test.com", max_pages=2)
    
    # All pages return links to other pages
    mock_get.return_value = mock_response("""
    <html>
        <a href="/page1">1</a>
        <a href="/page2">2</a>
        <a href="/page3">3</a>
    </html>
    """)
    
    results = crawler.crawl()
    
    assert len(results['urls']) == 2
    assert crawler.stats['pages_crawled'] == 2