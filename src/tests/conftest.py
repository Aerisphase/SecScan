import os
import sys
import pytest
import asyncio

# Add the project root to the Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, project_root)

# Configure asyncio for testing
@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
def test_config():
    """Fixture to provide test configuration"""
    return {
        'client': {
            'timeout': 30,
            'max_retries': 3,
            'delay': 1.0
        },
        'crawler': {
            'max_pages': 20,
            'delay': 1.0,
            'user_agent': 'SecScan/1.0',
            'verify_ssl': True,
            'max_retries': 3
        },
        'scan_type': 'fast',
        'scanners': {
            'xss': True,
            'sql_injection': True,
            'csrf': True,
            'ssrf': True,
            'xxe': True,
            'idor': True,
            'broken_auth': True,
            'sensitive_data': True,
            'security_misconfig': True
        }
    } 