import pytest
import asyncio
from src.core.scanner import Scanner
from src.core.scanners import (
    XSSScanner,
    SQLInjectionScanner,
    CSRFScanner,
    SSRFScanner,
    XXEScanner,
    IDORScanner,
    BrokenAuthScanner,
    SensitiveDataScanner,
    SecurityMisconfigScanner
)

@pytest.mark.asyncio
async def test_scanner_initialization(test_config):
    """Test that all scanners are properly initialized"""
    scanner = Scanner(test_config)
    
    # Test scanner initialization
    vulnerabilities = await scanner.scan_page("http://test.com")
    
    # Verify that all scanners were initialized
    assert len(scanner.config['scanners']) == 9  # Total number of scanners
    
    # Verify that all enabled scanners were initialized
    enabled_scanners = [name for name, enabled in scanner.config['scanners'].items() if enabled]
    assert len(enabled_scanners) == 9  # All scanners should be enabled in test config

@pytest.mark.asyncio
async def test_individual_scanner_initialization(test_config):
    """Test initialization of each scanner type"""
    # Test each scanner type
    scanner_types = {
        'xss': XSSScanner,
        'sql_injection': SQLInjectionScanner,
        'csrf': CSRFScanner,
        'ssrf': SSRFScanner,
        'xxe': XXEScanner,
        'idor': IDORScanner,
        'broken_auth': BrokenAuthScanner,
        'sensitive_data': SensitiveDataScanner,
        'security_misconfig': SecurityMisconfigScanner
    }
    
    for scanner_name, scanner_class in scanner_types.items():
        # Create a config with only this scanner enabled
        single_scanner_config = test_config.copy()
        single_scanner_config['scanners'] = {name: (name == scanner_name) for name in scanner_types.keys()}
        
        # Initialize scanner
        single_scanner = Scanner(single_scanner_config)
        
        # Test scanning
        try:
            vulnerabilities = await single_scanner.scan_page("http://test.com")
            assert isinstance(vulnerabilities, list), f"{scanner_name} scanner did not return a list of vulnerabilities"
        except Exception as e:
            pytest.fail(f"{scanner_name} scanner failed with error: {str(e)}")

@pytest.mark.asyncio
async def test_scanner_error_handling(test_config):
    """Test error handling during scanner initialization and execution"""
    scanner = Scanner(test_config)
    
    # Test with invalid URL
    try:
        vulnerabilities = await scanner.scan_page("invalid-url")
        assert isinstance(vulnerabilities, list)
    except Exception as e:
        pytest.fail(f"Scanner failed to handle invalid URL: {str(e)}")
    
    # Test with empty URL
    try:
        vulnerabilities = await scanner.scan_page("")
        assert isinstance(vulnerabilities, list)
    except Exception as e:
        pytest.fail(f"Scanner failed to handle empty URL: {str(e)}")

@pytest.mark.asyncio
async def test_scanner_concurrent_execution(test_config):
    """Test that scanners can run concurrently"""
    scanner = Scanner(test_config)
    
    # Test scanning multiple URLs concurrently
    urls = [
        "http://test1.com",
        "http://test2.com",
        "http://test3.com"
    ]
    
    tasks = [scanner.scan_page(url) for url in urls]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Verify all scans completed
    assert len(results) == len(urls)
    for result in results:
        assert isinstance(result, list), "Scanner did not return a list of vulnerabilities"

if __name__ == "__main__":
    pytest.main([__file__]) 