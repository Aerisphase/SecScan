import pytest
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

def test_scanner_config():
    """Test that scanner configuration is properly loaded"""
    config = {
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
    
    scanner = Scanner(config)
    assert scanner.config == config
    assert scanner.client is not None

def test_scanner_types():
    """Test that all scanner types are available"""
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
        assert scanner_class is not None, f"Scanner {scanner_name} is not properly imported"
        scanner_instance = scanner_class()
        assert hasattr(scanner_instance, 'scan'), f"Scanner {scanner_name} does not have a scan method" 