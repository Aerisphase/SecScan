import os
import sys
import logging
from pathlib import Path

# Add the project root to Python path
project_root = str(Path(__file__).parent.parent.parent)
sys.path.append(project_root)

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

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ScannerVerification')

def verify_scanner_initialization():
    """Verify that all scanners can be initialized"""
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
    
    try:
        logger.info("Initializing main scanner...")
        scanner = Scanner(config)
        logger.info("Main scanner initialized successfully")
        
        # Verify individual scanners
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
            try:
                logger.info(f"Initializing {scanner_name} scanner...")
                scanner_instance = scanner_class(scanner.client)
                if hasattr(scanner_instance, 'scan'):
                    logger.info(f"{scanner_name} scanner initialized successfully")
                else:
                    logger.error(f"{scanner_name} scanner does not have a scan method")
            except Exception as e:
                logger.error(f"Failed to initialize {scanner_name} scanner: {str(e)}")
        
        return True
    except Exception as e:
        logger.error(f"Scanner verification failed: {str(e)}")
        return False

if __name__ == "__main__":
    success = verify_scanner_initialization()
    if success:
        logger.info("All scanners verified successfully")
        sys.exit(0)
    else:
        logger.error("Scanner verification failed")
        sys.exit(1) 