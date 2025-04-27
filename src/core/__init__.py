from __future__ import annotations  # Must be the first line

import sys
from typing import Dict, List, Set, Optional
from requests import Session
from .http_client import HttpClient

# Basic types for annotations
__all__ = [
    'AdvancedCrawler',
    'XSSScanner',
    'SQLiScanner',
    'CSRFScanner',
    'CoreError'
]

class CoreError(Exception):
    """Base exception for core errors"""
    pass

try:
    # Core components
    from .crawler import AdvancedCrawler
except ImportError as e:
    raise CoreError(f"Critical component missing: {e}") from e

try:
    # Scanners (optional components)
    from .scanners.xss import XSSScanner
    from .scanners.sql_injection import SQLInjectionScanner as SQLiScanner
    from .scanners.csrf import CSRFScanner
except ImportError as e:
    import warnings
    warnings.warn(f"Some scanners not available: {e}")
    
    # Stubs for missing scanners
    if 'XSSScanner' not in globals():
        class XSSScanner:  # type: ignore
            def __init__(self, session: Session):
                raise CoreError("XSSScanner not implemented")
    
    if 'SQLiScanner' not in globals():
        class SQLiScanner:  # type: ignore
            def __init__(self, session: Session):
                raise CoreError("SQLiScanner not implemented")
    
    if 'CSRFScanner' not in globals():
        class CSRFScanner:  # type: ignore
            def __init__(self, session: Session):
                raise CoreError("CSRFScanner not implemented")

# Check minimum working configuration
def check_imports() -> bool:
    """Checks that all key components are loaded"""
    required = ['AdvancedCrawler', 'XSSScanner', 'SQLiScanner']
    return all(component in globals() for component in required)

# This file makes the core directory a Python package