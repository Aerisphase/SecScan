from __future__ import annotations  # Должен быть ПЕРВОЙ строкой в файле

from typing import Dict, List, Set
from requests import Session

try:
    from .crawler import AdvancedCrawler
    from .scanners.xss import XSSScanner
    from .scanners.sqli import SQLiScanner
    from .scanners.csrf import CSRFScanner
except ImportError as e:
    raise ImportError(f"Failed to import core modules: {e}") from e

__all__ = [
    'AdvancedCrawler',
    'XSSScanner',
    'SQLiScanner',
    'CSRFScanner'
]

class CoreError(Exception):
    """Базовое исключение для ошибок ядра"""
    pass