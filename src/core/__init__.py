"""
Инициализация модуля ядра сканера уязвимостей
"""

from .crawler import AdvancedCrawler
from .scanners.sqli import SQLiScanner
from .scanners.xss import XSSScanner
from .scanners.csrf import CSRFScanner
from .scanners.rce import RCEScanner
from .utils import normalize_url, is_same_domain

# Версия ядра
__version__ = "1.0.0"

# Экспортируемые публичные интерфейсы
__all__ = [
    'AdvancedCrawler',
    'SQLiScanner',
    'XSSScanner',
    'CSRFScanner',
    'RCEScanner',
    'normalize_url',
    'is_same_domain',
    '__version__'
]

class CoreConfig:
    """Конфигурация ядра по умолчанию"""
    MAX_CRAWL_DEPTH = 5
    REQUEST_TIMEOUT = 10