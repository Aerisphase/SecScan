
from .sqli import SQLiScanner
from .xss import XSSScanner

try:
    from .csrf import CSRFScanner
except ImportError:
    CSRFScanner = None  # Заглушка если модуль отсутствует

__all__ = [
    'SQLiScanner',
    'XSSScanner',
    'CSRFScanner'  
]