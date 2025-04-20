from __future__ import annotations  # Должен быть первой строкой

import sys
from typing import Dict, List, Set, Optional
from requests import Session

# Базовые типы для аннотаций
__all__ = [
    'AdvancedCrawler',
    'XSSScanner',
    'SQLiScanner',
    'CSRFScanner',
    'CoreError'
]

class CoreError(Exception):
    """Базовое исключение для ошибок ядра"""
    pass

try:
    # Основные компоненты
    from .crawler import AdvancedCrawler
except ImportError as e:
    raise CoreError(f"Critical component missing: {e}") from e

try:
    # Сканеры (опциональные компоненты)
    from .scanners.xss import XSSScanner
    from .scanners.sqli import SQLiScanner
    from .scanners.csrf import CSRFScanner
except ImportError as e:
    import warnings
    warnings.warn(f"Some scanners not available: {e}")
    
    # Заглушки для отсутствующих сканеров
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

# Проверка минимально рабочей конфигурации
def check_imports() -> bool:
    """Проверяет, что все ключевые компоненты загружены"""
    required = ['AdvancedCrawler', 'XSSScanner', 'SQLiScanner']
    return all(component in globals() for component in required)