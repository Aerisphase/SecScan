"""
Инициализация AI-модулей сканера
"""

from .fp_filter import FalsePositiveFilter
from .payload_gen import PayloadGenerator
from .risk_analyzer import RiskAnalyzer
from .waf_detector import WAFDetector

# Версия AI-модуля
__version__ = "1.0.0"

# Экспортируемые интерфейсы
__all__ = [
    'FalsePositiveFilter',
    'PayloadGenerator',
    'RiskAnalyzer',
    'WAFDetector',
    '__version__'
]

class AIConfig:
    """Конфигурация AI-модулей"""
    MODEL_PATH = "models/"
    CONFIDENCE_THRESHOLD = 0.85
    MAX_PAYLOADS = 100