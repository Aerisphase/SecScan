"""
Artificial Intelligence module for vulnerability scanner
"""

try:
    from .fp_filter import FalsePositiveFilter
    from .payload_gen import PayloadGenerator
    from .risk_analyzer import RiskAnalyzer
except ImportError as e:
    print(f"Warning: Some AI components not available - {e}")

__all__ = [
    'FalsePositiveFilter',
    'PayloadGenerator',
    'RiskAnalyzer'
]

class AIConfig:
    """AI modules configuration"""
    MODEL_PATH = "models/"
    CONFIDENCE_THRESHOLD = 0.85