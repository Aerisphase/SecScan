"""
Artificial Intelligence module for vulnerability scanner
"""

try:
    from .fp_filter import FalsePositiveFilter
    from .payload_gen import PayloadGenerator
    from .risk_analyzer import RiskAnalyzer
    from .recommender import RecommenderSystem
except ImportError as e:
    print(f"Warning: Some AI components not available - {e}")

__all__ = [
    'FalsePositiveFilter',
    'PayloadGenerator',
    'RiskAnalyzer',
    'RecommenderSystem'
]

class AIConfig:
    """AI modules configuration"""
    MODEL_PATH = "models/"
    CONFIDENCE_THRESHOLD = 0.85

    def __init__(self):
        self.model_path = "models/ai_model.joblib"
        self.confidence_threshold = 0.85
        self.recommender_model_path = "models/recommender_model.joblib"