import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from typing import Dict, Any

class FalsePositiveFilter:
    def __init__(self, model_path: str = None):
        if model_path:
            self.model = joblib.load(model_path)
        else:
            self.model = RandomForestClassifier(n_estimators=100)
        
    def extract_features(self, vulnerability: Dict[str, Any]) -> pd.DataFrame:
        """Извлекает признаки из данных об уязвимости"""
        features = {
            'payload_length': len(vulnerability.get('payload', '')),
            'response_similarity': vulnerability.get('similarity', 0),
            'status_code': vulnerability.get('status_code', 0)
        }
        return pd.DataFrame([features])
    
    def predict(self, vulnerability: Dict[str, Any]) -> bool:
        """Определяет, является ли уязвимость ложным срабатыванием"""
        try:
            features = self.extract_features(vulnerability)
            return bool(self.model.predict(features)[0])
        except Exception as e:
            print(f"Prediction error: {e}")
            return False