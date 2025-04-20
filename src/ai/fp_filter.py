import joblib
from sklearn.ensemble import RandomForestClassifier

class FalsePositiveFilter:
    def __init__(self, model_path: str = None):
        if model_path:
            self.model = joblib.load(model_path)
        else:
            self.model = RandomForestClassifier(n_estimators=100)
            
    def extract_features(self, vulnerability: Dict) -> List:
        """Извлечение признаков для классификации"""
        features = [
            len(vulnerability.get('payload', '')),
            vulnerability.get('confidence', 0),
            vulnerability.get('response_time', 0)
        ]
        return features
        
    def predict(self, vulnerability: Dict) -> bool:
        """Предсказание (True = реальная уязвимость)"""
        features = self.extract_features(vulnerability)
        return self.model.predict([features])[0]