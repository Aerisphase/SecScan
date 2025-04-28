import numpy as np
from typing import Dict, Any, Tuple
from pathlib import Path
import logging
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import joblib
import json
from config import MODEL_PARAMS, TRAIN_TEST_SPLIT, RANDOM_STATE, CV_FOLDS, MODELS_DIR

logger = logging.getLogger(__name__)

class ModelTrainer:
    def __init__(self):
        self.models_dir = MODELS_DIR
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        self.models = {
            'random_forest': RandomForestClassifier(**MODEL_PARAMS['random_forest']),
            'svm': SVC(**MODEL_PARAMS['svm']),
            'logistic_regression': LogisticRegression(**MODEL_PARAMS['logistic_regression'])
        }
        
    def train_model(self, model_name: str, X: np.ndarray, y: np.ndarray) -> Tuple[Any, Dict[str, Any]]:
        """Train a single model and return model and metrics"""
        try:
            # Check if we have enough samples for cross-validation
            n_samples = len(y)
            n_splits = min(CV_FOLDS, n_samples // 2)  # Ensure at least 2 samples per fold
            
            if n_splits < 2:
                logger.warning(f"Not enough samples for cross-validation, using simple train/test split")
                # Simple train/test split
                X_train, X_test, y_train, y_test = train_test_split(
                    X, y, test_size=0.2, random_state=RANDOM_STATE
                )
                
                model = self.models[model_name]
                model.fit(X_train, y_train)
                y_pred = model.predict(X_test)
                
                metrics = {
                    'accuracy': accuracy_score(y_test, y_pred),
                    'precision': precision_score(y_test, y_pred, average='weighted', zero_division=0),
                    'recall': recall_score(y_test, y_pred, average='weighted', zero_division=0),
                    'f1': f1_score(y_test, y_pred, average='weighted', zero_division=0),
                    'cv_mean': None,
                    'cv_std': None
                }
            else:
                # Use cross-validation
                cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=RANDOM_STATE)
                
                # Train model
                model = self.models[model_name]
                model.fit(X, y)
                
                # Cross-validation scores
                cv_scores = cross_val_score(model, X, y, cv=cv)
                
                # Make predictions on a small test set
                X_train, X_test, y_train, y_test = train_test_split(
                    X, y, test_size=0.2, random_state=RANDOM_STATE
                )
                y_pred = model.predict(X_test)
                
                metrics = {
                    'accuracy': accuracy_score(y_test, y_pred),
                    'precision': precision_score(y_test, y_pred, average='weighted', zero_division=0),
                    'recall': recall_score(y_test, y_pred, average='weighted', zero_division=0),
                    'f1': f1_score(y_test, y_pred, average='weighted', zero_division=0),
                    'cv_mean': float(cv_scores.mean()),
                    'cv_std': float(cv_scores.std())
                }
            
            # Save model and metrics
            self._save_model(model, f"{model_name}.joblib")
            self._save_metrics(metrics, f"{model_name}_metrics.json")
            
            logger.info(f"{model_name} training completed with metrics: {metrics}")
            return model, metrics
            
        except Exception as e:
            logger.error(f"Error training {model_name}: {e}")
            return None, {}
            
    def train_all_models(self, data: Dict[str, np.ndarray]) -> Dict[str, Dict[str, Tuple[Any, Dict[str, Any]]]]:
        """Train all models and return results"""
        results = {}
        
        # Get features
        X = data['X']
        
        # Train models for each target
        for target in ['type', 'severity', 'fp']:
            y = data[f'y_{target}']
            target_results = {}
            
            for model_name in self.models:
                model, metrics = self.train_model(model_name, X, y)
                if model is not None:
                    target_results[model_name] = (model, metrics)
                    
            results[target] = target_results
            
        return results
        
    def _save_model(self, model: Any, filename: str) -> None:
        """Save trained model"""
        joblib.dump(model, self.models_dir / filename)
        logger.info(f"Saved model to {self.models_dir / filename}")
        
    def _save_metrics(self, metrics: Dict[str, Any], filename: str) -> None:
        """Save model metrics"""
        with open(self.models_dir / filename, 'w') as f:
            json.dump(metrics, f, indent=2)
        logger.info(f"Saved metrics to {self.models_dir / filename}") 