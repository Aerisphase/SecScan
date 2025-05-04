import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
import numpy as np
import pandas as pd
import joblib
import time

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import GridSearchCV, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score
from sklearn.pipeline import Pipeline
from sklearn.feature_selection import SelectFromModel
import matplotlib.pyplot as plt
import seaborn as sns

from config import TRAINING_DATA_DIR, MODELS_DIR, RANDOM_STATE, MODEL_PARAMS

logger = logging.getLogger(__name__)

class EnhancedModelTrainer:
    def __init__(self):
        self.models_dir = Path(MODELS_DIR)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        # Define model configurations
        self.model_configs = {
            'random_forest': {
                'model': RandomForestClassifier(random_state=RANDOM_STATE),
                'params': {
                    'n_estimators': [100, 200, 300],
                    'max_depth': [None, 10, 20, 30],
                    'min_samples_split': [2, 5, 10],
                    'class_weight': ['balanced', 'balanced_subsample', None]
                }
            },
            'gradient_boosting': {
                'model': GradientBoostingClassifier(random_state=RANDOM_STATE),
                'params': {
                    'n_estimators': [100, 200],
                    'learning_rate': [0.01, 0.1, 0.2],
                    'max_depth': [3, 5, 7]
                }
            },
            'logistic_regression': {
                'model': LogisticRegression(random_state=RANDOM_STATE, max_iter=1000),
                'params': {
                    'C': [0.1, 1.0, 10.0],
                    'solver': ['liblinear', 'saga'],
                    'class_weight': ['balanced', None]
                }
            },
            'svm': {
                'model': SVC(random_state=RANDOM_STATE, probability=True),
                'params': {
                    'C': [0.1, 1.0, 10.0],
                    'kernel': ['linear', 'rbf'],
                    'gamma': ['scale', 'auto'],
                    'class_weight': ['balanced', None]
                }
            },
            'neural_network': {
                'model': MLPClassifier(random_state=RANDOM_STATE, max_iter=500),
                'params': {
                    'hidden_layer_sizes': [(50,), (100,), (50, 50)],
                    'activation': ['relu', 'tanh'],
                    'alpha': [0.0001, 0.001, 0.01],
                    'learning_rate': ['constant', 'adaptive']
                }
            }
        }
    
    def train(self, data_file: Optional[Path] = None) -> Dict[str, Any]:
        """Train models on the preprocessed data"""
        try:
            start_time = time.time()
            logger.info("Starting enhanced model training...")
            
            # Load preprocessed data
            if data_file is None:
                data_file = TRAINING_DATA_DIR / "enhanced_preprocessed_data.json"
                
            with open(data_file, 'r') as f:
                data = json.load(f)
                
            X = np.array(data['X'])
            y_type = np.array(data['y_type'])
            y_severity = np.array(data['y_severity'])
            
            # Feature selection to reduce dimensionality
            logger.info(f"Original feature dimensions: {X.shape}")
            X_reduced, selected_indices = self._feature_selection(X, y_type)
            logger.info(f"Reduced feature dimensions: {X_reduced.shape}")
            
            # Train multiple models for vulnerability type classification
            type_models = self._train_models(X_reduced, y_type, 'type')
            
            # Train models for severity classification
            severity_models = self._train_models(X_reduced, y_severity, 'severity')
            
            # Evaluate and select best models
            best_type_model = self._select_best_model(type_models, X_reduced, y_type, 'type')
            best_severity_model = self._select_best_model(severity_models, X_reduced, y_severity, 'severity')
            
            # Save feature selection model
            feature_selector_path = self.models_dir / "feature_selector.joblib"
            joblib.dump(selected_indices, feature_selector_path)
            logger.info(f"Feature selector saved to {feature_selector_path}")
            
            # Save model metadata
            metadata = {
                'training_time': time.time() - start_time,
                'num_samples': len(y_type),
                'feature_dimensions': X_reduced.shape[1],
                'type_classes': data['type_classes'],
                'severity_classes': data['severity_classes'],
                'best_type_model': best_type_model['name'],
                'best_severity_model': best_severity_model['name'],
                'type_model_scores': {model['name']: model['score'] for model in type_models},
                'severity_model_scores': {model['name']: model['score'] for model in severity_models}
            }
            
            metadata_path = self.models_dir / "model_metadata.json"
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
                
            logger.info(f"Model metadata saved to {metadata_path}")
            logger.info(f"Model training completed in {metadata['training_time']:.2f} seconds")
            
            return metadata
            
        except Exception as e:
            logger.error(f"Error training models: {e}", exc_info=True)
            raise
    
    def _feature_selection(self, X: np.ndarray, y: np.ndarray) -> Tuple[np.ndarray, List[int]]:
        """Perform feature selection to reduce dimensionality"""
        try:
            logger.info("Performing feature selection...")
            
            # Use Random Forest for feature importance-based selection
            selector = SelectFromModel(
                RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE),
                threshold='median'
            )
            
            selector.fit(X, y)
            selected_indices = selector.get_support(indices=True)
            X_reduced = selector.transform(X)
            
            logger.info(f"Selected {len(selected_indices)} features out of {X.shape[1]}")
            return X_reduced, selected_indices
            
        except Exception as e:
            logger.error(f"Error in feature selection: {e}")
            return X, list(range(X.shape[1]))  # Return original features if selection fails
    
    def _train_models(self, X: np.ndarray, y: np.ndarray, target_type: str) -> List[Dict[str, Any]]:
        """Train multiple models and return their performance"""
        trained_models = []
        
        for name, config in self.model_configs.items():
            try:
                logger.info(f"Training {name} for {target_type} classification...")
                
                # Perform grid search for hyperparameter tuning
                grid_search = GridSearchCV(
                    config['model'],
                    config['params'],
                    cv=5,
                    scoring='f1_weighted',
                    n_jobs=-1
                )
                
                grid_search.fit(X, y)
                
                # Get best model
                best_model = grid_search.best_estimator_
                best_params = grid_search.best_params_
                
                # Evaluate with cross-validation
                cv_scores = cross_val_score(best_model, X, y, cv=5, scoring='f1_weighted')
                mean_score = cv_scores.mean()
                
                # Save model
                model_path = self.models_dir / f"{target_type}_{name}_model.joblib"
                joblib.dump(best_model, model_path)
                
                trained_models.append({
                    'name': name,
                    'model': best_model,
                    'params': best_params,
                    'score': mean_score,
                    'path': str(model_path)
                })
                
                logger.info(f"{name} model trained with F1 score: {mean_score:.4f}")
                logger.info(f"Best parameters: {best_params}")
                
            except Exception as e:
                logger.error(f"Error training {name} model: {e}")
                continue
                
        return trained_models
    
    def _select_best_model(self, models: List[Dict[str, Any]], X: np.ndarray, y: np.ndarray, target_type: str) -> Dict[str, Any]:
        """Select the best performing model"""
        if not models:
            raise ValueError("No models were successfully trained")
            
        # Sort models by score
        sorted_models = sorted(models, key=lambda m: m['score'], reverse=True)
        best_model = sorted_models[0]
        
        logger.info(f"Best model for {target_type} classification: {best_model['name']} with score {best_model['score']:.4f}")
        
        # Generate detailed evaluation report
        y_pred = best_model['model'].predict(X)
        
        report = classification_report(y, y_pred, output_dict=True)
        
        # Save report
        report_path = self.models_dir / f"{target_type}_classification_report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
            
        # Generate confusion matrix
        cm = confusion_matrix(y, y_pred)
        
        # Save confusion matrix as image
        plt.figure(figsize=(10, 8))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        plt.title(f'Confusion Matrix for {target_type.capitalize()} Classification')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.savefig(self.models_dir / f"{target_type}_confusion_matrix.png")
        plt.close()
        
        return best_model
    
    def evaluate(self, test_data_file: Optional[Path] = None) -> Dict[str, Any]:
        """Evaluate models on test data"""
        try:
            logger.info("Evaluating models on test data...")
            
            # Load test data
            if test_data_file is None:
                test_data_file = TRAINING_DATA_DIR / "train_test_split.json"
                
            with open(test_data_file, 'r') as f:
                data = json.load(f)
                
            X_test = np.array(data['X_test'])
            y_type_test = np.array(data['y_type_test'])
            
            # Load metadata to get best models
            metadata_path = self.models_dir / "model_metadata.json"
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
                
            best_type_model_name = metadata['best_type_model']
            
            # Load best type model
            type_model_path = self.models_dir / f"type_{best_type_model_name}_model.joblib"
            type_model = joblib.load(type_model_path)
            
            # Evaluate on test data
            y_type_pred = type_model.predict(X_test)
            
            type_accuracy = accuracy_score(y_type_test, y_type_pred)
            type_f1 = f1_score(y_type_test, y_type_pred, average='weighted')
            
            logger.info(f"Test accuracy for vulnerability type classification: {type_accuracy:.4f}")
            logger.info(f"Test F1 score for vulnerability type classification: {type_f1:.4f}")
            
            # Return evaluation results
            return {
                'type_accuracy': type_accuracy,
                'type_f1': type_f1
            }
            
        except Exception as e:
            logger.error(f"Error evaluating models: {e}", exc_info=True)
            return {}

# If run directly, train models
if __name__ == "__main__":
    try:
        trainer = EnhancedModelTrainer()
        metadata = trainer.train()
        evaluation = trainer.evaluate()
        
        logger.info("Model training and evaluation completed successfully")
        
    except Exception as e:
        logger.error(f"Error running model trainer: {e}", exc_info=True)
