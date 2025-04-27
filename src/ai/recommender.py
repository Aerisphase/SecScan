import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from typing import List, Dict, Any
import joblib
import os

class RecommenderSystem:
    def __init__(self, model_path: str = None):
        self.vectorizer = TfidfVectorizer()
        self.recommendations_db = pd.DataFrame({
            'vulnerability_type': [
                'SQL Injection',
                'XSS',
                'CSRF',
                'File Inclusion',
                'Command Injection'
            ],
            'description': [
                'SQL injection vulnerability detected in input parameters',
                'Cross-site scripting vulnerability in user input',
                'Cross-site request forgery vulnerability',
                'Local/Remote file inclusion vulnerability',
                'Command injection vulnerability in system calls'
            ],
            'recommendation': [
                'Use parameterized queries and prepared statements. Implement input validation and sanitization.',
                'Implement proper output encoding. Use Content Security Policy (CSP). Sanitize user input.',
                'Implement CSRF tokens. Use SameSite cookie attribute. Validate origin headers.',
                'Implement strict file path validation. Use whitelist approach for file inclusion.',
                'Use proper input validation. Implement command whitelisting. Use secure system calls.'
            ],
            'severity': ['High', 'High', 'Medium', 'High', 'High'],
            'confidence': [0.95, 0.90, 0.85, 0.90, 0.95]
        })
        
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
        else:
            self.train_model()
    
    def train_model(self):
        """Train the recommendation model using TF-IDF and cosine similarity"""
        # Create feature vectors
        self.vectorizer.fit(self.recommendations_db['description'])
        self.feature_vectors = self.vectorizer.transform(self.recommendations_db['description'])
    
    def save_model(self, path: str):
        """Save the trained model to disk"""
        model_data = {
            'vectorizer': self.vectorizer,
            'feature_vectors': self.feature_vectors
        }
        joblib.dump(model_data, path)
    
    def load_model(self, path: str):
        """Load a trained model from disk"""
        model_data = joblib.load(path)
        self.vectorizer = model_data['vectorizer']
        self.feature_vectors = model_data['feature_vectors']
    
    def get_recommendations(self, vulnerability_data: Dict[str, Any], top_n: int = 3) -> List[Dict[str, Any]]:
        """
        Get security recommendations based on vulnerability data
        
        Args:
            vulnerability_data: Dictionary containing vulnerability information
            top_n: Number of top recommendations to return
        
        Returns:
            List of recommendation dictionaries
        """
        # Create input vector
        input_text = f"{vulnerability_data.get('type', '')} {vulnerability_data.get('description', '')}"
        input_vector = self.vectorizer.transform([input_text])
        
        # Calculate similarity scores
        similarity_scores = cosine_similarity(input_vector, self.feature_vectors)[0]
        
        # Get top N recommendations
        top_indices = np.argsort(similarity_scores)[-top_n:][::-1]
        
        recommendations = []
        for idx in top_indices:
            rec = self.recommendations_db.iloc[idx].to_dict()
            rec['similarity_score'] = float(similarity_scores[idx])
            recommendations.append(rec)
        
        return recommendations
    
    def add_recommendation(self, vulnerability_type: str, description: str, 
                          recommendation: str, severity: str, confidence: float):
        """Add a new recommendation to the database"""
        new_rec = pd.DataFrame([{
            'vulnerability_type': vulnerability_type,
            'description': description,
            'recommendation': recommendation,
            'severity': severity,
            'confidence': confidence
        }])
        self.recommendations_db = pd.concat([self.recommendations_db, new_rec], ignore_index=True)
        self.train_model()  # Retrain model with new data 