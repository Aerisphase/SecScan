import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from typing import Dict, List, Optional
import joblib
import os
from pathlib import Path

class VulnerabilityRecommender:
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path
        self.vectorizer = TfidfVectorizer()
        self.recommendations_db = self._load_recommendations_db()
        self.model = self._load_model() if model_path else None
        
    def _load_recommendations_db(self) -> pd.DataFrame:
        """Load the recommendations database"""
        # Sample recommendations database
        data = {
            'vulnerability_type': [
                'SQL Injection', 'XSS', 'CSRF', 'SSRF', 'XXE',
                'IDOR', 'File Upload', 'Command Injection', 'Path Traversal',
                'Broken Authentication'
            ],
            'description': [
                'SQL-инъекция возникает, когда ненадежные данные используются в SQL-запросах',
                'Межсайтовый скриптинг позволяет злоумышленникам внедрять клиентские скрипты',
                'Подделка межсайтовых запросов заставляет пользователей выполнять нежелательные действия',
                'Подделка серверных запросов позволяет злоумышленникам получать доступ к внутренним ресурсам',
                'Обработка внешних XML-сущностей может привести к раскрытию информации',
                'Небезопасные прямые ссылки на объекты раскрывают внутренние детали реализации',
                'Уязвимости загрузки файлов могут привести к выполнению удаленного кода',
                'Внедрение команд позволяет выполнять произвольные команды',
                'Обход пути позволяет получить доступ к файлам вне корневой директории',
                'Неисправные механизмы аутентификации могут быть обойдены'
            ],
            'recommendations': [
                'Используйте параметризованные запросы или подготовленные выражения\nРеализуйте проверку входных данных\nИспользуйте ORM-фреймворки\nПрименяйте принцип наименьших привилегий',
                'Реализуйте Content Security Policy (CSP)\nИспользуйте кодирование вывода\nПроверяйте и санируйте пользовательский ввод\nИспользуйте современные фреймворки со встроенной защитой от XSS',
                'Реализуйте CSRF-токены\nИспользуйте атрибут SameSite для куки\nПроверяйте заголовки origin\nРеализуйте паттерн двойной отправки куки',
                'Проверяйте и санируйте URL\nИспользуйте белый список разрешенных доменов\nРеализуйте сегментацию сети\nИспользуйте правильную аутентификацию',
                'Отключите обработку DTD\nИспользуйте безопасные XML-парсеры\nРеализуйте проверку входных данных\nИспользуйте белый список разрешенных сущностей',
                'Реализуйте правильный контроль доступа\nИспользуйте косвенные ссылки на объекты\nПроверяйте права пользователей\nРеализуйте правильное управление сессиями',
                'Проверяйте типы и расширения файлов\nИспользуйте безопасные имена файлов\nРеализуйте проверку на вирусы\nХраните файлы вне корневой директории',
                'Используйте безопасные API для выполнения команд\nРеализуйте проверку входных данных\nИспользуйте белый список\nПрименяйте принцип наименьших привилегий',
                'Проверяйте пути к файлам\nИспользуйте безопасные API для работы с файлами\nРеализуйте правильный контроль доступа\nИспользуйте белый список',
                'Реализуйте многофакторную аутентификацию\nИспользуйте безопасную политику паролей\nРеализуйте блокировку учетной записи\nИспользуйте безопасное управление сессиями'
            ],
            'severity': ['high', 'high', 'medium', 'high', 'high', 'medium', 'high', 'high', 'medium', 'high'],
            'prevention_score': [0.95, 0.90, 0.85, 0.88, 0.92, 0.80, 0.93, 0.94, 0.82, 0.87]
        }
        return pd.DataFrame(data)
    
    def _load_model(self) -> Optional[object]:
        """Load the trained model if it exists"""
        if self.model_path and os.path.exists(self.model_path):
            return joblib.load(self.model_path)
        return None
    
    def train_model(self, training_data: pd.DataFrame) -> None:
        """Train the recommendation model"""
        # Convert vulnerability descriptions to TF-IDF vectors
        X = self.vectorizer.fit_transform(training_data['description'])
        
        # Train a simple similarity model
        self.model = X
        
        # Save the model
        if self.model_path:
            joblib.dump(self.model, self.model_path)
    
    def get_recommendations(self, vulnerability: Dict) -> Dict:
        """Get recommendations for a specific vulnerability"""
        try:
            # Extract vulnerability features
            vuln_type = vulnerability.get('type', '')
            description = vulnerability.get('description', '')
            
            # Find exact match in database
            exact_match = self.recommendations_db[
                self.recommendations_db['vulnerability_type'].str.lower() == vuln_type.lower()
            ]
            
            if not exact_match.empty:
                return {
                    'recommendations': exact_match['recommendations'].iloc[0].split('\n'),
                    'severity': exact_match['severity'].iloc[0],
                    'prevention_score': exact_match['prevention_score'].iloc[0],
                    'confidence': 1.0
                }
            
            # If no exact match, use similarity-based recommendations
            if self.model is not None:
                # Convert vulnerability description to TF-IDF vector
                vuln_vector = self.vectorizer.transform([description])
                
                # Calculate similarity scores
                similarities = cosine_similarity(vuln_vector, self.model)
                
                # Get top 3 most similar vulnerabilities
                top_indices = np.argsort(similarities[0])[-3:][::-1]
                
                recommendations = []
                for idx in top_indices:
                    rec = self.recommendations_db.iloc[idx]
                    recommendations.extend(rec['recommendations'].split('\n'))
                
                return {
                    'recommendations': list(set(recommendations)),  # Remove duplicates
                    'severity': self.recommendations_db.iloc[top_indices[0]]['severity'],
                    'prevention_score': self.recommendations_db.iloc[top_indices[0]]['prevention_score'],
                    'confidence': float(similarities[0][top_indices[0]])
                }
            
            # Fallback to generic recommendations
            return {
                'recommendations': [
                    'Implement proper input validation',
                    'Use secure coding practices',
                    'Follow OWASP guidelines',
                    'Regular security testing'
                ],
                'severity': 'unknown',
                'prevention_score': 0.75,
                'confidence': 0.0
            }
            
        except Exception as e:
            print(f"Error generating recommendations: {str(e)}")
            return {
                'recommendations': ['Error generating recommendations'],
                'severity': 'unknown',
                'prevention_score': 0.0,
                'confidence': 0.0
            }
    
    def get_preventive_measures(self, code_context: str) -> List[str]:
        """Get preventive measures based on code context"""
        try:
            # Extract keywords from code context
            keywords = self._extract_keywords(code_context)
            
            # Find relevant recommendations based on keywords
            relevant_recs = []
            for _, row in self.recommendations_db.iterrows():
                if any(keyword in row['description'].lower() for keyword in keywords):
                    relevant_recs.extend(row['recommendations'].split('\n'))
            
            return list(set(relevant_recs))  # Remove duplicates
            
        except Exception as e:
            print(f"Error generating preventive measures: {str(e)}")
            return ['Error generating preventive measures']
    
    def _extract_keywords(self, code_context: str) -> List[str]:
        """Extract relevant keywords from code context"""
        # Basic keyword extraction - can be enhanced with NLP
        keywords = [
            'sql', 'query', 'database', 'input', 'user', 'file',
            'upload', 'command', 'path', 'authentication', 'session',
            'cookie', 'header', 'request', 'response', 'xml', 'json'
        ]
        return [k for k in keywords if k in code_context.lower()] 