import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from typing import Dict, List, Optional, Tuple
import joblib
import os
from pathlib import Path
from .vulnerability_analyzer import VulnerabilityAnalyzer

class VulnerabilityRecommender:
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path
        self.vectorizer = TfidfVectorizer()
        self.recommendations_db = self._load_recommendations_db()
        self.model = self._load_model() if model_path else None
        self.analyzer = VulnerabilityAnalyzer()
        
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
    
    def get_recommendations(self, vulnerability_type: str, context: str = '') -> Tuple[List[str], float]:
        """
        Get AI-generated recommendations for preventing a specific vulnerability type.
        
        Args:
            vulnerability_type: The type of vulnerability (e.g., 'SQL Injection', 'XSS')
            context: Additional context about the vulnerability (optional)
            
        Returns:
            Tuple containing:
            - List of recommendations
            - Confidence score (0.0 to 1.0)
        """
        return self.analyzer.get_recommendations(vulnerability_type, context)
    
    def get_preventive_measures(self, code_context: str) -> List[str]:
        """
        Get preventive measures based on code context.
        
        Args:
            code_context: The code context to analyze
            
        Returns:
            List of preventive measures
        """
        # This is a simplified version - in production, you'd want to analyze the code
        # using more sophisticated techniques
        measures = []
        
        if 'sql' in code_context.lower():
            measures.extend([
                'Use parameterized queries',
                'Implement input validation',
                'Apply principle of least privilege'
            ])
            
        if 'html' in code_context.lower() or 'javascript' in code_context.lower():
            measures.extend([
                'Implement Content Security Policy',
                'Use output encoding',
                'Validate user input'
            ])
            
        if 'form' in code_context.lower() or 'post' in code_context.lower():
            measures.extend([
                'Implement CSRF tokens',
                'Use SameSite cookie attribute',
                'Verify Origin headers'
            ])
            
        return measures 