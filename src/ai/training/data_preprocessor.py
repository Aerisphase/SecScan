import pandas as pd
import numpy as np
from typing import List, Dict, Any
import json
from pathlib import Path
import logging
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
import re
from config import TRAINING_DATA_DIR

logger = logging.getLogger(__name__)

class DataPreprocessor:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words='english',
            ngram_range=(1, 2)
        )
        self.label_encoders = {
            'type': LabelEncoder(),
            'severity': LabelEncoder(),
            'fp': LabelEncoder()
        }
        
    def preprocess(self, data: Dict[str, List[Dict[str, Any]]]) -> Dict[str, np.ndarray]:
        """Preprocess collected data for training"""
        try:
            # Extract text features from different sources
            texts = []
            types = []
            severities = []
            is_fp = []
            
            # Process CVE data
            for cve in data['cve_data']:
                desc = cve['cve']['descriptions'][0]['value']
                texts.append(desc)
                types.append('injection')  # Simplified type based on description
                severities.append(str(cve['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']))
                is_fp.append(0)
                
            # Process WAF logs
            for log in data['waf_logs']:
                text = f"{log['request_method']} {log['request_uri']} {log['rule_message']}"
                texts.append(text)
                types.append(log['rule_id'][:3])  # Use rule ID prefix as type
                severities.append(log['severity'].lower())
                is_fp.append(0)
                
            # Process pen test findings
            for finding in data['pen_test_findings']:
                # Handle both old and new format
                if isinstance(finding, dict):
                    if 'title' in finding:
                        text = f"{finding['title']} {finding['description']}"
                        types.append(finding['title'].split()[0].lower())
                        severities.append(finding['severity'].lower())
                    else:
                        text = finding.get('description', '')
                        types.append(finding.get('type', 'unknown'))
                        severities.append(finding.get('severity', 'unknown'))
                else:
                    text = str(finding)
                    types.append('unknown')
                    severities.append('unknown')
                texts.append(text)
                is_fp.append(0)
                
            # Process OWASP resources
            for resource in data['owasp_resources']:
                if 'categories' in resource:
                    for category in resource['categories']:
                        text = f"{category['name']} {category['description']}"
                        texts.append(text)
                        types.append(category['id'].lower())
                        severities.append('medium')  # Default severity
                        is_fp.append(0)
                else:
                    text = str(resource)
                    texts.append(text)
                    types.append('owasp')
                    severities.append('medium')
                    is_fp.append(0)
                    
            # Add some false positives
            fp_texts = [
                "Normal user login attempt",
                "Regular search query",
                "Standard API request",
                "Legitimate file upload",
                "Valid password reset request"
            ]
            for text in fp_texts:
                texts.append(text)
                types.append('normal')
                severities.append('low')
                is_fp.append(1)
                
            # Ensure we have enough samples
            if len(texts) < 10:
                logger.warning(f"Very small dataset: {len(texts)} samples")
                # Add more synthetic samples
                synthetic_samples = [
                    ("SQL injection attempt", "injection", "high"),
                    ("XSS payload detected", "xss", "medium"),
                    ("Directory traversal attempt", "path", "high"),
                    ("Command injection attempt", "cmd", "critical"),
                    ("CSRF token missing", "csrf", "medium")
                ]
                for text, type_, severity in synthetic_samples:
                    texts.append(text)
                    types.append(type_)
                    severities.append(severity)
                    is_fp.append(0)
                    
            # Verify all lists have the same length
            assert len(texts) == len(types) == len(severities) == len(is_fp), \
                f"Length mismatch: texts={len(texts)}, types={len(types)}, severities={len(severities)}, is_fp={len(is_fp)}"
                    
            # Vectorize text
            X = self.vectorizer.fit_transform(texts).toarray()
            
            # Encode labels
            y_type = self.label_encoders['type'].fit_transform(types)
            y_severity = self.label_encoders['severity'].fit_transform(severities)
            y_fp = np.array(is_fp)
            
            # Save preprocessed data
            preprocessed_data = {
                'X': X.tolist(),
                'y_type': y_type.tolist(),
                'y_severity': y_severity.tolist(),
                'y_fp': y_fp.tolist()
            }
            
            output_file = TRAINING_DATA_DIR / "preprocessed_data.json"
            with open(output_file, 'w') as f:
                json.dump(preprocessed_data, f, indent=2)
                
            logger.info(f"Preprocessed data saved to {output_file}")
            logger.info(f"Total samples: {len(texts)}")
            logger.info(f"Feature dimensions: {X.shape}")
            
            return {
                'X': X,
                'y_type': y_type,
                'y_severity': y_severity,
                'y_fp': y_fp
            }
            
        except Exception as e:
            logger.error(f"Error preprocessing data: {e}")
            raise
        
    def load_data(self) -> pd.DataFrame:
        """Load and combine all training data"""
        all_data = []
        
        # Load WAF logs
        waf_logs = self._load_waf_logs()
        if waf_logs:
            all_data.extend(waf_logs)
            
        # Load pen test findings
        pen_test_findings = self._load_pen_test_findings()
        if pen_test_findings:
            all_data.extend(pen_test_findings)
            
        # Load OWASP data
        owasp_data = self._load_owasp_data()
        if owasp_data:
            all_data.extend(owasp_data)
            
        if not all_data:
            raise ValueError("No training data found")
            
        return pd.DataFrame(all_data)
        
    def _load_waf_logs(self) -> List[Dict[str, Any]]:
        """Load and process WAF logs"""
        processed_data = []
        try:
            with open(TRAINING_DATA_DIR / "waf_logs.json", 'r') as f:
                logs = json.load(f)
                
            for log in logs:
                # Extract relevant information from ModSecurity log format
                message = log.get('message', '')
                if not message:
                    continue
                    
                # Extract vulnerability type from message
                vuln_type = "Unknown"
                if "SQL Injection" in message:
                    vuln_type = "SQL Injection"
                elif "XSS" in message:
                    vuln_type = "XSS"
                elif "Command Execution" in message:
                    vuln_type = "Command Injection"
                    
                # Extract severity
                severity = "Unknown"
                if "CRITICAL" in message:
                    severity = "Critical"
                elif "HIGH" in message:
                    severity = "High"
                    
                processed_data.append({
                    'type': vuln_type,
                    'description': message,
                    'severity': severity,
                    'is_false_positive': False,
                    'source': 'waf_logs'
                })
                
        except Exception as e:
            logger.error(f"Error processing WAF logs: {e}")
            
        return processed_data
        
    def _load_pen_test_findings(self) -> List[Dict[str, Any]]:
        """Load and process penetration test findings"""
        processed_data = []
        try:
            with open(TRAINING_DATA_DIR / "pen_test_findings.json", 'r') as f:
                findings = json.load(f)
                
            for finding in findings:
                processed_data.append({
                    'type': finding.get('vulnerability', 'Unknown'),
                    'description': finding.get('description', ''),
                    'severity': finding.get('severity', 'Unknown'),
                    'is_false_positive': finding.get('is_false_positive', False),
                    'source': 'pen_test'
                })
                
        except Exception as e:
            logger.error(f"Error processing pen test findings: {e}")
            
        return processed_data
        
    def _load_owasp_data(self) -> List[Dict[str, Any]]:
        """Load and process OWASP data"""
        processed_data = []
        try:
            with open(TRAINING_DATA_DIR / "owasp_data.json", 'r') as f:
                owasp_data = json.load(f)
                
            for data in owasp_data:
                if isinstance(data, dict) and 'content' in data:
                    # Process markdown content
                    content = data['content']
                    # Extract vulnerability information from markdown
                    vuln_type = "OWASP"
                    severity = "Unknown"
                    
                    # Look for common vulnerability patterns
                    if "SQL Injection" in content:
                        vuln_type = "SQL Injection"
                    elif "XSS" in content:
                        vuln_type = "XSS"
                    elif "Command Injection" in content:
                        vuln_type = "Command Injection"
                        
                    processed_data.append({
                        'type': vuln_type,
                        'description': content,
                        'severity': severity,
                        'is_false_positive': False,
                        'source': 'owasp'
                    })
                    
        except Exception as e:
            logger.error(f"Error processing OWASP data: {e}")
            
        return processed_data
        
    def preprocess_text(self, text: str) -> str:
        """Clean and preprocess text data"""
        if not isinstance(text, str):
            return ""
            
        # Remove special characters but keep important ones for security context
        text = re.sub(r'[^\w\s<>()\[\]{};=]', ' ', text)
        # Convert to lowercase
        text = text.lower()
        # Remove extra whitespace
        text = ' '.join(text.split())
        
        return text
        
    def prepare_training_data(self, df: pd.DataFrame) -> Dict[str, np.ndarray]:
        """Prepare data for training"""
        # Ensure all required columns exist with default values
        required_columns = ['type', 'description', 'severity', 'is_false_positive']
        for col in required_columns:
            if col not in df.columns:
                df[col] = '' if col in ['description'] else False if col == 'is_false_positive' else 'unknown'
        
        # Clean text data
        df['description'] = df['description'].apply(self.preprocess_text)
        
        # Combine text features
        df['text_features'] = df['description']
        
        # Vectorize text features
        X = self.vectorizer.fit_transform(df['text_features'])
        
        # Encode categorical features
        y_type = self.label_encoders['type'].fit_transform(df['type'])
        y_severity = self.label_encoders['severity'].fit_transform(df['severity'])
        y_fp = df['is_false_positive'].astype(int)
        
        return {
            'X': X,
            'y_type': y_type,
            'y_severity': y_severity,
            'y_fp': y_fp
        }
        
    def save_preprocessed_data(self, data: Dict[str, np.ndarray], output_dir: str = "data/preprocessed"):
        """Save preprocessed data"""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        for key, value in data.items():
            if isinstance(value, np.ndarray):
                np.save(output_dir / f"{key}.npy", value)
            elif hasattr(value, 'toarray'):
                np.save(output_dir / f"{key}.npy", value.toarray())
                
        # Save vectorizer and label encoder
        import joblib
        joblib.dump(self.vectorizer, output_dir / "vectorizer.joblib")
        joblib.dump(self.label_encoders['type'], output_dir / "type_encoder.joblib")
        joblib.dump(self.label_encoders['severity'], output_dir / "severity_encoder.joblib")
        joblib.dump(self.label_encoders['fp'], output_dir / "fp_encoder.joblib") 