import pandas as pd
import numpy as np
from typing import List, Dict, Any, Optional, Tuple, Union
import json
import logging
from pathlib import Path
import re
import string
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer
from config import TRAINING_DATA_DIR, RANDOM_STATE

# Initialize NLTK resources
try:
    nltk.data.find('tokenizers/punkt')
    nltk.data.find('corpora/stopwords')
    nltk.data.find('corpora/wordnet')
except LookupError:
    nltk.download('punkt')
    nltk.download('stopwords')
    nltk.download('wordnet')

logger = logging.getLogger(__name__)

class EnhancedDataPreprocessor:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            max_features=2000,  # Increased from 1000
            stop_words='english',
            ngram_range=(1, 3),  # Increased from (1, 2)
            min_df=2,
            max_df=0.95
        )
        self.label_encoders = {
            'type': LabelEncoder(),
            'severity': LabelEncoder(),
            'fp': LabelEncoder()
        }
        self.scaler = StandardScaler()
        self.lemmatizer = WordNetLemmatizer()
        self.stop_words = set(stopwords.words('english'))
        
    def preprocess(self, data: Dict[str, List[Dict[str, Any]]]) -> Dict[str, np.ndarray]:
        """Preprocess collected data for training with enhanced text processing"""
        try:
            logger.info("Starting enhanced data preprocessing...")
            
            # Extract features from different sources
            features = self._extract_features(data)
            
            # Text preprocessing
            processed_texts = [self._preprocess_text(text) for text in features['texts']]
            
            # Vectorize text
            X_text = self.vectorizer.fit_transform(processed_texts).toarray()
            logger.info(f"Text features shape: {X_text.shape}")
            
            # Additional numerical features
            X_numerical = self._extract_numerical_features(features)
            if X_numerical is not None and X_numerical.shape[0] > 0:
                # Scale numerical features
                X_numerical = self.scaler.fit_transform(X_numerical)
                logger.info(f"Numerical features shape: {X_numerical.shape}")
                
                # Combine text and numerical features
                X = np.hstack((X_text, X_numerical))
            else:
                X = X_text
                
            # Encode labels
            y_type = self.label_encoders['type'].fit_transform(features['types'])
            y_severity = self.label_encoders['severity'].fit_transform(features['severities'])
            y_fp = np.array(features['is_fp'])
            
            # Save preprocessed data
            preprocessed_data = {
                'X': X.tolist(),
                'y_type': y_type.tolist(),
                'y_severity': y_severity.tolist(),
                'y_fp': y_fp.tolist(),
                'feature_names': self.vectorizer.get_feature_names_out().tolist(),
                'type_classes': self.label_encoders['type'].classes_.tolist(),
                'severity_classes': self.label_encoders['severity'].classes_.tolist()
            }
            
            output_file = TRAINING_DATA_DIR / "enhanced_preprocessed_data.json"
            with open(output_file, 'w') as f:
                json.dump(preprocessed_data, f, indent=2)
                
            logger.info(f"Preprocessed data saved to {output_file}")
            logger.info(f"Total samples: {len(features['texts'])}")
            logger.info(f"Feature dimensions: {X.shape}")
            
            # Create train/test split for convenience
            X_train, X_test, y_type_train, y_type_test = train_test_split(
                X, y_type, test_size=0.2, random_state=RANDOM_STATE, stratify=y_type
            )
            
            train_test_data = {
                'X_train': X_train.tolist(),
                'X_test': X_test.tolist(),
                'y_type_train': y_type_train.tolist(),
                'y_type_test': y_type_test.tolist()
            }
            
            train_test_file = TRAINING_DATA_DIR / "train_test_split.json"
            with open(train_test_file, 'w') as f:
                json.dump(train_test_data, f, indent=2)
                
            logger.info(f"Train/test split saved to {train_test_file}")
            
            return {
                'X': X,
                'y_type': y_type,
                'y_severity': y_severity,
                'y_fp': y_fp
            }
            
        except Exception as e:
            logger.error(f"Error preprocessing data: {e}", exc_info=True)
            raise
            
    def _extract_features(self, data: Dict[str, List[Dict[str, Any]]]) -> Dict[str, List]:
        """Extract features from all data sources"""
        features = {
            'texts': [],
            'types': [],
            'severities': [],
            'is_fp': [],
            'payloads': [],
            'urls': [],
            'has_code': []
        }
        
        # Process CVE data
        for cve in data.get('cve_data', []):
            try:
                desc = cve['cve']['descriptions'][0]['value']
                features['texts'].append(desc)
                
                # Determine vulnerability type from description
                vuln_type = self._determine_vuln_type(desc)
                features['types'].append(vuln_type)
                
                # Get severity
                severity = "medium"  # Default
                if 'metrics' in cve['cve'] and 'cvssMetricV31' in cve['cve']['metrics']:
                    score = cve['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                    severity = self._score_to_severity(score)
                features['severities'].append(severity)
                
                features['is_fp'].append(0)
                features['payloads'].append("")
                features['urls'].append("")
                features['has_code'].append(0)
            except (KeyError, IndexError) as e:
                logger.warning(f"Error processing CVE: {e}")
                continue
                
        # Process WAF logs
        for log in data.get('waf_logs', []):
            try:
                # Combine relevant fields
                if isinstance(log, dict):
                    text_parts = []
                    for field in ['request_method', 'request_uri', 'rule_message']:
                        if field in log:
                            text_parts.append(str(log[field]))
                    text = " ".join(text_parts)
                    
                    if not text:
                        continue
                        
                    features['texts'].append(text)
                    
                    # Determine type from rule ID or message
                    if 'rule_id' in log:
                        rule_id = str(log['rule_id'])
                        if rule_id.startswith('94'):
                            vuln_type = "sql_injection"
                        elif rule_id.startswith('95'):
                            vuln_type = "xss"
                        elif rule_id.startswith('93'):
                            vuln_type = "lfi"
                        else:
                            vuln_type = self._determine_vuln_type(text)
                    else:
                        vuln_type = self._determine_vuln_type(text)
                        
                    features['types'].append(vuln_type)
                    
                    # Get severity
                    severity = log.get('severity', 'medium').lower()
                    features['severities'].append(severity)
                    
                    features['is_fp'].append(0)
                    features['payloads'].append(log.get('request_uri', ""))
                    features['urls'].append(log.get('request_uri', ""))
                    features['has_code'].append(0)
                else:
                    continue
            except Exception as e:
                logger.warning(f"Error processing WAF log: {e}")
                continue
                
        # Process pen test findings
        for finding in data.get('pen_test_findings', []):
            try:
                if isinstance(finding, dict):
                    # Extract text
                    text_parts = []
                    for field in ['title', 'description', 'impact']:
                        if field in finding:
                            text_parts.append(str(finding[field]))
                    text = " ".join(text_parts)
                    
                    if not text:
                        continue
                        
                    features['texts'].append(text)
                    
                    # Determine type
                    if 'title' in finding:
                        vuln_type = self._determine_vuln_type(finding['title'])
                    else:
                        vuln_type = self._determine_vuln_type(text)
                        
                    features['types'].append(vuln_type)
                    
                    # Get severity
                    severity = finding.get('severity', 'medium').lower()
                    features['severities'].append(severity)
                    
                    features['is_fp'].append(0)
                    features['payloads'].append("")
                    features['urls'].append("")
                    features['has_code'].append(0)
                else:
                    continue
            except Exception as e:
                logger.warning(f"Error processing pen test finding: {e}")
                continue
                
        # Process OWASP resources
        for resource in data.get('owasp_resources', []):
            try:
                if isinstance(resource, dict):
                    # Handle different formats
                    if 'sections' in resource:
                        for section in resource['sections']:
                            text = f"{section.get('title', '')} {section.get('content', '')}"
                            if not text.strip():
                                continue
                                
                            features['texts'].append(text)
                            features['types'].append(self._determine_vuln_type(text))
                            features['severities'].append('medium')  # Default
                            features['is_fp'].append(0)
                            features['payloads'].append("")
                            features['urls'].append(resource.get('url', ""))
                            features['has_code'].append(1 if '```' in text else 0)
                    elif 'content' in resource:
                        text = resource['content']
                        features['texts'].append(text)
                        features['types'].append(self._determine_vuln_type(text))
                        features['severities'].append('medium')  # Default
                        features['is_fp'].append(0)
                        features['payloads'].append("")
                        features['urls'].append(resource.get('url', ""))
                        features['has_code'].append(1 if '```' in text else 0)
                    elif 'categories' in resource:
                        for category in resource['categories']:
                            text = f"{category.get('name', '')} {category.get('description', '')}"
                            if not text.strip():
                                continue
                                
                            features['texts'].append(text)
                            features['types'].append(category.get('id', 'unknown').lower())
                            features['severities'].append('medium')  # Default
                            features['is_fp'].append(0)
                            features['payloads'].append("")
                            features['urls'].append("")
                            features['has_code'].append(0)
                else:
                    continue
            except Exception as e:
                logger.warning(f"Error processing OWASP resource: {e}")
                continue
                
        # Process GitHub security data
        for item in data.get('github_security_data', []):
            try:
                if isinstance(item, dict) and 'content' in item:
                    # Split content into chunks to avoid too large texts
                    content = item['content']
                    chunks = self._split_into_chunks(content)
                    
                    for chunk in chunks:
                        features['texts'].append(chunk)
                        features['types'].append(self._determine_vuln_type(chunk))
                        features['severities'].append('medium')  # Default
                        features['is_fp'].append(0)
                        features['payloads'].append("")
                        features['urls'].append(item.get('url', ""))
                        features['has_code'].append(1 if '```' in chunk else 0)
            except Exception as e:
                logger.warning(f"Error processing GitHub data: {e}")
                continue
                
        # Process CAPEC attack patterns
        for pattern in data.get('capec_attack_patterns', []):
            try:
                if isinstance(pattern, dict):
                    # Combine description and examples
                    text_parts = [pattern.get('description', '')]
                    for example in pattern.get('examples', []):
                        text_parts.append(example)
                    text = " ".join(text_parts)
                    
                    if not text.strip():
                        continue
                        
                    features['texts'].append(text)
                    features['types'].append(self._determine_vuln_type(pattern.get('name', '')))
                    features['severities'].append('medium')  # Default
                    features['is_fp'].append(0)
                    features['payloads'].append("")
                    features['urls'].append("")
                    features['has_code'].append(1 if '```' in text or '<code>' in text else 0)
            except Exception as e:
                logger.warning(f"Error processing CAPEC pattern: {e}")
                continue
                
        # Process CWE weaknesses
        for weakness in data.get('cwe_weaknesses', []):
            try:
                if isinstance(weakness, dict):
                    # Combine description and examples
                    text_parts = [weakness.get('description', '')]
                    for example in weakness.get('examples', []):
                        text_parts.append(example)
                    text = " ".join(text_parts)
                    
                    if not text.strip():
                        continue
                        
                    features['texts'].append(text)
                    features['types'].append(self._determine_vuln_type(weakness.get('name', '')))
                    features['severities'].append('medium')  # Default
                    features['is_fp'].append(0)
                    features['payloads'].append("")
                    features['urls'].append("")
                    features['has_code'].append(1 if '```' in text or '<code>' in text else 0)
            except Exception as e:
                logger.warning(f"Error processing CWE weakness: {e}")
                continue
                
        # Process synthetic data
        for item in data.get('synthetic_data', []):
            try:
                if isinstance(item, dict):
                    text = item.get('description', '')
                    if not text.strip():
                        continue
                        
                    features['texts'].append(text)
                    features['types'].append(item.get('type', 'unknown').lower().replace(' ', '_'))
                    features['severities'].append(item.get('severity', 'medium').lower())
                    features['is_fp'].append(0)
                    features['payloads'].append(item.get('payload', ""))
                    features['urls'].append(item.get('endpoint', ""))
                    features['has_code'].append(0)
            except Exception as e:
                logger.warning(f"Error processing synthetic data: {e}")
                continue
                
        # Add some false positives for balance
        fp_texts = [
            "Normal user login attempt with valid credentials",
            "Regular search query for products",
            "Standard API request with proper authentication",
            "Legitimate file upload with allowed extension",
            "Valid password reset request from authorized user",
            "Normal HTTP GET request to public endpoint",
            "Standard form submission with valid data",
            "Regular user profile update",
            "Normal pagination request",
            "Standard sorting parameter in API call"
        ]
        for text in fp_texts:
            features['texts'].append(text)
            features['types'].append('normal')
            features['severities'].append('low')
            features['is_fp'].append(1)
            features['payloads'].append("")
            features['urls'].append("")
            features['has_code'].append(0)
            
        # Ensure all lists have the same length
        min_length = min(len(features[key]) for key in features)
        for key in features:
            features[key] = features[key][:min_length]
            
        logger.info(f"Extracted features from {min_length} samples")
        return features
        
    def _extract_numerical_features(self, features: Dict[str, List]) -> Optional[np.ndarray]:
        """Extract numerical features from the data"""
        try:
            # Create numerical features
            numerical_features = []
            
            for i in range(len(features['texts'])):
                sample_features = []
                
                # Text length
                sample_features.append(len(features['texts'][i]))
                
                # Has payload
                sample_features.append(1 if features['payloads'][i] else 0)
                
                # Has URL
                sample_features.append(1 if features['urls'][i] else 0)
                
                # Has code
                sample_features.append(features['has_code'][i])
                
                # Word count
                sample_features.append(len(features['texts'][i].split()))
                
                # Special character count
                special_chars = sum(1 for c in features['texts'][i] if c in string.punctuation)
                sample_features.append(special_chars)
                
                numerical_features.append(sample_features)
                
            return np.array(numerical_features)
            
        except Exception as e:
            logger.error(f"Error extracting numerical features: {e}")
            return None
            
    def _preprocess_text(self, text: str) -> str:
        """Preprocess text with advanced NLP techniques"""
        try:
            # Convert to lowercase
            text = text.lower()
            
            # Remove code blocks for cleaner text
            text = re.sub(r'```.*?```', ' code_block ', text, flags=re.DOTALL)
            text = re.sub(r'<code>.*?</code>', ' code_block ', text, flags=re.DOTALL)
            
            # Remove URLs
            text = re.sub(r'https?://\S+', ' url ', text)
            
            # Remove HTML tags
            text = re.sub(r'<.*?>', ' ', text)
            
            # Remove special characters but keep important ones for security context
            text = re.sub(r'[^\w\s\'"><=/]', ' ', text)
            
            # Tokenize
            tokens = word_tokenize(text)
            
            # Remove stopwords but keep important ones for security context
            important_words = {'not', 'no', 'nor', 'against', 'very', 'can', 'cannot'}
            filtered_tokens = [word for word in tokens if word not in self.stop_words or word in important_words]
            
            # Lemmatize
            lemmatized_tokens = [self.lemmatizer.lemmatize(word) for word in filtered_tokens]
            
            # Join tokens back into text
            processed_text = ' '.join(lemmatized_tokens)
            
            return processed_text
            
        except Exception as e:
            logger.error(f"Error preprocessing text: {e}")
            return text
            
    def _determine_vuln_type(self, text: str) -> str:
        """Determine vulnerability type from text"""
        text = text.lower()
        
        # Define patterns for different vulnerability types
        patterns = {
            'sql_injection': ['sql injection', 'sqli', 'sql', 'database injection'],
            'xss': ['xss', 'cross site scripting', 'cross-site scripting', 'script injection'],
            'csrf': ['csrf', 'cross site request forgery', 'cross-site request forgery'],
            'ssrf': ['ssrf', 'server side request forgery', 'server-side request forgery'],
            'xxe': ['xxe', 'xml external entity', 'xml injection'],
            'command_injection': ['command injection', 'os command', 'shell injection', 'rce', 'remote code execution'],
            'path_traversal': ['path traversal', 'directory traversal', 'lfi', 'local file inclusion', 'rfi'],
            'ssti': ['ssti', 'server side template injection', 'template injection'],
            'open_redirect': ['open redirect', 'unvalidated redirect'],
            'idor': ['idor', 'insecure direct object reference'],
            'authentication': ['authentication', 'auth', 'login', 'password'],
            'authorization': ['authorization', 'access control', 'privilege']
        }
        
        # Check each pattern
        for vuln_type, keywords in patterns.items():
            if any(keyword in text for keyword in keywords):
                return vuln_type
                
        # Default to 'other' if no match
        return 'other'
        
    def _score_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity level"""
        if score >= 9.0:
            return 'critical'
        elif score >= 7.0:
            return 'high'
        elif score >= 4.0:
            return 'medium'
        else:
            return 'low'
            
    def _split_into_chunks(self, text: str, max_length: int = 1000) -> List[str]:
        """Split long text into smaller chunks"""
        if len(text) <= max_length:
            return [text]
            
        # Split by paragraphs first
        paragraphs = text.split('\n\n')
        
        chunks = []
        current_chunk = ""
        
        for paragraph in paragraphs:
            if len(current_chunk) + len(paragraph) <= max_length:
                current_chunk += paragraph + "\n\n"
            else:
                if current_chunk:
                    chunks.append(current_chunk)
                
                # If paragraph itself is too long, split it further
                if len(paragraph) > max_length:
                    sentences = paragraph.split('. ')
                    current_chunk = ""
                    
                    for sentence in sentences:
                        if len(current_chunk) + len(sentence) <= max_length:
                            current_chunk += sentence + ". "
                        else:
                            if current_chunk:
                                chunks.append(current_chunk)
                            current_chunk = sentence + ". "
                else:
                    current_chunk = paragraph + "\n\n"
        
        if current_chunk:
            chunks.append(current_chunk)
            
        return chunks

# If run directly, preprocess data
if __name__ == "__main__":
    try:
        # Load the collected data
        data_file = TRAINING_DATA_DIR / "enhanced_combined_data.json"
        with open(data_file, 'r') as f:
            data = json.load(f)
            
        # Preprocess the data
        preprocessor = EnhancedDataPreprocessor()
        preprocessed_data = preprocessor.preprocess(data)
        
        logger.info("Data preprocessing completed successfully")
        
    except Exception as e:
        logger.error(f"Error running data preprocessor: {e}", exc_info=True)
