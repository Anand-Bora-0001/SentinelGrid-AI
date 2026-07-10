"""
SentinelGrid Advanced ML Engine with Random Forest
Provides intelligent threat detection, anomaly detection, and attack classification
"""
import logging
import numpy as np
import pandas as pd
import joblib
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from pathlib import Path

# ML imports
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.feature_extraction.text import TfidfVectorizer
from imblearn.over_sampling import SMOTE
import matplotlib.pyplot as plt
import seaborn as sns

from .config import settings

logger = logging.getLogger(__name__)

@dataclass
class MLPrediction:
    """ML prediction result"""
    threat_level: str  # BENIGN, LOW, MEDIUM, HIGH, CRITICAL
    confidence: float  # 0.0 to 1.0
    threat_probability: float  # 0.0 to 1.0
    anomaly_score: float  # -1.0 to 1.0 (Isolation Forest)
    feature_importance: Dict[str, float]
    model_version: str
    prediction_time: str

@dataclass
class ModelMetrics:
    """Model performance metrics"""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    auc_score: float
    confusion_matrix: List[List[int]]
    feature_importance: Dict[str, float]
    training_samples: int
    model_version: str
    last_trained: str

class FeatureExtractor:
    """Extract features from attack events for ML training"""
    
    def __init__(self):
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=100,
            stop_words='english',
            ngram_range=(1, 2)
        )
        self.label_encoders = {}
        self.is_fitted = False
    
    def extract_features(self, events: List[Dict]) -> pd.DataFrame:
        """Extract comprehensive features from attack events"""
        features = []
        
        for event in events:
            feature_dict = {
                # Basic features
                'source_port': event.get('source_port', 0),
                'severity_encoded': self._encode_severity(event.get('severity', 'UNKNOWN')),
                'service_encoded': self._encode_categorical('service', event.get('service', 'UNKNOWN')),
                
                # Time-based features
                'hour_of_day': self._extract_hour(event.get('timestamp')),
                'day_of_week': self._extract_day_of_week(event.get('timestamp')),
                'is_weekend': self._is_weekend(event.get('timestamp')),
                
                # IP-based features
                'ip_entropy': self._calculate_ip_entropy(event.get('source_ip', '')),
                'is_private_ip': self._is_private_ip(event.get('source_ip', '')),
                'ip_geolocation_risk': self._calculate_geo_risk(event.get('location', {})),
                
                # Payload analysis
                'payload_length': len(event.get('payload', '') or ''),
                'has_special_chars': self._has_special_characters(event.get('payload', '')),
                'command_risk_score': self._calculate_command_risk(event.get('command', '')),
                'endpoint_risk_score': self._calculate_endpoint_risk(event.get('endpoint', '')),
                
                # Authentication features
                'username_length': len(event.get('username', '') or ''),
                'password_length': len(event.get('password', '') or ''),
                'is_common_username': self._is_common_username(event.get('username', '')),
                'password_complexity': self._calculate_password_complexity(event.get('password', '')),
                
                # Behavioral features
                'method_encoded': self._encode_categorical('method', event.get('method', 'UNKNOWN')),
                'threat_score': event.get('threat_score', 0.0),
                
                # Text features (will be processed separately)
                'payload_text': event.get('payload', '') or '',
                'command_text': event.get('command', '') or '',
                'endpoint_text': event.get('endpoint', '') or ''
            }
            
            features.append(feature_dict)
        
        df = pd.DataFrame(features)
        
        # Process text features with TF-IDF
        if not df.empty:
            df = self._add_text_features(df)
        
        return df
    
    def _encode_severity(self, severity: str) -> int:
        """Encode severity levels"""
        severity_map = {
            'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4, 'UNKNOWN': 0
        }
        return severity_map.get(severity.upper(), 0)
    
    def _encode_categorical(self, feature_name: str, value: str) -> int:
        """Encode categorical features with label encoder"""
        if feature_name not in self.label_encoders:
            self.label_encoders[feature_name] = LabelEncoder()
        
        encoder = self.label_encoders[feature_name]
        
        try:
            if hasattr(encoder, 'classes_'):
                # Encoder is fitted
                if value in encoder.classes_:
                    return encoder.transform([value])[0]
                else:
                    # Unknown value, return most common class or 0
                    return 0
            else:
                # Encoder not fitted, fit with current value
                return encoder.fit_transform([value])[0]
        except Exception:
            return 0
    
    def _extract_hour(self, timestamp: str) -> int:
        """Extract hour from timestamp"""
        try:
            if timestamp:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                return dt.hour
        except Exception:
            pass
        return 0
    
    def _extract_day_of_week(self, timestamp: str) -> int:
        """Extract day of week from timestamp"""
        try:
            if timestamp:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                return dt.weekday()
        except Exception:
            pass
        return 0
    
    def _is_weekend(self, timestamp: str) -> int:
        """Check if timestamp is weekend"""
        try:
            if timestamp:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                return 1 if dt.weekday() >= 5 else 0
        except Exception:
            pass
        return 0
    
    def _calculate_ip_entropy(self, ip: str) -> float:
        """Calculate entropy of IP address"""
        if not ip:
            return 0.0
        
        # Simple entropy calculation
        chars = list(ip.replace('.', ''))
        if not chars:
            return 0.0
        
        char_counts = {}
        for char in chars:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        entropy = 0.0
        total_chars = len(chars)
        for count in char_counts.values():
            prob = count / total_chars
            if prob > 0:
                entropy -= prob * np.log2(prob)
        
        return entropy
    
    def _is_private_ip(self, ip: str) -> int:
        """Check if IP is private"""
        if not ip:
            return 0
        
        private_ranges = [
            '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
            '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
            '127.', '169.254.'
        ]
        
        return 1 if any(ip.startswith(prefix) for prefix in private_ranges) else 0
    
    def _calculate_geo_risk(self, location: Dict) -> float:
        """Calculate geographical risk score"""
        if not location:
            return 0.5
        
        country_code = location.get('country_code', '')
        
        # High-risk countries
        high_risk_countries = {
            'CN', 'RU', 'KP', 'IR', 'PK', 'BD', 'VN', 'IN', 'BR', 'TR'
        }
        
        if country_code in high_risk_countries:
            return 0.8
        elif country_code in {'US', 'GB', 'DE', 'FR', 'CA', 'AU', 'JP'}:
            return 0.2
        else:
            return 0.5
    
    def _has_special_characters(self, text: str) -> int:
        """Check if text contains special characters"""
        if not text:
            return 0
        
        special_chars = set('!@#$%^&*()[]{}|\\:";\'<>?,./')
        return 1 if any(char in special_chars for char in text) else 0
    
    def _calculate_command_risk(self, command: str) -> float:
        """Calculate risk score for command"""
        if not command:
            return 0.0
        
        command_lower = command.lower()
        
        # High-risk commands
        high_risk_patterns = [
            'rm -rf', 'del /f', 'format', 'fdisk', 'mkfs',
            'cat /etc/passwd', 'cat /etc/shadow', 'sudo su',
            'wget', 'curl', 'nc -', 'netcat', 'bash -i',
            'python -c', 'perl -e', 'php -r', 'eval(',
            'exec(', 'system(', 'shell_exec', 'passthru'
        ]
        
        risk_score = 0.0
        for pattern in high_risk_patterns:
            if pattern in command_lower:
                risk_score += 0.3
        
        # Additional risk factors
        if len(command) > 100:
            risk_score += 0.1
        
        if any(char in command for char in '|;&$`'):
            risk_score += 0.2
        
        return min(risk_score, 1.0)
    
    def _calculate_endpoint_risk(self, endpoint: str) -> float:
        """Calculate risk score for endpoint"""
        if not endpoint:
            return 0.0
        
        endpoint_lower = endpoint.lower()
        
        # High-risk endpoints
        high_risk_patterns = [
            '/admin', '/wp-admin', '/phpmyadmin', '/cpanel',
            '.php', '.asp', '.jsp', '/config', '/backup',
            '/test', '/debug', '/api/admin', '/management'
        ]
        
        risk_score = 0.0
        for pattern in high_risk_patterns:
            if pattern in endpoint_lower:
                risk_score += 0.4
        
        return min(risk_score, 1.0)
    
    def _is_common_username(self, username: str) -> int:
        """Check if username is commonly attacked"""
        if not username:
            return 0
        
        common_usernames = {
            'admin', 'administrator', 'root', 'user', 'guest',
            'test', 'demo', 'sa', 'oracle', 'postgres', 'mysql'
        }
        
        return 1 if username.lower() in common_usernames else 0
    
    def _calculate_password_complexity(self, password: str) -> float:
        """Calculate password complexity score"""
        if not password:
            return 0.0
        
        score = 0.0
        
        # Length factor
        if len(password) >= 8:
            score += 0.3
        elif len(password) >= 6:
            score += 0.2
        elif len(password) >= 4:
            score += 0.1
        
        # Character diversity
        if any(c.isupper() for c in password):
            score += 0.2
        if any(c.islower() for c in password):
            score += 0.2
        if any(c.isdigit() for c in password):
            score += 0.2
        if any(c in '!@#$%^&*()[]{}|\\:";\'<>?,./' for c in password):
            score += 0.3
        
        return min(score, 1.0)
    
    def _add_text_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add TF-IDF features from text fields"""
        try:
            # Combine text fields
            text_combined = (
                df['payload_text'].fillna('') + ' ' +
                df['command_text'].fillna('') + ' ' +
                df['endpoint_text'].fillna('')
            ).str.strip()
            
            if not self.is_fitted and len(text_combined) > 0:
                # Fit TF-IDF vectorizer
                tfidf_features = self.tfidf_vectorizer.fit_transform(text_combined)
                self.is_fitted = True
            elif self.is_fitted:
                # Transform using fitted vectorizer
                tfidf_features = self.tfidf_vectorizer.transform(text_combined)
            else:
                # No text data, create empty features
                tfidf_features = np.zeros((len(df), 100))
            
            # Add TF-IDF features to dataframe
            feature_names = [f'tfidf_{i}' for i in range(tfidf_features.shape[1])]
            tfidf_df = pd.DataFrame(
                tfidf_features.toarray() if hasattr(tfidf_features, 'toarray') else tfidf_features,
                columns=feature_names,
                index=df.index
            )
            
            # Remove text columns and add TF-IDF features
            df = df.drop(['payload_text', 'command_text', 'endpoint_text'], axis=1)
            df = pd.concat([df, tfidf_df], axis=1)
            
        except Exception as e:
            logger.error(f"Error adding text features: {e}")
            # Remove text columns if TF-IDF fails
            df = df.drop(['payload_text', 'command_text', 'endpoint_text'], axis=1, errors='ignore')
        
        return df

class RandomForestMLEngine:
    """Advanced Random Forest ML Engine for threat detection"""
    
    def __init__(self):
        self.model = None
        self.anomaly_detector = None
        self.scaler = StandardScaler()
        self.feature_extractor = FeatureExtractor()
        self.model_version = "1.0.0"
        self.model_path = Path("models")
        self.model_path.mkdir(exist_ok=True)
        
        # Model parameters
        self.rf_params = {
            'n_estimators': 100,
            'max_depth': 20,
            'min_samples_split': 5,
            'min_samples_leaf': 2,
            'random_state': 42,
            'n_jobs': -1
        }
        
        self.isolation_params = {
            'n_estimators': 100,
            'contamination': 0.1,
            'random_state': 42,
            'n_jobs': -1
        }
        
        # Load existing model if available
        self._load_model()
    
    def train_model(self, events: List[Dict], retrain: bool = False) -> ModelMetrics:
        """Train Random Forest model on attack events"""
        try:
            logger.info(f"Training ML model with {len(events)} events...")
            
            if len(events) < 10:
                raise ValueError("Need at least 10 events to train model")
            
            # Extract features
            features_df = self.feature_extractor.extract_features(events)
            
            if features_df.empty:
                raise ValueError("No features extracted from events")
            
            # Prepare labels (threat classification)
            labels = self._create_labels(events)
            
            # Handle class imbalance with SMOTE
            X_resampled, y_resampled = self._balance_dataset(features_df, labels)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X_resampled, y_resampled, test_size=0.2, random_state=42, stratify=y_resampled
            )
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train Random Forest classifier
            if retrain or self.model is None:
                self.model = self._train_random_forest(X_train_scaled, y_train)
            
            # Train Isolation Forest for anomaly detection
            self.anomaly_detector = IsolationForest(**self.isolation_params)
            self.anomaly_detector.fit(X_train_scaled)
            
            # Evaluate model
            metrics = self._evaluate_model(X_test_scaled, y_test, X_train.columns)
            
            # Save model
            self._save_model()
            
            logger.info(f"Model training completed. Accuracy: {metrics.accuracy:.3f}")
            return metrics
            
        except Exception as e:
            logger.error(f"Model training failed: {e}")
            raise
    
    def predict_threat(self, event: Dict) -> MLPrediction:
        """Predict threat level for a single event"""
        try:
            if self.model is None:
                return self._default_prediction(event)
            
            # Extract features
            features_df = self.feature_extractor.extract_features([event])
            
            if features_df.empty:
                return self._default_prediction(event)
            
            # Scale features
            features_scaled = self.scaler.transform(features_df)
            
            # Get predictions
            threat_proba = self.model.predict_proba(features_scaled)[0]
            threat_class = self.model.predict(features_scaled)[0]
            
            # Get anomaly score
            anomaly_score = self.anomaly_detector.decision_function(features_scaled)[0]
            
            # Calculate feature importance for this prediction
            feature_importance = self._get_prediction_importance(features_df.iloc[0])
            
            # Map class to threat level
            threat_level = self._map_class_to_threat_level(threat_class)
            confidence = max(threat_proba)
            
            return MLPrediction(
                threat_level=threat_level,
                confidence=confidence,
                threat_probability=threat_proba[1] if len(threat_proba) > 1 else confidence,
                anomaly_score=anomaly_score,
                feature_importance=feature_importance,
                model_version=self.model_version,
                prediction_time=datetime.now().isoformat()
            )
            
        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            return self._default_prediction(event)
    
    def batch_predict(self, events: List[Dict]) -> List[MLPrediction]:
        """Predict threat levels for multiple events"""
        predictions = []
        
        for event in events:
            prediction = self.predict_threat(event)
            predictions.append(prediction)
        
        return predictions
    
    def update_model(self, new_events: List[Dict]) -> bool:
        """Incrementally update model with new events"""
        try:
            if len(new_events) < 5:
                logger.info("Not enough new events for model update")
                return False
            
            logger.info(f"Updating model with {len(new_events)} new events")
            
            # For now, retrain the model (in production, use incremental learning)
            self.train_model(new_events, retrain=True)
            
            return True
            
        except Exception as e:
            logger.error(f"Model update failed: {e}")
            return False
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model"""
        return {
            'model_version': self.model_version,
            'model_type': 'Random Forest + Isolation Forest',
            'is_trained': self.model is not None,
            'feature_count': len(self.scaler.feature_names_in_) if hasattr(self.scaler, 'feature_names_in_') else 0,
            'rf_params': self.rf_params,
            'isolation_params': self.isolation_params,
            'model_path': str(self.model_path)
        }
    
    def _create_labels(self, events: List[Dict]) -> np.ndarray:
        """Create labels for training based on severity and threat indicators"""
        labels = []
        
        for event in events:
            severity = event.get('severity', 'UNKNOWN').upper()
            ai_label = event.get('ai_label', 'unknown').lower()
            threat_score = event.get('threat_score', 0.0)
            
            # Create binary classification: 0 = benign, 1 = malicious
            if severity in ['CRITICAL', 'HIGH'] or ai_label == 'malicious' or threat_score > 0.7:
                labels.append(1)  # Malicious
            else:
                labels.append(0)  # Benign
        
        return np.array(labels)
    
    def _balance_dataset(self, X: pd.DataFrame, y: np.ndarray) -> Tuple[pd.DataFrame, np.ndarray]:
        """Balance dataset using SMOTE"""
        try:
            # Check if we have both classes
            unique_classes = np.unique(y)
            if len(unique_classes) < 2:
                logger.warning("Only one class present, skipping SMOTE")
                return X, y
            
            # Apply SMOTE
            smote = SMOTE(random_state=42)
            X_resampled, y_resampled = smote.fit_resample(X, y)
            
            logger.info(f"Dataset balanced: {len(X)} -> {len(X_resampled)} samples")
            return pd.DataFrame(X_resampled, columns=X.columns), y_resampled
            
        except Exception as e:
            logger.warning(f"SMOTE failed, using original dataset: {e}")
            return X, y
    
    def _train_random_forest(self, X_train: np.ndarray, y_train: np.ndarray) -> RandomForestClassifier:
        """Train Random Forest with hyperparameter tuning"""
        # Grid search for best parameters
        param_grid = {
            'n_estimators': [50, 100, 200],
            'max_depth': [10, 20, None],
            'min_samples_split': [2, 5, 10]
        }
        
        rf = RandomForestClassifier(random_state=42, n_jobs=-1)
        
        # Use grid search if we have enough data
        if len(X_train) > 100:
            grid_search = GridSearchCV(
                rf, param_grid, cv=3, scoring='f1', n_jobs=-1
            )
            grid_search.fit(X_train, y_train)
            best_model = grid_search.best_estimator_
            logger.info(f"Best RF parameters: {grid_search.best_params_}")
        else:
            # Use default parameters for small datasets
            best_model = RandomForestClassifier(**self.rf_params)
            best_model.fit(X_train, y_train)
        
        return best_model
    
    def _evaluate_model(self, X_test: np.ndarray, y_test: np.ndarray, feature_names: List[str]) -> ModelMetrics:
        """Evaluate model performance"""
        # Predictions
        y_pred = self.model.predict(X_test)
        y_proba = self.model.predict_proba(X_test)
        
        # Metrics
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
        recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
        f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
        
        # AUC score
        try:
            auc = roc_auc_score(y_test, y_proba[:, 1] if y_proba.shape[1] > 1 else y_proba[:, 0])
        except Exception:
            auc = 0.0
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred).tolist()
        
        # Feature importance
        feature_importance = dict(zip(
            feature_names,
            self.model.feature_importances_
        ))
        
        return ModelMetrics(
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1,
            auc_score=auc,
            confusion_matrix=cm,
            feature_importance=feature_importance,
            training_samples=len(X_test),
            model_version=self.model_version,
            last_trained=datetime.now().isoformat()
        )
    
    def _get_prediction_importance(self, features: pd.Series) -> Dict[str, float]:
        """Get feature importance for a specific prediction"""
        if self.model is None:
            return {}
        
        # Get top 10 most important features for this prediction
        feature_importance = dict(zip(
            features.index,
            self.model.feature_importances_
        ))
        
        # Sort by importance and return top 10
        sorted_importance = sorted(
            feature_importance.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        return dict(sorted_importance)
    
    def _map_class_to_threat_level(self, class_pred: int) -> str:
        """Map prediction class to threat level"""
        if class_pred == 1:
            return "HIGH"
        else:
            return "LOW"
    
    def _default_prediction(self, event: Dict) -> MLPrediction:
        """Return default prediction when model is not available"""
        severity = event.get('severity', 'UNKNOWN').upper()
        threat_score = event.get('threat_score', 0.5)
        
        return MLPrediction(
            threat_level=severity if severity in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] else 'MEDIUM',
            confidence=0.5,
            threat_probability=threat_score,
            anomaly_score=0.0,
            feature_importance={},
            model_version="default",
            prediction_time=datetime.now().isoformat()
        )
    
    def _save_model(self):
        """Save trained model to disk"""
        try:
            model_data = {
                'model': self.model,
                'anomaly_detector': self.anomaly_detector,
                'scaler': self.scaler,
                'feature_extractor': self.feature_extractor,
                'model_version': self.model_version
            }
            
            model_file = self.model_path / f"ml_model_v{self.model_version}.joblib"
            joblib.dump(model_data, model_file)
            
            logger.info(f"Model saved to {model_file}")
            
        except Exception as e:
            logger.error(f"Failed to save model: {e}")
    
    def _load_model(self):
        """Load trained model from disk"""
        try:
            model_file = self.model_path / f"ml_model_v{self.model_version}.joblib"
            
            if model_file.exists():
                model_data = joblib.load(model_file)
                
                self.model = model_data['model']
                self.anomaly_detector = model_data['anomaly_detector']
                self.scaler = model_data['scaler']
                self.feature_extractor = model_data['feature_extractor']
                
                logger.info(f"Model loaded from {model_file}")
            else:
                logger.info("No existing model found")
                
        except Exception as e:
            logger.error(f"Failed to load model: {e}")

# Global ML engine instance
ml_engine = RandomForestMLEngine()
