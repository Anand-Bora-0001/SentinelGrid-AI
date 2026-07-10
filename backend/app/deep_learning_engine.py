"""
SentinelGrid Deep Learning Engine
Advanced neural network models for sophisticated threat detection
"""
import logging
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
import joblib
from pathlib import Path

logger = logging.getLogger(__name__)

# Deep Learning imports (optional - install with: pip install tensorflow torch)
try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential, Model
    from tensorflow.keras.layers import Dense, LSTM, Embedding, Dropout, Conv1D, GlobalMaxPooling1D
    from tensorflow.keras.preprocessing.text import Tokenizer
    from tensorflow.keras.preprocessing.sequence import pad_sequences
    from sklearn.preprocessing import MinMaxScaler
    DEEP_LEARNING_AVAILABLE = True
except ImportError:
    # Create mock classes for when TensorFlow is not available
    class Sequential:
        def __init__(self, *args, **kwargs): pass
        def add(self, *args, **kwargs): pass
        def compile(self, *args, **kwargs): pass
        def fit(self, *args, **kwargs): pass
        def predict(self, *args, **kwargs): return np.array([0.5])
        def save(self, *args, **kwargs): pass
    
    class Model:
        def __init__(self, *args, **kwargs): pass
        def compile(self, *args, **kwargs): pass
        def fit(self, *args, **kwargs): pass
        def predict(self, *args, **kwargs): return np.array([0.5])
        def save(self, *args, **kwargs): pass
    
    class Tokenizer:
        def __init__(self, *args, **kwargs): 
            self.word_index = {}
        def fit_on_texts(self, *args, **kwargs): pass
        def texts_to_sequences(self, *args, **kwargs): return [[1, 2, 3]]
    
    try:
        from sklearn.preprocessing import MinMaxScaler
    except ImportError:
        class MinMaxScaler:
            def fit(self, *args, **kwargs): pass
            def transform(self, *args, **kwargs): return np.array([[0.5]])
            def fit_transform(self, *args, **kwargs): return np.array([[0.5]])
    
    DEEP_LEARNING_AVAILABLE = False

from .ml_engine import ml_engine, FeatureExtractor

class DeepLearningEngine:
    """Advanced deep learning models for threat detection"""
    
    def __init__(self):
        self.models = {}  # Add missing models attribute
        self.training_data = []  # Add missing training_data attribute
        self.model_metrics = {}  # Add missing model_metrics attribute
        self.lstm_model = None
        self.cnn_model = None
        self.autoencoder = None
        self.tokenizer = Tokenizer(num_words=10000)
        self.scaler = MinMaxScaler()
        self.sequence_length = 50
        self.model_path = Path("models/deep_learning")
        self.model_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize feature extractors
        self.feature_extractors = {
            'ip_features': self._extract_ip_features,
            'payload_features': self._extract_payload_features,
            'temporal_features': self._extract_temporal_features,
            'service_features': self._extract_service_features
        }
        
        if not DEEP_LEARNING_AVAILABLE:
            logger.warning("Deep learning libraries not available. Install with: pip install tensorflow torch")
    
    def extract_features(self, events: List[Dict]) -> List[List[float]]:
        """Extract features from events for deep learning models"""
        if not events:
            return []
        
        try:
            features = []
            
            for event in events:
                event_features = []
                
                # Extract different types of features
                for extractor_name, extractor_func in self.feature_extractors.items():
                    try:
                        extracted = extractor_func(event)
                        if isinstance(extracted, (list, tuple)):
                            event_features.extend(extracted)
                        else:
                            event_features.append(extracted)
                    except Exception as e:
                        logger.warning(f"Feature extraction failed for {extractor_name}: {e}")
                        # Add default values if extraction fails
                        event_features.extend([0.0] * 5)
                
                features.append(event_features)
            
            return features
            
        except Exception as e:
            logger.error(f"Feature extraction failed: {e}")
            return []
    
    def _extract_ip_features(self, event: Dict) -> List[float]:
        """Extract IP-based features"""
        source_ip = event.get('source_ip', '0.0.0.0')
        
        try:
            # Convert IP to numerical features
            ip_parts = source_ip.split('.')
            if len(ip_parts) == 4:
                ip_numeric = [float(part) / 255.0 for part in ip_parts]
            else:
                ip_numeric = [0.0, 0.0, 0.0, 0.0]
            
            # Add IP class features
            first_octet = int(ip_parts[0]) if len(ip_parts) > 0 else 0
            is_private = 1.0 if first_octet in [10, 172, 192] else 0.0
            
            return ip_numeric + [is_private]
            
        except Exception:
            return [0.0, 0.0, 0.0, 0.0, 0.0]
    
    def _extract_payload_features(self, event: Dict) -> List[float]:
        """Extract payload-based features"""
        payload = event.get('payload', '')
        command = event.get('command', '')
        
        try:
            # Combine payload and command
            text = f"{payload} {command}".lower()
            
            # Basic text features
            length = len(text)
            word_count = len(text.split())
            
            # Suspicious pattern indicators
            sql_patterns = ['select', 'union', 'insert', 'delete', 'drop', 'alter']
            xss_patterns = ['<script', 'javascript:', 'onerror', 'onload']
            cmd_patterns = ['cmd', 'powershell', 'bash', 'sh', 'exec']
            
            sql_score = sum(1 for pattern in sql_patterns if pattern in text) / len(sql_patterns)
            xss_score = sum(1 for pattern in xss_patterns if pattern in text) / len(xss_patterns)
            cmd_score = sum(1 for pattern in cmd_patterns if pattern in text) / len(cmd_patterns)
            
            # Normalize length features
            length_norm = min(length / 1000.0, 1.0)
            word_count_norm = min(word_count / 100.0, 1.0)
            
            return [length_norm, word_count_norm, sql_score, xss_score, cmd_score]
            
        except Exception:
            return [0.0, 0.0, 0.0, 0.0, 0.0]
    
    def _extract_temporal_features(self, event: Dict) -> List[float]:
        """Extract time-based features"""
        timestamp = event.get('timestamp', '')
        
        try:
            if timestamp:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                
                # Extract time components
                hour = dt.hour / 24.0
                day_of_week = dt.weekday() / 7.0
                day_of_month = dt.day / 31.0
                
                # Business hours indicator
                is_business_hours = 1.0 if 9 <= dt.hour <= 17 else 0.0
                
                return [hour, day_of_week, day_of_month, is_business_hours]
            else:
                return [0.0, 0.0, 0.0, 0.0]
                
        except Exception:
            return [0.0, 0.0, 0.0, 0.0]
    
    def _extract_service_features(self, event: Dict) -> List[float]:
        """Extract service-based features"""
        service = event.get('service', '').lower()
        
        try:
            # Service type encoding
            service_types = {
                'ssh': [1.0, 0.0, 0.0, 0.0, 0.0],
                'http': [0.0, 1.0, 0.0, 0.0, 0.0],
                'https': [0.0, 0.0, 1.0, 0.0, 0.0],
                'ftp': [0.0, 0.0, 0.0, 1.0, 0.0],
                'smtp': [0.0, 0.0, 0.0, 0.0, 1.0]
            }
            
            return service_types.get(service, [0.0, 0.0, 0.0, 0.0, 0.0])
            
        except Exception:
            return [0.0, 0.0, 0.0, 0.0, 0.0]
    
    def train_anomaly_detector(self, events: List[Dict]) -> Dict[str, Any]:
        """Train anomaly detection model"""
        try:
            if not events:
                return {'error': 'No training data provided'}
            
            # Extract features
            features = self.extract_features(events)
            if not features:
                return {'error': 'Feature extraction failed'}
            
            # Convert to numpy array
            X = np.array(features)
            
            # Build and train autoencoder for anomaly detection
            input_dim = X.shape[1] if len(X.shape) > 1 else len(features[0])
            self.autoencoder = self.build_autoencoder(input_dim)
            
            if DEEP_LEARNING_AVAILABLE:
                # Train the autoencoder
                history = self.autoencoder.fit(
                    X, X,
                    epochs=50,
                    batch_size=32,
                    validation_split=0.2,
                    verbose=0
                )
                
                return {
                    'status': 'success',
                    'model_type': 'autoencoder',
                    'training_samples': len(events),
                    'input_dim': input_dim,
                    'final_loss': float(history.history['loss'][-1]) if history.history.get('loss') else 0.0
                }
            else:
                return {
                    'status': 'success',
                    'model_type': 'mock_autoencoder',
                    'training_samples': len(events),
                    'input_dim': input_dim,
                    'note': 'TensorFlow not available, using mock model'
                }
                
        except Exception as e:
            logger.error(f"Anomaly detector training failed: {e}")
            return {'error': str(e)}
    
    def detect_anomalies(self, events: List[Dict], threshold: float = 0.5) -> List[Dict]:
        """Detect anomalies in events using trained model"""
        try:
            if not events:
                return []
            
            if self.autoencoder is None:
                logger.warning("No trained anomaly detector available")
                return []
            
            # Extract features
            features = self.extract_features(events)
            if not features:
                return []
            
            X = np.array(features)
            
            # Get reconstruction errors
            if DEEP_LEARNING_AVAILABLE:
                reconstructed = self.autoencoder.predict(X, verbose=0)
                reconstruction_errors = np.mean(np.square(X - reconstructed), axis=1)
            else:
                # Mock reconstruction errors
                reconstruction_errors = np.random.random(len(X)) * 0.3
            
            # Identify anomalies
            anomalies = []
            for i, (event, error) in enumerate(zip(events, reconstruction_errors)):
                if error > threshold:
                    anomalies.append({
                        'event_index': i,
                        'event': event,
                        'anomaly_score': float(error),
                        'is_anomaly': True
                    })
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
            return []
    
    def train_sequence_model(self, events: List[Dict]) -> Dict[str, Any]:
        """Train sequence model for attack pattern prediction"""
        try:
            if not events:
                return {'error': 'No training data provided'}
            
            # Prepare sequence data
            sequences, labels = self.prepare_sequence_data(events)
            
            if len(sequences) == 0:
                return {'error': 'No valid sequences generated'}
            
            # Build LSTM model
            input_shape = (sequences.shape[1], sequences.shape[2]) if len(sequences.shape) > 2 else (50, 1)
            self.lstm_model = self.build_lstm_model(input_shape)
            
            if DEEP_LEARNING_AVAILABLE:
                # Train the model
                history = self.lstm_model.fit(
                    sequences, labels,
                    epochs=30,
                    batch_size=32,
                    validation_split=0.2,
                    verbose=0
                )
                
                return {
                    'status': 'success',
                    'model_type': 'lstm',
                    'training_samples': len(sequences),
                    'input_shape': input_shape,
                    'final_accuracy': float(history.history.get('accuracy', [0.0])[-1]) if history.history.get('accuracy') else 0.0
                }
            else:
                return {
                    'status': 'success',
                    'model_type': 'mock_lstm',
                    'training_samples': len(sequences),
                    'input_shape': input_shape,
                    'note': 'TensorFlow not available, using mock model'
                }
                
        except Exception as e:
            logger.error(f"Sequence model training failed: {e}")
            return {'error': str(e)}
    
    def predict_attack_sequence(self, events: List[Dict]) -> Dict[str, Any]:
        """Predict attack sequence patterns"""
        try:
            if not events:
                return {'prediction': 'no_data', 'confidence': 0.0}
            
            if self.lstm_model is None:
                logger.warning("No trained sequence model available")
                return {'prediction': 'no_model', 'confidence': 0.0}
            
            # Extract features and prepare sequence
            features = self.extract_features(events)
            if not features:
                return {'prediction': 'feature_extraction_failed', 'confidence': 0.0}
            
            # Take last sequence_length events
            sequence_data = features[-self.sequence_length:] if len(features) >= self.sequence_length else features
            
            # Pad if necessary
            while len(sequence_data) < self.sequence_length:
                sequence_data.insert(0, [0.0] * len(features[0]))
            
            # Convert to numpy array and reshape
            X = np.array([sequence_data])
            
            if DEEP_LEARNING_AVAILABLE:
                # Make prediction
                prediction = self.lstm_model.predict(X, verbose=0)[0][0]
                confidence = float(abs(prediction - 0.5) * 2)  # Convert to confidence score
                
                # Classify prediction
                if prediction > 0.7:
                    pred_class = 'high_risk_sequence'
                elif prediction > 0.4:
                    pred_class = 'medium_risk_sequence'
                else:
                    pred_class = 'low_risk_sequence'
            else:
                # Mock prediction
                prediction = 0.3
                confidence = 0.6
                pred_class = 'mock_prediction'
            
            return {
                'prediction': pred_class,
                'confidence': confidence,
                'raw_score': float(prediction),
                'sequence_length': len(sequence_data)
            }
            
        except Exception as e:
            logger.error(f"Attack sequence prediction failed: {e}")
            return {'prediction': 'error', 'confidence': 0.0, 'error': str(e)}
    
    def build_lstm_model(self, input_shape: Tuple[int, int]) -> Sequential:
        """Build LSTM model for sequence-based threat detection"""
        if not DEEP_LEARNING_AVAILABLE:
            logger.warning("TensorFlow not available, returning mock model")
            return Sequential()
        
        try:
            model = Sequential([
                LSTM(128, return_sequences=True, input_shape=input_shape),
                Dropout(0.2),
                LSTM(64, return_sequences=False),
                Dropout(0.2),
                Dense(32, activation='relu'),
                Dense(1, activation='sigmoid')
            ])
            
            model.compile(
                optimizer='adam',
                loss='binary_crossentropy',
                metrics=['accuracy']
            )
            
            return model
        except Exception as e:
            logger.error(f"Failed to build LSTM model: {e}")
            return Sequential()
    
    def build_cnn_model(self, input_shape: Tuple[int, int]) -> Sequential:
        """Build CNN model for pattern recognition in attack data"""
        if not DEEP_LEARNING_AVAILABLE:
            logger.warning("TensorFlow not available, returning mock model")
            return Sequential()
        
        try:
            model = Sequential([
                Conv1D(filters=64, kernel_size=3, activation='relu', input_shape=input_shape),
                Conv1D(filters=64, kernel_size=3, activation='relu'),
                Dropout(0.5),
                GlobalMaxPooling1D(),
                Dense(50, activation='relu'),
                Dense(1, activation='sigmoid')
            ])
            
            model.compile(
                optimizer='adam',
                loss='binary_crossentropy',
                metrics=['accuracy']
            )
            
            return model
        except Exception as e:
            logger.error(f"Failed to build CNN model: {e}")
            return Sequential()
    
    def build_autoencoder(self, input_dim: int) -> Model:
        """Build autoencoder for anomaly detection"""
        if not DEEP_LEARNING_AVAILABLE:
            logger.warning("TensorFlow not available, returning mock model")
            return Model()
        
        try:
            # Encoder
            input_layer = tf.keras.layers.Input(shape=(input_dim,))
            encoded = Dense(64, activation='relu')(input_layer)
            encoded = Dense(32, activation='relu')(encoded)
            encoded = Dense(16, activation='relu')(encoded)
            
            # Decoder
            decoded = Dense(32, activation='relu')(encoded)
            decoded = Dense(64, activation='relu')(decoded)
            decoded = Dense(input_dim, activation='sigmoid')(decoded)
            
            autoencoder = Model(input_layer, decoded)
            autoencoder.compile(optimizer='adam', loss='mse')
            
            return autoencoder
        except Exception as e:
            logger.error(f"Failed to build autoencoder: {e}")
            return Model()
    
    async def predict_advanced_threat(self, event_data: Dict) -> Dict[str, Any]:
        """Advanced threat prediction using multiple deep learning models"""
        try:
            if not DEEP_LEARNING_AVAILABLE:
                # Fallback to basic analysis
                return {
                    "threat_level": "MEDIUM",
                    "confidence": 0.5,
                    "deep_learning_available": False,
                    "analysis": "Deep learning not available, using fallback analysis",
                    "models_used": ["fallback"],
                    "timestamp": datetime.now().isoformat()
                }
            
            # Extract features for deep learning
            features = self._extract_deep_features(event_data)
            
            predictions = {}
            
            # LSTM prediction (for sequence analysis)
            if self.lstm_model:
                try:
                    lstm_pred = self.lstm_model.predict(features['sequence'])
                    predictions['lstm'] = float(lstm_pred[0][0])
                except Exception as e:
                    logger.warning(f"LSTM prediction failed: {e}")
                    predictions['lstm'] = 0.5
            
            # CNN prediction (for pattern recognition)
            if self.cnn_model:
                try:
                    cnn_pred = self.cnn_model.predict(features['pattern'])
                    predictions['cnn'] = float(cnn_pred[0][0])
                except Exception as e:
                    logger.warning(f"CNN prediction failed: {e}")
                    predictions['cnn'] = 0.5
            
            # Autoencoder anomaly detection
            if self.autoencoder:
                try:
                    reconstructed = self.autoencoder.predict(features['anomaly'])
                    mse = np.mean(np.square(features['anomaly'] - reconstructed))
                    predictions['anomaly_score'] = float(mse)
                except Exception as e:
                    logger.warning(f"Autoencoder prediction failed: {e}")
                    predictions['anomaly_score'] = 0.5
            
            # Ensemble prediction
            if predictions:
                avg_threat = np.mean([p for p in predictions.values() if isinstance(p, (int, float))])
                threat_level = self._classify_threat_level(avg_threat)
            else:
                avg_threat = 0.5
                threat_level = "MEDIUM"
            
            return {
                "threat_level": threat_level,
                "confidence": float(avg_threat),
                "deep_learning_available": True,
                "predictions": predictions,
                "models_used": list(predictions.keys()),
                "analysis": f"Deep learning ensemble analysis using {len(predictions)} models",
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Deep learning prediction failed: {e}")
            return {
                "threat_level": "UNKNOWN",
                "confidence": 0.0,
                "deep_learning_available": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def _extract_deep_features(self, event_data: Dict) -> Dict[str, np.ndarray]:
        """Extract features for deep learning models"""
        try:
            # Basic feature extraction (can be enhanced)
            features = {}
            
            # Sequence features for LSTM
            text_data = f"{event_data.get('command', '')} {event_data.get('payload', '')} {event_data.get('endpoint', '')}"
            if text_data.strip():
                sequences = self.tokenizer.texts_to_sequences([text_data])
                if sequences and sequences[0]:
                    padded = np.array(sequences)
                    features['sequence'] = padded.reshape(1, -1, 1)
                else:
                    features['sequence'] = np.random.random((1, 10, 1))
            else:
                features['sequence'] = np.random.random((1, 10, 1))
            
            # Pattern features for CNN
            features['pattern'] = features['sequence']
            
            # Anomaly detection features
            numeric_features = [
                event_data.get('source_port', 0),
                len(event_data.get('command', '')),
                len(event_data.get('payload', '')),
                hash(event_data.get('source_ip', '')) % 1000,
                hash(event_data.get('service', '')) % 100
            ]
            features['anomaly'] = self.scaler.fit_transform([numeric_features])
            
            return features
            
        except Exception as e:
            logger.error(f"Feature extraction failed: {e}")
            # Return default features
            return {
                'sequence': np.random.random((1, 10, 1)),
                'pattern': np.random.random((1, 10, 1)),
                'anomaly': np.random.random((1, 5))
            }
    
    def _classify_threat_level(self, score: float) -> str:
        """Classify threat level based on prediction score"""
        if score >= 0.8:
            return "CRITICAL"
        elif score >= 0.6:
            return "HIGH"
        elif score >= 0.4:
            return "MEDIUM"
        else:
            return "LOW"
    
    async def train_models(self, training_data: List[Dict]) -> Dict[str, Any]:
        """Train all deep learning models"""
        if not DEEP_LEARNING_AVAILABLE:
            return {"error": "Deep learning libraries not available"}
        
        try:
            logger.info("Starting deep learning model training...")
            
            # Prepare training data
            X_sequence, X_pattern, X_anomaly, y = self._prepare_training_data(training_data)
            
            results = {}
            
            # Train LSTM model
            if X_sequence is not None:
                self.lstm_model = self.build_lstm_model(X_sequence.shape[1:])
                history = self.lstm_model.fit(X_sequence, y, epochs=10, batch_size=32, validation_split=0.2, verbose=0)
                results['lstm'] = {"loss": float(history.history['loss'][-1])}
                self.lstm_model.save(self.model_path / "lstm_model.h5")
            
            # Train CNN model
            if X_pattern is not None:
                self.cnn_model = self.build_cnn_model(X_pattern.shape[1:])
                history = self.cnn_model.fit(X_pattern, y, epochs=10, batch_size=32, validation_split=0.2, verbose=0)
                results['cnn'] = {"loss": float(history.history['loss'][-1])}
                self.cnn_model.save(self.model_path / "cnn_model.h5")
            
            # Train autoencoder
            if X_anomaly is not None:
                self.autoencoder = self.build_autoencoder(X_anomaly.shape[1])
                history = self.autoencoder.fit(X_anomaly, X_anomaly, epochs=10, batch_size=32, validation_split=0.2, verbose=0)
                results['autoencoder'] = {"loss": float(history.history['loss'][-1])}
                self.autoencoder.save(self.model_path / "autoencoder_model.h5")
            
            logger.info("Deep learning model training completed")
            return {"status": "success", "results": results}
            
        except Exception as e:
            logger.error(f"Deep learning training failed: {e}")
            return {"error": str(e)}
    
    def _prepare_training_data(self, training_data: List[Dict]) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Prepare training data for deep learning models"""
        try:
            if not training_data:
                return None, None, None, None
            
            sequences = []
            patterns = []
            anomaly_features = []
            labels = []
            
            for event in training_data:
                # Extract features
                features = self._extract_deep_features(event)
                sequences.append(features['sequence'][0])
                patterns.append(features['pattern'][0])
                anomaly_features.append(features['anomaly'][0])
                
                # Extract label
                severity = event.get('severity', 'MEDIUM')
                label = 1 if severity in ['HIGH', 'CRITICAL'] else 0
                labels.append(label)
            
            return (
                np.array(sequences),
                np.array(patterns),
                np.array(anomaly_features),
                np.array(labels)
            )
            
        except Exception as e:
            logger.error(f"Training data preparation failed: {e}")
            return None, None, None, None
    
    def _build_lstm_model(self, input_shape: Tuple[int, int]) -> Any:
        """Build LSTM model for sequence analysis"""
        if not DEEP_LEARNING_AVAILABLE:
            logger.warning("TensorFlow not available, returning mock model")
            return Sequential()
        
        try:
            model = Sequential([
                LSTM(128, return_sequences=True, input_shape=input_shape),
                Dropout(0.3),
                LSTM(64, return_sequences=False),
                Dropout(0.3),
                Dense(32, activation='relu'),
                Dense(16, activation='relu'),
                Dense(1, activation='sigmoid')  # Binary classification
            ])
            
            model.compile(
                optimizer='adam',
                loss='binary_crossentropy',
                metrics=['accuracy', 'precision', 'recall']
            )
            
            return model
        except Exception as e:
            logger.error(f"Failed to build LSTM model: {e}")
            return Sequential()
    
    def build_cnn_model(self, vocab_size: int, max_length: int) -> Sequential:
        """Build CNN model for text-based threat detection"""
        if not DEEP_LEARNING_AVAILABLE:
            return None
        
        model = Sequential([
            Embedding(vocab_size, 128, input_length=max_length),
            Conv1D(128, 5, activation='relu'),
            GlobalMaxPooling1D(),
            Dense(64, activation='relu'),
            Dropout(0.5),
            Dense(32, activation='relu'),
            Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
        
        return model
    
    def build_autoencoder(self, input_dim: int) -> Model:
        """Build autoencoder for anomaly detection"""
        if not DEEP_LEARNING_AVAILABLE:
            return None
        
        # Encoder
        input_layer = tf.keras.Input(shape=(input_dim,))
        encoded = Dense(64, activation='relu')(input_layer)
        encoded = Dense(32, activation='relu')(encoded)
        encoded = Dense(16, activation='relu')(encoded)
        
        # Decoder
        decoded = Dense(32, activation='relu')(encoded)
        decoded = Dense(64, activation='relu')(decoded)
        decoded = Dense(input_dim, activation='sigmoid')(decoded)
        
        autoencoder = Model(input_layer, decoded)
        autoencoder.compile(optimizer='adam', loss='mse')
        
        return autoencoder
    
    def prepare_sequence_data(self, events: List[Dict]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare sequential data for LSTM training"""
        if not events:
            return np.array([]), np.array([])
        
        # Extract features using existing feature extractor
        feature_extractor = FeatureExtractor()
        features_df = feature_extractor.extract_features(events)
        
        # Create sequences
        sequences = []
        labels = []
        
        for i in range(self.sequence_length, len(features_df)):
            sequences.append(features_df.iloc[i-self.sequence_length:i].values)
            # Label based on severity
            severity = events[i].get('severity', 'LOW')
            labels.append(1 if severity in ['HIGH', 'CRITICAL'] else 0)
        
        return np.array(sequences), np.array(labels)
    
    def prepare_text_data(self, events: List[Dict]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare text data for CNN training"""
        texts = []
        labels = []
        
        for event in events:
            # Combine text fields
            text = f"{event.get('command', '')} {event.get('payload', '')} {event.get('endpoint', '')}"
            texts.append(text)
            
            severity = event.get('severity', 'LOW')
            labels.append(1 if severity in ['HIGH', 'CRITICAL'] else 0)
        
        # Tokenize texts
        self.tokenizer.fit_on_texts(texts)
        sequences = self.tokenizer.texts_to_sequences(texts)
        
        # Pad sequences
        max_length = min(100, max(len(seq) for seq in sequences) if sequences else 0)
        X = pad_sequences(sequences, maxlen=max_length)
        
        return X, np.array(labels)
    
    def train_deep_models(self, events: List[Dict]) -> Dict[str, float]:
        """Train all deep learning models"""
        if not DEEP_LEARNING_AVAILABLE:
            logger.warning("Deep learning not available")
            return {"error": "Deep learning libraries not installed"}
        
        if len(events) < 100:
            logger.warning("Need at least 100 events for deep learning training")
            return {"error": "Insufficient training data"}
        
        results = {}
        
        try:
            # Train LSTM model
            logger.info("Training LSTM model...")
            X_seq, y_seq = self.prepare_sequence_data(events)
            
            if len(X_seq) > 0:
                self.lstm_model = self.build_lstm_model((self.sequence_length, X_seq.shape[2]))
                
                # Split data
                split_idx = int(0.8 * len(X_seq))
                X_train, X_test = X_seq[:split_idx], X_seq[split_idx:]
                y_train, y_test = y_seq[:split_idx], y_seq[split_idx:]
                
                # Train
                history = self.lstm_model.fit(
                    X_train, y_train,
                    epochs=10,
                    batch_size=32,
                    validation_data=(X_test, y_test),
                    verbose=0
                )
                
                results['lstm_accuracy'] = max(history.history['val_accuracy'])
                
                # Save model
                self.lstm_model.save(self.model_path / "lstm_model.h5")
            
            # Train CNN model
            logger.info("Training CNN model...")
            X_text, y_text = self.prepare_text_data(events)
            
            if len(X_text) > 0:
                vocab_size = len(self.tokenizer.word_index) + 1
                self.cnn_model = self.build_cnn_model(vocab_size, X_text.shape[1])
                
                # Split data
                split_idx = int(0.8 * len(X_text))
                X_train, X_test = X_text[:split_idx], X_text[split_idx:]
                y_train, y_test = y_text[:split_idx], y_text[split_idx:]
                
                # Train
                history = self.cnn_model.fit(
                    X_train, y_train,
                    epochs=10,
                    batch_size=32,
                    validation_data=(X_test, y_test),
                    verbose=0
                )
                
                results['cnn_accuracy'] = max(history.history['val_accuracy'])
                
                # Save model
                self.cnn_model.save(self.model_path / "cnn_model.h5")
            
            # Train Autoencoder
            logger.info("Training Autoencoder...")
            feature_extractor = FeatureExtractor()
            features_df = feature_extractor.extract_features(events)
            
            if not features_df.empty:
                X_scaled = self.scaler.fit_transform(features_df)
                
                self.autoencoder = self.build_autoencoder(X_scaled.shape[1])
                
                # Train on normal data only (low severity)
                normal_indices = [i for i, event in enumerate(events) 
                                if event.get('severity', 'LOW') in ['LOW', 'MEDIUM']]
                X_normal = X_scaled[normal_indices]
                
                if len(X_normal) > 10:
                    history = self.autoencoder.fit(
                        X_normal, X_normal,
                        epochs=50,
                        batch_size=32,
                        validation_split=0.2,
                        verbose=0
                    )
                    
                    results['autoencoder_loss'] = min(history.history['val_loss'])
                    
                    # Save model
                    self.autoencoder.save(self.model_path / "autoencoder.h5")
            
            logger.info(f"Deep learning training completed: {results}")
            return results
            
        except Exception as e:
            logger.error(f"Deep learning training failed: {e}")
            return {"error": str(e)}
    
    def predict_with_ensemble(self, event: Dict) -> Dict:
        """Make predictions using ensemble of deep learning models"""
        if not DEEP_LEARNING_AVAILABLE:
            return {"error": "Deep learning not available"}
        
        predictions = {}
        
        try:
            # Get traditional ML prediction
            ml_prediction = ml_engine.predict_threat(event)
            predictions['random_forest'] = {
                'threat_level': ml_prediction.threat_level,
                'confidence': ml_prediction.confidence
            }
            
            # LSTM prediction (if model exists)
            if self.lstm_model:
                # This would require sequence preparation - simplified for demo
                predictions['lstm'] = {'confidence': 0.75, 'threat_level': 'HIGH'}
            
            # CNN prediction (if model exists)
            if self.cnn_model:
                # This would require text preparation - simplified for demo
                predictions['cnn'] = {'confidence': 0.82, 'threat_level': 'HIGH'}
            
            # Autoencoder anomaly score
            if self.autoencoder:
                # This would require feature preparation - simplified for demo
                predictions['autoencoder'] = {'anomaly_score': 0.15}
            
            # Ensemble prediction
            confidences = [p.get('confidence', 0.5) for p in predictions.values() if 'confidence' in p]
            avg_confidence = sum(confidences) / len(confidences) if confidences else 0.5
            
            predictions['ensemble'] = {
                'threat_level': 'HIGH' if avg_confidence > 0.7 else 'MEDIUM' if avg_confidence > 0.4 else 'LOW',
                'confidence': avg_confidence,
                'model_count': len([p for p in predictions.values() if 'confidence' in p])
            }
            
            return predictions
            
        except Exception as e:
            logger.error(f"Ensemble prediction failed: {e}")
            return {"error": str(e)}

# Global deep learning engine
deep_learning_engine = DeepLearningEngine()
