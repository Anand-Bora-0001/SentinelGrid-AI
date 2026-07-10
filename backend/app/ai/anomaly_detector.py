"""
SentinelGrid AI — Behavioral Anomaly Detection Engine (Module 1)

Learns normal user, device, and network behavior.
Detects anomalies without signatures using Isolation Forest + One-Class SVM.

Output: risk_score, confidence, explanation
"""
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from collections import defaultdict
import json
import hashlib

from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class AnomalyResult:
    """Result of anomaly detection analysis"""
    is_anomaly: bool
    anomaly_score: float       # 0.0 to 1.0 (1.0 = most anomalous)
    risk_score: float          # 0.0 to 100.0
    confidence: float          # 0.0 to 1.0
    explanation: str           # Human-readable explanation
    contributing_factors: List[Dict[str, Any]]  # Top factors driving the score
    model_used: str            # isolation_forest, one_class_svm, ensemble


class TelemetryFeatureExtractor:
    """Extract features from SecurityTelemetry for anomaly detection"""

    # High-risk protocols
    HIGH_RISK_PROTOCOLS = {'MODBUS', 'DNP3', 'S7COMM', 'ENIP', 'BACNET'}
    SUSPICIOUS_ACTIONS = {
        'config_change', 'firmware_update', 'modbus_write',
        'privilege_escalation', 'lateral_movement', 'data_exfiltration',
        'root_login', 'sudo_su', 'password_change'
    }
    COMMON_USERNAMES = {
        'admin', 'administrator', 'root', 'user', 'guest',
        'test', 'demo', 'sa', 'oracle', 'postgres'
    }

    def __init__(self):
        self.label_encoders = {}
        self.fitted = False

    def extract_single(self, event: Dict) -> Dict[str, float]:
        """Extract features from a single telemetry event"""
        features = {}

        # Time-based features
        ts = self._parse_timestamp(event.get('timestamp'))
        features['hour_of_day'] = ts.hour if ts else 12
        features['day_of_week'] = ts.weekday() if ts else 0
        features['is_weekend'] = 1.0 if ts and ts.weekday() >= 5 else 0.0
        features['is_business_hours'] = 1.0 if ts and 8 <= ts.hour <= 18 else 0.0

        # Network features
        features['source_port'] = float(event.get('source_port', 0))
        features['dest_port'] = float(event.get('dest_port', 0))
        features['is_privileged_port'] = 1.0 if features['dest_port'] < 1024 else 0.0
        features['is_high_risk_protocol'] = 1.0 if event.get('protocol', '').upper() in self.HIGH_RISK_PROTOCOLS else 0.0

        # Protocol encoding
        protocol = event.get('protocol', 'UNKNOWN').upper()
        protocol_map = {'TCP': 1, 'UDP': 2, 'MODBUS': 3, 'DNP3': 4, 'HTTP': 5, 'SSH': 6, 'HTTPS': 7, 'FTP': 8}
        features['protocol_encoded'] = float(protocol_map.get(protocol, 0))

        # Event type encoding
        event_type = event.get('event_type', 'unknown')
        type_map = {'network_flow': 1, 'auth_event': 2, 'system_log': 3, 'scada_reading': 4, 'file_access': 5, 'process_start': 6}
        features['event_type_encoded'] = float(type_map.get(event_type, 0))

        # Severity encoding
        severity = event.get('severity', 'INFO').upper()
        severity_map = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        features['severity_encoded'] = float(severity_map.get(severity, 0))

        # Action risk
        action = event.get('action', '').lower()
        features['is_suspicious_action'] = 1.0 if action in self.SUSPICIOUS_ACTIONS else 0.0
        features['action_risk'] = self._calculate_action_risk(action)

        # User identity features
        user = event.get('user_identity', '')
        features['has_user'] = 1.0 if user else 0.0
        features['is_common_username'] = 1.0 if user and user.lower() in self.COMMON_USERNAMES else 0.0
        features['username_length'] = float(len(user or ''))

        # IP features
        src_ip = event.get('source_ip', '')
        features['is_internal_ip'] = 1.0 if self._is_private_ip(src_ip) else 0.0
        features['ip_entropy'] = self._calculate_entropy(src_ip)

        # Payload features
        payload = event.get('payload', '') or ''
        command = event.get('command', '') or ''
        features['payload_length'] = float(len(payload))
        features['command_length'] = float(len(command))
        features['has_special_chars'] = 1.0 if self._has_special_chars(payload + command) else 0.0
        features['command_risk'] = self._calculate_command_risk(command)

        return features

    def extract_batch(self, events: List[Dict]) -> pd.DataFrame:
        """Extract features from multiple events"""
        if not events:
            return pd.DataFrame()
        feature_list = [self.extract_single(e) for e in events]
        return pd.DataFrame(feature_list)

    def _parse_timestamp(self, ts) -> Optional[datetime]:
        if ts is None:
            return datetime.now()
        if isinstance(ts, datetime):
            return ts
        try:
            return datetime.fromisoformat(str(ts).replace('Z', '+00:00'))
        except Exception:
            return datetime.now()

    def _is_private_ip(self, ip: str) -> bool:
        if not ip:
            return False
        private_prefixes = ['192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
                            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                            '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
                            '127.', '169.254.']
        return any(ip.startswith(p) for p in private_prefixes)

    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        chars = list(text.replace('.', '').replace(':', ''))
        if not chars:
            return 0.0
        counts = defaultdict(int)
        for c in chars:
            counts[c] += 1
        total = len(chars)
        entropy = -sum((count / total) * np.log2(count / total) for count in counts.values() if count > 0)
        return entropy

    def _has_special_chars(self, text: str) -> bool:
        if not text:
            return False
        special = set('!@#$%^&*()[]{}|\\:";\'<>?,./`~')
        return any(c in special for c in text)

    def _calculate_action_risk(self, action: str) -> float:
        if not action:
            return 0.0
        high_risk = {'config_change': 0.8, 'firmware_update': 0.9, 'modbus_write': 0.7,
                     'privilege_escalation': 1.0, 'data_exfiltration': 1.0, 'root_login': 0.6,
                     'sudo_su': 0.7, 'password_change': 0.5, 'user_create': 0.4}
        return high_risk.get(action.lower(), 0.1)

    def _calculate_command_risk(self, command: str) -> float:
        if not command:
            return 0.0
        command_lower = command.lower()
        high_risk_patterns = [
            'rm -rf', 'del /f', 'format', 'fdisk', 'mkfs', 'cat /etc/passwd',
            'cat /etc/shadow', 'sudo su', 'wget', 'curl -o', 'nc -', 'netcat',
            'bash -i', 'python -c', 'perl -e', 'php -r', 'eval(', 'exec(',
            'powershell', 'certutil', 'bitsadmin', 'mimikatz', 'whoami /priv'
        ]
        score = sum(0.25 for p in high_risk_patterns if p in command_lower)
        if any(c in command for c in '|;&$`'):
            score += 0.2
        return min(score, 1.0)


class BehavioralAnomalyDetector:
    """
    Core anomaly detection engine using ensemble of:
    - Isolation Forest (unsupervised, efficient for high-dimensional data)
    - One-Class SVM (boundary-based, good for tight clusters)

    Learns normal behavior profiles per entity (user/device/segment).
    """

    def __init__(self, contamination: float = 0.1, svm_nu: float = 0.1):
        self.feature_extractor = TelemetryFeatureExtractor()
        self.scaler = StandardScaler()
        self.contamination = contamination
        self.svm_nu = svm_nu

        # Models
        self.isolation_forest = None
        self.one_class_svm = None
        self.is_trained = False

        # Entity-specific baselines
        self.entity_baselines: Dict[str, Dict] = {}

        # Feature names
        self.feature_names: List[str] = []

        # Model persistence
        self.model_dir = Path("models")
        self.model_dir.mkdir(exist_ok=True)
        self._load_model()

    def train(self, events: List[Dict], force_retrain: bool = False) -> Dict[str, Any]:
        """Train anomaly detection models on normal behavior data"""
        if self.is_trained and not force_retrain:
            logger.info("Models already trained. Use force_retrain=True to retrain.")
            return {"status": "already_trained"}

        if len(events) < 20:
            logger.warning(f"Need at least 20 events to train, got {len(events)}")
            return {"status": "insufficient_data", "count": len(events)}

        logger.info(f"Training anomaly detection models on {len(events)} events...")

        # Extract features
        features_df = self.feature_extractor.extract_batch(events)
        if features_df.empty:
            return {"status": "no_features"}

        self.feature_names = list(features_df.columns)

        # Handle NaN/Inf
        features_df = features_df.fillna(0).replace([np.inf, -np.inf], 0)

        # Scale features
        X_scaled = self.scaler.fit_transform(features_df)

        # Train Isolation Forest
        self.isolation_forest = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1
        )
        self.isolation_forest.fit(X_scaled)

        # Train One-Class SVM (on subset for speed)
        svm_sample_size = min(len(X_scaled), 5000)
        if svm_sample_size > 50:
            indices = np.random.choice(len(X_scaled), svm_sample_size, replace=False)
            X_svm = X_scaled[indices]
            self.one_class_svm = OneClassSVM(
                kernel='rbf',
                nu=self.svm_nu,
                gamma='scale'
            )
            self.one_class_svm.fit(X_svm)

        self.is_trained = True
        self._save_model()

        logger.info("Anomaly detection models trained successfully")
        return {
            "status": "trained",
            "samples": len(events),
            "features": len(self.feature_names),
            "models": ["isolation_forest", "one_class_svm"]
        }

    def detect(self, event: Dict) -> AnomalyResult:
        """Detect anomalies in a single telemetry event"""
        if not self.is_trained:
            return self._heuristic_detection(event)

        try:
            # Extract features
            features = self.feature_extractor.extract_single(event)
            feature_values = np.array([features.get(f, 0.0) for f in self.feature_names]).reshape(1, -1)

            # Handle NaN/Inf
            feature_values = np.nan_to_num(feature_values, nan=0.0, posinf=0.0, neginf=0.0)

            # Scale
            X_scaled = self.scaler.transform(feature_values)

            # Isolation Forest score
            if_score_raw = self.isolation_forest.decision_function(X_scaled)[0]
            if_prediction = self.isolation_forest.predict(X_scaled)[0]
            # Convert IF score to 0-1 range (more negative = more anomalous)
            if_anomaly_score = max(0.0, min(1.0, 0.5 - if_score_raw))

            # One-Class SVM score
            svm_anomaly_score = 0.0
            svm_prediction = 1
            if self.one_class_svm is not None:
                svm_score_raw = self.one_class_svm.decision_function(X_scaled)[0]
                svm_prediction = self.one_class_svm.predict(X_scaled)[0]
                svm_anomaly_score = max(0.0, min(1.0, 0.5 - svm_score_raw * 0.3))

            # Ensemble score (weighted average)
            ensemble_score = if_anomaly_score * 0.6 + svm_anomaly_score * 0.4
            is_anomaly = bool(if_prediction == -1) or svm_prediction == -1

            # Calculate risk score (0-100)
            severity_boost = features.get('severity_encoded', 0) * 10
            action_boost = features.get('action_risk', 0) * 20
            risk_score = min(100.0, ensemble_score * 60 + severity_boost + action_boost)

            # Confidence based on model agreement
            model_agreement = 1.0 if (if_prediction == svm_prediction) else 0.7
            confidence = min(1.0, model_agreement * (0.5 + ensemble_score * 0.5))

            # Generate explanation and contributing factors
            contributing_factors = self._get_contributing_factors(features, ensemble_score)
            explanation = self._generate_explanation(event, is_anomaly, ensemble_score, contributing_factors)

            return AnomalyResult(
                is_anomaly=is_anomaly,
                anomaly_score=round(ensemble_score, 4),
                risk_score=round(risk_score, 2),
                confidence=round(confidence, 4),
                explanation=explanation,
                contributing_factors=contributing_factors,
                model_used="ensemble"
            )

        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
            return self._heuristic_detection(event)

    def detect_batch(self, events: List[Dict]) -> List[AnomalyResult]:
        """Detect anomalies in a batch of events"""
        return [self.detect(event) for event in events]

    def update_entity_baseline(self, entity_type: str, entity_id: str, features: Dict) -> None:
        """Update behavior baseline for a specific entity"""
        key = f"{entity_type}:{entity_id}"
        if key not in self.entity_baselines:
            self.entity_baselines[key] = {
                "type": entity_type,
                "id": entity_id,
                "feature_history": [],
                "sample_count": 0
            }

        baseline = self.entity_baselines[key]
        baseline["feature_history"].append(features)
        baseline["sample_count"] += 1

        # Keep only last 1000 observations
        if len(baseline["feature_history"]) > 1000:
            baseline["feature_history"] = baseline["feature_history"][-1000:]

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the anomaly detection models"""
        return {
            "is_trained": self.is_trained,
            "models": {
                "isolation_forest": self.isolation_forest is not None,
                "one_class_svm": self.one_class_svm is not None,
            },
            "feature_count": len(self.feature_names),
            "feature_names": self.feature_names[:10],  # First 10 for display
            "contamination": self.contamination,
            "svm_nu": self.svm_nu,
            "entity_baselines": len(self.entity_baselines)
        }

    def _heuristic_detection(self, event: Dict) -> AnomalyResult:
        """Fallback heuristic-based detection when models aren't trained"""
        features = self.feature_extractor.extract_single(event)

        score = 0.0
        factors = []

        # Severity-based scoring
        severity_scores = {'INFO': 0.0, 'LOW': 0.1, 'MEDIUM': 0.3, 'HIGH': 0.6, 'CRITICAL': 0.9}
        sev = event.get('severity', 'INFO').upper()
        score += severity_scores.get(sev, 0.2) * 0.3
        if sev in ('HIGH', 'CRITICAL'):
            factors.append({"factor": "severity", "value": sev, "impact": "high"})

        # Action risk
        action_risk = features.get('action_risk', 0.0)
        score += action_risk * 0.25
        if action_risk > 0.5:
            factors.append({"factor": "suspicious_action", "value": event.get('action', ''), "impact": "high"})

        # Command risk
        cmd_risk = features.get('command_risk', 0.0)
        score += cmd_risk * 0.2
        if cmd_risk > 0.3:
            factors.append({"factor": "dangerous_command", "value": event.get('command', '')[:50], "impact": "medium"})

        # Time-based
        if not features.get('is_business_hours', 1.0):
            score += 0.1
            factors.append({"factor": "off_hours_activity", "value": "outside business hours", "impact": "low"})

        # High-risk protocol
        if features.get('is_high_risk_protocol', 0.0):
            score += 0.15
            factors.append({"factor": "scada_protocol", "value": event.get('protocol', ''), "impact": "medium"})

        score = min(score, 1.0)
        is_anomaly = score > 0.5
        risk_score = min(100.0, score * 100)

        return AnomalyResult(
            is_anomaly=is_anomaly,
            anomaly_score=round(score, 4),
            risk_score=round(risk_score, 2),
            confidence=0.5,  # Lower confidence for heuristic
            explanation=self._generate_explanation(event, is_anomaly, score, factors),
            contributing_factors=factors,
            model_used="heuristic"
        )

    def _get_contributing_factors(self, features: Dict, overall_score: float) -> List[Dict]:
        """Identify the top factors contributing to the anomaly score"""
        factors = []
        if features.get('severity_encoded', 0) >= 3:
            factors.append({"factor": "high_severity", "value": str(features['severity_encoded']), "impact": "high"})
        if features.get('is_suspicious_action', 0):
            factors.append({"factor": "suspicious_action", "value": "detected", "impact": "high"})
        if features.get('command_risk', 0) > 0.3:
            factors.append({"factor": "risky_command", "value": str(round(features['command_risk'], 2)), "impact": "medium"})
        if features.get('is_high_risk_protocol', 0):
            factors.append({"factor": "industrial_protocol", "value": "SCADA/ICS", "impact": "medium"})
        if not features.get('is_business_hours', 1):
            factors.append({"factor": "off_hours", "value": "non-business hours", "impact": "low"})
        if features.get('is_common_username', 0):
            factors.append({"factor": "default_credential", "value": "common username", "impact": "medium"})
        if features.get('payload_length', 0) > 500:
            factors.append({"factor": "large_payload", "value": str(int(features['payload_length'])), "impact": "low"})
        return factors[:5]  # Top 5 factors

    def _generate_explanation(self, event: Dict, is_anomaly: bool, score: float, factors: List[Dict]) -> str:
        """Generate human-readable explanation of the detection result"""
        if not is_anomaly:
            return "Event appears to be within normal behavioral patterns."

        parts = ["Anomalous behavior detected."]
        high_factors = [f for f in factors if f.get('impact') == 'high']
        med_factors = [f for f in factors if f.get('impact') == 'medium']

        if high_factors:
            parts.append(f"Critical indicators: {', '.join(f['factor'] for f in high_factors)}.")
        if med_factors:
            parts.append(f"Contributing factors: {', '.join(f['factor'] for f in med_factors)}.")

        event_type = event.get('event_type', 'unknown')
        src_ip = event.get('source_ip', 'unknown')
        parts.append(f"Source: {src_ip}, Type: {event_type}.")

        return " ".join(parts)

    def _save_model(self):
        """Save trained models to disk"""
        try:
            model_data = {
                'isolation_forest': self.isolation_forest,
                'one_class_svm': self.one_class_svm,
                'scaler': self.scaler,
                'feature_names': self.feature_names,
                'is_trained': self.is_trained,
                'contamination': self.contamination,
            }
            path = self.model_dir / "anomaly_detector.joblib"
            joblib.dump(model_data, path)
            logger.info(f"Anomaly detector saved to {path}")
        except Exception as e:
            logger.error(f"Failed to save anomaly detector: {e}")

    def _load_model(self):
        """Load trained models from disk"""
        try:
            path = self.model_dir / "anomaly_detector.joblib"
            if path.exists():
                model_data = joblib.load(path)
                self.isolation_forest = model_data['isolation_forest']
                self.one_class_svm = model_data['one_class_svm']
                self.scaler = model_data['scaler']
                self.feature_names = model_data['feature_names']
                self.is_trained = model_data['is_trained']
                logger.info("Anomaly detector loaded from disk")
        except Exception as e:
            logger.warning(f"Could not load anomaly detector: {e}")


# Global instance
anomaly_detector = BehavioralAnomalyDetector()
