import numpy as np
from sklearn.ensemble import IsolationForest
from typing import Dict, Any, List
from app.models import BehaviorProfile
from app.database import SessionLocal

class AnomalyDetector:
    def __init__(self):
        # We use Isolation Forest for anomaly detection
        self.model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        
    def train(self, historical_feature_vectors: List[List[float]]):
        """Train the Isolation Forest model on normal behavior data."""
        if not historical_feature_vectors:
            return
            
        X = np.array(historical_feature_vectors)
        self.model.fit(X)
        
    def detect_anomalies(self, current_event_features: Dict[str, float], profile: BehaviorProfile) -> Dict[str, Any]:
        """
        Compare current event features against the baseline profile using Isolation Forest.
        Returns a dictionary with 'is_anomaly' and 'deviation_scores'.
        """
        # In a real scenario, the model would be loaded/trained per entity or globally.
        # For this implementation, we will simulate the inference using the profile's feature vector.
        
        # Suppose we have a baseline feature vector for this user
        baseline = profile.feature_vector
        if not baseline:
            return {"is_anomaly": False, "deviation_scores": {}}
            
        # Create a simple synthetic training set based on the baseline
        # In production, this would be a real dataset of historical points.
        synthetic_train_data = []
        for _ in range(50):
            # add some noise around the baseline
            point = [
                max(0, baseline.get('avg_file_access', 0) + np.random.normal(0, 0.5)),
                max(0, baseline.get('avg_api_calls', 0) + np.random.normal(0, 0.5)),
                max(0, baseline.get('total_events', 0) + np.random.normal(0, 1.0))
            ]
            synthetic_train_data.append(point)
            
        self.train(synthetic_train_data)
        
        # Now predict for the current event
        current_vector = [
            current_event_features.get('file_access_count', 0),
            current_event_features.get('api_call_count', 0),
            current_event_features.get('event_count', 1)
        ]
        
        X_test = np.array([current_vector])
        
        # Predict returns 1 for inliers, -1 for outliers
        prediction = self.model.predict(X_test)[0]
        # Score samples returns the opposite of the anomaly score (lower is more anomalous)
        score = self.model.score_samples(X_test)[0]
        
        is_anomaly = bool(prediction == -1)
        
        # Calculate deviation per feature for the explanation engine
        # Cast to native Python float to avoid numpy serialization issues in FastAPI
        deviation_scores = {}
        deviation_scores['file_access'] = float(current_vector[0] - baseline.get('avg_file_access', 0))
        deviation_scores['api_calls'] = float(current_vector[1] - baseline.get('avg_api_calls', 0))
        
        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": float(abs(score)), # Normalize or invert for risk scoring later
            "deviation_scores": deviation_scores
        }
