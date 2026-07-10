from typing import Dict, Any, List
from .explanation_engine import ExplanationEngine

class RiskScorer:
    def __init__(self):
        self.explanation_engine = ExplanationEngine()
        
    def calculate_risk(self, anomaly_result: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculates a 0-100 risk score and provides explanations.
        """
        is_anomaly = anomaly_result.get("is_anomaly", False)
        anomaly_score = anomaly_result.get("anomaly_score", 0.0) # Raw isolation forest score
        deviation_scores = anomaly_result.get("deviation_scores", {})
        
        # Base calculation
        if not is_anomaly:
            return {
                "risk_score": 0.0,
                "reasons": []
            }
            
        # Map raw ML score to 0-100
        # This is a simplification; realistically, this involves a calibrated sigmoid or CDF
        risk_score = float(min(100, max(0, anomaly_score * 10))) 
        
        # Increase risk based on specific high-risk contexts
        if "location" in context and context.get("location") not in context.get("typical_locations", []):
            risk_score = min(100, risk_score + 25)
            
        # Get explanations
        reasons = self.explanation_engine.generate_explanations(deviation_scores, context)
        
        return {
            "risk_score": round(risk_score, 2),
            "reasons": reasons
        }
