"""
SentinelGrid AI — Attack Prediction Agent (Module 4)

Predicts likely attacker next actions based on current attack stage
and observed MITRE ATT&CK technique progression.
Uses Markov chain model on tactic transitions.
"""
import logging
from typing import Dict, List, Any
from collections import defaultdict
from datetime import datetime
import random

logger = logging.getLogger(__name__)

# Tactic transition probabilities (Markov chain)
# Based on real-world attack campaign analysis patterns
TACTIC_TRANSITIONS = {
    "Reconnaissance": {
        "Initial Access": 0.85,
        "Resource Development": 0.10,
        "Reconnaissance": 0.05,
    },
    "Resource Development": {
        "Initial Access": 0.90,
        "Resource Development": 0.10,
    },
    "Initial Access": {
        "Execution": 0.55,
        "Persistence": 0.20,
        "Discovery": 0.15,
        "Credential Access": 0.10,
    },
    "Execution": {
        "Persistence": 0.30,
        "Privilege Escalation": 0.25,
        "Discovery": 0.20,
        "Defense Evasion": 0.15,
        "Credential Access": 0.10,
    },
    "Persistence": {
        "Privilege Escalation": 0.35,
        "Defense Evasion": 0.25,
        "Discovery": 0.20,
        "Execution": 0.10,
        "Credential Access": 0.10,
    },
    "Privilege Escalation": {
        "Defense Evasion": 0.25,
        "Credential Access": 0.30,
        "Discovery": 0.20,
        "Lateral Movement": 0.15,
        "Execution": 0.10,
    },
    "Defense Evasion": {
        "Credential Access": 0.30,
        "Discovery": 0.25,
        "Lateral Movement": 0.20,
        "Collection": 0.15,
        "Persistence": 0.10,
    },
    "Credential Access": {
        "Lateral Movement": 0.40,
        "Discovery": 0.25,
        "Privilege Escalation": 0.15,
        "Collection": 0.10,
        "Defense Evasion": 0.10,
    },
    "Discovery": {
        "Lateral Movement": 0.35,
        "Collection": 0.25,
        "Credential Access": 0.20,
        "Execution": 0.10,
        "Privilege Escalation": 0.10,
    },
    "Lateral Movement": {
        "Collection": 0.35,
        "Discovery": 0.20,
        "Execution": 0.15,
        "Credential Access": 0.15,
        "Persistence": 0.15,
    },
    "Collection": {
        "Command and Control": 0.35,
        "Exfiltration": 0.30,
        "Lateral Movement": 0.15,
        "Impact": 0.10,
        "Discovery": 0.10,
    },
    "Command and Control": {
        "Exfiltration": 0.45,
        "Collection": 0.20,
        "Impact": 0.15,
        "Lateral Movement": 0.10,
        "Execution": 0.10,
    },
    "Exfiltration": {
        "Impact": 0.50,
        "Collection": 0.20,
        "Command and Control": 0.15,
        "Defense Evasion": 0.15,
    },
    "Impact": {
        "Exfiltration": 0.30,
        "Defense Evasion": 0.30,
        "Impact": 0.40,
    },
}

# Technique-specific predictions based on current technique
TECHNIQUE_PREDICTIONS = {
    "T1190": [  # Exploit Public-Facing App → likely next
        {"action": "Web Shell Deployment", "technique_id": "T1059", "probability": 0.88, "severity": "CRITICAL",
         "description": "Deploy web shell for persistent access", "defense": "Monitor web directories for new files, WAF rules"},
        {"action": "Credential Harvesting", "technique_id": "T1003", "probability": 0.72, "severity": "HIGH",
         "description": "Extract credentials from compromised application", "defense": "Implement credential rotation, vault usage"},
        {"action": "Internal Reconnaissance", "technique_id": "T1082", "probability": 0.65, "severity": "MEDIUM",
         "description": "Enumerate internal systems and services", "defense": "Network segmentation, IDS monitoring"},
    ],
    "T1110": [  # Brute Force → likely next
        {"action": "Credential Dumping", "technique_id": "T1003", "probability": 0.92, "severity": "CRITICAL",
         "description": "Extract additional credentials after successful brute force", "defense": "Enable MFA, monitor LSASS access"},
        {"action": "Lateral Movement via SSH/RDP", "technique_id": "T1021", "probability": 0.88, "severity": "HIGH",
         "description": "Use stolen credentials to move laterally", "defense": "Restrict RDP/SSH access, jump server architecture"},
        {"action": "Persistence via Scheduled Tasks", "technique_id": "T1053", "probability": 0.71, "severity": "MEDIUM",
         "description": "Create scheduled tasks for persistent access", "defense": "Monitor scheduled task creation, audit cron jobs"},
    ],
    "T1003": [  # Credential Dumping → likely next
        {"action": "Lateral Movement", "technique_id": "T1021", "probability": 0.92, "severity": "CRITICAL",
         "description": "Use dumped credentials for lateral movement", "defense": "Network segmentation, PAM solutions"},
        {"action": "Privilege Escalation", "technique_id": "T1548", "probability": 0.78, "severity": "HIGH",
         "description": "Escalate privileges with harvested credentials", "defense": "Least privilege enforcement, PAM"},
        {"action": "Data Exfiltration", "technique_id": "T1041", "probability": 0.65, "severity": "CRITICAL",
         "description": "Exfiltrate sensitive data using stolen credentials", "defense": "DLP solutions, egress monitoring"},
    ],
    "T1021": [  # Remote Services / Lateral Movement → likely next
        {"action": "Data Collection", "technique_id": "T1041", "probability": 0.82, "severity": "HIGH",
         "description": "Collect sensitive data from compromised systems", "defense": "File integrity monitoring, DLP"},
        {"action": "Further Lateral Movement", "technique_id": "T1021", "probability": 0.75, "severity": "HIGH",
         "description": "Continue spreading to additional systems", "defense": "Micro-segmentation, EDR deployment"},
        {"action": "SCADA/ICS Manipulation", "technique_id": "T0855", "probability": 0.58, "severity": "CRITICAL",
         "description": "Target industrial control systems", "defense": "Air-gap SCADA networks, protocol inspection"},
    ],
    "T0855": [  # Unauthorized Command (ICS) → likely next
        {"action": "Control Manipulation", "technique_id": "T0831", "probability": 0.85, "severity": "CRITICAL",
         "description": "Manipulate physical process controls", "defense": "Safety instrumented systems, process monitoring"},
        {"action": "Data Destruction", "technique_id": "T1485", "probability": 0.70, "severity": "CRITICAL",
         "description": "Destroy operational data and logs", "defense": "Offline backups, immutable logging"},
        {"action": "Ransomware Deployment", "technique_id": "T1486", "probability": 0.55, "severity": "CRITICAL",
         "description": "Encrypt systems for ransom", "defense": "Network isolation, backup verification"},
    ],
}


class AttackPredictor:
    """
    Predicts likely attacker next actions based on:
    1. Current attack stage (MITRE tactic)
    2. Observed techniques (technique-specific predictions)
    3. Tactic transition probabilities (Markov chain)
    """

    def __init__(self):
        self.transitions = TACTIC_TRANSITIONS
        self.technique_predictions = TECHNIQUE_PREDICTIONS
        self.observed_sequences: List[List[str]] = []

    def predict_next_actions(
        self,
        current_techniques: List[str],
        current_tactic: str = None,
        top_k: int = 5
    ) -> Dict[str, Any]:
        """
        Predict the most likely next attacker actions.

        Args:
            current_techniques: List of observed MITRE technique IDs
            current_tactic: Current attack stage (tactic name)
            top_k: Number of predictions to return

        Returns:
            Dict with predictions, risk assessment, and confidence
        """
        predictions = []

        # 1. Technique-specific predictions
        for tech_id in current_techniques:
            if tech_id in self.technique_predictions:
                for pred in self.technique_predictions[tech_id]:
                    # Avoid duplicates
                    if not any(p['technique_id'] == pred['technique_id'] for p in predictions):
                        predictions.append(pred.copy())

        # 2. Tactic-based predictions (Markov chain)
        if current_tactic and current_tactic in self.transitions:
            next_tactics = self.transitions[current_tactic]
            for tactic, prob in sorted(next_tactics.items(), key=lambda x: -x[1]):
                # Add a generic prediction for the tactic
                if not any(p.get('_tactic') == tactic for p in predictions):
                    predictions.append({
                        "action": f"{tactic} Phase",
                        "technique_id": "N/A",
                        "probability": prob,
                        "severity": self._tactic_severity(tactic),
                        "description": f"Attacker likely to progress to {tactic} phase",
                        "defense": self._tactic_defense(tactic),
                        "_tactic": tactic
                    })

        # Sort by probability and take top_k
        predictions.sort(key=lambda x: x['probability'], reverse=True)
        predictions = predictions[:top_k]

        # Clean up internal fields
        for p in predictions:
            p.pop('_tactic', None)

        # Determine overall risk
        if predictions:
            max_severity = max(
                predictions,
                key=lambda x: {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}.get(x['severity'], 0)
            )['severity']
            avg_probability = sum(p['probability'] for p in predictions) / len(predictions)
        else:
            max_severity = "LOW"
            avg_probability = 0.0

        return {
            "current_stage": current_tactic or "Unknown",
            "next_likely_actions": predictions,
            "risk_level": max_severity,
            "confidence": round(avg_probability, 3),
            "analysis_timestamp": datetime.now().isoformat(),
            "observed_techniques": current_techniques,
        }

    def get_risk_forecast(self, daily_event_counts: List[int], days_ahead: int = 7) -> Dict[str, Any]:
        """Simple risk forecast based on event volume trends"""
        import numpy as np

        if len(daily_event_counts) < 3:
            return {
                "forecast": [],
                "trend": "insufficient_data",
                "current_risk": 0
            }

        counts = np.array(daily_event_counts, dtype=float)
        x = np.arange(len(counts))

        # Linear regression
        coeffs = np.polyfit(x, counts, 1)
        trend_line = np.poly1d(coeffs)

        # Forecast
        future_x = np.arange(len(counts), len(counts) + days_ahead)
        forecast_values = np.maximum(trend_line(future_x), 0)

        # Confidence interval
        residuals = counts - trend_line(x)
        std_error = np.std(residuals)

        forecast = []
        for i, val in enumerate(forecast_values):
            from datetime import timedelta
            date = (datetime.now() + timedelta(days=i + 1)).strftime('%Y-%m-%d')
            forecast.append({
                "date": date,
                "predicted_risk": round(float(val), 2),
                "confidence_lower": round(max(0, float(val - 1.96 * std_error)), 2),
                "confidence_upper": round(float(val + 1.96 * std_error), 2),
            })

        # Determine trend
        if coeffs[0] > 0.5:
            trend = "increasing"
        elif coeffs[0] < -0.5:
            trend = "decreasing"
        else:
            trend = "stable"

        return {
            "forecast": forecast,
            "trend": trend,
            "current_risk": round(float(counts[-1]), 2),
            "trend_coefficient": round(float(coeffs[0]), 4),
        }

    def _tactic_severity(self, tactic: str) -> str:
        high_severity = {"Impact", "Exfiltration", "Command and Control"}
        medium_severity = {"Lateral Movement", "Collection", "Credential Access", "Privilege Escalation"}
        if tactic in high_severity:
            return "CRITICAL"
        elif tactic in medium_severity:
            return "HIGH"
        else:
            return "MEDIUM"

    def _tactic_defense(self, tactic: str) -> str:
        defenses = {
            "Initial Access": "Harden public-facing services, enable MFA, patch vulnerabilities",
            "Execution": "Application whitelisting, script block logging, EDR deployment",
            "Persistence": "Monitor startup locations, audit scheduled tasks, file integrity monitoring",
            "Privilege Escalation": "Least privilege enforcement, PAM solutions, UAC configuration",
            "Defense Evasion": "Enhanced logging, code signing enforcement, process monitoring",
            "Credential Access": "Credential guards, MFA enforcement, password rotation",
            "Discovery": "Network segmentation, honeytokens, deceptive assets",
            "Lateral Movement": "Micro-segmentation, just-in-time access, EDR lateral movement detection",
            "Collection": "DLP solutions, file access monitoring, encryption at rest",
            "Command and Control": "DNS monitoring, proxy inspection, network behavior analysis",
            "Exfiltration": "Egress filtering, DLP, bandwidth monitoring",
            "Impact": "Backup verification, incident response activation, business continuity plan",
        }
        return defenses.get(tactic, "Implement defense-in-depth strategy")


# Global instance
attack_predictor = AttackPredictor()
