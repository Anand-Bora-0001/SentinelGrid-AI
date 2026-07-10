import re
import logging
from typing import Dict, Any, Tuple

logger = logging.getLogger(__name__)

class DetectionEngine:
    """Advanced pattern-matching engine for manual attack detection"""
    
    # Attack Signatures
    SIGNATURES = {
        "SQL_INJECTION": [
            r"'.*--", r"'.*OR.*'1'='1'", r"UNION.*SELECT", r"ORDER.*BY", r"DROP.*TABLE", r"INSERT.*INTO", r"SLEEP\("
        ],
        "XSS": [
            r"<script.*?>", r"javascript:", r"onload=", r"onerror=", r"alert\(", r"<img.*src.*onerror"
        ],
        "PATH_TRAVERSAL": [
            r"\.\./\.\./", r"/etc/passwd", r"C:\\Windows", r"/var/www/html"
        ],
        "COMMAND_INJECTION": [
            r";.*id", r"\|.*ls", r"`.*whoami", r"\$\(.*uname", r"&&.*cat"
        ],
        "NOSQL_INJECTION": [
            r"\{\$gt:.*\}", r"\$where", r"\{\$ne:.*\}", r"\$regex"
        ]
    }

    @classmethod
    def analyze_request(cls, method: str, endpoint: str, body: Any = None, query_params: dict = None) -> Tuple[str, str]:
        """
        Analyzes a request and returns (AttackType, Severity)
        If no attack is detected, returns ("BENIGN", "LOW")
        """
        raw_data = f"{method} {endpoint} {str(body)} {str(query_params)}".lower()
        
        # Check for Critical Signatures first
        for attack_type, patterns in cls.SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern.lower(), raw_data):
                    severity = "CRITICAL" if attack_type in ["SQL_INJECTION", "COMMAND_INJECTION"] else "HIGH"
                    return attack_type, severity
        
        # Heuristic check for brute force or credential stuffing (basic logic)
        if "password" in raw_data and len(str(body)) > 1000:
            return "DATA_EXFILTRATION_ATTEMPT", "HIGH"

        return "BENIGN", "LOW"

detection_engine = DetectionEngine()
