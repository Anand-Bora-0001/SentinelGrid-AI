"""
SentinelGrid AI — Vulnerability Prioritization Agent (Module 5)

Ranks vulnerabilities by composite risk score considering:
- CVSS Score
- Exploit Availability
- Asset Criticality
- Business Impact
- Exposure Score

Generates risk-ranked patch queue.
"""
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# CVSS severity thresholds
CVSS_SEVERITY = {
    (0.0, 3.9): "LOW",
    (4.0, 6.9): "MEDIUM",
    (7.0, 8.9): "HIGH",
    (9.0, 10.0): "CRITICAL",
}

# Exploit maturity multipliers
EXPLOIT_MATURITY_WEIGHTS = {
    "weaponized": 1.0,
    "functional": 0.85,
    "proof_of_concept": 0.6,
    "unproven": 0.3,
    None: 0.2,
}

# Asset criticality multipliers
ASSET_CRITICALITY_WEIGHTS = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.3,
}

# Business impact multipliers
BUSINESS_IMPACT_WEIGHTS = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.3,
}


class VulnPrioritizer:
    """
    AI-powered vulnerability prioritization engine.
    Computes composite risk score and generates a risk-ranked patch queue.
    """

    def __init__(self):
        self.weights = {
            "cvss": 0.30,
            "exploit": 0.25,
            "asset_criticality": 0.20,
            "business_impact": 0.15,
            "exposure": 0.10,
        }

    def calculate_composite_score(self, vuln: Dict, asset: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Calculate composite risk score for a single vulnerability.

        Args:
            vuln: Vulnerability data dict with cvss_score, exploit_available, etc.
            asset: Optional asset data with criticality, network_segment, etc.

        Returns:
            Dict with composite_score, breakdown, and severity
        """
        # CVSS component (0-100)
        cvss_score = float(vuln.get('cvss_score', 0.0))
        cvss_normalized = (cvss_score / 10.0) * 100

        # Exploit availability component (0-100)
        exploit_available = vuln.get('exploit_available', False)
        exploit_maturity = vuln.get('exploit_maturity', None)
        if exploit_available:
            exploit_score = EXPLOIT_MATURITY_WEIGHTS.get(exploit_maturity, 0.6) * 100
        else:
            exploit_score = EXPLOIT_MATURITY_WEIGHTS.get(exploit_maturity, 0.2) * 100

        # Asset criticality component (0-100)
        if asset:
            asset_criticality = asset.get('criticality', 'medium')
        else:
            asset_criticality = vuln.get('asset_criticality', 'medium')
        criticality_score = ASSET_CRITICALITY_WEIGHTS.get(asset_criticality, 0.5) * 100

        # Business impact component (0-100)
        business_impact = vuln.get('business_impact', 'low')
        impact_score = BUSINESS_IMPACT_WEIGHTS.get(business_impact, 0.3) * 100

        # Exposure score: is the asset internet-facing or in a critical network segment?
        exposure_score = self._calculate_exposure(vuln, asset)

        # Composite score
        composite = (
            cvss_normalized * self.weights["cvss"] +
            exploit_score * self.weights["exploit"] +
            criticality_score * self.weights["asset_criticality"] +
            impact_score * self.weights["business_impact"] +
            exposure_score * self.weights["exposure"]
        )

        # Determine severity from composite score
        if composite >= 80:
            severity = "CRITICAL"
        elif composite >= 60:
            severity = "HIGH"
        elif composite >= 40:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "composite_risk_score": round(composite, 2),
            "severity": severity,
            "breakdown": {
                "cvss_component": round(cvss_normalized, 2),
                "exploit_component": round(exploit_score, 2),
                "asset_criticality_component": round(criticality_score, 2),
                "business_impact_component": round(impact_score, 2),
                "exposure_component": round(exposure_score, 2),
            },
            "weights": self.weights,
        }

    def generate_patch_queue(
        self,
        vulnerabilities: List[Dict],
        assets: Optional[Dict[int, Dict]] = None
    ) -> List[Dict]:
        """
        Generate risk-ranked patch queue from list of vulnerabilities.

        Args:
            vulnerabilities: List of vulnerability dicts
            assets: Optional dict mapping asset_id to asset data

        Returns:
            Sorted list of vulnerabilities with priority rankings
        """
        scored_vulns = []

        for vuln in vulnerabilities:
            asset_id = vuln.get('affected_asset_id')
            asset = assets.get(asset_id) if assets and asset_id else None

            scoring = self.calculate_composite_score(vuln, asset)

            enriched_vuln = {
                **vuln,
                "composite_risk_score": scoring["composite_risk_score"],
                "computed_severity": scoring["severity"],
                "score_breakdown": scoring["breakdown"],
                "asset_name": asset.get("name", "Unknown") if asset else "Unassigned",
                "asset_criticality": asset.get("criticality", "unknown") if asset else "unknown",
            }
            scored_vulns.append(enriched_vuln)

        # Sort by composite score descending
        scored_vulns.sort(key=lambda v: v["composite_risk_score"], reverse=True)

        # Assign priority ranks
        for rank, vuln in enumerate(scored_vulns, 1):
            vuln["patch_priority"] = rank

        return scored_vulns

    def get_summary_stats(self, patch_queue: List[Dict]) -> Dict[str, Any]:
        """Get summary statistics for the patch queue"""
        if not patch_queue:
            return {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "exploitable": 0}

        return {
            "total": len(patch_queue),
            "critical": sum(1 for v in patch_queue if v.get("computed_severity") == "CRITICAL"),
            "high": sum(1 for v in patch_queue if v.get("computed_severity") == "HIGH"),
            "medium": sum(1 for v in patch_queue if v.get("computed_severity") == "MEDIUM"),
            "low": sum(1 for v in patch_queue if v.get("computed_severity") == "LOW"),
            "exploitable": sum(1 for v in patch_queue if v.get("exploit_available")),
            "avg_cvss": round(sum(v.get("cvss_score", 0) for v in patch_queue) / len(patch_queue), 2),
            "max_risk_score": round(max(v.get("composite_risk_score", 0) for v in patch_queue), 2),
        }

    def _calculate_exposure(self, vuln: Dict, asset: Optional[Dict]) -> float:
        """Calculate exposure score based on network position and accessibility"""
        score = 30.0  # Default baseline

        if asset:
            segment = asset.get('network_segment', '').lower()
            if segment in ('dmz', 'internet', 'public'):
                score = 100.0  # Internet-facing
            elif segment in ('internal', 'corporate'):
                score = 50.0
            elif segment in ('scada', 'ics', 'ot'):
                score = 70.0  # High value even if isolated
            elif segment in ('management', 'admin'):
                score = 60.0
            else:
                score = 40.0

            # Adjust for open ports
            open_ports = asset.get('open_ports', [])
            internet_ports = {80, 443, 8080, 8443, 21, 22, 3389}
            if any(p in internet_ports for p in open_ports):
                score = min(100, score + 15)

        return score


# Global instance
vuln_prioritizer = VulnPrioritizer()
