"""
SentinelGrid AI — Autonomous Response Orchestrator (Module 6)

Generates incident response actions based on incident severity and context.
SIMULATION ONLY — never executes real actions.

Available actions: block_ip, disable_user, isolate_host, snapshot_vm, escalate
"""
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class ProposedAction:
    """A proposed response action"""
    action_type: str
    target: str
    parameters: Dict[str, Any]
    confidence: float
    rationale: str
    simulation_result: Dict[str, Any]
    severity: str
    priority: int


# Response playbooks keyed by incident severity × attack type
PLAYBOOKS = {
    "CRITICAL": [
        {
            "action_type": "reset_credentials",
            "conditions": ["always"],
            "confidence": 0.95,
            "rationale": "Reset potentially compromised credentials to revoke access.",
            "priority": 1,
        },
        {
            "action_type": "isolate_host",
            "conditions": ["always"],
            "confidence": 0.90,
            "rationale": "Isolate compromised host to prevent lateral movement",
            "priority": 2,
        },
        {
            "action_type": "block_external_ip",
            "conditions": ["always"],
            "confidence": 0.88,
            "rationale": "Block External IP to stop active exploitation and data exfiltration.",
            "priority": 3,
        },
        {
            "action_type": "rotate_secrets",
            "conditions": ["always"],
            "confidence": 0.92,
            "rationale": "Rotate Secrets to invalidate stolen session tokens and API keys.",
            "priority": 4,
        },
        {
            "action_type": "notify_soc_team",
            "conditions": ["always"],
            "confidence": 1.0,
            "rationale": "Notify SOC Team for immediate manual review and intervention.",
            "priority": 5,
        },
    ],
    "HIGH": [
        {
            "action_type": "block_ip",
            "conditions": ["source_ip_identified"],
            "confidence": 0.88,
            "rationale": "Block suspicious source IP",
            "priority": 1,
        },
        {
            "action_type": "disable_user",
            "conditions": ["suspicious_account"],
            "confidence": 0.80,
            "rationale": "Temporarily disable suspicious user account",
            "priority": 2,
        },
        {
            "action_type": "escalate",
            "conditions": ["always"],
            "confidence": 0.95,
            "rationale": "Escalate to SOC analyst for investigation",
            "priority": 3,
        },
    ],
    "MEDIUM": [
        {
            "action_type": "escalate",
            "conditions": ["always"],
            "confidence": 0.85,
            "rationale": "Flag for SOC analyst review during next shift",
            "priority": 1,
        },
    ],
    "LOW": [
        {
            "action_type": "escalate",
            "conditions": ["repeated_pattern"],
            "confidence": 0.60,
            "rationale": "Log for trend analysis, investigate if pattern repeats",
            "priority": 1,
        },
    ],
}

# Simulation templates for each action type
SIMULATION_TEMPLATES = {
    "block_external_ip": {
        "action": "Add IP to firewall deny list",
        "systems_affected": ["perimeter_firewall", "internal_firewall", "WAF"],
        "estimated_time": "< 1 minute",
        "reversible": True,
        "side_effects": "May block legitimate traffic from the same IP range",
        "rollback_procedure": "Remove IP from deny list on all firewalls",
    },
    "reset_credentials": {
        "action": "Force password reset for compromised accounts",
        "systems_affected": ["active_directory", "vpn_gateway", "email_server"],
        "estimated_time": "< 30 seconds",
        "reversible": True,
        "side_effects": "User will lose access to all corporate systems immediately",
        "rollback_procedure": "Restore access after password reset",
    },
    "isolate_host": {
        "action": "Network isolation via VLAN change or firewall rules",
        "systems_affected": ["switch_infrastructure", "firewall", "SIEM"],
        "estimated_time": "1-5 minutes",
        "reversible": True,
        "side_effects": "Host will be disconnected from all network services",
        "rollback_procedure": "Restore original VLAN, verify connectivity, run health checks",
    },
    "rotate_secrets": {
        "action": "Rotate API keys and session tokens",
        "systems_affected": ["secrets_manager", "iam_roles"],
        "estimated_time": "2-10 minutes",
        "reversible": False,
        "side_effects": "Active sessions will be terminated",
        "rollback_procedure": "Cannot be rolled back, must issue new secrets",
    },
    "notify_soc_team": {
        "action": "Create escalation ticket and notify SOC",
        "systems_affected": ["ticketing_system", "notification_channels"],
        "estimated_time": "< 30 seconds",
        "reversible": False,
        "side_effects": "None - informational only",
        "rollback_procedure": "Close ticket if false positive",
    },
}


class ResponseOrchestrator:
    """
    Autonomous response orchestrator.
    Generates response actions based on incident context.
    ALL ACTIONS ARE SIMULATION ONLY.
    """

    def __init__(self):
        self.playbooks = PLAYBOOKS
        self.simulation_templates = SIMULATION_TEMPLATES
        self.action_history: List[Dict] = []

    def generate_response(self, incident: Dict) -> List[ProposedAction]:
        """
        Generate proposed response actions for an incident.

        Args:
            incident: Dict with severity, affected_assets, mitre_techniques, etc.

        Returns:
            List of ProposedAction recommendations
        """
        severity = incident.get('severity', 'MEDIUM').upper()
        playbook = self.playbooks.get(severity, self.playbooks['MEDIUM'])

        proposed_actions = []

        for action_template in playbook:
            # Check conditions
            if self._check_conditions(action_template['conditions'], incident):
                target = self._determine_target(action_template['action_type'], incident)
                parameters = self._build_parameters(action_template['action_type'], incident)

                # Generate simulation result
                simulation = self._simulate_action(action_template['action_type'], target, incident)

                action = ProposedAction(
                    action_type=action_template['action_type'],
                    target=target,
                    parameters=parameters,
                    confidence=action_template['confidence'],
                    rationale=action_template['rationale'],
                    simulation_result=simulation,
                    severity=severity,
                    priority=action_template['priority'],
                )
                proposed_actions.append(action)

        # Log the proposals
        for action in proposed_actions:
            self.action_history.append({
                "timestamp": datetime.now().isoformat(),
                "incident_id": incident.get('id'),
                "action_type": action.action_type,
                "target": action.target,
                "status": "proposed",
            })

        return proposed_actions

    def simulate_action(self, action_type: str, target: str, context: Dict = None) -> Dict[str, Any]:
        """Simulate a specific response action"""
        return self._simulate_action(action_type, target, context or {})

    def get_playbook(self, severity: str) -> List[Dict]:
        """Get the response playbook for a given severity level"""
        return self.playbooks.get(severity.upper(), [])

    def get_action_history(self, limit: int = 50) -> List[Dict]:
        """Get recent action history"""
        return self.action_history[-limit:]

    def _check_conditions(self, conditions: List[str], incident: Dict) -> bool:
        """Check if action conditions are met"""
        for condition in conditions:
            if condition == "always":
                continue
            elif condition == "source_ip_identified":
                telemetry = incident.get('telemetry_events', [])
                if not any(e.get('source_ip') for e in telemetry):
                    # Check top-level too
                    if not incident.get('source_ip'):
                        return False
            elif condition == "host_compromised":
                if not incident.get('affected_assets'):
                    return False
            elif condition == "host_identified":
                if not incident.get('affected_assets'):
                    return False
            elif condition == "compromised_account" or condition == "suspicious_account":
                telemetry = incident.get('telemetry_events', [])
                if not any(e.get('user_identity') for e in telemetry):
                    if not incident.get('user_identity'):
                        return False
            elif condition == "repeated_pattern":
                # For LOW severity, only escalate if pattern repeats
                return True  # Always true in simulation
        return True

    def _determine_target(self, action_type: str, incident: Dict) -> str:
        """Determine the target for an action"""
        if action_type == "block_external_ip":
            telemetry = incident.get('telemetry_events', [])
            for event in telemetry:
                if event.get('source_ip'):
                    return event['source_ip']
            return incident.get('source_ip', 'unknown_ip')

        elif action_type == "reset_credentials":
            telemetry = incident.get('telemetry_events', [])
            for event in telemetry:
                if event.get('user_identity'):
                    return event['user_identity']
            return incident.get('user_identity', 'unknown_user')

        elif action_type == "isolate_host":
            assets = incident.get('affected_assets', [])
            if assets:
                first_asset = assets[0]
                if isinstance(first_asset, dict):
                    return first_asset.get('name', first_asset.get('ip_address', 'unknown_host'))
                elif isinstance(first_asset, int):
                    return f"asset_id_{first_asset}"
                else:
                    return str(first_asset)
            return 'affected_host'

        elif action_type == "rotate_secrets":
            return 'all_active_sessions'

        elif action_type == "notify_soc_team":
            return f"Incident #{incident.get('id', 'N/A')}"

        return 'unknown_target'

    def _build_parameters(self, action_type: str, incident: Dict) -> Dict:
        """Build parameters for an action"""
        params = {
            "incident_id": incident.get('id'),
            "severity": incident.get('severity'),
            "triggered_at": datetime.now().isoformat(),
            "simulation_mode": True,  # ALWAYS TRUE
        }

        if action_type == "block_external_ip":
            params["block_duration"] = "24h"
            params["scope"] = "perimeter"

        elif action_type == "isolate_host":
            params["isolation_type"] = "network_vlan"
            params["preserve_logging"] = True

        elif action_type == "notify_soc_team":
            params["escalate_to"] = ["soc_analyst"]
            params["notification_channels"] = ["email", "sms"]

        return params

    def _simulate_action(self, action_type: str, target: str, incident: Dict) -> Dict[str, Any]:
        """Generate simulation result for an action"""
        template = self.simulation_templates.get(action_type, {})

        simulation = {
            "action": template.get("action", f"Execute {action_type}"),
            "target": target,
            "systems_affected": template.get("systems_affected", []),
            "estimated_time": template.get("estimated_time", "unknown"),
            "reversible": template.get("reversible", True),
            "side_effects": template.get("side_effects", "None identified"),
            "rollback_procedure": template.get("rollback_procedure", "Manual rollback required"),
            "simulation_status": "SIMULATED",
            "execution_status": "NOT_EXECUTED",
            "note": "️ This is a SIMULATION. No real actions were taken.",
        }

        return simulation


# Global instance
response_orchestrator = ResponseOrchestrator()
