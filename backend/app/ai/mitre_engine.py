"""
SentinelGrid AI — MITRE ATT&CK Intelligence Engine (Module 2)

Maps security telemetry events to ATT&CK techniques.
Identifies attack stages, generates timelines, and finds threat actor similarity.
"""
import logging
import json
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
from collections import defaultdict

logger = logging.getLogger(__name__)


# ========================
# MITRE ATT&CK KNOWLEDGE BASE
# ========================

# Embedded subset of MITRE ATT&CK Enterprise Matrix (v14)
# Full matrix is loaded from JSON if available
MITRE_TACTICS = [
    {"id": "TA0043", "name": "Reconnaissance", "shortname": "reconnaissance"},
    {"id": "TA0042", "name": "Resource Development", "shortname": "resource-development"},
    {"id": "TA0001", "name": "Initial Access", "shortname": "initial-access"},
    {"id": "TA0002", "name": "Execution", "shortname": "execution"},
    {"id": "TA0003", "name": "Persistence", "shortname": "persistence"},
    {"id": "TA0004", "name": "Privilege Escalation", "shortname": "privilege-escalation"},
    {"id": "TA0005", "name": "Defense Evasion", "shortname": "defense-evasion"},
    {"id": "TA0006", "name": "Credential Access", "shortname": "credential-access"},
    {"id": "TA0007", "name": "Discovery", "shortname": "discovery"},
    {"id": "TA0008", "name": "Lateral Movement", "shortname": "lateral-movement"},
    {"id": "TA0009", "name": "Collection", "shortname": "collection"},
    {"id": "TA0011", "name": "Command and Control", "shortname": "command-and-control"},
    {"id": "TA0010", "name": "Exfiltration", "shortname": "exfiltration"},
    {"id": "TA0040", "name": "Impact", "shortname": "impact"},
]

# Core techniques with detection patterns
TECHNIQUE_PATTERNS = {
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "patterns": ["sql_injection", "xss", "rce", "exploit", "cve-"],
        "severity": "CRITICAL",
        "description": "Adversary exploits a vulnerability in an internet-facing application"
    },
    "T1133": {
        "name": "External Remote Services",
        "tactic": "Initial Access",
        "patterns": ["rdp", "vnc", "ssh_external", "remote_desktop"],
        "severity": "HIGH",
        "description": "Adversary uses legitimate remote access services"
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "patterns": ["valid_credential", "successful_login_unusual", "default_password"],
        "severity": "HIGH",
        "description": "Adversary uses compromised or default credentials"
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "patterns": ["brute_force", "failed_login", "credential_stuffing", "password_spray"],
        "severity": "HIGH",
        "description": "Adversary attempts to gain access through systematic credential guessing"
    },
    "T1110.001": {
        "name": "Password Guessing",
        "tactic": "Credential Access",
        "patterns": ["password_guess", "common_password", "admin_login_attempt"],
        "severity": "MEDIUM",
        "description": "Adversary guesses passwords with common or default values"
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "patterns": ["cmd", "powershell", "bash", "python_exec", "script_execution"],
        "severity": "HIGH",
        "description": "Adversary uses command-line interpreters or scripting to execute commands"
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "patterns": ["powershell", "pwsh", "invoke-expression", "iex"],
        "severity": "HIGH",
        "description": "Adversary uses PowerShell for execution"
    },
    "T1059.004": {
        "name": "Unix Shell",
        "tactic": "Execution",
        "patterns": ["bash", "/bin/sh", "sh -c", "curl | bash"],
        "severity": "HIGH",
        "description": "Adversary uses Unix shell for execution"
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "patterns": ["mimikatz", "credential_dump", "/etc/shadow", "hashdump", "lsass"],
        "severity": "CRITICAL",
        "description": "Adversary dumps credentials from the operating system"
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "patterns": ["ssh_lateral", "rdp_lateral", "smb_access", "wmi_remote", "psexec"],
        "severity": "HIGH",
        "description": "Adversary uses remote services to move laterally"
    },
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "patterns": ["rdp", "mstsc", "remote_desktop", "port_3389"],
        "severity": "MEDIUM",
        "description": "Adversary uses RDP for lateral movement"
    },
    "T1021.004": {
        "name": "SSH",
        "tactic": "Lateral Movement",
        "patterns": ["ssh_key", "ssh_agent", "authorized_keys"],
        "severity": "MEDIUM",
        "description": "Adversary uses SSH for lateral movement"
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "Persistence",
        "patterns": ["cron", "at_job", "schtasks", "scheduled_task", "systemd_timer"],
        "severity": "MEDIUM",
        "description": "Adversary creates scheduled tasks for persistence"
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
        "patterns": ["autostart", "startup_folder", "registry_run", "rc.local", "init.d"],
        "severity": "HIGH",
        "description": "Adversary establishes persistence through boot or logon autostart"
    },
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "patterns": ["sudo", "su_root", "privilege_escalation", "setuid", "runas"],
        "severity": "CRITICAL",
        "description": "Adversary escalates privileges through elevation control mechanisms"
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "patterns": ["uname", "systeminfo", "hostname", "ifconfig", "ipconfig", "whoami"],
        "severity": "LOW",
        "description": "Adversary gathers system configuration information"
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "patterns": ["ls -la", "dir", "find /", "tree", "file_listing"],
        "severity": "LOW",
        "description": "Adversary enumerates files and directories"
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "patterns": ["nmap", "port_scan", "netstat", "netscan", "service_discovery"],
        "severity": "MEDIUM",
        "description": "Adversary discovers network services"
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "patterns": ["http_c2", "dns_tunnel", "c2_beacon", "reverse_shell"],
        "severity": "HIGH",
        "description": "Adversary uses application layer protocols for C2"
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "patterns": ["data_exfil", "file_transfer_out", "upload_sensitive", "exfiltration"],
        "severity": "CRITICAL",
        "description": "Adversary exfiltrates data over the C2 channel"
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "patterns": ["ransomware", "encrypt_files", "ransom_note", "crypto_lock"],
        "severity": "CRITICAL",
        "description": "Adversary encrypts data to disrupt operations"
    },
    "T1485": {
        "name": "Data Destruction",
        "tactic": "Impact",
        "patterns": ["rm -rf", "format", "data_wipe", "disk_destroy", "del /f /s"],
        "severity": "CRITICAL",
        "description": "Adversary destroys data to disrupt operations"
    },
    "T0855": {
        "name": "Unauthorized Command Message (ICS)",
        "tactic": "Impact",
        "patterns": ["modbus_write", "dnp3_operate", "scada_command", "plc_reprogram"],
        "severity": "CRITICAL",
        "description": "Adversary sends unauthorized commands to ICS equipment"
    },
    "T0831": {
        "name": "Manipulation of Control (ICS)",
        "tactic": "Impact",
        "patterns": ["control_manipulation", "setpoint_change", "process_modification"],
        "severity": "CRITICAL",
        "description": "Adversary manipulates control system to affect physical process"
    },
}

# Known threat actor profiles for similarity matching
THREAT_ACTORS = {
    "APT28": {"techniques": ["T1190", "T1059.001", "T1003", "T1021", "T1071", "T1041"], "origin": "Russia"},
    "APT29": {"techniques": ["T1078", "T1059.001", "T1547", "T1021", "T1071"], "origin": "Russia"},
    "APT41": {"techniques": ["T1190", "T1059", "T1053", "T1021", "T1041"], "origin": "China"},
    "Lazarus": {"techniques": ["T1190", "T1059", "T1486", "T1071", "T1041"], "origin": "North Korea"},
    "Sandworm": {"techniques": ["T1190", "T1059", "T1485", "T0855", "T0831"], "origin": "Russia"},
    "TRITON": {"techniques": ["T1190", "T1059", "T0855", "T0831"], "origin": "Russia"},
    "Dragonfly": {"techniques": ["T1133", "T1078", "T1059", "T0855"], "origin": "Russia"},
    "MuddyWater": {"techniques": ["T1059.001", "T1547", "T1071", "T1041"], "origin": "Iran"},
}


class MitreAttackEngine:
    """
    Maps security telemetry events to MITRE ATT&CK techniques.
    Provides attack stage identification, timeline generation, and threat actor matching.
    """

    def __init__(self):
        self.techniques = TECHNIQUE_PATTERNS
        self.tactics = MITRE_TACTICS
        self.threat_actors = THREAT_ACTORS
        self._compiled_patterns = {}
        self._compile_patterns()

    def _compile_patterns(self):
        """Pre-compile regex patterns for efficient matching"""
        for tech_id, tech_data in self.techniques.items():
            compiled = []
            for pattern in tech_data.get('patterns', []):
                try:
                    compiled.append(re.compile(pattern, re.IGNORECASE))
                except re.error:
                    compiled.append(re.compile(re.escape(pattern), re.IGNORECASE))
            self._compiled_patterns[tech_id] = compiled

    def map_event(self, event: Dict) -> List[Dict[str, Any]]:
        """
        Map a single telemetry event to MITRE ATT&CK techniques.
        Returns list of matched techniques with confidence scores.
        """
        matches = []
        event_text = self._build_event_text(event)

        for tech_id, patterns in self._compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(event_text):
                    tech_data = self.techniques[tech_id]
                    confidence = self._calculate_confidence(event, tech_id, event_text)

                    matches.append({
                        "technique_id": tech_id,
                        "technique_name": tech_data["name"],
                        "tactic": tech_data["tactic"],
                        "severity": tech_data["severity"],
                        "confidence": confidence,
                        "description": tech_data["description"],
                        "threat_actors": self._find_similar_actors([tech_id])
                    })
                    break  # One match per technique is enough

        # Rule-based detection for common patterns
        rule_matches = self._apply_rules(event)
        for rm in rule_matches:
            if not any(m['technique_id'] == rm['technique_id'] for m in matches):
                matches.append(rm)

        # Sort by confidence
        matches.sort(key=lambda x: x['confidence'], reverse=True)
        return matches

    def map_events_batch(self, events: List[Dict]) -> Dict[str, List[Dict]]:
        """Map multiple events and return aggregated results"""
        all_mappings = {}
        for event in events:
            event_id = event.get('id', id(event))
            mappings = self.map_event(event)
            if mappings:
                all_mappings[str(event_id)] = mappings
        return all_mappings

    def get_attack_timeline(self, events: List[Dict]) -> List[Dict]:
        """Generate attack timeline from mapped events"""
        timeline = []

        for event in sorted(events, key=lambda e: e.get('timestamp', '')):
            mappings = self.map_event(event)
            for mapping in mappings[:1]:  # Top mapping per event
                timeline.append({
                    "timestamp": event.get('timestamp', datetime.now().isoformat()),
                    "technique_id": mapping['technique_id'],
                    "technique_name": mapping['technique_name'],
                    "tactic": mapping['tactic'],
                    "severity": mapping['severity'],
                    "source_ip": event.get('source_ip', 'unknown'),
                    "description": f"{mapping['technique_name']}: {event.get('action', '')} from {event.get('source_ip', 'unknown')}",
                    "confidence": mapping['confidence']
                })

        return timeline

    def identify_attack_stage(self, technique_ids: List[str]) -> Dict[str, Any]:
        """Identify the current attack stage based on detected techniques"""
        tactic_order = [t['name'] for t in self.tactics]
        detected_tactics = set()

        for tech_id in technique_ids:
            if tech_id in self.techniques:
                detected_tactics.add(self.techniques[tech_id]['tactic'])

        # Find the latest (most advanced) tactic
        current_stage = "Unknown"
        stage_index = -1
        for i, tactic in enumerate(tactic_order):
            if tactic in detected_tactics:
                current_stage = tactic
                stage_index = i

        # Determine progress through kill chain
        total_tactics = len(tactic_order)
        progress = (stage_index + 1) / total_tactics if stage_index >= 0 else 0

        return {
            "current_stage": current_stage,
            "detected_tactics": list(detected_tactics),
            "kill_chain_progress": round(progress * 100, 1),
            "stages_remaining": tactic_order[stage_index + 1:] if stage_index >= 0 else tactic_order,
            "threat_level": self._assess_stage_threat(stage_index, total_tactics)
        }

    def get_technique_heatmap(self, technique_counts: Dict[str, int]) -> Dict[str, List[Dict]]:
        """Generate heatmap data: techniques organized by tactic with counts"""
        heatmap = {}

        for tactic in self.tactics:
            tactic_name = tactic['name']
            heatmap[tactic_name] = []

            for tech_id, tech_data in self.techniques.items():
                if tech_data['tactic'] == tactic_name:
                    count = technique_counts.get(tech_id, 0)
                    heatmap[tactic_name].append({
                        "technique_id": tech_id,
                        "technique_name": tech_data['name'],
                        "count": count,
                        "severity": tech_data['severity'],
                        "intensity": min(1.0, count / 10) if count > 0 else 0  # Normalize for heatmap
                    })

        return heatmap

    def get_matrix_data(self) -> Dict[str, Any]:
        """Return full ATT&CK matrix structure for frontend rendering"""
        matrix = {
            "tactics": self.tactics,
            "techniques_by_tactic": {}
        }

        for tactic in self.tactics:
            tactic_name = tactic['name']
            techniques = []
            for tech_id, tech_data in self.techniques.items():
                if tech_data['tactic'] == tactic_name:
                    techniques.append({
                        "id": tech_id,
                        "name": tech_data['name'],
                        "severity": tech_data['severity'],
                        "description": tech_data['description']
                    })
            matrix['techniques_by_tactic'][tactic_name] = techniques

        return matrix

    def _find_similar_actors(self, technique_ids: List[str]) -> List[Dict]:
        """Find threat actors with similar technique usage"""
        similarities = []

        for actor_name, actor_data in self.threat_actors.items():
            actor_techniques = set(actor_data['techniques'])
            overlap = len(set(technique_ids) & actor_techniques)
            if overlap > 0:
                similarity = overlap / len(actor_techniques)
                similarities.append({
                    "name": actor_name,
                    "similarity": round(similarity, 2),
                    "origin": actor_data['origin'],
                    "shared_techniques": list(set(technique_ids) & actor_techniques)
                })

        similarities.sort(key=lambda x: x['similarity'], reverse=True)
        return similarities[:5]

    def _build_event_text(self, event: Dict) -> str:
        """Build searchable text from event fields"""
        parts = [
            str(event.get('action', '')),
            str(event.get('command', '')),
            str(event.get('payload', '')),
            str(event.get('resource', '')),
            str(event.get('protocol', '')),
            str(event.get('event_type', '')),
            str(event.get('raw_log', '')),
        ]
        return ' '.join(p for p in parts if p).lower()

    def _calculate_confidence(self, event: Dict, tech_id: str, event_text: str) -> float:
        """Calculate confidence score for a technique mapping"""
        base_confidence = 0.6

        # Boost for multiple pattern matches
        tech_data = self.techniques[tech_id]
        pattern_matches = sum(1 for p in tech_data['patterns'] if p.lower() in event_text)
        if pattern_matches > 1:
            base_confidence += 0.1 * min(pattern_matches, 3)

        # Boost for high severity events
        severity = event.get('severity', 'INFO').upper()
        severity_boost = {'CRITICAL': 0.15, 'HIGH': 0.1, 'MEDIUM': 0.05}.get(severity, 0)
        base_confidence += severity_boost

        return min(base_confidence, 0.98)

    def _apply_rules(self, event: Dict) -> List[Dict]:
        """Apply rule-based detection for common attack patterns"""
        matches = []
        action = str(event.get('action', '')).lower()
        protocol = str(event.get('protocol', '')).upper()
        event_type = str(event.get('event_type', '')).lower()
        user = str(event.get('user_identity', '')).lower()

        # Failed authentication → Brute Force
        if action in ('failed_login', 'auth_failure') or 'failed' in action:
            matches.append(self._make_match("T1110", 0.7))

        # Successful login with common creds → Valid Accounts
        if action in ('login', 'successful_login') and user in ('admin', 'root', 'administrator', 'guest'):
            matches.append(self._make_match("T1078", 0.65))

        # SCADA protocol write → Unauthorized Command
        if protocol in ('MODBUS', 'DNP3', 'S7COMM') and 'write' in action:
            matches.append(self._make_match("T0855", 0.85))

        # Privilege escalation
        if 'sudo' in action or 'su_root' in action or 'privilege' in action:
            matches.append(self._make_match("T1548", 0.75))

        # Port scanning
        if 'scan' in action or event_type == 'port_scan':
            matches.append(self._make_match("T1046", 0.7))

        return matches

    def _make_match(self, tech_id: str, confidence: float) -> Dict:
        """Create a technique match result"""
        tech_data = self.techniques.get(tech_id, {"name": "Unknown", "tactic": "Unknown", "severity": "MEDIUM", "description": ""})
        return {
            "technique_id": tech_id,
            "technique_name": tech_data["name"],
            "tactic": tech_data["tactic"],
            "severity": tech_data["severity"],
            "confidence": confidence,
            "description": tech_data["description"],
            "threat_actors": self._find_similar_actors([tech_id])
        }

    def _assess_stage_threat(self, stage_index: int, total: int) -> str:
        """Assess threat level based on attack stage progression"""
        if stage_index < 0:
            return "MINIMAL"
        progress = stage_index / total
        if progress >= 0.7:
            return "CRITICAL"
        elif progress >= 0.5:
            return "HIGH"
        elif progress >= 0.3:
            return "MEDIUM"
        else:
            return "LOW"


# Global instance
mitre_engine = MitreAttackEngine()
