"""
SentinelGrid Advanced Security Features
Enhanced security controls, threat hunting, and automated response
"""
import logging
import hashlib
import hmac
import secrets
import time
import re
from typing import Dict, List, Optional, Set, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from collections import defaultdict
import json

logger = logging.getLogger(__name__)

@dataclass
class SecurityEvent:
    """Security event data structure"""
    event_id: str
    timestamp: datetime
    event_type: str
    severity: str
    source_ip: str
    target: str
    description: str
    indicators: List[str]
    mitre_techniques: List[str]
    confidence: float

class ThreatHunter:
    """Advanced threat hunting capabilities"""
    
    def __init__(self):
        self.hunting_rules = []
        self.ioc_database = set()
        self.threat_patterns = {}
        self.false_positives = set()
        
        # Load default hunting rules
        self._load_default_rules()
    
    def _load_default_rules(self):
        """Load default threat hunting rules"""
        self.hunting_rules = [
            {
                'name': 'Credential Stuffing',
                'pattern': self._detect_credential_stuffing,
                'severity': 'HIGH',
                'mitre': ['T1110.004']
            },
            {
                'name': 'Living Off The Land',
                'pattern': self._detect_lolbins,
                'severity': 'MEDIUM',
                'mitre': ['T1059']
            },
            {
                'name': 'Lateral Movement',
                'pattern': self._detect_lateral_movement,
                'severity': 'HIGH',
                'mitre': ['T1021']
            }
        ]
    
    def hunt_threats(self, events: List[Dict]) -> List[SecurityEvent]:
        """Hunt for threats in event data"""
        security_events = []
        
        for rule in self.hunting_rules:
            try:
                detected_events = rule['pattern'](events)
                
                for event in detected_events:
                    security_event = SecurityEvent(
                        event_id=f"hunt_{int(time.time())}_{hash(str(event))}",
                        timestamp=datetime.now(),
                        event_type=rule['name'],
                        severity=rule['severity'],
                        source_ip=event.get('source_ip', 'unknown'),
                        target=event.get('target', 'unknown'),
                        description=event.get('description', ''),
                        indicators=event.get('indicators', []),
                        mitre_techniques=rule['mitre'],
                        confidence=event.get('confidence', 0.8)
                    )
                    security_events.append(security_event)
                    
            except Exception as e:
                logger.error(f"Threat hunting rule '{rule['name']}' failed: {e}")
        
        return security_events
    
    def _detect_credential_stuffing(self, events: List[Dict]) -> List[Dict]:
        """Detect credential stuffing attacks"""
        detected = []
        ip_attempts = defaultdict(list)
        
        # Group login attempts by IP
        for event in events:
            if event.get('service') in ['SSH', 'HTTP', 'FTP'] and event.get('username'):
                ip_attempts[event.get('source_ip', 'unknown')].append(event)
        
        # Analyze patterns
        for ip, attempts in ip_attempts.items():
            if len(attempts) > 20:  # High volume
                unique_usernames = len(set(a.get('username') for a in attempts))
                unique_passwords = len(set(a.get('password') for a in attempts))
                
                if unique_usernames > 10 and unique_passwords > 10:
                    detected.append({
                        'source_ip': ip,
                        'target': 'authentication_services',
                        'description': f'Credential stuffing: {len(attempts)} attempts, {unique_usernames} usernames',
                        'indicators': [f'ip:{ip}', f'attempts:{len(attempts)}'],
                        'confidence': 0.9
                    })
        
        return detected
    
    def _detect_lolbins(self, events: List[Dict]) -> List[Dict]:
        """Detect Living Off The Land binaries usage"""
        detected = []
        lolbins = [
            'powershell', 'cmd', 'wmic', 'certutil', 'bitsadmin',
            'regsvr32', 'rundll32', 'mshta', 'cscript', 'wscript'
        ]
        
        for event in events:
            command = event.get('command', '').lower()
            payload = event.get('payload', '').lower()
            
            for lolbin in lolbins:
                if lolbin in command or lolbin in payload:
                    detected.append({
                        'source_ip': event.get('source_ip', 'unknown'),
                        'target': event.get('service', 'unknown'),
                        'description': f'LOLBin usage detected: {lolbin}',
                        'indicators': [f'command:{command}', f'lolbin:{lolbin}'],
                        'confidence': 0.7
                    })
                    break
        
        return detected
    
    def _detect_lateral_movement(self, events: List[Dict]) -> List[Dict]:
        """Detect lateral movement patterns"""
        detected = []
        ip_services = defaultdict(set)
        
        # Track services accessed by each IP
        for event in events:
            ip = event.get('source_ip', 'unknown')
            service = event.get('service', 'unknown')
            ip_services[ip].add(service)
        
        # Look for IPs accessing multiple services
        for ip, services in ip_services.items():
            if len(services) >= 3:  # Multiple services
                detected.append({
                    'source_ip': ip,
                    'target': 'multiple_services',
                    'description': f'Lateral movement: accessing {len(services)} services',
                    'indicators': [f'ip:{ip}', f'services:{",".join(services)}'],
                    'confidence': 0.6
                })
        
        return detected
    
    def add_ioc(self, indicator: str, ioc_type: str, description: str = ""):
        """Add Indicator of Compromise"""
        self.ioc_database.add(f"{ioc_type}:{indicator}")
        logger.info(f"Added IOC: {ioc_type}:{indicator}")
    
    def check_iocs(self, event: Dict) -> List[str]:
        """Check event against IOC database"""
        matches = []
        
        # Check IP
        ip = event.get('source_ip', '')
        if f"ip:{ip}" in self.ioc_database:
            matches.append(f"ip:{ip}")
        
        return matches

class AutomatedResponseSystem:
    """Automated incident response system"""
    
    def __init__(self):
        self.response_rules = []
        self.blocked_ips = set()
        self.quarantined_events = []
        self.response_history = []
        
        # Load default response rules
        self._load_default_responses()
    
    def _load_default_responses(self):
        """Load default response rules"""
        self.response_rules = [
            {
                'name': 'Block High-Risk IPs',
                'condition': lambda event: event.get('severity') == 'CRITICAL',
                'action': self._block_ip,
                'cooldown': 300  # 5 minutes
            }
        ]
    
    def process_security_event(self, security_event: SecurityEvent) -> Dict[str, Any]:
        """Process security event and trigger responses"""
        responses_triggered = []
        
        event_dict = {
            'source_ip': security_event.source_ip,
            'severity': security_event.severity,
            'confidence': security_event.confidence
        }
        
        for rule in self.response_rules:
            try:
                if rule['condition'](event_dict):
                    response = rule['action'](security_event)
                    responses_triggered.append({
                        'rule': rule['name'],
                        'response': response,
                        'timestamp': datetime.now().isoformat()
                    })
                        
            except Exception as e:
                logger.error(f"Response rule '{rule['name']}' failed: {e}")
        
        return {
            'event_id': security_event.event_id,
            'responses_triggered': responses_triggered,
            'total_responses': len(responses_triggered)
        }
    
    def _block_ip(self, security_event: SecurityEvent) -> str:
        """Block IP address"""
        ip = security_event.source_ip
        self.blocked_ips.add(ip)
        
        logger.warning(f"BLOCKED IP: {ip} (Event: {security_event.event_type})")
        
        return f"Blocked IP {ip}"
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        return ip in self.blocked_ips

class SecurityAuditLogger:
    """Security audit logging system"""
    
    def __init__(self):
        self.audit_logs = []
        self.log_retention_days = 90
    
    def log_security_event(self, event: SecurityEvent, action: str = "detected"):
        """Log security event for audit"""
        audit_entry = {
            'timestamp': datetime.now().isoformat(),
            'event_id': event.event_id,
            'event_type': event.event_type,
            'severity': event.severity,
            'source_ip': event.source_ip,
            'action': action,
            'description': event.description
        }
        
        self.audit_logs.append(audit_entry)
        logger.info(f"Security audit: {action} - {event.event_type} from {event.source_ip}")
    
    def get_audit_logs(self, limit: int = 100) -> List[Dict]:
        """Get recent audit logs"""
        return list(self.audit_logs)[-limit:]

# ========================
# GLOBAL INSTANCES
# ========================

threat_hunter = ThreatHunter()
automated_response = AutomatedResponseSystem()
security_audit_logger = SecurityAuditLogger()
