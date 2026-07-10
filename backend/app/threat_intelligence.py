"""
SentinelGrid Phase 2: Advanced Threat Intelligence System
Provides enhanced threat analysis, IP reputation checking, and attack pattern recognition
"""
import logging
import re
import json
import hashlib
import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from .config import settings

logger = logging.getLogger(__name__)

@dataclass
class ThreatIntelligence:
    """Threat intelligence data structure"""
    ip_address: str
    reputation_score: float  # 0.0 (clean) to 1.0 (malicious)
    threat_types: List[str]
    is_tor: bool
    is_vpn: bool
    is_proxy: bool
    abuse_confidence: int
    country_risk_score: float
    isp_risk_score: float
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    attack_count: int
    sources: List[str]
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        # Convert datetime objects to ISO strings
        if self.first_seen:
            data['first_seen'] = self.first_seen.isoformat()
        if self.last_seen:
            data['last_seen'] = self.last_seen.isoformat()
        return data

class ThreatIntelligenceEngine:
    """Advanced threat intelligence engine for IP analysis"""
    
    def __init__(self):
        self.cache = {}  # Simple in-memory cache
        self.cache_ttl = 3600  # 1 hour cache
        self.high_risk_countries = {
            'CN', 'RU', 'KP', 'IR', 'PK', 'BD', 'VN', 'IN', 'BR', 'TR'
        }
        self.high_risk_asns = {
            'AS4134',  # China Telecom
            'AS4837',  # China Unicom
            'AS9808',  # China Mobile
            'AS12389', # Rostelecom (Russia)
            'AS8359',  # MTS (Russia)
        }
        self.tor_exit_nodes = set()  # Will be populated from external source
        self.vpn_providers = set()   # Will be populated from external source
    
    async def analyze_ip(self, ip_address: str) -> ThreatIntelligence:
        """Comprehensive IP threat analysis"""
        try:
            # Check cache first
            cache_key = f"threat_{ip_address}"
            if cache_key in self.cache:
                cached_data, timestamp = self.cache[cache_key]
                if datetime.now().timestamp() - timestamp < self.cache_ttl:
                    logger.debug(f"Using cached threat intelligence for {ip_address}")
                    return cached_data
            
            # Perform analysis
            threat_data = await self._analyze_ip_comprehensive(ip_address)
            
            # Cache the result
            self.cache[cache_key] = (threat_data, datetime.now().timestamp())
            
            logger.info(f"Threat analysis completed for {ip_address}: score={threat_data.reputation_score}")
            return threat_data
            
        except Exception as e:
            logger.error(f"Threat analysis failed for {ip_address}: {e}")
            # Return default safe analysis
            return self._create_default_threat_intelligence(ip_address)
    
    async def _analyze_ip_comprehensive(self, ip_address: str) -> ThreatIntelligence:
        """Perform comprehensive IP analysis"""
        # Initialize threat intelligence object
        threat_intel = ThreatIntelligence(
            ip_address=ip_address,
            reputation_score=0.0,
            threat_types=[],
            is_tor=False,
            is_vpn=False,
            is_proxy=False,
            abuse_confidence=0,
            country_risk_score=0.0,
            isp_risk_score=0.0,
            first_seen=None,
            last_seen=datetime.now(),
            attack_count=0,
            sources=[]
        )
        
        # Gather intelligence from multiple sources
        tasks = [
            self._check_geolocation(ip_address),
            self._check_abuse_databases(ip_address),
            self._check_tor_exit_nodes(ip_address),
            self._check_vpn_providers(ip_address),
            self._analyze_local_history(ip_address)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        geo_data, abuse_data, tor_check, vpn_check, local_history = results
        
        # Update threat intelligence based on results
        if isinstance(geo_data, dict):
            threat_intel.country_risk_score = self._calculate_country_risk(geo_data.get('country_code'))
            threat_intel.isp_risk_score = self._calculate_isp_risk(geo_data.get('org', ''))
        
        if isinstance(abuse_data, dict):
            threat_intel.abuse_confidence = abuse_data.get('abuseConfidencePercentage', 0)
            threat_intel.threat_types.extend(abuse_data.get('usageType', []))
            threat_intel.sources.append('AbuseIPDB')
        
        if tor_check:
            threat_intel.is_tor = True
            threat_intel.threat_types.append('tor_exit_node')
            threat_intel.sources.append('TorProject')
        
        if vpn_check:
            threat_intel.is_vpn = True
            threat_intel.threat_types.append('vpn_provider')
            threat_intel.sources.append('VPN_Detection')
        
        if isinstance(local_history, dict):
            threat_intel.attack_count = local_history.get('attack_count', 0)
            threat_intel.first_seen = local_history.get('first_seen')
            threat_intel.sources.append('Local_History')
        
        # Calculate overall reputation score
        threat_intel.reputation_score = self._calculate_reputation_score(threat_intel)
        
        return threat_intel
    
    async def _check_geolocation(self, ip_address: str) -> Dict:
        """Check IP geolocation and ISP information"""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://ipapi.co/{ip_address}/json/"
                async with session.get(url, timeout=5) as response:
                    if response.status == 200:
                        data = await response.json()
                        if 'error' not in data:
                            return data
        except Exception as e:
            logger.warning(f"Geolocation check failed for {ip_address}: {e}")
        
        return {}
    
    async def _check_abuse_databases(self, ip_address: str) -> Dict:
        """Check IP against abuse databases"""
        try:
            if not settings.abuseipdb_key:
                logger.debug("AbuseIPDB API key not configured")
                return {}
            
            headers = {
                'Key': settings.abuseipdb_key,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            async with aiohttp.ClientSession() as session:
                url = "https://api.abuseipdb.com/api/v2/check"
                async with session.get(url, headers=headers, params=params, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get('data', {})
                    
        except Exception as e:
            logger.warning(f"Abuse database check failed for {ip_address}: {e}")
        
        return {}
    
    async def _check_tor_exit_nodes(self, ip_address: str) -> bool:
        """Check if IP is a Tor exit node"""
        try:
            # Simple check against known patterns or cached list
            # In production, this would check against Tor's exit node list
            if ip_address in self.tor_exit_nodes:
                return True
            
            # Could also check against Tor's official exit node list
            # This is a simplified implementation
            return False
            
        except Exception as e:
            logger.warning(f"Tor check failed for {ip_address}: {e}")
            return False
    
    async def _check_vpn_providers(self, ip_address: str) -> bool:
        """Check if IP belongs to known VPN providers"""
        try:
            # Simple check against known VPN provider ranges
            # In production, this would use commercial VPN detection services
            if ip_address in self.vpn_providers:
                return True
            
            return False
            
        except Exception as e:
            logger.warning(f"VPN check failed for {ip_address}: {e}")
            return False
    
    async def _analyze_local_history(self, ip_address: str) -> Dict:
        """Analyze local attack history for IP"""
        try:
            # This would query the local database for historical attacks
            # For now, return empty data
            return {
                'attack_count': 0,
                'first_seen': None,
                'severity_distribution': {}
            }
            
        except Exception as e:
            logger.warning(f"Local history analysis failed for {ip_address}: {e}")
            return {}
    
    def _calculate_country_risk(self, country_code: str) -> float:
        """Calculate risk score based on country"""
        if not country_code:
            return 0.0
        
        if country_code in self.high_risk_countries:
            return 0.7
        
        # Medium risk countries
        medium_risk = {'US', 'DE', 'FR', 'GB', 'NL', 'CA'}
        if country_code in medium_risk:
            return 0.3
        
        return 0.1
    
    def _calculate_isp_risk(self, org: str) -> float:
        """Calculate risk score based on ISP/Organization"""
        if not org:
            return 0.0
        
        org_lower = org.lower()
        
        # High risk indicators
        high_risk_keywords = ['hosting', 'cloud', 'server', 'datacenter', 'vps']
        for keyword in high_risk_keywords:
            if keyword in org_lower:
                return 0.6
        
        # Check against known high-risk ASNs
        for asn in self.high_risk_asns:
            if asn.lower() in org_lower:
                return 0.8
        
        return 0.2
    
    def _calculate_reputation_score(self, threat_intel: ThreatIntelligence) -> float:
        """Calculate overall reputation score"""
        score = 0.0
        
        # Base score from abuse confidence
        score += (threat_intel.abuse_confidence / 100) * 0.4
        
        # Country risk contribution
        score += threat_intel.country_risk_score * 0.2
        
        # ISP risk contribution
        score += threat_intel.isp_risk_score * 0.2
        
        # Tor/VPN/Proxy penalties
        if threat_intel.is_tor:
            score += 0.3
        if threat_intel.is_vpn:
            score += 0.2
        if threat_intel.is_proxy:
            score += 0.2
        
        # Attack history contribution
        if threat_intel.attack_count > 0:
            attack_score = min(threat_intel.attack_count / 100, 0.3)
            score += attack_score
        
        # Threat types contribution
        threat_type_scores = {
            'malware': 0.4,
            'botnet': 0.4,
            'scanner': 0.3,
            'brute_force': 0.3,
            'spam': 0.2,
            'tor_exit_node': 0.3,
            'vpn_provider': 0.2
        }
        
        for threat_type in threat_intel.threat_types:
            score += threat_type_scores.get(threat_type, 0.1)
        
        # Ensure score is between 0.0 and 1.0
        return min(max(score, 0.0), 1.0)
    
    def _create_default_threat_intelligence(self, ip_address: str) -> ThreatIntelligence:
        """Create default threat intelligence when analysis fails"""
        return ThreatIntelligence(
            ip_address=ip_address,
            reputation_score=0.5,  # Neutral score when unknown
            threat_types=['unknown'],
            is_tor=False,
            is_vpn=False,
            is_proxy=False,
            abuse_confidence=0,
            country_risk_score=0.5,
            isp_risk_score=0.5,
            first_seen=None,
            last_seen=datetime.now(),
            attack_count=0,
            sources=['default']
        )
    
    def get_threat_level(self, reputation_score: float) -> str:
        """Convert reputation score to threat level"""
        if reputation_score >= 0.8:
            return "CRITICAL"
        elif reputation_score >= 0.6:
            return "HIGH"
        elif reputation_score >= 0.4:
            return "MEDIUM"
        elif reputation_score >= 0.2:
            return "LOW"
        else:
            return "MINIMAL"
    
    def should_block_ip(self, threat_intel: ThreatIntelligence) -> bool:
        """Determine if IP should be blocked based on threat intelligence"""
        # Block if reputation score is very high
        if threat_intel.reputation_score >= 0.9:
            return True
        
        # Block if abuse confidence is very high
        if threat_intel.abuse_confidence >= 90:
            return True
        
        # Block if multiple high-risk indicators
        risk_indicators = 0
        if threat_intel.is_tor:
            risk_indicators += 1
        if threat_intel.abuse_confidence >= 50:
            risk_indicators += 1
        if threat_intel.attack_count >= 10:
            risk_indicators += 1
        if threat_intel.country_risk_score >= 0.7:
            risk_indicators += 1
        
        return risk_indicators >= 3
    
    async def bulk_analyze_ips(self, ip_addresses: List[str]) -> Dict[str, ThreatIntelligence]:
        """Analyze multiple IPs in parallel"""
        tasks = [self.analyze_ip(ip) for ip in ip_addresses]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        analysis_results = {}
        for ip, result in zip(ip_addresses, results):
            if isinstance(result, ThreatIntelligence):
                analysis_results[ip] = result
            else:
                logger.error(f"Failed to analyze {ip}: {result}")
                analysis_results[ip] = self._create_default_threat_intelligence(ip)
        
        return analysis_results
    
    def clear_cache(self):
        """Clear the threat intelligence cache"""
        self.cache.clear()
        logger.info("Threat intelligence cache cleared")
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics"""
        current_time = datetime.now().timestamp()
        valid_entries = 0
        expired_entries = 0
        
        for _, (_, timestamp) in self.cache.items():
            if current_time - timestamp < self.cache_ttl:
                valid_entries += 1
            else:
                expired_entries += 1
        
        return {
            'total_entries': len(self.cache),
            'valid_entries': valid_entries,
            'expired_entries': expired_entries,
            'cache_ttl': self.cache_ttl
        }

# ========================
# ATTACK PATTERN ANALYZER
# ========================

class AttackPatternAnalyzer:
    """Analyze attack patterns and behaviors"""
    
    def __init__(self):
        self.known_patterns = {
            'sql_injection': [
                r"union\s+select", r"or\s+1\s*=\s*1", r"drop\s+table",
                r"insert\s+into", r"delete\s+from", r"update\s+.*\s+set"
            ],
            'xss': [
                r"<script", r"javascript:", r"onerror\s*=", r"onload\s*=",
                r"alert\s*\(", r"document\.cookie"
            ],
            'path_traversal': [
                r"\.\./", r"\.\.\\", r"%2e%2e%2f", r"%2e%2e%5c"
            ],
            'command_injection': [
                r";\s*cat\s+", r";\s*ls\s+", r";\s*id\s*;", r";\s*whoami",
                r"\|\s*nc\s+", r"&&\s*cat\s+"
            ],
            'brute_force': [
                r"admin", r"root", r"administrator", r"test", r"guest"
            ]
        }
    
    def analyze_payload(self, payload: str) -> Dict[str, Any]:
        """Analyze attack payload for patterns"""
        if not payload:
            return {'patterns': [], 'risk_score': 0.0}
        
        detected_patterns = []
        risk_score = 0.0
        
        payload_lower = payload.lower()
        
        for pattern_type, patterns in self.known_patterns.items():
            for pattern in patterns:
                if re.search(pattern, payload_lower, re.IGNORECASE):
                    detected_patterns.append(pattern_type)
                    risk_score += 0.2
                    break  # Only count each pattern type once
        
        # Additional risk factors
        if len(payload) > 1000:
            risk_score += 0.1  # Long payloads are suspicious
        
        if re.search(r'[<>"\']', payload):
            risk_score += 0.1  # Special characters
        
        # Normalize risk score
        risk_score = min(risk_score, 1.0)
        
        return {
            'patterns': list(set(detected_patterns)),
            'risk_score': risk_score,
            'payload_length': len(payload),
            'contains_special_chars': bool(re.search(r'[<>"\']', payload))
        }
    
    def analyze_endpoint(self, endpoint: str) -> Dict[str, Any]:
        """Analyze endpoint for suspicious patterns"""
        if not endpoint:
            return {'suspicious': False, 'risk_score': 0.0}
        
        suspicious_endpoints = [
            r'/admin', r'/wp-admin', r'/phpmyadmin', r'/cpanel',
            r'\.php$', r'\.asp$', r'\.jsp$', r'/api/v\d+/admin',
            r'/config', r'/backup', r'/test', r'/debug'
        ]
        
        risk_score = 0.0
        suspicious = False
        
        for pattern in suspicious_endpoints:
            if re.search(pattern, endpoint, re.IGNORECASE):
                suspicious = True
                risk_score += 0.3
                break
        
        return {
            'suspicious': suspicious,
            'risk_score': min(risk_score, 1.0),
            'endpoint': endpoint
        }

# ========================
# GLOBAL INSTANCES
# ========================

# Global threat intelligence engine
threat_intelligence_engine = ThreatIntelligenceEngine()

# Global attack pattern analyzer
attack_pattern_analyzer = AttackPatternAnalyzer()
