"""
SentinelGrid Real-time Stream Processing
Handles high-volume attack streams with real-time analytics
"""
import asyncio
import logging
from typing import Dict, List, Optional, Callable
from datetime import datetime, timedelta
from collections import deque, defaultdict
import json
import time
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

@dataclass
class StreamMetrics:
    """Real-time stream metrics"""
    events_per_second: float
    total_events: int
    unique_ips: int
    top_attack_types: Dict[str, int]
    geographic_distribution: Dict[str, int]
    severity_distribution: Dict[str, int]
    timestamp: str

class RealTimeStreamProcessor:
    """Process attack events in real-time with sliding window analytics"""
    
    def __init__(self, window_size_seconds: int = 300):  # 5-minute window
        self.window_size = window_size_seconds
        self.event_buffer = deque(maxlen=10000)  # Keep last 10k events
        self.time_windows = defaultdict(lambda: deque())
        self.metrics_cache = {}
        self.subscribers = []  # WebSocket subscribers
        self.running = False
        
        # Rate limiting and burst detection
        self.ip_counters = defaultdict(lambda: deque())
        self.burst_threshold = 50  # events per minute
        self.suspicious_ips = set()
        
        # Pattern detection
        self.attack_patterns = defaultdict(list)
        self.coordinated_attack_threshold = 5  # IPs attacking same target
        
    async def start_processing(self):
        """Start the real-time processing loop"""
        self.running = True
        logger.info("🚀 Starting real-time stream processor")
        
        # Start background tasks
        asyncio.create_task(self._metrics_updater())
        asyncio.create_task(self._pattern_detector())
        asyncio.create_task(self._burst_detector())
        asyncio.create_task(self._cleanup_task())
    
    async def process_event(self, event: Dict) -> Dict:
        """Process a single event in real-time"""
        try:
            # Add timestamp if not present
            if 'timestamp' not in event:
                event['timestamp'] = datetime.now().isoformat()
            
            # Add to buffer
            self.event_buffer.append(event)
            
            # Update time windows
            current_time = time.time()
            self.time_windows[current_time].append(event)
            
            # Update IP counters for burst detection
            source_ip = event.get('source_ip', 'unknown')
            self.ip_counters[source_ip].append(current_time)
            
            # Real-time analysis
            analysis = await self._analyze_event_realtime(event)
            
            # Notify subscribers
            await self._notify_subscribers(event, analysis)
            
            return analysis
            
        except Exception as e:
            logger.error(f"Stream processing error: {e}")
            return {"error": str(e)}
    
    async def _analyze_event_realtime(self, event: Dict) -> Dict:
        """Perform real-time analysis on incoming event"""
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'event_id': event.get('id', 'unknown'),
            'real_time_flags': []
        }
        
        source_ip = event.get('source_ip', 'unknown')
        severity = event.get('severity', 'LOW')
        service = event.get('service', 'unknown')
        
        # Check for burst activity
        if self._is_burst_activity(source_ip):
            analysis['real_time_flags'].append('BURST_ACTIVITY')
            self.suspicious_ips.add(source_ip)
        
        # Check for coordinated attacks
        if self._is_coordinated_attack(event):
            analysis['real_time_flags'].append('COORDINATED_ATTACK')
        
        # Check for rapid escalation
        if self._is_rapid_escalation(source_ip, severity):
            analysis['real_time_flags'].append('RAPID_ESCALATION')
        
        # Geographic anomaly detection
        if self._is_geographic_anomaly(event):
            analysis['real_time_flags'].append('GEOGRAPHIC_ANOMALY')
        
        # Service targeting analysis
        if self._is_service_targeting(source_ip, service):
            analysis['real_time_flags'].append('SERVICE_TARGETING')
        
        # Calculate risk score
        analysis['real_time_risk_score'] = self._calculate_realtime_risk(analysis['real_time_flags'])
        
        return analysis
    
    def _is_burst_activity(self, ip: str) -> bool:
        """Detect burst activity from IP"""
        current_time = time.time()
        minute_ago = current_time - 60
        
        # Count events in last minute
        recent_events = [t for t in self.ip_counters[ip] if t > minute_ago]
        return len(recent_events) > self.burst_threshold
    
    def _is_coordinated_attack(self, event: Dict) -> bool:
        """Detect coordinated attacks on same target"""
        target_key = f"{event.get('service', 'unknown')}:{event.get('endpoint', 'unknown')}"
        current_time = time.time()
        
        # Add to pattern tracking
        self.attack_patterns[target_key].append({
            'ip': event.get('source_ip', 'unknown'),
            'timestamp': current_time
        })
        
        # Check for multiple IPs attacking same target
        minute_ago = current_time - 60
        recent_attacks = [a for a in self.attack_patterns[target_key] if a['timestamp'] > minute_ago]
        unique_ips = len(set(a['ip'] for a in recent_attacks))
        
        return unique_ips >= self.coordinated_attack_threshold
    
    def _is_rapid_escalation(self, ip: str, current_severity: str) -> bool:
        """Detect rapid severity escalation from same IP"""
        severity_scores = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        current_score = severity_scores.get(current_severity, 1)
        
        # Check recent events from this IP
        recent_events = [e for e in self.event_buffer 
                        if e.get('source_ip') == ip and 
                        (datetime.now() - datetime.fromisoformat(e.get('timestamp', datetime.now().isoformat()))).seconds < 300]
        
        if len(recent_events) < 2:
            return False
        
        # Check if severity increased significantly
        prev_severity = recent_events[-2].get('severity', 'LOW')
        prev_score = severity_scores.get(prev_severity, 1)
        
        return current_score > prev_score and (current_score - prev_score) >= 2
    
    def _is_geographic_anomaly(self, event: Dict) -> bool:
        """Detect geographic anomalies"""
        location = event.get('location', {})
        country = location.get('country_code', 'XX')
        
        # Simple anomaly: multiple countries from same IP (impossible)
        source_ip = event.get('source_ip', 'unknown')
        
        # Check if this IP has been seen from different countries
        ip_countries = set()
        for e in self.event_buffer:
            if e.get('source_ip') == source_ip:
                e_country = e.get('location', {}).get('country_code', 'XX')
                ip_countries.add(e_country)
        
        return len(ip_countries) > 1
    
    def _is_service_targeting(self, ip: str, service: str) -> bool:
        """Detect systematic service targeting"""
        # Count unique services targeted by this IP
        ip_services = set()
        for e in self.event_buffer:
            if e.get('source_ip') == ip:
                ip_services.add(e.get('service', 'unknown'))
        
        return len(ip_services) >= 3  # Targeting multiple services
    
    def _calculate_realtime_risk(self, flags: List[str]) -> float:
        """Calculate real-time risk score based on flags"""
        flag_weights = {
            'BURST_ACTIVITY': 0.3,
            'COORDINATED_ATTACK': 0.4,
            'RAPID_ESCALATION': 0.3,
            'GEOGRAPHIC_ANOMALY': 0.2,
            'SERVICE_TARGETING': 0.2
        }
        
        score = sum(flag_weights.get(flag, 0.1) for flag in flags)
        return min(score, 1.0)
    
    async def get_realtime_metrics(self) -> StreamMetrics:
        """Get current real-time metrics"""
        current_time = time.time()
        window_start = current_time - self.window_size
        
        # Filter events in current window
        window_events = [e for e in self.event_buffer 
                        if (current_time - time.mktime(datetime.fromisoformat(e.get('timestamp', datetime.now().isoformat())).timetuple())) <= self.window_size]
        
        if not window_events:
            return StreamMetrics(
                events_per_second=0.0,
                total_events=0,
                unique_ips=0,
                top_attack_types={},
                geographic_distribution={},
                severity_distribution={},
                timestamp=datetime.now().isoformat()
            )
        
        # Calculate metrics
        events_per_second = len(window_events) / self.window_size
        unique_ips = len(set(e.get('source_ip', 'unknown') for e in window_events))
        
        # Attack types
        attack_types = defaultdict(int)
        for event in window_events:
            service = event.get('service', 'unknown')
            attack_types[service] += 1
        
        # Geographic distribution
        geo_dist = defaultdict(int)
        for event in window_events:
            country = event.get('location', {}).get('country', 'Unknown')
            geo_dist[country] += 1
        
        # Severity distribution
        severity_dist = defaultdict(int)
        for event in window_events:
            severity = event.get('severity', 'UNKNOWN')
            severity_dist[severity] += 1
        
        return StreamMetrics(
            events_per_second=events_per_second,
            total_events=len(window_events),
            unique_ips=unique_ips,
            top_attack_types=dict(sorted(attack_types.items(), key=lambda x: x[1], reverse=True)[:5]),
            geographic_distribution=dict(sorted(geo_dist.items(), key=lambda x: x[1], reverse=True)[:5]),
            severity_distribution=dict(severity_dist),
            timestamp=datetime.now().isoformat()
        )
    
    async def _metrics_updater(self):
        """Background task to update metrics"""
        while self.running:
            try:
                metrics = await self.get_realtime_metrics()
                self.metrics_cache = asdict(metrics)
                
                # Broadcast to WebSocket subscribers
                await self._broadcast_metrics(metrics)
                
                await asyncio.sleep(5)  # Update every 5 seconds
                
            except Exception as e:
                logger.error(f"Metrics updater error: {e}")
                await asyncio.sleep(5)
    
    async def _pattern_detector(self):
        """Background task for pattern detection"""
        while self.running:
            try:
                # Detect attack campaigns
                campaigns = self._detect_attack_campaigns()
                
                if campaigns:
                    logger.warning(f"🚨 Detected {len(campaigns)} attack campaigns")
                    await self._notify_campaigns(campaigns)
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Pattern detector error: {e}")
                await asyncio.sleep(30)
    
    async def _burst_detector(self):
        """Background task for burst detection"""
        while self.running:
            try:
                current_time = time.time()
                new_suspicious = set()
                
                for ip, timestamps in self.ip_counters.items():
                    # Clean old timestamps
                    recent = [t for t in timestamps if current_time - t < 300]  # 5 minutes
                    self.ip_counters[ip] = deque(recent, maxlen=1000)
                    
                    # Check for burst
                    if len(recent) > self.burst_threshold:
                        new_suspicious.add(ip)
                
                # Alert on new suspicious IPs
                newly_detected = new_suspicious - self.suspicious_ips
                if newly_detected:
                    logger.warning(f"🚨 New burst activity detected from {len(newly_detected)} IPs")
                    await self._notify_burst_activity(newly_detected)
                
                self.suspicious_ips.update(new_suspicious)
                
                await asyncio.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                logger.error(f"Burst detector error: {e}")
                await asyncio.sleep(10)
    
    async def _cleanup_task(self):
        """Background cleanup task"""
        while self.running:
            try:
                current_time = time.time()
                
                # Clean old time windows
                old_windows = [t for t in self.time_windows.keys() if current_time - t > self.window_size * 2]
                for t in old_windows:
                    del self.time_windows[t]
                
                # Clean old attack patterns
                for target, attacks in self.attack_patterns.items():
                    recent_attacks = [a for a in attacks if current_time - a['timestamp'] < 3600]  # 1 hour
                    self.attack_patterns[target] = recent_attacks
                
                # Clean old suspicious IPs
                self.suspicious_ips = {ip for ip in self.suspicious_ips 
                                     if any(current_time - t < 1800 for t in self.ip_counters[ip])}  # 30 minutes
                
                await asyncio.sleep(300)  # Cleanup every 5 minutes
                
            except Exception as e:
                logger.error(f"Cleanup task error: {e}")
                await asyncio.sleep(300)
    
    def _detect_attack_campaigns(self) -> List[Dict]:
        """Detect coordinated attack campaigns"""
        campaigns = []
        current_time = time.time()
        hour_ago = current_time - 3600
        
        # Group attacks by target and time
        target_groups = defaultdict(list)
        for event in self.event_buffer:
            event_time = time.mktime(datetime.fromisoformat(event.get('timestamp', datetime.now().isoformat())).timetuple())
            if event_time > hour_ago:
                target = f"{event.get('service', 'unknown')}:{event.get('endpoint', 'unknown')}"
                target_groups[target].append(event)
        
        # Identify campaigns (multiple IPs, high volume)
        for target, events in target_groups.items():
            unique_ips = len(set(e.get('source_ip', 'unknown') for e in events))
            if unique_ips >= 5 and len(events) >= 50:  # Campaign criteria
                campaigns.append({
                    'target': target,
                    'unique_ips': unique_ips,
                    'total_events': len(events),
                    'start_time': min(e.get('timestamp') for e in events),
                    'severity': 'HIGH' if len(events) > 100 else 'MEDIUM'
                })
        
        return campaigns
    
    async def _notify_subscribers(self, event: Dict, analysis: Dict):
        """Notify WebSocket subscribers of new events"""
        if not self.subscribers:
            return
        
        notification = {
            'type': 'real_time_event',
            'event': event,
            'analysis': analysis,
            'timestamp': datetime.now().isoformat()
        }
        
        # Send to all subscribers (would integrate with WebSocket manager)
        logger.debug(f"Broadcasting real-time event to {len(self.subscribers)} subscribers")
    
    async def _broadcast_metrics(self, metrics: StreamMetrics):
        """Broadcast metrics to subscribers"""
        if not self.subscribers:
            return
        
        notification = {
            'type': 'real_time_metrics',
            'metrics': asdict(metrics)
        }
        
        logger.debug("Broadcasting real-time metrics")
    
    async def _notify_campaigns(self, campaigns: List[Dict]):
        """Notify about detected attack campaigns"""
        notification = {
            'type': 'attack_campaigns',
            'campaigns': campaigns,
            'timestamp': datetime.now().isoformat()
        }
        
        logger.warning(f"🚨 Attack campaigns detected: {campaigns}")
    
    async def _notify_burst_activity(self, suspicious_ips: set):
        """Notify about burst activity"""
        notification = {
            'type': 'burst_activity',
            'suspicious_ips': list(suspicious_ips),
            'timestamp': datetime.now().isoformat()
        }
        
        logger.warning(f"🚨 Burst activity from IPs: {suspicious_ips}")
    
    def add_subscriber(self, subscriber_id: str, callback: Callable):
        """Add WebSocket subscriber"""
        self.subscribers.append({'id': subscriber_id, 'callback': callback})
    
    def remove_subscriber(self, subscriber_id: str):
        """Remove WebSocket subscriber"""
        self.subscribers = [s for s in self.subscribers if s['id'] != subscriber_id]
    
    def stop_processing(self):
        """Stop the stream processor"""
        self.running = False
        logger.info("🛑 Stream processor stopped")

# Global stream processor
stream_processor = RealTimeStreamProcessor()
