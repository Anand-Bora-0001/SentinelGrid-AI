"""
SentinelGrid Metrics Collector
Collects and exposes system metrics for monitoring and alerting
"""
import time
import psutil
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from .config import settings

logger = logging.getLogger(__name__)

@dataclass
class SystemMetrics:
    """System performance metrics"""
    timestamp: str
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    memory_available_mb: float
    disk_usage_percent: float
    disk_free_gb: float
    network_bytes_sent: int
    network_bytes_recv: int
    active_connections: int
    
    def to_dict(self) -> Dict:
        return asdict(self)

@dataclass
class APIMetrics:
    """API performance metrics"""
    timestamp: str
    endpoint: str
    method: str
    response_time: float
    status_code: int
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None

@dataclass
class DatabaseMetrics:
    """Database performance metrics"""
    timestamp: str
    query_type: str
    execution_time: float
    rows_affected: int
    table_name: Optional[str] = None

@dataclass
class WebSocketMetrics:
    """WebSocket connection metrics"""
    timestamp: str
    total_connections: int
    active_connections: int
    messages_sent: int
    messages_received: int
    connection_errors: int

class MetricsCollector:
    """Collects and manages system metrics"""
    
    def __init__(self):
        self.system_metrics_history = deque(maxlen=1000)  # Keep last 1000 entries
        self.api_metrics_history = deque(maxlen=5000)     # Keep last 5000 API calls
        self.database_metrics_history = deque(maxlen=2000) # Keep last 2000 DB operations
        self.websocket_metrics_history = deque(maxlen=500)  # Keep last 500 WS metrics
        
        # Performance thresholds
        self.thresholds = {
            'cpu_percent': 80.0,
            'memory_percent': 85.0,
            'disk_usage_percent': 90.0,
            'api_response_time': 1.0,  # 1 second
            'database_query_time': 0.5,  # 500ms
            'websocket_connection_errors': 10  # per minute
        }
        
        # Counters for rate calculations
        self.counters = defaultdict(int)
        self.last_reset = time.time()
        
        # Network baseline (for calculating rates)
        self.network_baseline = None
        self._update_network_baseline()
    
    def collect_system_metrics(self) -> SystemMetrics:
        """Collect current system metrics"""
        try:
            # CPU and Memory
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            
            # Disk usage
            disk = psutil.disk_usage('/')
            
            # Network stats
            network = psutil.net_io_counters()
            
            # Active connections (approximate)
            connections = len(psutil.net_connections())
            
            metrics = SystemMetrics(
                timestamp=datetime.now().isoformat(),
                cpu_percent=cpu_percent,
                memory_percent=memory.percent,
                memory_used_mb=memory.used / (1024 * 1024),
                memory_available_mb=memory.available / (1024 * 1024),
                disk_usage_percent=disk.percent,
                disk_free_gb=disk.free / (1024 * 1024 * 1024),
                network_bytes_sent=network.bytes_sent,
                network_bytes_recv=network.bytes_recv,
                active_connections=connections
            )
            
            # Store in history
            self.system_metrics_history.append(metrics)
            
            # Check thresholds
            self._check_system_thresholds(metrics)
            
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to collect system metrics: {e}")
            # Return default metrics
            return SystemMetrics(
                timestamp=datetime.now().isoformat(),
                cpu_percent=0.0,
                memory_percent=0.0,
                memory_used_mb=0.0,
                memory_available_mb=0.0,
                disk_usage_percent=0.0,
                disk_free_gb=0.0,
                network_bytes_sent=0,
                network_bytes_recv=0,
                active_connections=0
            )
    
    def record_api_request(self, endpoint: str, method: str, response_time: float, 
                          status_code: int, user_agent: Optional[str] = None, 
                          ip_address: Optional[str] = None):
        """Record API request metrics"""
        metrics = APIMetrics(
            timestamp=datetime.now().isoformat(),
            endpoint=endpoint,
            method=method,
            response_time=response_time,
            status_code=status_code,
            user_agent=user_agent,
            ip_address=ip_address
        )
        
        self.api_metrics_history.append(metrics)
        self.counters['api_requests'] += 1
        
        # Check response time threshold
        if response_time > self.thresholds['api_response_time']:
            logger.warning(f"Slow API response: {endpoint} took {response_time:.3f}s")
    
    def record_database_operation(self, query_type: str, execution_time: float, 
                                 rows_affected: int, table_name: Optional[str] = None):
        """Record database operation metrics"""
        metrics = DatabaseMetrics(
            timestamp=datetime.now().isoformat(),
            query_type=query_type,
            execution_time=execution_time,
            rows_affected=rows_affected,
            table_name=table_name
        )
        
        self.database_metrics_history.append(metrics)
        self.counters['database_operations'] += 1
        
        # Check execution time threshold
        if execution_time > self.thresholds['database_query_time']:
            logger.warning(f"Slow database query: {query_type} on {table_name} took {execution_time:.3f}s")
    
    def record_websocket_metrics(self, total_connections: int, active_connections: int,
                                messages_sent: int, messages_received: int, 
                                connection_errors: int):
        """Record WebSocket metrics"""
        metrics = WebSocketMetrics(
            timestamp=datetime.now().isoformat(),
            total_connections=total_connections,
            active_connections=active_connections,
            messages_sent=messages_sent,
            messages_received=messages_received,
            connection_errors=connection_errors
        )
        
        self.websocket_metrics_history.append(metrics)
        
        # Check connection error threshold
        if connection_errors > self.thresholds['websocket_connection_errors']:
            logger.warning(f"High WebSocket connection errors: {connection_errors}")
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get comprehensive metrics summary"""
        current_time = datetime.now()
        
        # System metrics
        latest_system = self.system_metrics_history[-1] if self.system_metrics_history else None
        
        # API metrics (last hour)
        hour_ago = current_time - timedelta(hours=1)
        recent_api_metrics = [
            m for m in self.api_metrics_history 
            if datetime.fromisoformat(m.timestamp) > hour_ago
        ]
        
        # Database metrics (last hour)
        recent_db_metrics = [
            m for m in self.database_metrics_history 
            if datetime.fromisoformat(m.timestamp) > hour_ago
        ]
        
        # WebSocket metrics
        latest_websocket = self.websocket_metrics_history[-1] if self.websocket_metrics_history else None
        
        return {
            'timestamp': current_time.isoformat(),
            'system': {
                'cpu_percent': latest_system.cpu_percent if latest_system else 0,
                'memory_percent': latest_system.memory_percent if latest_system else 0,
                'disk_usage_percent': latest_system.disk_usage_percent if latest_system else 0,
                'active_connections': latest_system.active_connections if latest_system else 0
            },
            'api': {
                'requests_last_hour': len(recent_api_metrics),
                'average_response_time': self._calculate_average_response_time(recent_api_metrics),
                'error_rate': self._calculate_error_rate(recent_api_metrics),
                'top_endpoints': self._get_top_endpoints(recent_api_metrics)
            },
            'database': {
                'operations_last_hour': len(recent_db_metrics),
                'average_execution_time': self._calculate_average_db_time(recent_db_metrics),
                'slow_queries': self._count_slow_queries(recent_db_metrics),
                'operations_by_type': self._group_db_operations(recent_db_metrics)
            },
            'websocket': {
                'total_connections': latest_websocket.total_connections if latest_websocket else 0,
                'active_connections': latest_websocket.active_connections if latest_websocket else 0,
                'messages_sent': latest_websocket.messages_sent if latest_websocket else 0,
                'connection_errors': latest_websocket.connection_errors if latest_websocket else 0
            },
            'counters': dict(self.counters),
            'thresholds_exceeded': self._get_threshold_violations()
        }
    
    def get_prometheus_metrics(self) -> str:
        """Export metrics in Prometheus format"""
        metrics_lines = []
        
        # System metrics
        if self.system_metrics_history:
            latest = self.system_metrics_history[-1]
            metrics_lines.extend([
                f'# HELP sentinelgrid_cpu_percent CPU usage percentage',
                f'# TYPE sentinelgrid_cpu_percent gauge',
                f'sentinelgrid_cpu_percent {latest.cpu_percent}',
                f'# HELP sentinelgrid_memory_percent Memory usage percentage',
                f'# TYPE sentinelgrid_memory_percent gauge',
                f'sentinelgrid_memory_percent {latest.memory_percent}',
                f'# HELP sentinelgrid_disk_usage_percent Disk usage percentage',
                f'# TYPE sentinelgrid_disk_usage_percent gauge',
                f'sentinelgrid_disk_usage_percent {latest.disk_usage_percent}',
                f'# HELP sentinelgrid_active_connections Active network connections',
                f'# TYPE sentinelgrid_active_connections gauge',
                f'sentinelgrid_active_connections {latest.active_connections}'
            ])
        
        # API metrics
        metrics_lines.extend([
            f'# HELP sentinelgrid_api_requests_total Total API requests',
            f'# TYPE sentinelgrid_api_requests_total counter',
            f'sentinelgrid_api_requests_total {self.counters["api_requests"]}',
            f'# HELP sentinelgrid_database_operations_total Total database operations',
            f'# TYPE sentinelgrid_database_operations_total counter',
            f'sentinelgrid_database_operations_total {self.counters["database_operations"]}'
        ])
        
        # WebSocket metrics
        if self.websocket_metrics_history:
            latest_ws = self.websocket_metrics_history[-1]
            metrics_lines.extend([
                f'# HELP sentinelgrid_websocket_connections WebSocket connections',
                f'# TYPE sentinelgrid_websocket_connections gauge',
                f'sentinelgrid_websocket_connections {{state="total"}} {latest_ws.total_connections}',
                f'sentinelgrid_websocket_connections {{state="active"}} {latest_ws.active_connections}',
                f'# HELP sentinelgrid_websocket_messages WebSocket messages',
                f'# TYPE sentinelgrid_websocket_messages counter',
                f'sentinelgrid_websocket_messages {{direction="sent"}} {latest_ws.messages_sent}',
                f'sentinelgrid_websocket_messages {{direction="received"}} {latest_ws.messages_received}'
            ])
        
        return '\n'.join(metrics_lines)
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get system health status"""
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'checks': {}
        }
        
        # System health checks
        if self.system_metrics_history:
            latest = self.system_metrics_history[-1]
            
            health_status['checks']['cpu'] = {
                'status': 'healthy' if latest.cpu_percent < self.thresholds['cpu_percent'] else 'warning',
                'value': latest.cpu_percent,
                'threshold': self.thresholds['cpu_percent']
            }
            
            health_status['checks']['memory'] = {
                'status': 'healthy' if latest.memory_percent < self.thresholds['memory_percent'] else 'warning',
                'value': latest.memory_percent,
                'threshold': self.thresholds['memory_percent']
            }
            
            health_status['checks']['disk'] = {
                'status': 'healthy' if latest.disk_usage_percent < self.thresholds['disk_usage_percent'] else 'warning',
                'value': latest.disk_usage_percent,
                'threshold': self.thresholds['disk_usage_percent']
            }
        
        # API health check
        recent_api_errors = self._count_recent_api_errors()
        health_status['checks']['api'] = {
            'status': 'healthy' if recent_api_errors < 10 else 'warning',
            'recent_errors': recent_api_errors
        }
        
        # Database health check
        recent_slow_queries = self._count_recent_slow_queries()
        health_status['checks']['database'] = {
            'status': 'healthy' if recent_slow_queries < 5 else 'warning',
            'slow_queries': recent_slow_queries
        }
        
        # Overall status
        warning_checks = [check for check in health_status['checks'].values() if check['status'] == 'warning']
        if warning_checks:
            health_status['status'] = 'warning'
        
        return health_status
    
    def _check_system_thresholds(self, metrics: SystemMetrics):
        """Check if system metrics exceed thresholds"""
        if metrics.cpu_percent > self.thresholds['cpu_percent']:
            logger.warning(f"High CPU usage: {metrics.cpu_percent}%")
        
        if metrics.memory_percent > self.thresholds['memory_percent']:
            logger.warning(f"High memory usage: {metrics.memory_percent}%")
        
        if metrics.disk_usage_percent > self.thresholds['disk_usage_percent']:
            logger.warning(f"High disk usage: {metrics.disk_usage_percent}%")
    
    def _update_network_baseline(self):
        """Update network baseline for rate calculations"""
        try:
            self.network_baseline = psutil.net_io_counters()
        except Exception as e:
            logger.error(f"Failed to update network baseline: {e}")
    
    def _calculate_average_response_time(self, api_metrics: List[APIMetrics]) -> float:
        """Calculate average API response time"""
        if not api_metrics:
            return 0.0
        return sum(m.response_time for m in api_metrics) / len(api_metrics)
    
    def _calculate_error_rate(self, api_metrics: List[APIMetrics]) -> float:
        """Calculate API error rate"""
        if not api_metrics:
            return 0.0
        error_count = sum(1 for m in api_metrics if m.status_code >= 400)
        return error_count / len(api_metrics)
    
    def _get_top_endpoints(self, api_metrics: List[APIMetrics]) -> List[Dict]:
        """Get top API endpoints by request count"""
        endpoint_counts = defaultdict(int)
        for metric in api_metrics:
            endpoint_counts[metric.endpoint] += 1
        
        return [
            {'endpoint': endpoint, 'count': count}
            for endpoint, count in sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
    
    def _calculate_average_db_time(self, db_metrics: List[DatabaseMetrics]) -> float:
        """Calculate average database execution time"""
        if not db_metrics:
            return 0.0
        return sum(m.execution_time for m in db_metrics) / len(db_metrics)
    
    def _count_slow_queries(self, db_metrics: List[DatabaseMetrics]) -> int:
        """Count slow database queries"""
        return sum(1 for m in db_metrics if m.execution_time > self.thresholds['database_query_time'])
    
    def _group_db_operations(self, db_metrics: List[DatabaseMetrics]) -> Dict[str, int]:
        """Group database operations by type"""
        operation_counts = defaultdict(int)
        for metric in db_metrics:
            operation_counts[metric.query_type] += 1
        return dict(operation_counts)
    
    def _get_threshold_violations(self) -> List[str]:
        """Get list of current threshold violations"""
        violations = []
        
        if self.system_metrics_history:
            latest = self.system_metrics_history[-1]
            
            if latest.cpu_percent > self.thresholds['cpu_percent']:
                violations.append(f"CPU usage: {latest.cpu_percent}% > {self.thresholds['cpu_percent']}%")
            
            if latest.memory_percent > self.thresholds['memory_percent']:
                violations.append(f"Memory usage: {latest.memory_percent}% > {self.thresholds['memory_percent']}%")
            
            if latest.disk_usage_percent > self.thresholds['disk_usage_percent']:
                violations.append(f"Disk usage: {latest.disk_usage_percent}% > {self.thresholds['disk_usage_percent']}%")
        
        return violations
    
    def _count_recent_api_errors(self) -> int:
        """Count recent API errors (last 10 minutes)"""
        ten_minutes_ago = datetime.now() - timedelta(minutes=10)
        return sum(
            1 for m in self.api_metrics_history
            if datetime.fromisoformat(m.timestamp) > ten_minutes_ago and m.status_code >= 400
        )
    
    def _count_recent_slow_queries(self) -> int:
        """Count recent slow queries (last 10 minutes)"""
        ten_minutes_ago = datetime.now() - timedelta(minutes=10)
        return sum(
            1 for m in self.database_metrics_history
            if datetime.fromisoformat(m.timestamp) > ten_minutes_ago 
            and m.execution_time > self.thresholds['database_query_time']
        )
    
    def reset_counters(self):
        """Reset rate counters"""
        self.counters.clear()
        self.last_reset = time.time()
        logger.info("Metrics counters reset")

# Global metrics collector instance
metrics_collector = MetricsCollector()
