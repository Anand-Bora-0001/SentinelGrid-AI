"""
SentinelGrid Security Module
Implements comprehensive security controls, rate limiting, and input validation
"""
import re
import ipaddress
import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
import hashlib
import hmac
import json
import time
import asyncio
from fastapi import HTTPException, Request, Response, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, validator, Field
from starlette.middleware.base import BaseHTTPMiddleware

from .config import settings

logger = logging.getLogger(__name__)

# ========================
# RATE LIMITING MODELS
# ========================

class RateLimitResult(BaseModel):
    """Result of rate limit check"""
    allowed: bool
    remaining: int
    reset_time: datetime
    retry_after: Optional[int] = None

class RateLimitConfig(BaseModel):
    """Rate limit configuration"""
    requests_per_minute: int = 100
    requests_per_hour: int = 1000
    burst_limit: int = 20
    progressive_factor: float = 0.5

# ========================
# IN-MEMORY RATE LIMITER
# ========================

class InMemoryRateLimiter:
    """In-memory rate limiter with Redis-like interface"""
    
    def __init__(self):
        self.counters: Dict[str, Dict] = defaultdict(dict)
        self.suspicious_ips: Dict[str, float] = {}
        self.cleanup_interval = 300  # 5 minutes
        self.last_cleanup = time.time()
    
    def _cleanup_expired(self):
        """Clean up expired entries"""
        current_time = time.time()
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
        
        expired_keys = []
        for key, data in self.counters.items():
            if data.get('expires', 0) < current_time:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.counters[key]
        
        self.last_cleanup = current_time
    
    def check_rate_limit(self, key: str, limit: int, window: int) -> RateLimitResult:
        """Check if request is within rate limit"""
        self._cleanup_expired()
        
        current_time = time.time()
        window_start = int(current_time // window) * window
        window_key = f"{key}:{window_start}"
        
        # Get current count
        current_count = self.counters[window_key].get('count', 0)
        
        # Apply progressive limiting for suspicious IPs
        effective_limit = limit
        if key.startswith('ip:') and key[3:] in self.suspicious_ips:
            factor = self.suspicious_ips[key[3:]]
            effective_limit = int(limit * factor)
            logger.warning(f"Progressive rate limiting applied to {key[3:]}: {effective_limit}/{limit}")
        
        if current_count >= effective_limit:
            return RateLimitResult(
                allowed=False,
                remaining=0,
                reset_time=datetime.fromtimestamp(window_start + window),
                retry_after=int(window_start + window - current_time)
            )
        
        # Increment counter
        self.counters[window_key] = {
            'count': current_count + 1,
            'expires': window_start + window + 60  # Keep for 1 minute after window
        }
        
        return RateLimitResult(
            allowed=True,
            remaining=effective_limit - (current_count + 1),
            reset_time=datetime.fromtimestamp(window_start + window)
        )
    
    def mark_suspicious(self, ip: str, factor: float = 0.5):
        """Mark IP as suspicious for progressive rate limiting"""
        self.suspicious_ips[ip] = factor
        logger.warning(f"IP {ip} marked as suspicious with factor {factor}")
    
    def get_request_count(self, key: str, window: int) -> int:
        """Get current request count for a key"""
        current_time = time.time()
        window_start = int(current_time // window) * window
        window_key = f"{key}:{window_start}"
        return self.counters[window_key].get('count', 0)

# ========================
# RATE LIMITER CLASS
# ========================

class RateLimiter:
    """Main rate limiter with Redis fallback to in-memory"""
    
    def __init__(self):
        self.redis_client = None
        self.in_memory_limiter = InMemoryRateLimiter()
        self.config = {
            'anonymous': RateLimitConfig(requests_per_minute=100, requests_per_hour=1000),
            'authenticated': RateLimitConfig(requests_per_minute=500, requests_per_hour=5000),
            'api_key': RateLimitConfig(requests_per_minute=1000, requests_per_hour=10000)
        }
        
        # Try to initialize Redis
        self._init_redis()
    
    def _init_redis(self):
        """Initialize Redis connection"""
        try:
            import redis
            self.redis_client = redis.Redis(
                host='localhost',
                port=6379,
                db=0,
                decode_responses=True,
                socket_timeout=1
            )
            # Test connection
            self.redis_client.ping()
            logger.info(" Redis connected for rate limiting")
        except Exception as e:
            logger.warning(f"️ Redis not available, using in-memory rate limiting: {e}")
            self.redis_client = None
    
    def check_rate_limit(self, key: str, limit: int, window: int) -> RateLimitResult:
        """Check rate limit using Redis or fallback to in-memory"""
        if self.redis_client:
            return self._check_redis_rate_limit(key, limit, window)
        else:
            return self.in_memory_limiter.check_rate_limit(key, limit, window)
    
    def _check_redis_rate_limit(self, key: str, limit: int, window: int) -> RateLimitResult:
        """Redis-based rate limiting"""
        try:
            current_time = time.time()
            window_start = int(current_time // window) * window
            window_key = f"rate_limit:{key}:{window_start}"
            
            # Get current count
            current_count = int(self.redis_client.get(window_key) or 0)
            
            if current_count >= limit:
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_time=datetime.fromtimestamp(window_start + window),
                    retry_after=int(window_start + window - current_time)
                )
            
            # Increment counter
            pipe = self.redis_client.pipeline()
            pipe.incr(window_key)
            pipe.expire(window_key, window + 60)  # Keep for 1 minute after window
            pipe.execute()
            
            return RateLimitResult(
                allowed=True,
                remaining=limit - (current_count + 1),
                reset_time=datetime.fromtimestamp(window_start + window)
            )
            
        except Exception as e:
            logger.error(f"Redis rate limiting failed: {e}")
            # Fallback to in-memory
            return self.in_memory_limiter.check_rate_limit(key, limit, window)
    
    def get_rate_limit_for_request(self, request: Request, user: Optional[Dict] = None) -> Tuple[str, RateLimitConfig]:
        """Determine rate limit configuration for request"""
        # Check for API key
        api_key = request.headers.get('X-API-Key')
        if api_key:
            return f"api_key:{api_key}", self.config['api_key']
        
        # Check for authenticated user
        if user:
            return f"user:{user.get('username')}", self.config['authenticated']
        
        # Default to IP-based limiting
        client_ip = self._get_client_ip(request)
        return f"ip:{client_ip}", self.config['anonymous']
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request"""
        # Check X-Forwarded-For header
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        # Check X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fallback to client host
        return request.client.host if request.client else "unknown"
    
    def detect_suspicious_patterns(self, request: Request, key: str):
        """Detect suspicious request patterns"""
        client_ip = self._get_client_ip(request)
        
        # Check for rapid requests (burst detection)
        minute_count = self.in_memory_limiter.get_request_count(key, 60)
        if minute_count > 50:  # More than 50 requests per minute
            self.in_memory_limiter.mark_suspicious(client_ip, 0.3)
        
        # Check for unusual endpoints
        path = request.url.path
        suspicious_patterns = [
            r'/admin', r'/wp-admin', r'/phpmyadmin', r'\.php$',
            r'\.asp$', r'\.jsp$', r'/api/v\d+/admin'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                self.in_memory_limiter.mark_suspicious(client_ip, 0.5)
                logger.warning(f"Suspicious endpoint access from {client_ip}: {path}")
                break

# ========================
# SECURITY HEADERS
# ========================

class SecurityHeaders:
    """Security headers configuration"""
    
    @staticmethod
    def get_security_headers() -> Dict[str, str]:
        """Get standard security headers"""
        return {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
        }

# ========================
# RATE LIMITING MIDDLEWARE
# ========================

class RateLimitMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for rate limiting"""
    
    def __init__(self, app, rate_limiter: RateLimiter):
        super().__init__(app)
        self.rate_limiter = rate_limiter
        self.excluded_paths = {'/health', '/docs', '/openapi.json'}
    
    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for excluded paths
        if request.url.path in self.excluded_paths:
            response = await call_next(request)
            return self._add_security_headers(response)
        
        # Get rate limit configuration
        user = getattr(request.state, 'user', None)
        key, config = self.rate_limiter.get_rate_limit_for_request(request, user)
        
        # Check minute-based rate limit
        minute_result = self.rate_limiter.check_rate_limit(key, config.requests_per_minute, 60)
        
        if not minute_result.allowed:
            logger.warning(f"Rate limit exceeded for {key}: {config.requests_per_minute}/min")
            return self._create_rate_limit_response(minute_result)
        
        # Check hour-based rate limit
        hour_result = self.rate_limiter.check_rate_limit(key, config.requests_per_hour, 3600)
        
        if not hour_result.allowed:
            logger.warning(f"Hourly rate limit exceeded for {key}: {config.requests_per_hour}/hour")
            return self._create_rate_limit_response(hour_result)
        
        # Detect suspicious patterns
        self.rate_limiter.detect_suspicious_patterns(request, key)
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(config.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(minute_result.remaining)
        response.headers["X-RateLimit-Reset"] = str(int(minute_result.reset_time.timestamp()))
        
        # Add security headers
        return self._add_security_headers(response)
    
    def _create_rate_limit_response(self, result: RateLimitResult) -> Response:
        """Create rate limit exceeded response"""
        headers = {
            "Retry-After": str(result.retry_after or 60),
            "X-RateLimit-Limit": "0",
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": str(int(result.reset_time.timestamp()))
        }
        
        # Add security headers
        headers.update(SecurityHeaders.get_security_headers())
        
        return Response(
            content=json.dumps({
                "error": "Rate limit exceeded",
                "message": f"Too many requests. Try again in {result.retry_after} seconds.",
                "retry_after": result.retry_after
            }),
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers=headers,
            media_type="application/json"
        )
    
    def _add_security_headers(self, response: Response) -> Response:
        """Add security headers to response"""
        security_headers = SecurityHeaders.get_security_headers()
        for header, value in security_headers.items():
            response.headers[header] = value
        return response

# ========================
# API KEY VALIDATION
# ========================

class APIKeyValidator:
    """API key validation and tracking"""
    
    def __init__(self):
        self.api_keys: Dict[str, Dict] = {}
        self.usage_stats: Dict[str, Dict] = defaultdict(lambda: {
            'requests_today': 0,
            'last_used': None,
            'total_requests': 0
        })
    
    def register_api_key(self, key: str, name: str, rate_limit: int = 1000):
        """Register a new API key"""
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        self.api_keys[key_hash] = {
            'name': name,
            'rate_limit': rate_limit,
            'created_at': datetime.now(),
            'is_active': True
        }
        logger.info(f"API key registered for {name}")
    
    def validate_api_key(self, key: str) -> Optional[Dict]:
        """Validate API key and return key info"""
        if not key:
            return None
        
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        key_info = self.api_keys.get(key_hash)
        
        if not key_info or not key_info['is_active']:
            return None
        
        # Update usage stats
        self.usage_stats[key_hash]['requests_today'] += 1
        self.usage_stats[key_hash]['last_used'] = datetime.now()
        self.usage_stats[key_hash]['total_requests'] += 1
        
        return key_info
    
    def get_usage_stats(self, key: str) -> Dict:
        """Get usage statistics for API key"""
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        return self.usage_stats.get(key_hash, {})

# ========================
# INPUT VALIDATION
# ========================

class InputValidator:
    """Input validation and sanitization"""
    
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def sanitize_string(text: str, max_length: int = 1000) -> str:
        """Sanitize string input"""
        if not text:
            return ""
        
        # Remove null bytes and control characters
        text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', text)
        
        # Limit length
        if len(text) > max_length:
            text = text[:max_length]
        
        return text.strip()
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

# ========================
# GLOBAL INSTANCES
# ========================

# Global rate limiter instance
rate_limiter = RateLimiter()

# Global API key validator
api_key_validator = APIKeyValidator()

# Global input validator
input_validator = InputValidator()
