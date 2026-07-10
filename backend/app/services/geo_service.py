"""
Geo-location service with caching and fallback.
Uses ip-api.com (free, includes lat/lng for attack map).
"""
import logging
import requests
from datetime import datetime
from typing import Dict, Optional
from functools import lru_cache

logger = logging.getLogger(__name__)

# In-memory geo cache (TTL managed by LRU size)
_geo_cache: Dict[str, dict] = {}

def get_country_flag(country_code: str) -> str:
    """Convert country code to flag emoji"""
    if not country_code or country_code == 'XX':
        return '🌍'
    try:
        codepoints = [127397 + ord(char) for char in country_code.upper()]
        return ''.join(chr(cp) for cp in codepoints)
    except Exception:
        return '🌍'

def get_location_from_ip(ip: str) -> dict:
    """Get location from IP using ip-api.com (free, includes lat/lng)"""
    # Check cache first
    if ip in _geo_cache:
        return _geo_cache[ip]

    # Handle local/private IPs by trying to resolve to the server's public external IP
    if ip in ("127.0.0.1", "localhost", "::1") or ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")):
        try:
            # Fetch the actual public IP
            response = requests.get("https://api.ipify.org?format=json", timeout=3)
            if response.ok:
                public_ip = response.json().get("ip")
                if public_ip and public_ip != ip:
                    logger.info(f"[GEO] Local IP {ip} resolved to public IP {public_ip} for geolocation.")
                    # Geocode public IP instead
                    location = get_location_from_ip(public_ip)
                    # Cache under the local IP so we don't fetch repeatedly
                    _geo_cache[ip] = location
                    return location
        except Exception as e:
            logger.warning(f"[GEO] Public IP lookup failed for private IP fallback: {e}")

        # Fallback local network info (Default coordinates to India/Asia center if lookup failed)
        local_info = {
            'city': 'Local Network',
            'country': 'India Fallback',
            'country_code': 'IN',
            'region': 'Local',
            'isp': 'Private IP Address',
            'lat': 20.5937,
            'lng': 78.9629,
        }
        _geo_cache[ip] = local_info
        return local_info

    try:
        logger.info(f"[GEO] Looking up location for IP: {ip}")
        # ip-api.com: free, 45 req/min, includes lat/lng
        response = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org",
            timeout=5
        )
        if response.ok:
            data = response.json()
            if data.get('status') == 'success':
                location = {
                    'city': data.get('city', 'Unknown'),
                    'country': data.get('country', 'Unknown'),
                    'country_code': data.get('countryCode', 'XX'),
                    'region': data.get('regionName', ''),
                    'isp': data.get('isp') or data.get('org', 'Unknown ISP'),
                    'lat': data.get('lat', 0.0),
                    'lng': data.get('lon', 0.0),
                }
                logger.info(f"[GEO] Found: {location['city']}, {location['country']}")
                _geo_cache[ip] = location
                return location
    except Exception as e:
        logger.warning(f"[GEO] ip-api.com failed: {e}")

    # Fallback to ipapi.co
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        if response.ok:
            data = response.json()
            if 'error' not in data and data.get('city'):
                location = {
                    'city': data.get('city', 'Unknown'),
                    'country': data.get('country_name', 'Unknown'),
                    'country_code': data.get('country_code', 'XX'),
                    'region': data.get('region', ''),
                    'isp': data.get('org', 'Unknown ISP'),
                    'lat': data.get('latitude', 0.0),
                    'lng': data.get('longitude', 0.0),
                }
                _geo_cache[ip] = location
                return location
    except Exception as e:
        logger.warning(f"[GEO] ipapi.co fallback failed: {e}")

    # Final fallback
    fallback = {
        'city': 'Unknown',
        'country': 'Unknown',
        'country_code': 'XX',
        'region': '',
        'isp': 'Unknown ISP',
        'lat': 0.0,
        'lng': 0.0,
    }
    _geo_cache[ip] = fallback
    return fallback

def get_real_client_ip(request) -> str:
    """Extract real client IP from request headers"""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        ip = forwarded_for.split(",")[0].strip()
        return ip

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip

    client_ip = request.client.host

    if client_ip.startswith(("172.", "192.168.", "10.")) or client_ip == "127.0.0.1":
        try:
            response = requests.get("https://api.ipify.org?format=json", timeout=3)
            if response.ok:
                return response.json()["ip"]
        except Exception:
            pass

    return client_ip

def clear_geo_cache():
    """Clear the geo-location cache"""
    _geo_cache.clear()
    logger.info("[GEO] Cache cleared")
