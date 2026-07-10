"""
Event routes: ingest, list, clear, stream, simulate.
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from sse_starlette.sse import EventSourceResponse
from datetime import datetime, timezone
from typing import Optional, Dict
import asyncio
import json
import random
import logging

from ..deps import get_current_user, get_admin_user, get_db
from ...services.geo_service import get_location_from_ip, get_real_client_ip, get_country_flag
from ...config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["Events"])

# In-memory event storage (shared state)
security_events = []


@router.post("/ingest")
async def ingest_event(event: Dict, request: Request):
    """
    PUBLIC endpoint - NO AUTH REQUIRED
    Used by Flask threat_sensor / external threat_sensors to send attack data.
    """
    from ...database import get_db
    from ...models import SecurityEvent, Organization

    try:
        source_ip = event.get("source_ip") or get_real_client_ip(request)
        location_data = get_location_from_ip(source_ip)

        # ML prediction (if available)
        ml_prediction = None
        try:
            from ...ml_engine import ml_engine
            if ml_engine:
                temp_event = {
                    "service": event.get("service", "EXTERNAL"),
                    "source_ip": source_ip,
                    "source_port": event.get("source_port", 0),
                    "username": event.get("username"),
                    "password": event.get("password"),
                    "command": event.get("command") or event.get("endpoint"),
                    "payload": event.get("payload"),
                    "method": event.get("method", "UNKNOWN"),
                    "endpoint": event.get("endpoint"),
                    "severity": event.get("severity", "MEDIUM"),
                    "timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    "location": location_data
                }
                ml_prediction = ml_engine.predict_threat(temp_event)
        except Exception as ml_error:
            logger.warning(f"ML prediction skipped: {ml_error}")

        # Enrich event
        enriched_event = {
            "id": len(security_events) + 1,
            "timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "service": event.get("service", "EXTERNAL"),
            "source_ip": source_ip,
            "source_port": event.get("source_port", 0),
            "username": event.get("username"),
            "password": event.get("password"),
            "command": event.get("command") or event.get("endpoint"),
            "payload": event.get("payload"),
            "method": event.get("method", "UNKNOWN"),
            "endpoint": event.get("endpoint"),
            "severity": ml_prediction.threat_level if ml_prediction else event.get("severity", "MEDIUM"),
            "ai_label": "ml_predicted" if ml_prediction else event.get("ai_label", "anomaly"),
            "threat_score": ml_prediction.threat_probability if ml_prediction else event.get("threat_score", 0.5),
            "ml_confidence": ml_prediction.confidence if ml_prediction else 0.0,
            "anomaly_score": ml_prediction.anomaly_score if ml_prediction else 0.0,
            "location": {
                'city': location_data['city'],
                'country': location_data['country'],
                'country_code': location_data['country_code'],
                'flag': get_country_flag(location_data['country_code']),
                'isp': location_data['isp'],
                'region': location_data['region'],
                'lat': location_data.get('lat', 0.0),
                'lng': location_data.get('lng', 0.0),
            },
            "event_metadata": event.get("metadata", {})
        }

        security_events.append(enriched_event)

        # Save to database
        db = None
        try:
            db = next(get_db())
            org = db.query(Organization).first()
            if not org:
                org = Organization(
                    name="Demo Organization", slug="demo-org",
                    email="demo@sentinelgrid.local", plan="free", is_trial=True
                )
                db.add(org)
                db.commit()
                db.refresh(org)

            db_event = SecurityEvent(
                organization_id=org.id,
                service_name=enriched_event["service"],
                source_ip=source_ip,
                source_port=enriched_event.get("source_port", 0),
                endpoint=enriched_event.get("endpoint"),
                method=enriched_event.get("method"),
                username=enriched_event.get("username"),
                password=enriched_event.get("password"),
                command=enriched_event.get("command"),
                payload=enriched_event.get("payload"),
                severity=enriched_event["severity"],
                ai_label=enriched_event["ai_label"],
                threat_score=enriched_event["threat_score"],
                location=enriched_event["location"],
                event_metadata=enriched_event.get("event_metadata", {})
            )
            db.add(db_event)
            db.commit()
            db.refresh(db_event)
            enriched_event["id"] = db_event.id

            # Trigger alerts for critical events
            if enriched_event['severity'] in ['CRITICAL', 'HIGH']:
                try:
                    from ...alert_system import handle_security_event
                    enriched_event['organization_id'] = db_event.organization_id
                    handle_security_event(enriched_event, db)
                except Exception:
                    pass

        except Exception as db_error:
            logger.error(f"[DB] Save failed: {db_error}")
        finally:
            if db:
                db.close()

        return {"status": "received", "id": enriched_event["id"]}

    except Exception as e:
        logger.error(f"❌ Ingest failed: {e}")
        raise HTTPException(status_code=500, detail=f"Ingest failed: {str(e)}")


@router.get("/events")
def get_events(
    limit: int = 50,
    service: Optional[str] = None,
    severity: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get attack events with optional filters"""
    try:
        from ...models import SecurityEvent, User

        if db is None:
            raise Exception("Database not available")

        user = db.query(User).filter(User.username == current_user["username"]).first()
        if not user:
            raise Exception("User not found in database")

        query = db.query(SecurityEvent).filter(SecurityEvent.organization_id == user.organization_id)
        if service:
            query = query.filter(SecurityEvent.service_name == service)
        if severity:
            query = query.filter(SecurityEvent.severity == severity)

        events = query.order_by(SecurityEvent.timestamp.desc()).limit(limit).all()

        result = []
        for event in events:
            result.append({
                "id": event.id,
                "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                "service": event.service_name,
                "source_ip": event.source_ip,
                "source_port": event.source_port,
                "username": event.username,
                "password": event.password,
                "command": event.command,
                "endpoint": event.endpoint,
                "method": event.method,
                "payload": event.payload,
                "severity": event.severity,
                "ai_label": event.ai_label,
                "threat_score": event.threat_score,
                "location": event.location,
                "event_metadata": event.event_metadata
            })

        return result

    except Exception as e:
        logger.warning(f"DB query failed ({e}), using in-memory events")
        filtered_events = security_events
        if service:
            filtered_events = [ev for ev in filtered_events if ev.get('service') == service]
        if severity:
            filtered_events = [ev for ev in filtered_events if ev.get('severity') == severity]
        return filtered_events[-limit:]


@router.delete("/events/clear")
def clear_events(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Clear all attack events for the current organization"""
    try:
        from ...models import SecurityEvent, User
        user = db.query(User).filter(User.username == current_user["username"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        deleted_count = db.query(SecurityEvent).filter(
            SecurityEvent.organization_id == user.organization_id
        ).delete()
        db.commit()

        if current_user.get("role") == "admin":
            security_events.clear()

        # Invalidate stats cache
        try:
            from ...core.cache import cache_delete
            cache_delete(f"stats:{current_user['username']}")
        except Exception:
            pass

        logger.info(f"✅ User {current_user['username']} cleared {deleted_count} events")
        return {"status": "success", "message": f"Successfully purged {deleted_count} intelligence records"}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"❌ Failed to clear events: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/events/stream")
async def event_stream(current_user: dict = Depends(get_current_user)):
    """Server-Sent Events endpoint for real-time updates"""
    async def event_generator():
        last_id = len(security_events)
        while True:
            if len(security_events) > last_id:
                for event in security_events[last_id:]:
                    yield {"event": "new_attack", "data": json.dumps(event)}
                last_id = len(security_events)
            await asyncio.sleep(2)

    return EventSourceResponse(event_generator())


@router.get("/stats")
def get_statistics(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get dashboard statistics (cached for 10s)"""
    from ...core.cache import cache_get_json, cache_set_json
    from datetime import timedelta

    # Check cache first
    cache_key = f"stats:{current_user.get('username', 'anon')}"
    cached = cache_get_json(cache_key)
    if cached:
        return cached

    try:
        from ...models import SecurityEvent, User

        if db is None:
            raise Exception("Database not available")

        user = db.query(User).filter(User.username == current_user["username"]).first()
        if not user:
            raise Exception("User not found in database")

        events = db.query(SecurityEvent).filter(
            SecurityEvent.organization_id == user.organization_id
        ).all()

        service_counts = {}
        severity_counts = {}
        label_counts = {}
        for event in events:
            s = event.service_name or 'UNKNOWN'
            service_counts[s] = service_counts.get(s, 0) + 1
            sv = event.severity or 'UNKNOWN'
            severity_counts[sv] = severity_counts.get(sv, 0) + 1
            lbl = event.ai_label or 'unknown'
            label_counts[lbl] = label_counts.get(lbl, 0) + 1

        # Calculate unique IPs, average ML confidence, and active services count
        unique_ips = len(set(e.source_ip for e in events if e.source_ip))
        avg_ml = sum(e.threat_score for e in events if e.threat_score is not None) / len(events) if events else 0.0
        active_services = len(set(e.service_name for e in events if e.service_name))

        # Get hourly volume trend for last 7 hours
        now = datetime.now(timezone.utc)
        hourly_data = []
        hourly_labels = []
        for i in range(6, -1, -1):
            hour_time = now - timedelta(hours=i)
            hourly_labels.append(hour_time.strftime("%H:00"))
            count = 0
            for e in events:
                if e.timestamp:
                    evt_time = e.timestamp
                    if evt_time.tzinfo is None:
                        evt_time = evt_time.replace(tzinfo=timezone.utc)
                    if evt_time.hour == hour_time.hour and (now - evt_time).days == 0:
                        count += 1
            hourly_data.append(count)

        result = {
            'total_events': len(events),
            'unique_ips': unique_ips,
            'avg_ml_confidence': avg_ml,
            'active_services_count': active_services,
            'events_by_service': service_counts,
            'events_by_severity': severity_counts,
            'ai_labels': label_counts,
            'hourly_trend': {
                'labels': hourly_labels,
                'data': hourly_data
            },
            'last_updated': datetime.now().isoformat()
        }

        # Cache for 10 seconds
        cache_set_json(cache_key, result, ttl_seconds=10)
        return result

    except Exception as e:
        logger.warning(f"DB stats failed ({e}), using in-memory")
        service_counts = {}
        severity_counts = {}
        label_counts = {}
        for ev in security_events:
            s = ev.get('service', 'UNKNOWN')
            service_counts[s] = service_counts.get(s, 0) + 1
            sv = ev.get('severity', 'UNKNOWN')
            severity_counts[sv] = severity_counts.get(sv, 0) + 1
            lbl = ev.get('ai_label', 'unknown')
            label_counts[lbl] = label_counts.get(lbl, 0) + 1

        # In-memory calculations
        unique_ips = len(set(ev.get('source_ip') for ev in security_events if ev.get('source_ip')))
        avg_ml = sum(ev.get('threat_score', 0.5) for ev in security_events) / len(security_events) if security_events else 0.0
        active_services = len(set(ev.get('service') for ev in security_events if ev.get('service')))

        # Get hourly volume trend for last 7 hours
        now = datetime.now(timezone.utc)
        hourly_data = []
        hourly_labels = []
        for i in range(6, -1, -1):
            hour_time = now - timedelta(hours=i)
            hourly_labels.append(hour_time.strftime("%H:00"))
            count = 0
            for ev in security_events:
                try:
                    evt_time = datetime.fromisoformat(ev['timestamp'])
                    if evt_time.tzinfo is None:
                        evt_time = evt_time.replace(tzinfo=timezone.utc)
                    if evt_time.hour == hour_time.hour and (now - evt_time).days == 0:
                        count += 1
                except:
                    pass
            hourly_data.append(count)

        return {
            'total_events': len(security_events),
            'unique_ips': unique_ips,
            'avg_ml_confidence': avg_ml,
            'active_services_count': active_services,
            'events_by_service': service_counts,
            'events_by_severity': severity_counts,
            'ai_labels': label_counts,
            'hourly_trend': {
                'labels': hourly_labels,
                'data': hourly_data
            },
            'last_updated': datetime.now().isoformat()
        }


@router.post("/simulate-attacks")
async def simulate_attacks(
    request: Request,
    count: int = 30,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Manually trigger attack simulation with randomized global origins and coordinates"""
    global_origins = [
        {"ip": "198.51.100.42", "lat": 37.0902, "lng": -95.7129, "country": "United States", "country_code": "US", "city": "Coffeyville", "region": "Kansas", "isp": "Google LLC", "flag": "🇺🇸"},
        {"ip": "95.163.220.12", "lat": 55.7558, "lng": 37.6173, "country": "Russia", "country_code": "RU", "city": "Moscow", "region": "Moscow", "isp": "Digital Ocean", "flag": "🇷🇺"},
        {"ip": "220.181.38.148", "lat": 39.9042, "lng": 116.4074, "country": "China", "country_code": "CN", "city": "Beijing", "region": "Beijing", "isp": "CHINANET", "flag": "🇨🇳"},
        {"ip": "46.165.2.14", "lat": 52.5200, "lng": 13.4050, "country": "Germany", "country_code": "DE", "city": "Berlin", "region": "Berlin", "isp": "Leaseweb", "flag": "🇩🇪"},
        {"ip": "200.221.2.45", "lat": -23.5505, "lng": -46.6333, "country": "Brazil", "country_code": "BR", "city": "Sao Paulo", "region": "Sao Paulo", "isp": "UOL", "flag": "🇧🇷"},
        {"ip": "82.197.200.4", "lat": 52.3676, "lng": 4.9041, "country": "Netherlands", "country_code": "NL", "city": "Amsterdam", "region": "North Holland", "isp": "Hostnet", "flag": "🇳🇱"},
        {"ip": "101.100.180.2", "lat": 1.3521, "lng": 103.8198, "country": "Singapore", "country_code": "SG", "city": "Singapore", "region": "Singapore", "isp": "SingTel", "flag": "🇸🇬"},
        {"ip": "103.241.136.1", "lat": 28.6139, "lng": 77.2090, "country": "India", "country_code": "IN", "city": "New Delhi", "region": "Delhi", "isp": "Airtel", "flag": "🇮🇳"},
        {"ip": "43.242.144.1", "lat": 19.0760, "lng": 72.8777, "country": "India", "country_code": "IN", "city": "Mumbai", "region": "Maharashtra", "isp": "Reliance Jio", "flag": "🇮🇳"},
        {"ip": "210.140.10.10", "lat": 35.6762, "lng": 139.6503, "country": "Japan", "country_code": "JP", "city": "Tokyo", "region": "Tokyo", "isp": "NTT Communications", "flag": "🇯🇵"},
        {"ip": "109.228.0.1", "lat": 51.5074, "lng": -0.1278, "country": "United Kingdom", "country_code": "GB", "city": "London", "region": "England", "isp": "British Telecom", "flag": "🇬🇧"},
        {"ip": "198.41.0.4", "lat": 43.6532, "lng": -79.3832, "country": "Canada", "country_code": "CA", "city": "Toronto", "region": "Ontario", "isp": "Rogers", "flag": "🇨🇦"},
    ]

    new_attacks = []
    attack_types = [
        ('root', 'CRITICAL', 'malicious', 0.95, 'rm -rf /', 'SSH'),
        ('admin', 'CRITICAL', 'malicious', 0.93, 'cat /etc/shadow', 'SSH'),
        ('admin', 'HIGH', 'malicious', 0.85, 'sudo su', 'SSH'),
        ('root', 'HIGH', 'anomaly', 0.82, 'netstat -tulpn', 'HTTP'),
        ('user', 'MEDIUM', 'anomaly', 0.65, 'ls -la /root', 'SSH'),
        ('guest', 'MEDIUM', 'anomaly', 0.63, 'whoami', 'HTTP'),
        ('anonymous', 'LOW', 'benign', 0.35, 'help', 'SSH'),
        ('visitor', 'LOW', 'benign', 0.30, 'ls', 'HTTP'),
    ]

    from ...models import SecurityEvent, Organization

    org = None
    try:
        org = db.query(Organization).first()
    except Exception:
        pass

    for i in range(count):
        attack = random.choice(attack_types)
        origin = random.choice(global_origins)
        
        # Add slight offsets to lat/lng so markers don't overlap exactly
        lat_offset = random.uniform(-1.5, 1.5)
        lng_offset = random.uniform(-1.5, 1.5)
        
        simulated_ip = origin["ip"]
        parts = simulated_ip.split('.')
        if len(parts) == 4:
            simulated_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.{random.randint(2, 254)}"

        new_event = {
            'id': len(security_events) + 1,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'service': attack[5],
            'source_ip': simulated_ip,
            'source_port': random.randint(1024, 65535),
            'username': attack[0],
            'password': f"pass{random.randint(1000,9999)}",
            'command': attack[4],
            'severity': attack[1],
            'ai_label': attack[2],
            'threat_score': attack[3],
            'ml_confidence': random.uniform(0.7, 0.99) if attack[2] != 'benign' else random.uniform(0.1, 0.4),
            'location': {
                'city': origin['city'],
                'country': origin['country'],
                'country_code': origin['country_code'],
                'flag': origin['flag'],
                'isp': origin['isp'],
                'region': origin['region'],
                'lat': origin['lat'] + lat_offset,
                'lng': origin['lng'] + lng_offset,
            }
        }
        security_events.append(new_event)
        new_attacks.append(new_event)

        # Save to DB
        if db:
            try:
                db_event = SecurityEvent(
                    organization_id=org.id if org else 1,
                    service_name=new_event["service"],
                    source_ip=new_event["source_ip"],
                    source_port=new_event["source_port"],
                    username=new_event["username"],
                    password=new_event["password"],
                    command=new_event["command"],
                    severity=new_event["severity"],
                    ai_label=new_event["ai_label"],
                    threat_score=new_event["threat_score"],
                    location=new_event["location"],
                    event_metadata={}
                )
                db.add(db_event)
                db.commit()
                db.refresh(db_event)
                new_event["id"] = db_event.id
            except Exception as e:
                db.rollback()
                logger.error(f"Failed to save simulated attack to DB: {e}")

        # Trigger alerts for high severity
        if new_event['severity'] in ['CRITICAL', 'HIGH']:
            try:
                from ...alert_system import handle_security_event
                org_id = current_user.get("organization_id") or (org.id if org else 1)
                new_event['organization_id'] = org_id
                handle_security_event(new_event, db)
            except Exception:
                pass

    # Invalidate stats cache
    try:
        from ...core.cache import cache_delete
        cache_delete(f"stats:{current_user['username']}")
    except Exception:
        pass

    breakdown = {sev: len([a for a in new_attacks if a['severity'] == sev]) for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}

    return {
        "status": "success",
        "message": f"Generated {count} attacks across global origins",
        "total_attacks": len(security_events),
        "new_attacks": len(new_attacks),
        "breakdown": breakdown
    }

