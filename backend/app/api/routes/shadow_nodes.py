from fastapi import APIRouter, Request, Depends, HTTPException
from sqlalchemy.orm import Session
import logging
import json
from datetime import datetime

from ..deps import get_db
from ...models import SecurityEvent, User
from ...services.detection_service import detection_engine
from ...services.geo_service import get_location_from_ip, get_real_client_ip
from ...alert_system import handle_security_event

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Shadow Sensors"])

async def capture_and_report(request: Request, db: Session, node_name: str):
    """Utility to capture raw manual attacks and report them to the SIEM"""
    client_ip = get_real_client_ip(request)
    method = request.method
    endpoint = str(request.url.path)
    
    # Extract body if present
    body = None
    try:
        if method in ["POST", "PUT", "PATCH"]:
            body = await request.json()
    except:
        pass

    query_params = dict(request.query_params)
    
    # Analyze the manual attack
    attack_type, severity = detection_engine.analyze_request(method, endpoint, body, query_params)
    
    # Create the Intelligence Record
    location = get_location_from_ip(client_ip)
    
    # Use the first admin user as the owner for these global sensor events
    admin_user = db.query(User).filter(User.role == "admin").first()
    org_id = admin_user.organization_id if admin_user else 1

    event_data = {
        "organization_id": org_id,
        "service_name": node_name,
        "source_ip": client_ip,
        "endpoint": endpoint,
        "method": method,
        "payload": json.dumps(body) if body else str(query_params),
        "severity": severity,
        "timestamp": datetime.now().isoformat(),
        "location": location,
        "event_metadata": {
            "attack_classification": attack_type,
            "manual_entry": True,
            "user_agent": request.headers.get("user_agent", "Unknown")
        }
    }

    # Store in DB
    db_event = SecurityEvent(
        organization_id=org_id,
        service_name=node_name,
        source_ip=client_ip,
        endpoint=endpoint,
        method=method,
        payload=event_data["payload"],
        severity=severity,
        location=location,
        event_metadata=event_data["event_metadata"]
    )
    db.add(db_event)
    db.commit()
    
    # Trigger Alerts
    handle_security_event(event_data, db=db)
    
    # Return a "Fake" error or response to mislead the attacker
    return {"status": "error", "message": "Unauthorized access attempt logged."}

# ========================
# SHADOW ENDPOINTS (SENSORS)
# ========================

@router.post("/v1/auth/login")
async def fake_login(request: Request, db: Session = Depends(get_db)):
    """Mimics an ecommerce login page"""
    return await capture_and_report(request, db, "ECOMMERCE_LOGIN_NODE")

@router.get("/api/admin/config")
async def fake_admin(request: Request, db: Session = Depends(get_db)):
    """Mimics a sensitive configuration endpoint"""
    return await capture_and_report(request, db, "ADMIN_CORE_NODE")

@router.get("/etc/passwd")
@router.get("/windows/system32")
async def fake_traversal(request: Request, db: Session = Depends(get_db)):
    """Mimics a file system traversal vulnerability"""
    return await capture_and_report(request, db, "FILE_SYSTEM_NODE")

@router.post("/wp-login.php")
async def fake_wordpress(request: Request, db: Session = Depends(get_db)):
    """Mimics a WordPress site (common target)"""
    return await capture_and_report(request, db, "WORDPRESS_SHADOW_NODE")
