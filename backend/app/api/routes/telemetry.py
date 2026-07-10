"""
SentinelGrid AI — Telemetry API Routes
Ingest, query, enrich, simulate, and stream security telemetry.
"""
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from sqlalchemy.orm import Session
from sse_starlette.sse import EventSourceResponse
from datetime import datetime, timezone
from typing import Optional
import asyncio
import json
import logging

from ..deps import get_current_user, get_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/telemetry", tags=["Telemetry"])

# In-memory event buffer for SSE streaming
_event_buffer = []


@router.post("/ingest")
async def ingest_telemetry(event: dict, request: Request):
    """
    Ingest a security telemetry event.
    Enriches with AI anomaly detection, MITRE mapping, and threat intelligence.
    """
    from ...models import SecurityTelemetry, Organization
    from ...database import get_db as get_db_gen
    from ...ai.anomaly_detector import anomaly_detector
    from ...ai.mitre_engine import mitre_engine
    from ...ai.threat_rag import threat_rag

    try:
        # AI Enrichment — Anomaly Detection
        anomaly_result = anomaly_detector.detect(event)

        # AI Enrichment — MITRE ATT&CK Mapping
        mitre_matches = mitre_engine.map_event(event)
        top_mitre = mitre_matches[0] if mitre_matches else None

        # Determine final severity
        severity = event.get('severity', 'INFO').upper()
        if anomaly_result.is_anomaly and anomaly_result.risk_score > 70:
            severity = 'CRITICAL' if anomaly_result.risk_score > 85 else 'HIGH'

        # Build enriched event
        enriched = {
            "timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "event_type": event.get("event_type", "network_flow"),
            "source": event.get("source"),
            "source_ip": event.get("source_ip"),
            "dest_ip": event.get("dest_ip"),
            "source_port": event.get("source_port"),
            "dest_port": event.get("dest_port"),
            "protocol": event.get("protocol"),
            "user_identity": event.get("user_identity"),
            "action": event.get("action"),
            "resource": event.get("resource"),
            "method": event.get("method"),
            "payload": event.get("payload"),
            "command": event.get("command"),
            "severity": severity,
            "anomaly_score": anomaly_result.anomaly_score,
            "risk_score": anomaly_result.risk_score,
            "confidence": anomaly_result.confidence,
            "is_anomaly": anomaly_result.is_anomaly,
            "ai_explanation": anomaly_result.explanation,
            "mitre_technique_id": top_mitre["technique_id"] if top_mitre else None,
            "mitre_tactic": top_mitre["tactic"] if top_mitre else None,
            "location": event.get("location"),
            "event_metadata": event.get("metadata", {}),
        }

        # Add to in-memory buffer for SSE
        _event_buffer.append(enriched)
        if len(_event_buffer) > 500:
            _event_buffer.pop(0)

        # Save to database
        db = None
        try:
            db = next(get_db_gen())
            org = db.query(Organization).first()
            if not org:
                org = Organization(
                    name="SentinelGrid Demo", slug="sentinelgrid-demo",
                    email="admin@sentinelgrid.ai", industry="critical_infrastructure"
                )
                db.add(org)
                db.commit()
                db.refresh(org)

            db_event = SecurityTelemetry(
                organization_id=org.id,
                timestamp=datetime.fromisoformat(enriched["timestamp"].replace('Z', '+00:00')) if isinstance(enriched["timestamp"], str) else enriched["timestamp"],
                event_type=enriched["event_type"],
                source=enriched["source"],
                source_ip=enriched["source_ip"],
                dest_ip=enriched["dest_ip"],
                source_port=enriched["source_port"],
                dest_port=enriched["dest_port"],
                protocol=enriched["protocol"],
                user_identity=enriched["user_identity"],
                action=enriched["action"],
                resource=enriched["resource"],
                method=enriched["method"],
                payload=enriched["payload"],
                command=enriched["command"],
                severity=enriched["severity"],
                anomaly_score=enriched["anomaly_score"],
                risk_score=enriched["risk_score"],
                confidence=enriched["confidence"],
                is_anomaly=enriched["is_anomaly"],
                ai_explanation=enriched["ai_explanation"],
                mitre_technique_id=enriched["mitre_technique_id"],
                mitre_tactic=enriched["mitre_tactic"],
                location=enriched["location"],
                event_metadata=enriched["event_metadata"],
            )
            db.add(db_event)
            db.commit()
            db.refresh(db_event)
            enriched["id"] = db_event.id
        except Exception as db_err:
            logger.error(f"DB save failed: {db_err}")
            enriched["id"] = len(_event_buffer)
        finally:
            if db:
                db.close()

        return {"status": "ingested", "id": enriched.get("id"), "is_anomaly": enriched["is_anomaly"], "risk_score": enriched["risk_score"]}

    except Exception as e:
        logger.error(f"Telemetry ingest failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("")
def get_telemetry(
    limit: int = Query(50, ge=1, le=500),
    page: int = Query(1, ge=1),
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    is_anomaly: Optional[bool] = None,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Query telemetry events with filters and pagination"""
    from ...models import SecurityTelemetry, User

    try:
        user = db.query(User).filter(User.username == current_user["username"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        query = db.query(SecurityTelemetry).filter(
            SecurityTelemetry.organization_id == user.organization_id,
            SecurityTelemetry.is_deleted == False
        )

        if event_type:
            query = query.filter(SecurityTelemetry.event_type == event_type)
        if severity:
            query = query.filter(SecurityTelemetry.severity == severity)
        if source_ip:
            query = query.filter(SecurityTelemetry.source_ip == source_ip)
        if is_anomaly is not None:
            query = query.filter(SecurityTelemetry.is_anomaly == is_anomaly)

        total = query.count()
        offset = (page - 1) * limit
        events = query.order_by(SecurityTelemetry.timestamp.desc()).offset(offset).limit(limit).all()

        items = []
        for e in events:
            items.append({
                "id": e.id,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "event_type": e.event_type,
                "source": e.source,
                "source_ip": e.source_ip,
                "dest_ip": e.dest_ip,
                "source_port": e.source_port,
                "dest_port": e.dest_port,
                "protocol": e.protocol,
                "user_identity": e.user_identity,
                "action": e.action,
                "resource": e.resource,
                "severity": e.severity,
                "anomaly_score": e.anomaly_score,
                "risk_score": e.risk_score,
                "confidence": e.confidence,
                "is_anomaly": e.is_anomaly,
                "ai_explanation": e.ai_explanation,
                "mitre_technique_id": e.mitre_technique_id,
                "mitre_tactic": e.mitre_tactic,
                "incident_id": e.incident_id,
                "location": e.location,
                "event_metadata": e.event_metadata,
            })

        return {"items": items, "total": total, "page": page, "page_size": limit}

    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"DB query failed: {e}, using buffer")
        return {"items": _event_buffer[-limit:], "total": len(_event_buffer), "page": 1, "page_size": limit}


@router.get("/{telemetry_id}")
def get_telemetry_detail(
    telemetry_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get detailed telemetry event with AI enrichment"""
    from ...models import SecurityTelemetry
    from ...ai.threat_rag import threat_rag

    event = db.query(SecurityTelemetry).filter(SecurityTelemetry.id == telemetry_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    # Get threat intelligence context
    event_dict = {
        "event_type": event.event_type,
        "action": event.action,
        "protocol": event.protocol,
        "severity": event.severity,
        "source_ip": event.source_ip,
        "command": event.command,
        "mitre_technique_id": event.mitre_technique_id,
    }
    threat_context = threat_rag.query(event_dict)

    return {
        "event": {
            "id": event.id,
            "timestamp": event.timestamp.isoformat() if event.timestamp else None,
            "event_type": event.event_type,
            "source": event.source,
            "source_ip": event.source_ip,
            "dest_ip": event.dest_ip,
            "protocol": event.protocol,
            "user_identity": event.user_identity,
            "action": event.action,
            "resource": event.resource,
            "command": event.command,
            "severity": event.severity,
            "anomaly_score": event.anomaly_score,
            "risk_score": event.risk_score,
            "confidence": event.confidence,
            "is_anomaly": event.is_anomaly,
            "ai_explanation": event.ai_explanation,
            "mitre_technique_id": event.mitre_technique_id,
            "mitre_tactic": event.mitre_tactic,
            "location": event.location,
        },
        "threat_intelligence": threat_context,
    }


@router.post("/simulate")
async def simulate_telemetry(
    count: int = Query(50, ge=1, le=200),
    include_attack: bool = True,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generate simulated security telemetry for demonstration"""
    from ...services.simulation_engine import simulation_engine
    from ...models import SecurityTelemetry, Organization
    from ...ai.anomaly_detector import anomaly_detector
    from ...ai.mitre_engine import mitre_engine

    org = db.query(Organization).first()
    if not org:
        org = Organization(
            name="SentinelGrid Demo", slug="sentinelgrid-demo",
            email="admin@sentinelgrid.ai", industry="critical_infrastructure"
        )
        db.add(org)
        db.commit()
        db.refresh(org)

    # Generate events
    events = simulation_engine.generate_telemetry_batch(count, include_attack)

    # If attack campaign, also include one
    if include_attack:
        campaign_events = simulation_engine.generate_attack_campaign()
        events.extend(campaign_events)

    # Distribute events over the past 14 days to provide historical trend data
    import random
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    for event_data in events:
        day_offset = random.randint(0, 13)
        hour_offset = random.randint(0, 23)
        minute_offset = random.randint(0, 59)
        event_time = now - timedelta(days=day_offset, hours=hour_offset, minutes=minute_offset)
        event_data["timestamp"] = event_time.isoformat()

    saved_count = 0
    severity_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for event_data in events:
        # AI enrichment
        anomaly_result = anomaly_detector.detect(event_data)
        mitre_matches = mitre_engine.map_event(event_data)
        top_mitre = mitre_matches[0] if mitre_matches else None

        severity = event_data.get("severity", "INFO")
        threshold_score = (getattr(org, 'anomaly_threshold', None) or 0.70) * 100
        if anomaly_result.is_anomaly and anomaly_result.risk_score >= threshold_score:
            severity = "CRITICAL" if anomaly_result.risk_score >= (threshold_score + 15) else "HIGH"

        severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1

        try:
            ts = event_data.get("timestamp")
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts.replace('Z', '+00:00'))

            db_event = SecurityTelemetry(
                organization_id=org.id,
                timestamp=ts,
                event_type=event_data.get("event_type"),
                source=event_data.get("source"),
                source_ip=event_data.get("source_ip"),
                dest_ip=event_data.get("dest_ip"),
                source_port=event_data.get("source_port"),
                dest_port=event_data.get("dest_port"),
                protocol=event_data.get("protocol"),
                user_identity=event_data.get("user_identity"),
                action=event_data.get("action"),
                resource=event_data.get("resource"),
                command=event_data.get("command"),
                severity=severity,
                anomaly_score=anomaly_result.anomaly_score,
                risk_score=anomaly_result.risk_score,
                confidence=anomaly_result.confidence,
                is_anomaly=anomaly_result.is_anomaly,
                ai_explanation=anomaly_result.explanation,
                mitre_technique_id=event_data.get("mitre_technique_id") or (top_mitre["technique_id"] if top_mitre else None),
                mitre_tactic=event_data.get("mitre_tactic") or (top_mitre["tactic"] if top_mitre else None),
                location=event_data.get("location"),
                event_metadata=event_data.get("metadata"),
            )
            db.add(db_event)
            saved_count += 1
        except Exception as e:
            logger.warning(f"Failed to save event: {e}")

    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Commit failed: {e}")

    # Add to SSE buffer
    for event_data in events[-20:]:  # Last 20 for buffer
        _event_buffer.append(event_data)

    return {
        "status": "success",
        "message": f"Generated {saved_count} telemetry events",
        "total": saved_count,
        "breakdown": severity_breakdown,
        "includes_campaign": include_attack,
    }


@router.get("/stream/live")
async def telemetry_stream(current_user: dict = Depends(get_current_user)):
    """SSE stream for real-time telemetry events"""
    async def event_generator():
        last_count = len(_event_buffer)
        while True:
            current_count = len(_event_buffer)
            if current_count > last_count:
                for event in _event_buffer[last_count:]:
                    yield {"event": "telemetry", "data": json.dumps(event, default=str)}
                last_count = current_count
            await asyncio.sleep(2)

    return EventSourceResponse(event_generator())


@router.delete("/clear")
def clear_telemetry(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Clear all telemetry data"""
    from ...models import SecurityTelemetry, User

    user = db.query(User).filter(User.username == current_user["username"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    updated = db.query(SecurityTelemetry).filter(
        SecurityTelemetry.organization_id == user.organization_id,
        SecurityTelemetry.is_deleted == False
    ).update({"is_deleted": True})
    db.commit()
    _event_buffer.clear()

    return {"status": "success", "deleted": updated}


@router.get("/deleted/all")
def list_deleted_telemetry(
    limit: int = Query(50, ge=1, le=500),
    page: int = Query(1, ge=1),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Fetch all soft-deleted telemetry logs"""
    from ...models import SecurityTelemetry, User
    user = db.query(User).filter(User.username == current_user["username"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    query = db.query(SecurityTelemetry).filter(
        SecurityTelemetry.organization_id == user.organization_id,
        SecurityTelemetry.is_deleted == True
    )
    total = query.count()
    offset = (page - 1) * limit
    events = query.order_by(SecurityTelemetry.timestamp.desc()).offset(offset).limit(limit).all()
    
    items = []
    for e in events:
        items.append({
            "id": e.id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "event_type": e.event_type,
            "source": e.source,
            "source_ip": e.source_ip,
            "dest_ip": e.dest_ip,
            "protocol": e.protocol,
            "action": e.action,
            "severity": e.severity,
            "is_anomaly": e.is_anomaly,
            "risk_score": e.risk_score
        })
    return {"items": items, "total": total, "page": page, "page_size": limit}


@router.delete("/{telemetry_id}")
def delete_telemetry(
    telemetry_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Soft-delete a telemetry log"""
    from ...models import SecurityTelemetry
    event = db.query(SecurityTelemetry).filter(SecurityTelemetry.id == telemetry_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    event.is_deleted = True
    db.commit()
    return {"status": "success", "message": f"Log #{telemetry_id} moved to Recycle Bin."}


@router.post("/{telemetry_id}/restore")
def restore_telemetry(
    telemetry_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Restore a soft-deleted telemetry log"""
    from ...models import SecurityTelemetry
    event = db.query(SecurityTelemetry).filter(SecurityTelemetry.id == telemetry_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    event.is_deleted = False
    db.commit()
    return {"status": "success", "message": f"Log #{telemetry_id} restored."}
