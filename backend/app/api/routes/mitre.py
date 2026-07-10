"""SentinelGrid AI — MITRE ATT&CK API Routes"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import Optional
import logging
from ..deps import get_current_user, get_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/mitre", tags=["MITRE ATT&CK"])


@router.get("/matrix")
def get_mitre_matrix(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get full ATT&CK matrix with detection counts"""
    from ...ai.mitre_engine import mitre_engine
    from ...models import SecurityTelemetry, User
    matrix = mitre_engine.get_matrix_data()
    try:
        user = db.query(User).filter(User.username == current_user["username"]).first()
        events = db.query(SecurityTelemetry).filter(
            SecurityTelemetry.organization_id == user.organization_id,
            SecurityTelemetry.mitre_technique_id.isnot(None)
        ).all()
        counts = {}
        for e in events:
            if e.mitre_technique_id:
                counts[e.mitre_technique_id] = counts.get(e.mitre_technique_id, 0) + 1
        for tactic, techniques in matrix.get("techniques_by_tactic", {}).items():
            for tech in techniques:
                tech["detection_count"] = counts.get(tech["id"], 0)
        matrix["total_detections"] = sum(counts.values())
    except Exception as e:
        logger.warning(f"Count enrichment failed: {e}")
        matrix["total_detections"] = 0
    return matrix


@router.get("/heatmap")
def get_mitre_heatmap(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Technique frequency heatmap data"""
    from ...ai.mitre_engine import mitre_engine
    from ...models import SecurityTelemetry, User
    counts = {}
    try:
        user = db.query(User).filter(User.username == current_user["username"]).first()
        events = db.query(SecurityTelemetry).filter(
            SecurityTelemetry.organization_id == user.organization_id,
            SecurityTelemetry.mitre_technique_id.isnot(None)
        ).all()
        for e in events:
            if e.mitre_technique_id:
                counts[e.mitre_technique_id] = counts.get(e.mitre_technique_id, 0) + 1
    except Exception:
        pass
    return mitre_engine.get_technique_heatmap(counts)


@router.get("/attack-timeline")
def get_attack_timeline(limit: int = Query(50, ge=1, le=200), current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get attack progression timeline"""
    from ...ai.mitre_engine import mitre_engine
    from ...models import SecurityTelemetry, User
    try:
        user = db.query(User).filter(User.username == current_user["username"]).first()
        events = db.query(SecurityTelemetry).filter(
            SecurityTelemetry.organization_id == user.organization_id,
            SecurityTelemetry.mitre_technique_id.isnot(None)
        ).order_by(SecurityTelemetry.timestamp.desc()).limit(limit).all()
        event_dicts = [{"timestamp": e.timestamp.isoformat() if e.timestamp else "", "action": e.action, "source_ip": e.source_ip,
                        "command": e.command, "protocol": e.protocol, "event_type": e.event_type, "severity": e.severity,
                        "mitre_technique_id": e.mitre_technique_id, "mitre_tactic": e.mitre_tactic} for e in events]
        timeline = mitre_engine.get_attack_timeline(event_dicts)
        technique_ids = list(set(e.mitre_technique_id for e in events if e.mitre_technique_id))
        stage_info = mitre_engine.identify_attack_stage(technique_ids)
        return {"timeline": timeline, "attack_stage": stage_info}
    except Exception as e:
        logger.warning(f"Timeline generation failed: {e}")
        return {"timeline": [], "attack_stage": {"current_stage": "Unknown", "detected_tactics": []}}


@router.get("/techniques/{technique_id}")
def get_technique_detail(technique_id: str, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get technique details with related events"""
    from ...ai.mitre_engine import mitre_engine, TECHNIQUE_PATTERNS
    from ...models import SecurityTelemetry, User
    if technique_id not in TECHNIQUE_PATTERNS:
        return {"technique_id": technique_id, "found": False}
    tech = TECHNIQUE_PATTERNS[technique_id]
    related_events = []
    try:
        user = db.query(User).filter(User.username == current_user["username"]).first()
        events = db.query(SecurityTelemetry).filter(
            SecurityTelemetry.organization_id == user.organization_id,
            SecurityTelemetry.mitre_technique_id == technique_id
        ).order_by(SecurityTelemetry.timestamp.desc()).limit(20).all()
        related_events = [{"id": e.id, "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                           "source_ip": e.source_ip, "action": e.action, "severity": e.severity} for e in events]
    except Exception:
        pass
    actors = mitre_engine._find_similar_actors([technique_id])
    return {"technique_id": technique_id, "name": tech["name"], "tactic": tech["tactic"],
            "severity": tech["severity"], "description": tech["description"],
            "related_events": related_events, "threat_actors": actors, "found": True}
