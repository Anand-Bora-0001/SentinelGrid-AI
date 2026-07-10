"""SentinelGrid AI — Incident API Routes"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from typing import Optional
import logging, json

from ..deps import get_current_user, get_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/incidents", tags=["Incidents"])


@router.get("")
def list_incidents(
    status: Optional[str] = None, severity: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200), page: int = Query(1, ge=1),
    current_user: dict = Depends(get_current_user), db: Session = Depends(get_db),
):
    from ...models import Incident, User
    user = db.query(User).filter(User.username == current_user["username"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    q = db.query(Incident).filter(Incident.organization_id == user.organization_id, Incident.is_deleted == False)
    if status: q = q.filter(Incident.status == status)
    if severity: q = q.filter(Incident.severity == severity)
    total = q.count()
    active = db.query(Incident).filter(Incident.organization_id == user.organization_id, Incident.status.in_(["new", "investigating"]), Incident.is_deleted == False).count()
    critical = db.query(Incident).filter(Incident.organization_id == user.organization_id, Incident.severity == "CRITICAL", Incident.is_deleted == False).count()
    items = q.order_by(Incident.created_at.desc()).offset((page-1)*limit).limit(limit).all()
    return {
        "items": [_incident_to_dict(i) for i in items],
        "total": total, "active_count": active, "critical_count": critical,
    }


@router.post("")
def create_incident(
    data: dict, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db),
):
    from ...models import Incident, User
    user = db.query(User).filter(User.username == current_user["username"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    severity = data.get("severity", "MEDIUM").upper()
    blast_radius = 35.0
    if severity == "CRITICAL":
        blast_radius = 85.0
    elif severity == "HIGH":
        blast_radius = 60.0
    elif severity == "LOW":
        blast_radius = 15.0
    elif severity == "INFO":
        blast_radius = 5.0

    incident = Incident(
        organization_id=user.organization_id, title=data["title"],
        description=data.get("description"), severity=severity,
        created_by=current_user["username"], mitre_techniques=data.get("mitre_techniques", []),
        affected_assets=data.get("affected_assets", []),
        blast_radius=blast_radius,
        timeline=[{"timestamp": datetime.now(timezone.utc).isoformat(), "event": "Incident created", "actor": current_user["username"]}],
    )
    db.add(incident); db.commit(); db.refresh(incident)
    return _incident_to_dict(incident)


@router.get("/{incident_id}")
def get_incident(incident_id: int, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    from ...models import Incident
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _incident_to_dict(incident)


@router.put("/{incident_id}")
def update_incident(incident_id: int, data: dict, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    from ...models import Incident
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    for field in ["title", "description", "severity", "status", "assigned_to_id", "business_impact"]:
        if field in data:
            setattr(incident, field, data[field])
    
    timeline = incident.timeline or []
    
    if data.get("status") == "resolved":
        incident.resolved_at = datetime.now(timezone.utc)
        
        # Adaptive Anomaly Threshold Feedback Loop (Active Reinforcement Learning)
        from ...models import Organization
        org = db.query(Organization).filter(Organization.id == incident.organization_id).first()
        if org:
            impact = data.get("business_impact", incident.business_impact or "low").lower()
            old_threshold = getattr(org, 'anomaly_threshold', None) or 0.70
            
            # If resolved as low/none impact or user flags as false alarm in title/description, raise threshold
            if impact == "none" or "false alarm" in (incident.title.lower() + (incident.description or "").lower()):
                # Raise threshold to reduce future false positives (make it less sensitive)
                org.anomaly_threshold = min(0.95, old_threshold + 0.02)
                feedback_msg = f"Feedback loop: False Positive registered. Anomaly threshold raised from {old_threshold:.2f} to {org.anomaly_threshold:.2f} to suppress false alerts."
            else:
                # Confirmed threat (True Positive) -> Lower threshold slightly to make it more sensitive
                org.anomaly_threshold = max(0.40, old_threshold - 0.01)
                feedback_msg = f"Feedback loop: True Positive confirmed. Anomaly threshold lowered from {old_threshold:.2f} to {org.anomaly_threshold:.2f} to reinforce threat sensitivity."
            
            logger.info(feedback_msg)
            timeline.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": "AI Baseline Calibration",
                "actor": "reinforcement_agent",
                "details": feedback_msg
            })
            
    timeline.append({"timestamp": datetime.now(timezone.utc).isoformat(), "event": f"Updated: {', '.join(data.keys())}", "actor": current_user["username"]})
    incident.timeline = timeline
    db.commit(); db.refresh(incident)
    return _incident_to_dict(incident)


@router.get("/{incident_id}/timeline")
def get_incident_timeline(incident_id: int, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    from ...models import Incident
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"incident_id": incident_id, "timeline": incident.timeline or [], "mitre_techniques": incident.mitre_techniques or []}


@router.post("/{incident_id}/response")
def generate_response(incident_id: int, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Generate AI response actions for an incident"""
    from ...models import Incident, ResponseAction
    from ...services.response_orchestrator import response_orchestrator

    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    inc_dict = _incident_to_dict(incident)
    proposed = response_orchestrator.generate_response(inc_dict)

    actions = []
    for p in proposed:
        action = ResponseAction(
            incident_id=incident_id, action_type=p.action_type,
            target=p.target, parameters=p.parameters, confidence=p.confidence,
            rationale=p.rationale, simulation_result=p.simulation_result,
        )
        db.add(action)
        actions.append({"action_type": p.action_type, "target": p.target, "confidence": p.confidence, "rationale": p.rationale})

    db.commit()
    return {"incident_id": incident_id, "proposed_actions": actions}


def _incident_to_dict(i) -> dict:
    return {
        "id": i.id, "title": i.title, "description": i.description,
        "severity": i.severity, "status": i.status,
        "assigned_to_id": i.assigned_to_id, "created_by": i.created_by,
        "created_at": i.created_at.isoformat() if i.created_at else None,
        "updated_at": i.updated_at.isoformat() if i.updated_at else None,
        "resolved_at": i.resolved_at.isoformat() if i.resolved_at else None,
        "mitre_techniques": i.mitre_techniques or [],
        "attack_stage": i.attack_stage,
        "affected_assets": i.affected_assets or [],
        "blast_radius": i.blast_radius or 0,
        "business_impact": i.business_impact or "low",
        "timeline": i.timeline or [],
        "organization_id": i.organization_id,
        "is_deleted": i.is_deleted or False,
    }


@router.get("/deleted/all")
def list_deleted_incidents(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Fetch all soft-deleted incidents"""
    from ...models import Incident, User
    user = db.query(User).filter(User.username == current_user["username"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    items = db.query(Incident).filter(Incident.organization_id == user.organization_id, Incident.is_deleted == True).order_by(Incident.created_at.desc()).all()
    return [_incident_to_dict(i) for i in items]


@router.delete("/clear")
def clear_incidents(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Soft-delete all incidents"""
    from ...models import Incident, User
    user = db.query(User).filter(User.username == current_user["username"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    updated = db.query(Incident).filter(
        Incident.organization_id == user.organization_id,
        Incident.is_deleted == False
    ).update({"is_deleted": True})
    
    db.commit()
    return {"status": "success", "message": f"Moved {updated} incidents to Recycle Bin."}


@router.delete("/{incident_id}")
def delete_incident(incident_id: int, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Soft-delete an incident"""
    from ...models import Incident
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident.is_deleted = True
    
    # Log event to timeline
    timeline = incident.timeline or []
    timeline.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "Incident Soft-Deleted",
        "actor": current_user["username"],
        "details": "Incident moved to Recycle Bin."
    })
    incident.timeline = timeline
    
    db.commit()
    return {"status": "success", "message": f"Incident #{incident_id} soft-deleted."}


@router.post("/{incident_id}/restore")
def restore_incident(incident_id: int, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Restore a soft-deleted incident"""
    from ...models import Incident
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident.is_deleted = False
    
    # Log event to timeline
    timeline = incident.timeline or []
    timeline.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "Incident Restored",
        "actor": current_user["username"],
        "details": "Incident restored from Recycle Bin."
    })
    incident.timeline = timeline
    
    db.commit()
    return {"status": "success", "message": f"Incident #{incident_id} restored."}
