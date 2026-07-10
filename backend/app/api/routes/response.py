"""SentinelGrid AI — Response Action API Routes"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import logging
from ..deps import get_current_user, get_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/response", tags=["Response Orchestrator"])


@router.get("/actions")
def list_actions(
    incident_id: int = None,
    status: str = None,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List response actions"""
    from ...models import ResponseAction, User
    user = db.query(User).filter(User.username == current_user["username"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    q = db.query(ResponseAction).join(ResponseAction.incident)
    q = q.filter(ResponseAction.incident.has(organization_id=user.organization_id))
    
    if incident_id:
        q = q.filter(ResponseAction.incident_id == incident_id)
    if status:
        q = q.filter(ResponseAction.status == status)
        
    actions = q.order_by(ResponseAction.created_at.desc()).all()
    return [_action_to_dict(a) for a in actions]


@router.post("/actions/{action_id}/approve")
def approve_action(
    action_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Approve a response action (simulates execution)"""
    from ...models import ResponseAction
    action = db.query(ResponseAction).filter(ResponseAction.id == action_id).first()
    if not action:
        raise HTTPException(status_code=404, detail="Response action not found")
        
    action.status = "approved"
    action.approved_by = current_user["username"]
    action.simulated_at = datetime.now(timezone.utc)
    
    # Log approval in incident timeline
    incident = action.incident
    if incident:
        timeline = incident.timeline or []
        timeline.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": f"Approved response action: {action.action_type} for {action.target}",
            "actor": current_user["username"]
        })
        incident.timeline = timeline
        
    db.commit()
    db.refresh(action)
    return _action_to_dict(action)


@router.post("/actions/{action_id}/reject")
def reject_action(
    action_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Reject a proposed response action"""
    from ...models import ResponseAction
    action = db.query(ResponseAction).filter(ResponseAction.id == action_id).first()
    if not action:
        raise HTTPException(status_code=404, detail="Response action not found")
        
    action.status = "rejected"
    
    # Log rejection in incident timeline
    incident = action.incident
    if incident:
        timeline = incident.timeline or []
        timeline.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": f"Rejected response action: {action.action_type} for {action.target}",
            "actor": current_user["username"]
        })
        incident.timeline = timeline
        
    db.commit()
    db.refresh(action)
    return _action_to_dict(action)


@router.get("/playbooks")
def get_playbooks(
    severity: str = None,
    current_user: dict = Depends(get_current_user),
):
    """Get all response playbooks"""
    from ...services.response_orchestrator import response_orchestrator
    if severity:
        return response_orchestrator.get_playbook(severity)
    return response_orchestrator.playbooks


def _action_to_dict(a) -> dict:
    return {
        "id": a.id,
        "incident_id": a.incident_id,
        "action_type": a.action_type,
        "target": a.target,
        "parameters": a.parameters or {},
        "status": a.status,
        "proposed_by": a.proposed_by,
        "approved_by": a.approved_by,
        "confidence": a.confidence,
        "rationale": a.rationale,
        "simulation_result": a.simulation_result or {},
        "simulated_at": a.simulated_at.isoformat() if a.simulated_at else None,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }
