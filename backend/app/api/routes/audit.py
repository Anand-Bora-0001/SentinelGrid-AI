"""SentinelGrid AI — Audit Trail API Routes"""
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import logging
import csv
import io
import json
from typing import Optional
from ..deps import get_current_user, get_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/audit", tags=["Audit Trail"])


@router.delete("/clear")
def clear_audit_logs(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Clear all audit logs for the organization"""
    from ...models import AuditLog, User
    user = db.query(User).filter(User.username == current_user["username"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    deleted = db.query(AuditLog).filter(AuditLog.organization_id == user.organization_id).delete()
    db.commit()
    
    # Log this action in the audit trail itself
    new_log = AuditLog(
        timestamp=datetime.now(timezone.utc),
        actor=user.username,
        actor_user_id=user.id,
        action="clear_audit_logs",
        resource_type="audit",
        details={"message": f"Cleared {deleted} audit logs"},
        organization_id=user.organization_id
    )
    db.add(new_log)
    db.commit()
    
    return {"message": f"Successfully deleted {deleted} audit logs."}


@router.get("")
def list_audit_logs(
    actor: Optional[str] = None,
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    page: int = Query(1, ge=1),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List audit logs with filters and pagination"""
    from ...models import AuditLog, User
    user = db.query(User).filter(User.username == current_user["username"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    q = db.query(AuditLog).filter(AuditLog.organization_id == user.organization_id)
    if actor:
        q = q.filter(AuditLog.actor == actor)
    if action:
        q = q.filter(AuditLog.action == action)
    if resource_type:
        q = q.filter(AuditLog.resource_type == resource_type)

    total = q.count()
    offset = (page - 1) * limit
    logs = q.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit).all()

    return {
        "items": [_log_to_dict(l) for l in logs],
        "total": total,
        "page": page,
        "page_size": limit
    }


@router.get("/export")
def export_audit_logs(
    format: str = Query("csv", regex="^(csv|json)$"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Export audit logs as CSV or JSON"""
    from ...models import AuditLog, User
    user = db.query(User).filter(User.username == current_user["username"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    logs = db.query(AuditLog).filter(AuditLog.organization_id == user.organization_id).order_by(AuditLog.timestamp.desc()).all()

    if format == "json":
        data = [_log_to_dict(l) for l in logs]
        return Response(content=json.dumps(data, indent=2), media_type="application/json", headers={"Content-Disposition": "attachment; filename=audit_log.json"})
    
    # CSV format
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Actor", "Role", "Action", "Resource Type", "Resource ID", "IP Address", "Details"])
    
    for l in logs:
        writer.writerow([
            l.id,
            l.timestamp.isoformat() if l.timestamp else "",
            l.actor,
            l.actor_role or "",
            l.action,
            l.resource_type,
            l.resource_id or "",
            l.ip_address or "",
            json.dumps(l.details or {})
        ])
        
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_log.csv"}
    )


def _log_to_dict(l) -> dict:
    return {
        "id": l.id,
        "timestamp": l.timestamp.isoformat() if l.timestamp else None,
        "actor": l.actor,
        "actor_user_id": l.actor_user_id,
        "actor_role": l.actor_role,
        "action": l.action,
        "resource_type": l.resource_type,
        "resource_id": l.resource_id,
        "details": l.details or {},
        "ip_address": l.ip_address,
        "user_agent": l.user_agent,
        "organization_id": l.organization_id,
    }
