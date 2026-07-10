"""SentinelGrid AI — Vulnerability API Routes"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import logging
from ..deps import get_current_user, get_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/vulnerabilities", tags=["Vulnerabilities"])


@router.get("")
def list_vulnerabilities(
    severity: str = None, status: str = None,
    limit: int = Query(50, ge=1, le=200), page: int = Query(1, ge=1),
    current_user: dict = Depends(get_current_user), db: Session = Depends(get_db),
):
    from ...models import Vulnerability, User
    user = db.query(User).filter(User.username == current_user["username"]).first()
    if not user: raise HTTPException(status_code=404, detail="User not found")
    q = db.query(Vulnerability).filter(Vulnerability.organization_id == user.organization_id)
    if severity: q = q.filter(Vulnerability.severity == severity)
    if status: q = q.filter(Vulnerability.status == status)
    total = q.count()
    items = q.order_by(Vulnerability.composite_risk_score.desc()).offset((page-1)*limit).limit(limit).all()
    return {
        "items": [_vuln_to_dict(v) for v in items], "total": total,
        "critical_count": db.query(Vulnerability).filter(Vulnerability.organization_id == user.organization_id, Vulnerability.severity == "CRITICAL").count(),
        "exploitable_count": db.query(Vulnerability).filter(Vulnerability.organization_id == user.organization_id, Vulnerability.exploit_available == True).count(),
    }


@router.get("/patch-queue")
def get_patch_queue(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get AI-ranked patch queue"""
    from ...models import Vulnerability, Asset, User
    from ...ai.vuln_prioritizer import vuln_prioritizer
    user = db.query(User).filter(User.username == current_user["username"]).first()
    if not user: raise HTTPException(status_code=404, detail="User not found")
    vulns = db.query(Vulnerability).filter(Vulnerability.organization_id == user.organization_id, Vulnerability.status == "open").all()
    assets = {a.id: {"name": a.name, "criticality": a.criticality, "network_segment": a.network_segment, "open_ports": a.open_ports or []}
              for a in db.query(Asset).filter(Asset.organization_id == user.organization_id).all()}
    vuln_dicts = [_vuln_to_dict(v) for v in vulns]
    queue = vuln_prioritizer.generate_patch_queue(vuln_dicts, assets)
    stats = vuln_prioritizer.get_summary_stats(queue)
    # Update DB with computed priorities
    for item in queue:
        vuln = db.query(Vulnerability).filter(Vulnerability.id == item.get("id")).first()
        if vuln:
            vuln.composite_risk_score = item["composite_risk_score"]
            vuln.patch_priority = item["patch_priority"]
    try: db.commit()
    except: db.rollback()
    return {"queue": queue[:50], "stats": stats}


@router.post("/scan")
def trigger_scan(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Seed vulnerability data from simulation engine"""
    from ...models import Vulnerability, Asset, User
    from ...services.simulation_engine import simulation_engine
    user = db.query(User).filter(User.username == current_user["username"]).first()
    if not user: raise HTTPException(status_code=404, detail="User not found")
    seed_vulns = simulation_engine.get_seed_vulnerabilities()
    assets = {a.name: a.id for a in db.query(Asset).filter(Asset.organization_id == user.organization_id).all()}
    created = 0
    for sv in seed_vulns:
        exists = db.query(Vulnerability).filter(Vulnerability.organization_id == user.organization_id, Vulnerability.cve_id == sv["cve_id"]).first()
        if not exists:
            v = Vulnerability(
                organization_id=user.organization_id, cve_id=sv["cve_id"], title=sv["title"],
                cvss_score=sv["cvss_score"], severity=sv["severity"],
                exploit_available=sv["exploit_available"], exploit_maturity=sv.get("exploit_maturity"),
                affected_asset_id=assets.get(sv.get("affected_asset")),
                business_impact=sv["business_impact"], affected_component=sv.get("affected_component"),
            )
            db.add(v); created += 1
    db.commit()
    return {"status": "success", "created": created, "total": len(seed_vulns)}


@router.put("/{vuln_id}")
def update_vulnerability(vuln_id: int, data: dict, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    from ...models import Vulnerability
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln: raise HTTPException(status_code=404, detail="Vulnerability not found")
    for f in ["status", "patch_priority", "remediation_notes"]:
        if f in data: setattr(vuln, f, data[f])
    if data.get("status") == "patched": vuln.patched_at = datetime.now(timezone.utc)
    db.commit(); db.refresh(vuln)
    return _vuln_to_dict(vuln)


def _vuln_to_dict(v) -> dict:
    return {
        "id": v.id, "cve_id": v.cve_id, "title": v.title, "description": v.description,
        "cvss_score": v.cvss_score, "severity": v.severity, "exploit_available": v.exploit_available,
        "exploit_maturity": v.exploit_maturity, "affected_asset_id": v.affected_asset_id,
        "business_impact": v.business_impact, "composite_risk_score": v.composite_risk_score or 0,
        "patch_priority": v.patch_priority, "status": v.status,
        "discovered_at": v.discovered_at.isoformat() if v.discovered_at else None,
        "patched_at": v.patched_at.isoformat() if v.patched_at else None,
        "affected_component": v.affected_component, "remediation_notes": v.remediation_notes,
    }
