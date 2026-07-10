"""SentinelGrid AI — Asset API Routes"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
import logging
from ..deps import get_current_user, get_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/assets", tags=["Assets"])


@router.get("")
def list_assets(
    asset_type: str = None, network_segment: str = None,
    current_user: dict = Depends(get_current_user), db: Session = Depends(get_db),
):
    from ...models import Asset, User
    user = db.query(User).filter(User.username == current_user["username"]).first()
    if not user: raise HTTPException(status_code=404, detail="User not found")
    q = db.query(Asset).filter(Asset.organization_id == user.organization_id)
    if asset_type: q = q.filter(Asset.asset_type == asset_type)
    if network_segment: q = q.filter(Asset.network_segment == network_segment)
    assets = q.all()
    return [_asset_to_dict(a) for a in assets]


@router.post("")
def create_asset(data: dict, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    from ...models import Asset, User
    user = db.query(User).filter(User.username == current_user["username"]).first()
    if not user: raise HTTPException(status_code=404, detail="User not found")
    asset = Asset(organization_id=user.organization_id, **{k: v for k, v in data.items() if k != "organization_id"})
    db.add(asset); db.commit(); db.refresh(asset)
    return _asset_to_dict(asset)


@router.get("/topology")
def get_topology(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get network topology for Digital Twin"""
    from ...models import Asset, Vulnerability, User
    from ...services.simulation_engine import simulation_engine
    user = db.query(User).filter(User.username == current_user["username"]).first()
    if not user: raise HTTPException(status_code=404, detail="User not found")
    assets = db.query(Asset).filter(Asset.organization_id == user.organization_id).all()
    # Get vulnerability counts per asset
    vuln_counts = {}
    for a in assets:
        count = db.query(Vulnerability).filter(Vulnerability.affected_asset_id == a.id, Vulnerability.status == "open").count()
        vuln_counts[a.id] = count
    nodes = []
    for a in assets:
        node = _asset_to_dict(a)
        node["vulnerability_count"] = vuln_counts.get(a.id, 0)
        nodes.append(node)
    edges = simulation_engine.get_topology_edges()
    return {"nodes": nodes, "edges": edges}


@router.post("/seed")
def seed_assets(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Seed infrastructure assets from simulation engine"""
    from ...models import Asset, User
    from ...services.simulation_engine import simulation_engine
    user = db.query(User).filter(User.username == current_user["username"]).first()
    if not user: raise HTTPException(status_code=404, detail="User not found")
    seed_data = simulation_engine.get_seed_assets()
    created = 0
    for ad in seed_data:
        exists = db.query(Asset).filter(Asset.organization_id == user.organization_id, Asset.name == ad["name"]).first()
        if not exists:
            asset = Asset(organization_id=user.organization_id, **ad)
            db.add(asset); created += 1
    db.commit()
    return {"status": "success", "created": created, "total": len(seed_data)}


@router.put("/{asset_id}")
def update_asset(asset_id: int, data: dict, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    from ...models import Asset
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset: raise HTTPException(status_code=404, detail="Asset not found")
    for f in ["name", "status", "criticality", "position_x", "position_y"]:
        if f in data: setattr(asset, f, data[f])
    db.commit(); db.refresh(asset)
    return _asset_to_dict(asset)


def _asset_to_dict(a) -> dict:
    return {
        "id": a.id, "name": a.name, "asset_type": a.asset_type, "hostname": a.hostname,
        "ip_address": a.ip_address, "os_type": a.os_type, "criticality": a.criticality,
        "business_unit": a.business_unit, "location": a.location,
        "network_segment": a.network_segment, "parent_asset_id": a.parent_asset_id,
        "position_x": a.position_x, "position_y": a.position_y,
        "status": a.status, "last_seen": a.last_seen.isoformat() if a.last_seen else None,
        "services_running": a.services_running or [], "open_ports": a.open_ports or [],
        "tags": a.tags or [],
    }
