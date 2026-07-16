"""
SentinelGrid SaaS API Endpoints
Multi-tenant subscription management, billing, and organization features
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone, timedelta
import secrets
import string

from .database import get_db
from .models import Organization, User, Service, SubscriptionPlan, BillingHistory, SecurityEvent
from .schemas import (
    OrganizationCreate, OrganizationResponse, OrganizationUpdate,
    ServiceCreate, ServiceResponse, ServiceUpdate,
    SubscriptionPlanResponse, UsageStatsResponse,
    BillingHistoryResponse
)
from .auth import get_current_user, get_admin_user
from .subscription_manager import SubscriptionManager, PLAN_CONFIGS
from .notification_manager import NotificationManager
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/saas", tags=["SaaS Platform"])

# ========================
# HELPER FUNCTIONS
# ========================

def generate_api_key():
    """Generate secure API key"""
    alphabet = string.ascii_letters + string.digits
    return 'hc_' + ''.join(secrets.choice(alphabet) for _ in range(32))

def generate_slug(name: str) -> str:
    """Generate URL-safe slug"""
    import re
    slug = name.lower()
    slug = re.sub(r'[^a-z0-9]+', '-', slug)
    slug = slug.strip('-')
    return slug

# ========================
# ORGANIZATION MANAGEMENT
# ========================

@router.post("/organizations", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(
    org_data: OrganizationCreate,
    db: Session = Depends(get_db)
):
    """
    Create new organization with free trial
    PUBLIC endpoint - no authentication required for signup
    """
    
    # Check if slug already exists
    slug = generate_slug(org_data.name)
    existing = db.query(Organization).filter(Organization.slug == slug).first()
    if existing:
        slug = f"{slug}-{secrets.token_hex(4)}"
    
    # Create organization with trial
    org = SubscriptionManager.create_organization_with_trial(
        db=db,
        name=org_data.name,
        email=org_data.email,
        slug=slug,
        trial_days=10
    )
    
    # Create default notification config
    NotificationManager.create_default_config(db, org.id)
    
    logger.info(f"✅ New organization created: {org.name}")
    
    return org

@router.get("/organizations/me", response_model=OrganizationResponse)
async def get_my_organization(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get current user's organization"""
    user = db.query(User).filter(User.username == current_user["username"]).first()
    if not user or not user.organization:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    return user.organization

@router.put("/organizations/me", response_model=OrganizationResponse)
async def update_my_organization(
    org_update: OrganizationUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update organization details (owner/admin only)"""
    user = db.query(User).filter(User.username == current_user["username"]).first()
    
    if not user or user.role not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    org = user.organization
    
    if org_update.name:
        org.name = org_update.name
    if org_update.email:
        org.email = org_update.email
    
    db.commit()
    db.refresh(org)
    
    return org

# ========================
# SUBSCRIPTION MANAGEMENT
# ========================

@router.get("/plans", response_model=List[SubscriptionPlanResponse])
async def get_subscription_plans(db: Session = Depends(get_db)):
    """Get all available subscription plans - PUBLIC"""
    plans = SubscriptionManager.get_all_plans(db)
    return plans

@router.post("/subscribe/{plan_name}")
async def subscribe_to_plan(
    plan_name: str,
    billing_period: str = "monthly",
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Subscribe to a plan (owner only)
    In production, this would integrate with Stripe
    """
    user = db.query(User).filter(User.username == current_user["username"]).first()
    
    if not user or user.role != "owner":
        raise HTTPException(status_code=403, detail="Only organization owner can manage subscription")
    
    org = user.organization
    
    # Validate plan
    if plan_name not in PLAN_CONFIGS:
        raise HTTPException(status_code=400, detail="Invalid plan")
    
    # Check if downgrading
    current_plan_order = list(PLAN_CONFIGS.keys()).index(org.plan)
    new_plan_order = list(PLAN_CONFIGS.keys()).index(plan_name)
    
    if new_plan_order < current_plan_order:
        # Check if current usage fits in new plan
        usage = SubscriptionManager.get_usage_stats(db, org)
        new_config = PLAN_CONFIGS[plan_name]
        
        if usage["services"]["current"] > new_config["max_services"]:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot downgrade: You have {usage['services']['current']} services but {plan_name} allows only {new_config['max_services']}"
            )
    
    # Upgrade subscription
    success = SubscriptionManager.upgrade_subscription(
        db=db,
        organization=org,
        new_plan=plan_name,
        billing_period=billing_period
    )
    
    if not success:
        raise HTTPException(status_code=500, detail="Failed to upgrade subscription")
    
    config = PLAN_CONFIGS[plan_name]
    amount = config["price_yearly"] if billing_period == "yearly" else config["price_monthly"]
    
    return {
        "status": "success",
        "message": f"Successfully subscribed to {config['display_name']}",
        "plan": plan_name,
        "billing_period": billing_period,
        "amount": amount,
        "expires_at": org.plan_expires_at.isoformat() if org.plan_expires_at else None
    }

@router.get("/usage", response_model=UsageStatsResponse)
async def get_usage_stats(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get current usage statistics"""
    user = db.query(User).filter(User.username == current_user["username"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    org = user.organization
    usage = SubscriptionManager.get_usage_stats(db, org)
    
    return usage

# ========================
# SERVICE MANAGEMENT
# ========================

@router.post("/services", response_model=ServiceResponse, status_code=status.HTTP_201_CREATED)
async def create_service(
    service_data: ServiceCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create new service/application to monitor"""
    user = db.query(User).filter(User.username == current_user["username"]).first()
    
    if not user or user.role not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    org = user.organization
    
    # Check service limit
    current_services = db.query(Service).filter(
        Service.organization_id == org.id,
        Service.is_active == True
    ).count()
    
    if not SubscriptionManager.check_limits(org, "services", current_services):
        raise HTTPException(
            status_code=403,
            detail=f"Service limit reached ({org.max_services}). Please upgrade your plan."
        )
    
    # Generate slug and API key
    slug = generate_slug(service_data.name)
    existing = db.query(Service).filter(
        Service.organization_id == org.id,
        Service.slug == slug
    ).first()
    
    if existing:
        slug = f"{slug}-{secrets.token_hex(4)}"
    
    # Create service
    service = Service(
        organization_id=org.id,
        name=service_data.name,
        slug=slug,
        description=service_data.description,
        service_type=service_data.service_type or "web",
        api_key=generate_api_key(),
        is_active=True
    )
    
    db.add(service)
    db.commit()
    db.refresh(service)
    
    logger.info(f"✅ Service created: {service.name} for {org.name}")
    
    return service

@router.get("/services", response_model=List[ServiceResponse])
async def list_services(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all services for current organization"""
    user = db.query(User).filter(User.username == current_user["username"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    services = db.query(Service).filter(
        Service.organization_id == user.organization_id,
        Service.is_active == True
    ).all()
    
    return services

@router.get("/services/{service_id}", response_model=ServiceResponse)
async def get_service(
    service_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get service details"""
    user = db.query(User).filter(User.username == current_user["username"]).first()
    
    service = db.query(Service).filter(
        Service.id == service_id,
        Service.organization_id == user.organization_id
    ).first()
    
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    return service

@router.put("/services/{service_id}", response_model=ServiceResponse)
async def update_service(
    service_id: int,
    service_update: ServiceUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update service configuration"""
    user = db.query(User).filter(User.username == current_user["username"]).first()
    
    if user.role not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    service = db.query(Service).filter(
        Service.id == service_id,
        Service.organization_id == user.organization_id
    ).first()
    
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    if service_update.name:
        service.name = service_update.name
    if service_update.description is not None:
        service.description = service_update.description
    if service_update.webhook_url is not None:
        service.webhook_url = service_update.webhook_url
    if service_update.alert_threshold:
        service.alert_threshold = service_update.alert_threshold
    
    db.commit()
    db.refresh(service)
    
    return service

@router.delete("/services/{service_id}")
async def delete_service(
    service_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete/deactivate service"""
    user = db.query(User).filter(User.username == current_user["username"]).first()
    
    if user.role not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    service = db.query(Service).filter(
        Service.id == service_id,
        Service.organization_id == user.organization_id
    ).first()
    
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    service.is_active = False
    db.commit()
    
    return {"status": "success", "message": f"Service {service.name} deactivated"}

@router.post("/services/{service_id}/regenerate-key", response_model=ServiceResponse)
async def regenerate_api_key(
    service_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Regenerate API key for service"""
    user = db.query(User).filter(User.username == current_user["username"]).first()
    
    if user.role not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    service = db.query(Service).filter(
        Service.id == service_id,
        Service.organization_id == user.organization_id
    ).first()
    
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    service.api_key = generate_api_key()
    db.commit()
    db.refresh(service)
    
    logger.warning(f"⚠️ API key regenerated for service: {service.name}")
    
    return service

# ========================
# BILLING & INVOICES
# ========================

@router.get("/billing/history", response_model=List[BillingHistoryResponse])
async def get_billing_history(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get billing history (owner only)"""
    user = db.query(User).filter(User.username == current_user["username"]).first()
    
    if user.role != "owner":
        raise HTTPException(status_code=403, detail="Only organization owner can view billing")
    
    history = db.query(BillingHistory).filter(
        BillingHistory.organization_id == user.organization_id
    ).order_by(BillingHistory.created_at.desc()).all()
    
    return history

# ========================
# ANALYTICS PER SERVICE
# ========================

@router.get("/services/{service_id}/stats")
async def get_service_stats(
    service_id: int,
    days: int = 30,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get statistics for specific service"""
    from sqlalchemy import func, extract
    
    user = db.query(User).filter(User.username == current_user["username"]).first()
    
    service = db.query(Service).filter(
        Service.id == service_id,
        Service.organization_id == user.organization_id
    ).first()
    
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    # Get events for this service
    since = datetime.now(timezone.utc) - timedelta(days=days)
    
    events = db.query(SecurityEvent).filter(
        SecurityEvent.service_id == service_id,
        SecurityEvent.timestamp >= since
    ).all()
    
    # Calculate stats
    total_events = len(events)
    severity_counts = {}
    for event in events:
        severity = event.severity or "UNKNOWN"
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    # Top IPs
    ip_counts = {}
    for event in events:
        ip = event.source_ip
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
    
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    
    return {
        "service_id": service_id,
        "service_name": service.name,
        "period_days": days,
        "total_events": total_events,
        "severity_breakdown": severity_counts,
        "top_attacking_ips": [{"ip": ip, "count": count} for ip, count in top_ips],
        "last_event_at": service.last_event_at.isoformat() if service.last_event_at else None
    }
