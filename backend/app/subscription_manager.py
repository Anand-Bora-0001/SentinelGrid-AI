"""
Subscription and Billing Management
"""

from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List
from sqlalchemy.orm import Session
from .models import Organization, SubscriptionPlan, BillingHistory, User
import logging

logger = logging.getLogger(__name__)

# ========================
# PLAN DEFINITIONS
# ========================

PLAN_CONFIGS = {
    "free": {
        "display_name": "Free Trial",
        "description": "Perfect for testing and small projects",
        "price_monthly": 0.0,
        "price_yearly": 0.0,
        "max_services": 1,
        "max_events_per_month": 1000,
        "max_users": 1,
        "data_retention_days": 7,
        "features": [
            "1 Service/Application",
            "1,000 events/month",
            "7 days data retention",
            "Email notifications",
            "Basic dashboard",
            "10-day free trial"
        ]
    },
    "starter": {
        "display_name": "Starter",
        "description": "For small teams and growing applications",
        "price_monthly": 29.0,
        "price_yearly": 290.0,  # 2 months free
        "max_services": 5,
        "max_events_per_month": 50000,
        "max_users": 3,
        "data_retention_days": 30,
        "features": [
            "5 Services/Applications",
            "50,000 events/month",
            "30 days data retention",
            "Email + Telegram + Slack notifications",
            "Advanced dashboard",
            "API access",
            "Export reports (CSV, PDF, Excel)",
            "Priority email support"
        ]
    },
    "professional": {
        "display_name": "Professional",
        "description": "For serious security monitoring",
        "price_monthly": 99.0,
        "price_yearly": 990.0,  # 2 months free
        "max_services": 20,
        "max_events_per_month": 500000,
        "max_users": 10,
        "data_retention_days": 90,
        "features": [
            "20 Services/Applications",
            "500,000 events/month",
            "90 days data retention",
            "All notification channels",
            "Advanced analytics",
            "Custom webhooks",
            "Real-time alerts",
            "Threat intelligence integration",
            "Custom reports",
            "Priority support (24/7)"
        ]
    },
    "enterprise": {
        "display_name": "Enterprise",
        "description": "For large organizations with custom needs",
        "price_monthly": 499.0,
        "price_yearly": 4990.0,  # 2 months free
        "max_services": 999,  # Unlimited
        "max_events_per_month": 10000000,  # 10M
        "max_users": 100,
        "data_retention_days": 365,
        "features": [
            "Unlimited Services",
            "10M+ events/month",
            "1 year data retention",
            "All features included",
            "Dedicated account manager",
            "Custom integrations",
            "SLA guarantee (99.9%)",
            "On-premise deployment option",
            "Advanced threat hunting",
            "Custom ML models",
            "White-label option",
            "24/7 Premium support"
        ]
    }
}

# ========================
# SUBSCRIPTION MANAGER
# ========================

class SubscriptionManager:
    """Manage subscriptions and billing"""
    
    @staticmethod
    def initialize_plans(db: Session):
        """Initialize subscription plans in database"""
        for plan_name, config in PLAN_CONFIGS.items():
            existing = db.query(SubscriptionPlan).filter(
                SubscriptionPlan.name == plan_name
            ).first()
            
            if not existing:
                plan = SubscriptionPlan(
                    name=plan_name,
                    display_name=config["display_name"],
                    description=config["description"],
                    price_monthly=config["price_monthly"],
                    price_yearly=config["price_yearly"],
                    max_services=config["max_services"],
                    max_events_per_month=config["max_events_per_month"],
                    max_users=config["max_users"],
                    data_retention_days=config["data_retention_days"],
                    features=config["features"],
                    sort_order=list(PLAN_CONFIGS.keys()).index(plan_name)
                )
                db.add(plan)
        
        db.commit()
        logger.info("✅ Subscription plans initialized")
    
    @staticmethod
    def create_organization_with_trial(
        db: Session,
        name: str,
        email: str,
        slug: str,
        trial_days: int = 10
    ) -> Organization:
        """Create new organization with free trial"""
        
        trial_ends = datetime.now(timezone.utc) + timedelta(days=trial_days)
        
        org = Organization(
            name=name,
            slug=slug,
            email=email,
            plan="free",
            is_trial=True,
            trial_ends_at=trial_ends,
            max_services=PLAN_CONFIGS["free"]["max_services"],
            max_events_per_month=PLAN_CONFIGS["free"]["max_events_per_month"],
            max_users=PLAN_CONFIGS["free"]["max_users"]
        )
        
        db.add(org)
        db.commit()
        db.refresh(org)
        
        logger.info(f"✅ Created organization: {name} with {trial_days}-day trial")
        return org
    
    @staticmethod
    def upgrade_subscription(
        db: Session,
        organization: Organization,
        new_plan: str,
        billing_period: str = "monthly"
    ) -> bool:
        """Upgrade organization subscription"""
        
        if new_plan not in PLAN_CONFIGS:
            logger.error(f"Invalid plan: {new_plan}")
            return False
        
        config = PLAN_CONFIGS[new_plan]
        
        # Update organization
        organization.plan = new_plan
        organization.is_trial = False
        organization.trial_ends_at = None
        organization.max_services = config["max_services"]
        organization.max_events_per_month = config["max_events_per_month"]
        organization.max_users = config["max_users"]
        
        # Set expiration based on billing period
        if billing_period == "yearly":
            organization.plan_expires_at = datetime.now(timezone.utc) + timedelta(days=365)
            amount = config["price_yearly"]
        else:
            organization.plan_expires_at = datetime.now(timezone.utc) + timedelta(days=30)
            amount = config["price_monthly"]
        
        organization.plan_started_at = datetime.now(timezone.utc)
        
        # Create billing record
        billing = BillingHistory(
            organization_id=organization.id,
            amount=amount,
            plan=new_plan,
            billing_period=billing_period,
            status="completed",
            paid_at=datetime.now(timezone.utc)
        )
        
        db.add(billing)
        db.commit()
        
        logger.info(f"✅ Upgraded {organization.name} to {new_plan} ({billing_period})")
        return True
    
    @staticmethod
    def check_limits(organization: Organization, check_type: str, current_count: int) -> bool:
        """Check if organization is within limits"""
        
        if not organization.is_plan_active():
            return False
        
        if check_type == "services":
            return current_count < organization.max_services
        elif check_type == "events":
            return current_count < organization.max_events_per_month
        elif check_type == "users":
            return current_count < organization.max_users
        
        return True
    
    @staticmethod
    def get_usage_stats(db: Session, organization: Organization) -> Dict:
        """Get current usage statistics"""
        from .models import Service, SecurityEvent
        from sqlalchemy import func, extract
        
        # Count services
        service_count = db.query(Service).filter(
            Service.organization_id == organization.id,
            Service.is_active == True
        ).count()
        
        # Count events this month
        current_month = datetime.now(timezone.utc).month
        current_year = datetime.now(timezone.utc).year
        
        events_this_month = db.query(SecurityEvent).filter(
            SecurityEvent.organization_id == organization.id,
            extract('month', SecurityEvent.timestamp) == current_month,
            extract('year', SecurityEvent.timestamp) == current_year
        ).count()
        
        # Count users
        user_count = db.query(User).filter(
            User.organization_id == organization.id,
            User.is_active == True
        ).count()
        
        return {
            "services": {
                "current": service_count,
                "limit": organization.max_services,
                "percentage": (service_count / organization.max_services * 100) if organization.max_services > 0 else 0
            },
            "events": {
                "current": events_this_month,
                "limit": organization.max_events_per_month,
                "percentage": (events_this_month / organization.max_events_per_month * 100) if organization.max_events_per_month > 0 else 0
            },
            "users": {
                "current": user_count,
                "limit": organization.max_users,
                "percentage": (user_count / organization.max_users * 100) if organization.max_users > 0 else 0
            },
            "plan": organization.plan,
            "is_trial": organization.is_trial,
            "trial_ends_at": organization.trial_ends_at.isoformat() if organization.trial_ends_at else None,
            "plan_expires_at": organization.plan_expires_at.isoformat() if organization.plan_expires_at else None
        }
    
    @staticmethod
    def get_all_plans(db: Session) -> List[SubscriptionPlan]:
        """Get all available subscription plans"""
        return db.query(SubscriptionPlan).filter(
            SubscriptionPlan.is_active == True
        ).order_by(SubscriptionPlan.sort_order).all()
