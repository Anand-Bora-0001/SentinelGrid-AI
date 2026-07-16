"""
Initialize SentinelGrid SaaS Platform
- Create database tables
- Initialize subscription plans
- Create demo organizations
- Set up default configurations
"""

import sys
import os
from datetime import datetime, timezone, timedelta

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import engine, SessionLocal, init_db
from app.models import Base, Organization, User, Service, SubscriptionPlan, NotificationConfig
from app.subscription_manager import SubscriptionManager
from app.notification_manager import NotificationManager
from passlib.context import CryptContext
import secrets
import string

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def generate_api_key():
    """Generate secure API key"""
    alphabet = string.ascii_letters + string.digits
    return 'hc_' + ''.join(secrets.choice(alphabet) for _ in range(32))

def generate_slug(name: str) -> str:
    """Generate URL-safe slug"""
    return name.lower().replace(' ', '-').replace('_', '-')

def init_saas_platform():
    """Initialize complete SaaS platform"""
    
    print("\n" + "="*70)
    print("🚀 Initializing SentinelGrid SaaS Platform")
    print("="*70 + "\n")
    
    # Step 1: Create database tables
    print("📊 Creating database tables...")
    init_db()
    
    db = SessionLocal()
    
    try:
        # Step 2: Initialize subscription plans
        print("\n💳 Initializing subscription plans...")
        SubscriptionManager.initialize_plans(db)
        
        # Step 3: Create demo organizations
        print("\n🏢 Creating demo organizations...")
        
        # Demo Organization 1: Free Trial
        demo_org1 = db.query(Organization).filter(Organization.slug == "demo-startup").first()
        if not demo_org1:
            demo_org1 = SubscriptionManager.create_organization_with_trial(
                db=db,
                name="Demo Startup",
                email="demo@startup.com",
                slug="demo-startup",
                trial_days=10
            )
            print(f"   ✅ Created: {demo_org1.name} (Free Trial)")
        
        # Demo Organization 2: Starter Plan
        demo_org2 = db.query(Organization).filter(Organization.slug == "acme-corp").first()
        if not demo_org2:
            demo_org2 = Organization(
                name="Acme Corporation",
                slug="acme-corp",
                email="security@acme.com",
                plan="starter",
                is_trial=False,
                max_services=5,
                max_events_per_month=50000,
                max_users=3,
                plan_started_at=datetime.now(timezone.utc),
                plan_expires_at=datetime.now(timezone.utc) + timedelta(days=30)
            )
            db.add(demo_org2)
            db.commit()
            db.refresh(demo_org2)
            print(f"   ✅ Created: {demo_org2.name} (Starter Plan)")
        
        # Step 4: Create demo users
        print("\n👤 Creating demo users...")
        
        # Admin user for Demo Startup
        admin1 = db.query(User).filter(User.username == "demo-admin").first()
        if not admin1:
            admin1 = User(
                email="admin@startup.com",
                username="demo-admin",
                hashed_password=pwd_context.hash("admin123"),
                full_name="Demo Admin",
                organization_id=demo_org1.id,
                role="owner",
                is_active=True,
                is_verified=True
            )
            db.add(admin1)
            print(f"   ✅ Created user: demo-admin / admin123")
        
        # Admin user for Acme Corp
        admin2 = db.query(User).filter(User.username == "acme-admin").first()
        if not admin2:
            admin2 = User(
                email="admin@acme.com",
                username="acme-admin",
                hashed_password=pwd_context.hash("acme123"),
                full_name="Acme Admin",
                organization_id=demo_org2.id,
                role="owner",
                is_active=True,
                is_verified=True
            )
            db.add(admin2)
            print(f"   ✅ Created user: acme-admin / acme123")
        
        db.commit()
        
        # Step 5: Create demo services
        print("\n🔧 Creating demo services...")
        
        service1 = db.query(Service).filter(Service.slug == "demo-ecommerce").first()
        if not service1:
            service1 = Service(
                organization_id=demo_org1.id,
                name="Demo E-Commerce",
                slug="demo-ecommerce",
                description="Demo e-commerce website with threat_sensors",
                service_type="web",
                api_key=generate_api_key(),
                is_active=True
            )
            db.add(service1)
            print(f"   ✅ Created service: Demo E-Commerce")
            print(f"      API Key: {service1.api_key}")
        
        service2 = db.query(Service).filter(Service.slug == "acme-api").first()
        if not service2:
            service2 = Service(
                organization_id=demo_org2.id,
                name="Acme API",
                slug="acme-api",
                description="Main API service",
                service_type="api",
                api_key=generate_api_key(),
                is_active=True
            )
            db.add(service2)
            print(f"   ✅ Created service: Acme API")
            print(f"      API Key: {service2.api_key}")
        
        db.commit()
        
        # Step 6: Create notification configs
        print("\n🔔 Creating notification configurations...")
        
        config1 = db.query(NotificationConfig).filter(
            NotificationConfig.organization_id == demo_org1.id
        ).first()
        if not config1:
            NotificationManager.create_default_config(db, demo_org1.id)
        
        config2 = db.query(NotificationConfig).filter(
            NotificationConfig.organization_id == demo_org2.id
        ).first()
        if not config2:
            NotificationManager.create_default_config(db, demo_org2.id)
        
        # Step 7: Display summary
        print("\n" + "="*70)
        print("✅ SentinelGrid SaaS Platform Initialized Successfully!")
        print("="*70)
        
        print("\n📋 Demo Accounts:")
        print("\n1️⃣  Demo Startup (Free Trial - 10 days)")
        print("   Username: demo-admin")
        print("   Password: admin123")
        print("   Services: 1/1")
        print("   Events: 0/1,000 per month")
        
        print("\n2️⃣  Acme Corporation (Starter Plan)")
        print("   Username: acme-admin")
        print("   Password: acme123")
        print("   Services: 1/5")
        print("   Events: 0/50,000 per month")
        
        print("\n🔗 Access URLs:")
        print("   • Frontend: http://localhost:5173")
        print("   • API: http://localhost:8000")
        print("   • API Docs: http://localhost:8000/docs")
        
        print("\n💡 Next Steps:")
        print("   1. Start the backend: docker-compose up")
        print("   2. Login with demo credentials")
        print("   3. Create services and get API keys")
        print("   4. Integrate with your applications")
        print("   5. Monitor security events in real-time")
        
        print("\n" + "="*70 + "\n")
        
    except Exception as e:
        print(f"\n❌ Error during initialization: {e}")
        db.rollback()
        raise
    finally:
        db.close()

if __name__ == "__main__":
    init_saas_platform()
