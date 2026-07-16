"""
Script to seed the exact 3 demo scenarios requested for the final pitch.
Run this with: python -m app.scripts.seed_demo_scenarios
"""

import os
from sqlalchemy.orm import Session
from app.database import SessionLocal, init_db
from app.models import Incident, Organization, Asset, User
from app.auth import ensure_demo_users_in_db
from datetime import datetime, timezone, timedelta

def create_demo_scenarios(db: Session):
    print("Clearing existing incidents...")
    db.query(Incident).delete()
    db.commit()

    # Get demo org
    org = db.query(Organization).first()
    if not org:
        ensure_demo_users_in_db(db)
        org = db.query(Organization).first()

    # Ensure some assets exist to link to
    scada_asset = db.query(Asset).filter(Asset.name == "SCADA Controller").first()
    if not scada_asset:
        scada_asset = Asset(organization_id=org.id, name="SCADA Controller", asset_type="ics_node", criticality="high", ip_address="10.0.5.50")
        db.add(scada_asset)
    
    gov_asset = db.query(Asset).filter(Asset.name == "GovAuth Gateway").first()
    if not gov_asset:
        gov_asset = Asset(organization_id=org.id, name="GovAuth Gateway", asset_type="server", criticality="high", ip_address="192.168.10.10")
        db.add(gov_asset)

    edu_asset = db.query(Asset).filter(Asset.name == "CBSE Student DB").first()
    if not edu_asset:
        edu_asset = Asset(organization_id=org.id, name="CBSE Student DB", asset_type="database", criticality="high", ip_address="10.1.20.100")
        db.add(edu_asset)
    
    db.commit()

    now = datetime.now(timezone.utc)

    from app.models import SecurityTelemetry
    
    t1 = SecurityTelemetry(organization_id=org.id, event_type="auth_anomaly", user_identity="gov_admin", source_ip="185.10.50.1", action="brute_force")
    db.add(t1)

    # Scenario 1: Government Account Takeover
    inc1 = Incident(
        organization_id=org.id,
        title="Government Account Takeover",
        description="Multiple failed logins followed by successful access from a blacklisted VPN IP targeting the GovAuth gateway.",
        severity="HIGH",
        status="new",
        created_by="system",
        created_at=now - timedelta(hours=2),
        affected_assets=[gov_asset.id],
        mitre_techniques=["T1078", "T1110", "T1098"],
        telemetry_events=[t1],
        blast_radius=60,
        business_impact="high",
        attack_stage="Credential Access"
    )

    t2 = SecurityTelemetry(organization_id=org.id, event_type="sql_injection", source_ip="203.0.113.50", action="union select from students")
    db.add(t2)

    # Scenario 2: Education Data Breach (CBSE-style)
    inc2 = Incident(
        organization_id=org.id,
        title="Education Data Breach (CBSE-style)",
        description="Mass data exfiltration detected from student records database via unusual SQL query patterns during off-hours.",
        severity="HIGH",
        status="investigating",
        created_by="system",
        created_at=now - timedelta(hours=1),
        affected_assets=[edu_asset.id],
        mitre_techniques=["T1190", "T1041", "T1567"],
        telemetry_events=[t2],
        blast_radius=85,
        business_impact="severe",
        attack_stage="Exfiltration"
    )

    t3 = SecurityTelemetry(organization_id=org.id, event_type="ransomware_precursor", user_identity="admin", source_ip="95.105.10.10", location={"country": "Russia"}, event_metadata={"login_time": "02:13", "failed_logins": 15, "privilege_escalation": True, "prediction": "T1003", "prediction_confidence": 0.91})
    db.add(t3)

    # Scenario 3: Critical Infrastructure Ransomware
    inc3 = Incident(
        organization_id=org.id,
        title="Critical Infrastructure Ransomware",
        description="Anomalous behavior on SCADA network indicating ransomware deployment. User admin logging in from Russia at 02:13 with 15 failed logins prior, followed by privilege escalation.",
        severity="CRITICAL",
        status="new",
        created_by="system",
        created_at=now - timedelta(minutes=15),
        affected_assets=[scada_asset.id],
        mitre_techniques=["T1078", "T1068"], # Valid Accounts, Privilege Escalation
        telemetry_events=[t3],
        blast_radius=95,
        business_impact="severe",
        attack_stage="Execution"
    )

    db.add(inc1)
    db.add(inc2)
    db.add(inc3)
    db.commit()
    print(" Successfully seeded 3 perfect demo scenarios!")

if __name__ == "__main__":
    db = SessionLocal()
    try:
        create_demo_scenarios(db)
    finally:
        db.close()
