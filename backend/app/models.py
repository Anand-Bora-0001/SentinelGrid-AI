"""
SentinelGrid AI — Database Models
AI-Powered Cyber Resilience Platform for Critical National Infrastructure

Core data models for security telemetry, incidents, assets, vulnerabilities,
response actions, MITRE ATT&CK mappings, and audit logging.
"""
from sqlalchemy import (
    Column, Integer, String, Float, DateTime, Text, JSON, Boolean,
    ForeignKey, Index, Enum as SAEnum
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .database import Base
from datetime import datetime, timezone, timedelta
import enum


# ========================
# ENUMS
# ========================

class SeverityLevel(str, enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(str, enum.Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


class ResponseActionType(str, enum.Enum):
    BLOCK_IP = "block_ip"
    DISABLE_USER = "disable_user"
    ISOLATE_HOST = "isolate_host"
    SNAPSHOT_VM = "snapshot_vm"
    ESCALATE = "escalate"


class ResponseActionStatus(str, enum.Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    SIMULATED = "simulated"
    REJECTED = "rejected"


class AssetType(str, enum.Enum):
    FIREWALL = "firewall"
    ROUTER = "router"
    SWITCH = "switch"
    WEB_SERVER = "web_server"
    APP_SERVER = "app_server"
    DATABASE = "database"
    ENDPOINT = "endpoint"
    SCADA_HMI = "scada_hmi"
    PLC = "plc"
    IOT_DEVICE = "iot_device"
    LOAD_BALANCER = "load_balancer"
    DNS_SERVER = "dns_server"
    MAIL_SERVER = "mail_server"


class VulnStatus(str, enum.Enum):
    OPEN = "open"
    PATCHED = "patched"
    MITIGATED = "mitigated"
    ACCEPTED = "accepted"


# ========================
# ORGANIZATION / TENANT
# ========================

class Organization(Base):
    """Multi-tenant organization model"""
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, index=True, nullable=False)
    email = Column(String(255), nullable=False)
    industry = Column(String(100), default="critical_infrastructure")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Status
    is_active = Column(Boolean, default=True)

    # AI Thresholds
    anomaly_threshold = Column(Float, default=0.70)

    # Relationships
    users = relationship("User", back_populates="organization")
    telemetry = relationship("SecurityTelemetry", back_populates="organization")
    incidents = relationship("Incident", back_populates="organization")
    assets = relationship("Asset", back_populates="organization")
    notification_configs = relationship("NotificationConfig", back_populates="organization")

    def __repr__(self):
        return f"<Organization {self.name}>"


# ========================
# USER MODEL
# ========================

class User(Base):
    """User model with SOC role-based access control"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)

    # Organization relationship
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    organization = relationship("Organization", back_populates="users")

    # Role within SOC: admin, soc_analyst, ir_lead, ciso, viewer
    role = Column(String(50), default="soc_analyst")

    # Status
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)

    # Preferences
    is_first_login = Column(Boolean, default=True)
    telegram_configured = Column(Boolean, default=False)
    notification_preferences = Column(JSON, default=dict)

    # Relationships
    assigned_incidents = relationship("Incident", back_populates="assignee", foreign_keys="Incident.assigned_to_id")
    audit_logs = relationship("AuditLog", back_populates="actor_user")

    def __repr__(self):
        return f"<User {self.username} [{self.role}]>"


# ========================
# SECURITY TELEMETRY
# ========================

class SecurityTelemetry(Base):
    """
    Core telemetry model — replaces SecurityEvent.
    Ingests SCADA/ICS, network, user, and system telemetry.
    """
    __tablename__ = "security_telemetry"
    __table_args__ = (
        Index('ix_telemetry_org_timestamp', 'organization_id', 'timestamp'),
        Index('ix_telemetry_org_severity', 'organization_id', 'severity'),
        Index('ix_telemetry_src_ip', 'source_ip', 'timestamp'),
        Index('ix_telemetry_event_type', 'event_type', 'timestamp'),
        Index('ix_telemetry_incident', 'incident_id'),
    )

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    # Multi-tenant
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    organization = relationship("Organization", back_populates="telemetry")

    # Event classification
    event_type = Column(String(50), index=True)  # network_flow, auth_event, system_log, scada_reading, file_access, process_start
    source = Column(String(100))  # originating sensor/system

    # Network fields
    source_ip = Column(String(45), index=True)
    dest_ip = Column(String(45))
    source_port = Column(Integer)
    dest_port = Column(Integer)
    protocol = Column(String(20))  # TCP, UDP, MODBUS, DNP3, HTTP, SSH

    # Identity/Action fields
    user_identity = Column(String(255))  # username or service account
    action = Column(String(100))  # login, file_access, config_change, process_start, modbus_write
    resource = Column(String(500))  # target resource path or system
    method = Column(String(20))  # GET, POST, READ, WRITE

    # Payload
    payload = Column(Text, nullable=True)
    raw_log = Column(Text, nullable=True)
    command = Column(String(500), nullable=True)

    # Severity classification
    severity = Column(String(20), index=True, default="INFO")

    # AI/ML enrichment
    anomaly_score = Column(Float, default=0.0)  # 0.0 to 1.0
    risk_score = Column(Float, default=0.0)  # 0.0 to 100.0
    confidence = Column(Float, default=0.0)  # ML model confidence 0.0 to 1.0
    is_anomaly = Column(Boolean, default=False)
    ai_explanation = Column(Text, nullable=True)
    is_deleted = Column(Boolean, default=False, index=True)

    # MITRE ATT&CK
    mitre_technique_id = Column(String(20), nullable=True)  # e.g., T1059.001
    mitre_tactic = Column(String(50), nullable=True)  # e.g., Execution

    # Correlation
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)
    incident = relationship("Incident", back_populates="telemetry_events")
    cluster_id = Column(String(50), nullable=True)  # For signal correlation grouping

    # Geolocation
    location = Column(JSON, nullable=True)
    user_agent = Column(String(500), nullable=True)

    # Metadata
    event_metadata = Column(JSON, nullable=True)
    notification_sent = Column(Boolean, default=False)

    # Relationships
    mitre_mappings = relationship("MitreMapping", back_populates="telemetry_event")

    def __repr__(self):
        return f"<Telemetry {self.id} [{self.event_type}] {self.source_ip} → {self.dest_ip}>"


# ========================
# BEHAVIOR BASELINE
# ========================

class BehaviorBaseline(Base):
    """Learned normal behavior profiles for anomaly detection"""
    __tablename__ = "behavior_baselines"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)

    entity_type = Column(String(50), index=True)  # user, device, network_segment
    entity_id = Column(String(255), index=True)  # username, device_ip, segment_name

    # Learned features
    feature_vector = Column(JSON)  # Statistical distribution of normal features
    feature_names = Column(JSON)  # Names of features in the vector

    # Model info
    model_type = Column(String(50), default="isolation_forest")  # isolation_forest, one_class_svm
    model_version = Column(String(20))
    last_updated = Column(DateTime(timezone=True), server_default=func.now())
    sample_count = Column(Integer, default=0)

    # Thresholds
    anomaly_threshold = Column(Float, default=0.7)


# ========================
# MITRE ATT&CK MAPPING
# ========================

class MitreMapping(Base):
    """Event-to-MITRE ATT&CK technique mappings"""
    __tablename__ = "mitre_mappings"

    id = Column(Integer, primary_key=True, index=True)

    telemetry_id = Column(Integer, ForeignKey("security_telemetry.id"), nullable=False)
    telemetry_event = relationship("SecurityTelemetry", back_populates="mitre_mappings")

    technique_id = Column(String(20), index=True)  # T1059.001
    technique_name = Column(String(200))  # Command and Scripting Interpreter: PowerShell
    tactic = Column(String(50))  # execution, persistence, lateral_movement, etc.
    sub_technique = Column(String(200), nullable=True)

    confidence = Column(Float, default=0.8)
    severity = Column(String(20), default="MEDIUM")

    # Threat actor similarity
    threat_actor_similarity = Column(JSON, nullable=True)  # [{name: "APT29", similarity: 0.85}]

    created_at = Column(DateTime(timezone=True), server_default=func.now())


# ========================
# INCIDENT
# ========================

class Incident(Base):
    """Correlated security incidents from signal correlation"""
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    organization = relationship("Organization", back_populates="incidents")

    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)

    severity = Column(String(20), default="MEDIUM")
    status = Column(String(20), default="new")  # new, investigating, contained, resolved, closed

    # Assignment
    assigned_to_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    assignee = relationship("User", back_populates="assigned_incidents", foreign_keys=[assigned_to_id])
    created_by = Column(String(100))  # 'ai_correlator' or username

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    # ATT&CK context
    mitre_techniques = Column(JSON, default=list)  # ["T1059", "T1021"]
    attack_stage = Column(String(50), nullable=True)  # current stage in kill chain

    # Impact
    affected_assets = Column(JSON, default=list)  # [{"id": 1, "name": "Web Server"}]
    blast_radius = Column(Float, default=0.0)  # estimated impact 0-100
    business_impact = Column(String(20), default="low")  # low, medium, high, critical

    # Timeline
    timeline = Column(JSON, default=list)  # [{timestamp, event, details}]
    is_deleted = Column(Boolean, default=False, index=True)

    # Relationships
    telemetry_events = relationship("SecurityTelemetry", back_populates="incident")
    response_actions = relationship("ResponseAction", back_populates="incident")

    def __repr__(self):
        return f"<Incident #{self.id} [{self.severity}] {self.title[:50]}>"


# ========================
# ASSET
# ========================

class Asset(Base):
    """Infrastructure asset inventory for Digital Twin"""
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    organization = relationship("Organization", back_populates="assets")

    name = Column(String(255), nullable=False)
    asset_type = Column(String(50))  # firewall, web_server, database, endpoint, scada_hmi, plc
    hostname = Column(String(255), nullable=True)
    ip_address = Column(String(45), nullable=True)
    mac_address = Column(String(20), nullable=True)
    os_type = Column(String(100), nullable=True)  # Windows Server 2022, Ubuntu 22.04, Firmware v3.2

    # Classification
    criticality = Column(String(20), default="medium")  # low, medium, high, critical
    business_unit = Column(String(100), nullable=True)
    location = Column(String(200), nullable=True)  # physical location / zone

    # Network topology (for Digital Twin)
    network_segment = Column(String(100))  # DMZ, internal, scada, management
    parent_asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    position_x = Column(Float, nullable=True)  # React Flow canvas position
    position_y = Column(Float, nullable=True)

    # Status
    status = Column(String(20), default="online")  # online, offline, degraded, compromised
    last_seen = Column(DateTime(timezone=True), nullable=True)
    last_scan_at = Column(DateTime(timezone=True), nullable=True)

    # Metadata
    services_running = Column(JSON, default=list)  # ["nginx", "postgresql", "modbus"]
    open_ports = Column(JSON, default=list)  # [80, 443, 502]
    tags = Column(JSON, default=list)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    vulnerabilities = relationship("Vulnerability", back_populates="asset")
    children = relationship("Asset", backref="parent", remote_side="Asset.id", foreign_keys=[parent_asset_id])

    def __repr__(self):
        return f"<Asset {self.name} [{self.asset_type}] {self.ip_address}>"


# ========================
# VULNERABILITY
# ========================

class Vulnerability(Base):
    """CVE-based vulnerability tracking with prioritization"""
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)

    cve_id = Column(String(20), index=True)  # CVE-2024-12345
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)

    # Scoring
    cvss_score = Column(Float, default=0.0)  # 0.0 to 10.0
    severity = Column(String(20))  # LOW, MEDIUM, HIGH, CRITICAL
    epss_score = Column(Float, nullable=True)  # Exploit Prediction Scoring System

    # Exploit intelligence
    exploit_available = Column(Boolean, default=False)
    exploit_maturity = Column(String(50), nullable=True)  # proof_of_concept, functional, weaponized

    # Asset relationship
    affected_asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    asset = relationship("Asset", back_populates="vulnerabilities")

    # Business impact
    business_impact = Column(String(20), default="low")  # low, medium, high, critical

    # Prioritization (computed by AI)
    composite_risk_score = Column(Float, default=0.0)  # Combined risk 0-100
    patch_priority = Column(Integer, nullable=True)  # Rank in patch queue (1 = highest)

    # Status
    status = Column(String(20), default="open")  # open, patched, mitigated, accepted
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())
    patched_at = Column(DateTime(timezone=True), nullable=True)

    # Remediation
    remediation_notes = Column(Text, nullable=True)
    affected_component = Column(String(255), nullable=True)  # e.g., "OpenSSL 1.1.1"

    def __repr__(self):
        return f"<Vulnerability {self.cve_id} [{self.severity}] Priority: {self.patch_priority}>"


# ========================
# RESPONSE ACTION
# ========================

class ResponseAction(Base):
    """Autonomous response actions (SIMULATION ONLY - never executes real actions)"""
    __tablename__ = "response_actions"

    id = Column(Integer, primary_key=True, index=True)

    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    incident = relationship("Incident", back_populates="response_actions")

    action_type = Column(String(50))  # block_ip, disable_user, isolate_host, snapshot_vm, escalate
    target = Column(String(255))  # IP address, username, hostname
    parameters = Column(JSON, default=dict)  # Additional action parameters

    # AI recommendation
    status = Column(String(20), default="proposed")  # proposed, approved, simulated, rejected
    proposed_by = Column(String(100), default="ai")  # 'ai' or username
    approved_by = Column(String(100), nullable=True)
    confidence = Column(Float, default=0.8)
    rationale = Column(Text, nullable=True)  # Why this action is recommended

    # Simulation result
    simulation_result = Column(JSON, nullable=True)  # What would happen if executed
    simulated_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<ResponseAction {self.action_type} → {self.target} [{self.status}]>"


# ========================
# AUDIT LOG
# ========================

class AuditLog(Base):
    """Comprehensive audit trail for all platform actions"""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    # Actor
    actor = Column(String(100))  # username or 'system'
    actor_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    actor_user = relationship("User", back_populates="audit_logs")
    actor_role = Column(String(50), nullable=True)

    # Action
    action = Column(String(50), index=True)  # view, create, update, delete, respond, escalate, login, logout
    resource_type = Column(String(50))  # incident, telemetry, asset, vulnerability, response_action, user
    resource_id = Column(Integer, nullable=True)

    # Details
    details = Column(JSON, nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)

    # Organization scope
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=True)

    def __repr__(self):
        return f"<AuditLog {self.actor}: {self.action} {self.resource_type}>"


# ========================
# NOTIFICATION CONFIG
# ========================

class NotificationConfig(Base):
    """Notification settings per organization"""
    __tablename__ = "notification_configs"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    organization = relationship("Organization", back_populates="notification_configs")

    # Notification channels
    email_enabled = Column(Boolean, default=True)
    email_addresses = Column(JSON, default=list)

    telegram_enabled = Column(Boolean, default=False)
    telegram_bot_token = Column(String(255), nullable=True)
    telegram_chat_id = Column(String(255), nullable=True)

    slack_enabled = Column(Boolean, default=False)
    slack_webhook_url = Column(String(500), nullable=True)

    webhook_enabled = Column(Boolean, default=False)
    webhook_url = Column(String(500), nullable=True)

    # Alert settings
    alert_on_critical = Column(Boolean, default=True)
    alert_on_high = Column(Boolean, default=True)
    alert_on_medium = Column(Boolean, default=False)
    alert_on_low = Column(Boolean, default=False)

    # Rate limiting
    max_alerts_per_hour = Column(Integer, default=20)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    def __repr__(self):
        return f"<NotificationConfig org_id={self.organization_id}>"


# ========================
# UEBA ENGINE MODELS
# ========================

class BehaviorProfile(Base):
    """Stores the baseline behavior for users, networks, and devices"""
    __tablename__ = "behavior_profiles"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    
    entity_type = Column(String(50), index=True)  # user, network, device
    entity_id = Column(String(255), index=True)   # username, ip_address, device_mac
    
    # Baseline Features
    normal_hours = Column(JSON, default=dict)
    typical_locations = Column(JSON, default=list)
    avg_file_access = Column(Float, default=0.0)
    avg_api_calls = Column(Float, default=0.0)
    
    # Device/Network specific
    typical_protocols = Column(JSON, default=list)
    avg_connections_per_hour = Column(Float, default=0.0)
    typical_destinations = Column(JSON, default=list)
    
    # ML features
    feature_vector = Column(JSON, default=dict)
    last_updated = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

class AnomalyEvent(Base):
    """Logs isolated events that deviated from the baseline"""
    __tablename__ = "anomaly_events"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    
    profile_id = Column(Integer, ForeignKey("behavior_profiles.id"), nullable=False)
    profile = relationship("BehaviorProfile", backref="anomaly_events")
    
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    
    event_type = Column(String(50)) # login_anomaly, volume_anomaly, location_anomaly
    details = Column(JSON, default=dict) # The specific features that deviated
    deviation_score = Column(Float, default=0.0)

class RiskAssessment(Base):
    """Stores aggregated risk scores and explanations"""
    __tablename__ = "risk_assessments"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    
    entity_type = Column(String(50), index=True)
    entity_id = Column(String(255), index=True)
    
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    
    risk_score = Column(Float, default=0.0) # 0-100
    explanations = Column(JSON, default=list) # e.g., ["login occurred at 02:14 AM", "12x normal file access volume"]
