"""
SentinelGrid AI — Pydantic Schemas
Request/response validation for all API endpoints.
"""

from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


# ========================
# ORGANIZATION SCHEMAS
# ========================

class OrganizationCreate(BaseModel):
    name: str
    email: EmailStr
    industry: str = "critical_infrastructure"


class OrganizationResponse(BaseModel):
    id: int
    name: str
    slug: str
    email: str
    industry: str
    is_active: bool
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ========================
# USER SCHEMAS
# ========================

class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str
    full_name: Optional[str] = None
    role: str = "soc_analyst"


class UserResponse(BaseModel):
    id: int
    email: str
    username: str
    full_name: Optional[str]
    role: str
    is_active: bool
    organization_id: int

    class Config:
        from_attributes = True


class UserLogin(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str
    is_first_login: bool = False


# ========================
# SECURITY TELEMETRY SCHEMAS
# ========================

class TelemetryIngest(BaseModel):
    """Schema for ingesting security telemetry events"""
    event_type: str = "network_flow"  # network_flow, auth_event, system_log, scada_reading
    source: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    user_identity: Optional[str] = None
    action: Optional[str] = None
    resource: Optional[str] = None
    method: Optional[str] = None
    payload: Optional[str] = None
    raw_log: Optional[str] = None
    command: Optional[str] = None
    severity: str = "INFO"
    metadata: Optional[Dict[str, Any]] = None


class TelemetryResponse(BaseModel):
    id: int
    timestamp: datetime
    event_type: str
    source: Optional[str]
    source_ip: Optional[str]
    dest_ip: Optional[str]
    source_port: Optional[int]
    dest_port: Optional[int]
    protocol: Optional[str]
    user_identity: Optional[str]
    action: Optional[str]
    resource: Optional[str]
    severity: str
    anomaly_score: float
    risk_score: float
    confidence: float
    is_anomaly: bool
    ai_explanation: Optional[str]
    mitre_technique_id: Optional[str]
    mitre_tactic: Optional[str]
    incident_id: Optional[int]
    location: Optional[dict]
    event_metadata: Optional[dict]

    class Config:
        from_attributes = True


class TelemetryListResponse(BaseModel):
    items: List[TelemetryResponse]
    total: int
    page: int
    page_size: int


# ========================
# INCIDENT SCHEMAS
# ========================

class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "MEDIUM"
    affected_assets: Optional[List[Dict]] = []
    mitre_techniques: Optional[List[str]] = []


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    assigned_to_id: Optional[int] = None
    business_impact: Optional[str] = None


class IncidentResponse(BaseModel):
    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    assigned_to_id: Optional[int]
    created_by: Optional[str]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    resolved_at: Optional[datetime]
    mitre_techniques: Optional[List[str]]
    attack_stage: Optional[str]
    affected_assets: Optional[List[Dict]]
    blast_radius: float
    business_impact: str
    timeline: Optional[List[Dict]]
    organization_id: int

    class Config:
        from_attributes = True


class IncidentListResponse(BaseModel):
    items: List[IncidentResponse]
    total: int
    active_count: int
    critical_count: int


# ========================
# ASSET SCHEMAS
# ========================

class AssetCreate(BaseModel):
    name: str
    asset_type: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    os_type: Optional[str] = None
    criticality: str = "medium"
    business_unit: Optional[str] = None
    location: Optional[str] = None
    network_segment: str = "internal"
    parent_asset_id: Optional[int] = None
    position_x: Optional[float] = None
    position_y: Optional[float] = None
    services_running: Optional[List[str]] = []
    open_ports: Optional[List[int]] = []


class AssetUpdate(BaseModel):
    name: Optional[str] = None
    status: Optional[str] = None
    criticality: Optional[str] = None
    position_x: Optional[float] = None
    position_y: Optional[float] = None


class AssetResponse(BaseModel):
    id: int
    name: str
    asset_type: str
    hostname: Optional[str]
    ip_address: Optional[str]
    os_type: Optional[str]
    criticality: str
    business_unit: Optional[str]
    location: Optional[str]
    network_segment: str
    parent_asset_id: Optional[int]
    position_x: Optional[float]
    position_y: Optional[float]
    status: str
    last_seen: Optional[datetime]
    services_running: Optional[List[str]]
    open_ports: Optional[List[int]]
    tags: Optional[List[str]]

    class Config:
        from_attributes = True


class TopologyResponse(BaseModel):
    """Network topology for Digital Twin view"""
    nodes: List[AssetResponse]
    edges: List[Dict[str, Any]]  # {source_id, target_id, edge_type, is_attack_path}


# ========================
# VULNERABILITY SCHEMAS
# ========================

class VulnerabilityCreate(BaseModel):
    cve_id: str
    title: str
    description: Optional[str] = None
    cvss_score: float = 0.0
    severity: str = "MEDIUM"
    exploit_available: bool = False
    affected_asset_id: Optional[int] = None
    business_impact: str = "low"
    affected_component: Optional[str] = None


class VulnerabilityUpdate(BaseModel):
    status: Optional[str] = None
    patch_priority: Optional[int] = None
    remediation_notes: Optional[str] = None


class VulnerabilityResponse(BaseModel):
    id: int
    cve_id: str
    title: str
    description: Optional[str]
    cvss_score: float
    severity: str
    exploit_available: bool
    exploit_maturity: Optional[str]
    affected_asset_id: Optional[int]
    business_impact: str
    composite_risk_score: float
    patch_priority: Optional[int]
    status: str
    discovered_at: Optional[datetime]
    patched_at: Optional[datetime]
    affected_component: Optional[str]

    class Config:
        from_attributes = True


class PatchQueueResponse(BaseModel):
    items: List[VulnerabilityResponse]
    total: int
    critical_count: int
    exploitable_count: int


# ========================
# MITRE ATT&CK SCHEMAS
# ========================

class MitreTechniqueResponse(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    description: Optional[str] = None
    detection_count: int = 0
    severity: str = "MEDIUM"
    confidence: float = 0.8
    threat_actors: Optional[List[Dict]] = []


class MitreMatrixResponse(BaseModel):
    tactics: List[Dict[str, Any]]
    techniques_by_tactic: Dict[str, List[MitreTechniqueResponse]]
    total_detections: int


class AttackTimelineEntry(BaseModel):
    timestamp: datetime
    technique_id: str
    technique_name: str
    tactic: str
    severity: str
    source_ip: Optional[str]
    description: str


class AttackTimelineResponse(BaseModel):
    entries: List[AttackTimelineEntry]
    attack_stages: List[str]
    campaign_duration_minutes: Optional[float]


# ========================
# PREDICTION SCHEMAS
# ========================

class PredictedAction(BaseModel):
    action: str  # e.g., "Credential Dumping"
    technique_id: str  # e.g., "T1003"
    probability: float  # 0.0 to 1.0
    severity: str
    description: str
    recommended_defense: str


class AttackPredictionResponse(BaseModel):
    current_stage: str  # e.g., "Initial Access"
    next_likely_actions: List[PredictedAction]
    risk_level: str
    confidence: float
    analysis_timestamp: datetime


class RiskForecastPoint(BaseModel):
    date: str
    predicted_risk: float
    confidence_lower: float
    confidence_upper: float


class RiskForecastResponse(BaseModel):
    forecast: List[RiskForecastPoint]
    trend: str  # increasing, decreasing, stable
    current_risk: float


# ========================
# RESPONSE ACTION SCHEMAS
# ========================

class ResponseActionResponse(BaseModel):
    id: int
    incident_id: int
    action_type: str
    target: str
    parameters: Optional[Dict]
    status: str
    proposed_by: str
    approved_by: Optional[str]
    confidence: float
    rationale: Optional[str]
    simulation_result: Optional[Dict]
    simulated_at: Optional[datetime]
    created_at: Optional[datetime]

    class Config:
        from_attributes = True


class ResponseActionApproval(BaseModel):
    approved_by: str


# ========================
# AUDIT LOG SCHEMAS
# ========================

class AuditLogResponse(BaseModel):
    id: int
    timestamp: datetime
    actor: str
    action: str
    resource_type: str
    resource_id: Optional[int]
    details: Optional[Dict]
    ip_address: Optional[str]

    class Config:
        from_attributes = True


class AuditLogListResponse(BaseModel):
    items: List[AuditLogResponse]
    total: int
    page: int
    page_size: int


# ========================
# DASHBOARD STATS
# ========================

class DashboardStats(BaseModel):
    total_events: int
    active_incidents: int
    critical_incidents: int
    mean_time_to_detect_minutes: Optional[float]
    coverage_score: float  # 0-100, how well MITRE tactics are covered
    global_risk_score: float  # 0-100
    anomaly_rate: float  # percentage of events flagged as anomalous
    events_by_severity: Dict[str, int]
    events_by_type: Dict[str, int]
    top_mitre_techniques: List[Dict[str, Any]]
    hourly_trend: Dict[str, Any]
    recent_incidents: List[IncidentResponse]
    ai_model_status: Dict[str, Any]
    last_updated: str


# ========================
# NOTIFICATION SCHEMAS
# ========================

class NotificationConfigUpdate(BaseModel):
    email_enabled: Optional[bool] = None
    email_addresses: Optional[List[str]] = None
    telegram_enabled: Optional[bool] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    slack_enabled: Optional[bool] = None
    slack_webhook_url: Optional[str] = None
    alert_on_critical: Optional[bool] = None
    alert_on_high: Optional[bool] = None
    alert_on_medium: Optional[bool] = None
    alert_on_low: Optional[bool] = None


class NotificationConfigResponse(BaseModel):
    id: int
    email_enabled: bool
    email_addresses: List[str]
    telegram_enabled: bool
    slack_enabled: bool
    alert_on_critical: bool
    alert_on_high: bool
    alert_on_medium: bool
    alert_on_low: bool

    class Config:
        from_attributes = True


# ========================
# HEALTH CHECK
# ========================

class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    database: str
    redis: str
    ai_models: Dict[str, Any]
    chromadb: str
    uptime_seconds: float
