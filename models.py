"""
SecureView - Pydantic Data Models
All request/response schemas for the REST API
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum


# ─── Enums ────────────────────────────────────────────────────────────────────
class SeverityLevel(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class EndpointStatus(str, Enum):
    ok = "ok"
    warn = "warn"
    critical = "critical"
    offline = "offline"


class VulnStatus(str, Enum):
    open = "open"
    patching = "patching"
    patched = "patched"
    accepted = "accepted"


class AlertStatus(str, Enum):
    active = "active"
    blocked = "blocked"
    quarantined = "quarantined"
    investigating = "investigating"
    resolved = "resolved"
    escalated = "escalated"


# ─── Alert ────────────────────────────────────────────────────────────────────
class Alert(BaseModel):
    id: str
    title: str
    source_ip: str
    destination: str
    severity: SeverityLevel
    threat_type: str
    protocol: str
    country: str
    attempts: int
    status: AlertStatus
    timestamp: datetime
    description: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)

    class Config:
        use_enum_values = True


# ─── Endpoint ─────────────────────────────────────────────────────────────────
class Endpoint(BaseModel):
    id: str
    name: str
    status: EndpointStatus
    os: str
    ip: str
    last_seen: datetime
    agent_version: str
    threats_blocked: int
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None

    class Config:
        use_enum_values = True


# ─── Vulnerability ────────────────────────────────────────────────────────────
class Vulnerability(BaseModel):
    cve_id: str
    description: str
    cvss_score: float = Field(..., ge=0.0, le=10.0)
    severity: SeverityLevel
    affected_assets: int
    status: VulnStatus
    published_date: datetime
    patch_available: bool
    exploit_available: bool

    class Config:
        use_enum_values = True


# ─── Network Traffic ──────────────────────────────────────────────────────────
class NetworkTraffic(BaseModel):
    hour: int = Field(..., ge=0, le=23)
    label: str
    bytes_in: int
    bytes_out: int
    packets: int
    blocked_packets: int
    threat_score: float = Field(..., ge=0.0, le=1.0)


# ─── Protocol Data ────────────────────────────────────────────────────────────
class ProtocolData(BaseModel):
    protocol: str
    percentage: float
    threat_percentage: float
    bytes_total: int
    color: str


# ─── Log Entry ────────────────────────────────────────────────────────────────
class LogEntry(BaseModel):
    id: str
    timestamp: datetime
    source_ip: str
    destination: str
    action: str        # BLOCKED / ALLOWED / ALERT
    message: str
    protocol: str
    severity: SeverityLevel
    rule_id: Optional[str] = None

    class Config:
        use_enum_values = True


# ─── Stats ────────────────────────────────────────────────────────────────────
class ThreatStats(BaseModel):
    active_threats: int
    blocked_attacks: int
    endpoints_monitored: int
    open_vulnerabilities: int
    cloud_assets: int
    attacks_per_minute: int
    threat_level: str    # LOW / MEDIUM / HIGH / CRITICAL
    firewall_status: str
    ids_status: str
    siem_status: str
    cloud_waf_status: str
    last_updated: datetime


# ─── Geo Threat ───────────────────────────────────────────────────────────────
class GeoThreat(BaseModel):
    country: str
    country_code: str
    latitude: float
    longitude: float
    attack_count: int
    threat_type: str
    is_active: bool


# ─── Request Bodies ───────────────────────────────────────────────────────────
class AlertAction(BaseModel):
    action: str   # resolve / block / escalate / quarantine
    notes: Optional[str] = None
    analyst: Optional[str] = "auto"


class PatchRequest(BaseModel):
    target_assets: Optional[List[str]] = None
    priority: Optional[str] = "high"
    schedule: Optional[str] = "immediate"
