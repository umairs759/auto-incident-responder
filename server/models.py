"""
server/models.py
Pydantic schemas for API request/response validation. Kept separate from
the SQLAlchemy ORM models in database.py (server/database.py) so the wire
format can evolve independently of storage.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class EndpointEnrollRequest(BaseModel):
    endpoint_id: str
    hostname: str
    agent_version: Optional[str] = "1.0.0"


class EndpointOut(BaseModel):
    endpoint_id: str
    hostname: str
    agent_version: Optional[str]
    enrolled_at: float
    last_heartbeat_at: Optional[float]
    status: str

    class Config:
        from_attributes = True


class AlertIn(BaseModel):
    """Shape of an alert as shipped by the agent (agent/detector.py Alert)."""

    alert_id: str
    rule_id: str
    severity: str
    title: str
    description: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    pid: Optional[int] = None
    ppid: Optional[int] = None
    process_name: Optional[str] = None
    cmdline: Optional[List[str]] = None
    raddr: Optional[List[Any]] = None  # [ip, port] tuple serialized as list
    timestamp: float
    requires_containment: bool = True


class AlertOut(BaseModel):
    alert_id: str
    endpoint_id: str
    rule_id: str
    severity: str
    title: str
    description: Optional[str]
    mitre_tactic: Optional[str]
    mitre_technique_id: Optional[str]
    mitre_technique_name: Optional[str]
    pid: Optional[int]
    process_name: Optional[str]
    raddr_ip: Optional[str]
    raddr_port: Optional[int]
    timestamp: float
    status: str

    class Config:
        from_attributes = True


class AlertTriageRequest(BaseModel):
    status: str = Field(..., pattern="^(open|triaged|resolved|false_positive)$")


class ContainmentResultIn(BaseModel):
    alert_id: str
    pid: Optional[int] = None
    actions_taken: List[str] = Field(default_factory=list)
    forensic_artifact_path: Optional[str] = None
    blocked_ip: Optional[str] = None
    success: bool = True
    error: Optional[str] = None
    timestamp: float


class IncidentOut(BaseModel):
    alert_id: str
    endpoint_id: str
    pid: Optional[int]
    actions_taken: Optional[str]
    forensic_artifact_path: Optional[str]
    blocked_ip: Optional[str]
    success: bool
    timestamp: float

    class Config:
        from_attributes = True


class QuarantineCommand(BaseModel):
    endpoint_id: str
    pid: int


class MitreMatrixEntry(BaseModel):
    tactic: str
    technique_id: str
    technique_name: str
    alert_count: int


class DashboardSummary(BaseModel):
    total_endpoints: int
    online_endpoints: int
    open_alerts: int
    critical_alerts_24h: int
    incidents_24h: int
    mitre_matrix: List[MitreMatrixEntry]
