"""
server/routes/alerts.py
REST endpoints for querying, triaging, and manually responding to alerts,
plus the aggregate dashboard summary (MITRE matrix, counts) consumed by
the SecOps Web Dashboard on load and periodic refresh.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc
from sqlalchemy.orm import Session

from ..database import AlertRecord, Endpoint, Incident, get_db
from ..models import (
    AlertOut,
    AlertTriageRequest,
    DashboardSummary,
    IncidentOut,
    MitreMatrixEntry,
    QuarantineCommand,
)
from .ws import manager

router = APIRouter(prefix="/api", tags=["alerts"])


@router.get("/alerts", response_model=List[AlertOut])
def list_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    endpoint_id: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    query = db.query(AlertRecord)
    if status:
        query = query.filter(AlertRecord.status == status)
    if severity:
        query = query.filter(AlertRecord.severity == severity)
    if endpoint_id:
        query = query.filter(AlertRecord.endpoint_id == endpoint_id)
    return query.order_by(desc(AlertRecord.timestamp)).limit(limit).all()


@router.get("/alerts/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: str, db: Session = Depends(get_db)):
    alert = db.query(AlertRecord).filter_by(alert_id=alert_id).first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/alerts/{alert_id}/triage", response_model=AlertOut)
def triage_alert(alert_id: str, req: AlertTriageRequest, db: Session = Depends(get_db)):
    alert = db.query(AlertRecord).filter_by(alert_id=alert_id).first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = req.status
    db.commit()
    db.refresh(alert)
    return alert


@router.get("/incidents", response_model=List[IncidentOut])
def list_incidents(
    endpoint_id: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    query = db.query(Incident)
    if endpoint_id:
        query = query.filter(Incident.endpoint_id == endpoint_id)
    return query.order_by(desc(Incident.timestamp)).limit(limit).all()


@router.post("/quarantine")
async def manual_quarantine(cmd: QuarantineCommand):
    """
    One-Click Manual Quarantine: dashboard calls this REST endpoint,
    server dispatches a live command over the agent's WebSocket
    connection (see ws.ConnectionManager.send_command_to_agent).
    """
    sent = await manager.send_command_to_agent(
        cmd.endpoint_id, {"command": "quarantine", "pid": cmd.pid}
    )
    if not sent:
        raise HTTPException(
            status_code=503,
            detail=f"Agent {cmd.endpoint_id} is not currently connected",
        )
    return {"status": "command_dispatched", "endpoint_id": cmd.endpoint_id, "pid": cmd.pid}


@router.get("/dashboard/summary", response_model=DashboardSummary)
def dashboard_summary(db: Session = Depends(get_db)):
    now = time.time()
    day_ago = now - 86400

    total_endpoints = db.query(Endpoint).count()
    online_endpoints = db.query(Endpoint).filter(Endpoint.status == "online").count()
    open_alerts = db.query(AlertRecord).filter(AlertRecord.status == "open").count()
    critical_24h = (
        db.query(AlertRecord)
        .filter(AlertRecord.severity == "CRITICAL", AlertRecord.timestamp >= day_ago)
        .count()
    )
    incidents_24h = db.query(Incident).filter(Incident.timestamp >= day_ago).count()

    # MITRE matrix aggregation: count alerts per technique
    technique_counts: dict[tuple[str, str, str], int] = defaultdict(int)
    rows = (
        db.query(
            AlertRecord.mitre_tactic,
            AlertRecord.mitre_technique_id,
            AlertRecord.mitre_technique_name,
        )
        .filter(AlertRecord.mitre_technique_id.isnot(None))
        .all()
    )
    for tactic, tech_id, tech_name in rows:
        technique_counts[(tactic or "Unknown", tech_id, tech_name or "")] += 1

    mitre_matrix = [
        MitreMatrixEntry(
            tactic=tactic, technique_id=tech_id, technique_name=tech_name, alert_count=count
        )
        for (tactic, tech_id, tech_name), count in sorted(
            technique_counts.items(), key=lambda kv: -kv[1]
        )
    ]

    return DashboardSummary(
        total_endpoints=total_endpoints,
        online_endpoints=online_endpoints,
        open_alerts=open_alerts,
        critical_alerts_24h=critical_24h,
        incidents_24h=incidents_24h,
        mitre_matrix=mitre_matrix,
    )
