"""
server/routes/endpoints.py
REST endpoints for agent enrollment, listing, and status queries.
Real-time enrollment/heartbeats happen over /ws/agent (see ws.py);
these REST routes back the dashboard's endpoint inventory view.
"""

from __future__ import annotations

import time
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import Endpoint, get_db
from ..models import EndpointEnrollRequest, EndpointOut

router = APIRouter(prefix="/api/endpoints", tags=["endpoints"])

OFFLINE_THRESHOLD_SECS = 45  # no heartbeat in this window -> considered offline


@router.post("/enroll", response_model=EndpointOut)
def enroll_endpoint(req: EndpointEnrollRequest, db: Session = Depends(get_db)):
    """
    Fallback REST enrollment (in addition to the WebSocket enrollment
    event) so agents can register before their WS connection is fully
    established, and so the dashboard has an immediate record.
    """
    ep = db.get(Endpoint, req.endpoint_id)
    if ep is None:
        ep = Endpoint(
            endpoint_id=req.endpoint_id,
            hostname=req.hostname,
            agent_version=req.agent_version,
            enrolled_at=time.time(),
            last_heartbeat_at=time.time(),
            status="online",
        )
        db.add(ep)
    else:
        ep.hostname = req.hostname
        ep.agent_version = req.agent_version
        ep.last_heartbeat_at = time.time()
        ep.status = "online"
    db.commit()
    db.refresh(ep)
    return ep


@router.get("", response_model=List[EndpointOut])
def list_endpoints(db: Session = Depends(get_db)):
    endpoints = db.query(Endpoint).order_by(Endpoint.enrolled_at.desc()).all()
    now = time.time()
    for ep in endpoints:
        if ep.last_heartbeat_at and (now - ep.last_heartbeat_at) > OFFLINE_THRESHOLD_SECS:
            ep.status = "offline"
    db.commit()
    return endpoints


@router.get("/{endpoint_id}", response_model=EndpointOut)
def get_endpoint(endpoint_id: str, db: Session = Depends(get_db)):
    ep = db.get(Endpoint, endpoint_id)
    if ep is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return ep
