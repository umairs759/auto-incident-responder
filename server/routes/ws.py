"""
server/routes/ws.py
WebSocket gateway for bidirectional agent<->server telemetry and
server->agent command dispatch (e.g. manual quarantine from dashboard).

Two distinct WebSocket endpoints:
  /ws/agent      - Endpoint agents connect here to stream telemetry and
                    receive commands.
  /ws/dashboard  - SecOps dashboard clients connect here to receive
                    real-time alert/incident pushes.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Dict, List

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from ..database import AlertRecord, Endpoint, Incident, SessionLocal
from ..models import AlertIn, ContainmentResultIn

logger = logging.getLogger("edr.server.ws")

router = APIRouter()

VALID_ENROLLMENT_TOKEN = "change-me-in-production"  # overridden via env in app.py


class ConnectionManager:
    """Tracks live WebSocket connections for agents and dashboards."""

    def __init__(self) -> None:
        self.agent_connections: Dict[str, WebSocket] = {}
        self.dashboard_connections: List[WebSocket] = []

    async def connect_agent(self, endpoint_id: str, ws: WebSocket) -> None:
        await ws.accept()
        self.agent_connections[endpoint_id] = ws
        logger.info("Agent connected: %s", endpoint_id)

    def disconnect_agent(self, endpoint_id: str) -> None:
        self.agent_connections.pop(endpoint_id, None)
        logger.info("Agent disconnected: %s", endpoint_id)

    async def connect_dashboard(self, ws: WebSocket) -> None:
        await ws.accept()
        self.dashboard_connections.append(ws)

    def disconnect_dashboard(self, ws: WebSocket) -> None:
        if ws in self.dashboard_connections:
            self.dashboard_connections.remove(ws)

    async def broadcast_to_dashboards(self, message: dict) -> None:
        stale: List[WebSocket] = []
        for ws in self.dashboard_connections:
            try:
                await ws.send_json(message)
            except Exception:  # noqa: BLE001
                stale.append(ws)
        for ws in stale:
            self.disconnect_dashboard(ws)

    async def send_command_to_agent(self, endpoint_id: str, command: dict) -> bool:
        ws = self.agent_connections.get(endpoint_id)
        if ws is None:
            logger.warning("Cannot send command; agent %s not connected", endpoint_id)
            return False
        try:
            await ws.send_json(command)
            return True
        except Exception:  # noqa: BLE001
            logger.exception("Failed to send command to agent %s", endpoint_id)
            return False


manager = ConnectionManager()


def _upsert_endpoint(db: Session, endpoint_id: str, hostname: str, agent_version: str | None) -> None:
    ep = db.get(Endpoint, endpoint_id)
    if ep is None:
        ep = Endpoint(
            endpoint_id=endpoint_id,
            hostname=hostname,
            agent_version=agent_version,
            enrolled_at=time.time(),
            last_heartbeat_at=time.time(),
            status="online",
        )
        db.add(ep)
    else:
        ep.hostname = hostname
        ep.last_heartbeat_at = time.time()
        ep.status = "online"
    db.commit()


def _store_alert(db: Session, endpoint_id: str, alert: AlertIn) -> None:
    existing = db.query(AlertRecord).filter_by(alert_id=alert.alert_id).first()
    if existing:
        return
    raddr_ip, raddr_port = (None, None)
    if alert.raddr and len(alert.raddr) == 2:
        raddr_ip, raddr_port = alert.raddr[0], alert.raddr[1]

    record = AlertRecord(
        alert_id=alert.alert_id,
        endpoint_id=endpoint_id,
        rule_id=alert.rule_id,
        severity=alert.severity,
        title=alert.title,
        description=alert.description,
        mitre_tactic=alert.mitre_tactic,
        mitre_technique_id=alert.mitre_technique_id,
        mitre_technique_name=alert.mitre_technique_name,
        pid=alert.pid,
        ppid=alert.ppid,
        process_name=alert.process_name,
        cmdline=json.dumps(alert.cmdline) if alert.cmdline else None,
        raddr_ip=raddr_ip,
        raddr_port=raddr_port,
        timestamp=alert.timestamp,
        requires_containment=alert.requires_containment,
    )
    db.add(record)
    db.commit()


def _store_incident(db: Session, endpoint_id: str, result: ContainmentResultIn) -> None:
    existing = db.query(Incident).filter_by(alert_id=result.alert_id).first()
    if existing:
        return
    incident = Incident(
        alert_id=result.alert_id,
        endpoint_id=endpoint_id,
        pid=result.pid,
        actions_taken=json.dumps(result.actions_taken),
        forensic_artifact_path=result.forensic_artifact_path,
        blocked_ip=result.blocked_ip,
        success=result.success,
        error=result.error,
        timestamp=result.timestamp,
    )
    db.add(incident)
    db.commit()


@router.websocket("/ws/agent")
async def agent_ws(
    ws: WebSocket,
    token: str = Query(default=""),
    endpoint_id: str = Query(default=""),
):
    if not endpoint_id:
        await ws.close(code=4001)
        return

    await manager.connect_agent(endpoint_id, ws)
    db = SessionLocal()
    try:
        while True:
            raw = await ws.receive_text()
            message = json.loads(raw)
            event_type = message.get("event_type")
            payload = message.get("payload", {})
            hostname = message.get("hostname", "unknown")

            if event_type == "enrollment":
                _upsert_endpoint(db, endpoint_id, hostname, payload.get("agent_version"))
                await manager.broadcast_to_dashboards(
                    {"type": "endpoint_online", "endpoint_id": endpoint_id, "hostname": hostname}
                )

            elif event_type == "heartbeat":
                ep = db.get(Endpoint, endpoint_id)
                if ep:
                    ep.last_heartbeat_at = time.time()
                    ep.status = "online"
                    db.commit()

            elif event_type == "alert":
                alert = AlertIn(**payload)
                _store_alert(db, endpoint_id, alert)
                await manager.broadcast_to_dashboards(
                    {"type": "new_alert", "endpoint_id": endpoint_id, "alert": payload}
                )

            elif event_type == "containment_result":
                result = ContainmentResultIn(**payload)
                _store_incident(db, endpoint_id, result)
                await manager.broadcast_to_dashboards(
                    {"type": "new_incident", "endpoint_id": endpoint_id, "incident": payload}
                )

            elif event_type == "pong":
                pass  # liveness ack from a server-initiated ping command

            else:
                logger.debug("Unhandled event_type from %s: %s", endpoint_id, event_type)

    except WebSocketDisconnect:
        manager.disconnect_agent(endpoint_id)
        ep = db.get(Endpoint, endpoint_id)
        if ep:
            ep.status = "offline"
            db.commit()
        await manager.broadcast_to_dashboards(
            {"type": "endpoint_offline", "endpoint_id": endpoint_id}
        )
    finally:
        db.close()


@router.websocket("/ws/dashboard")
async def dashboard_ws(ws: WebSocket):
    await manager.connect_dashboard(ws)
    try:
        while True:
            # Dashboard -> server commands, e.g. manual quarantine
            raw = await ws.receive_text()
            message = json.loads(raw)
            if message.get("command") == "quarantine":
                target_endpoint = message.get("endpoint_id")
                pid = message.get("pid")
                sent = await manager.send_command_to_agent(
                    target_endpoint, {"command": "quarantine", "pid": pid}
                )
                await ws.send_json({"type": "command_ack", "sent": sent})
    except WebSocketDisconnect:
        manager.disconnect_dashboard(ws)
