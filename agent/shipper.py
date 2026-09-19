"""
agent/shipper.py
Resilient async WebSocket client that ships telemetry/alerts/containment
results to the Central Telemetry Server. Buffers events in a bounded ring
buffer during disconnects and replays them on reconnect (oldest dropped
first once full, so the agent never blocks or grows unbounded memory).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import deque
from dataclasses import asdict, is_dataclass
from typing import Any, Deque, Dict, Optional

import websockets
from websockets.exceptions import ConnectionClosed

from .config import ShipperPolicy

logger = logging.getLogger("edr.shipper")


def _serialize(obj: Any) -> Any:
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: _serialize(v) for k, v in asdict(obj).items()}
    if isinstance(obj, (list, tuple)):
        return [_serialize(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    return obj


class TelemetryShipper:
    def __init__(self, policy: ShipperPolicy, endpoint_id: str, hostname: str) -> None:
        self.policy = policy
        self.endpoint_id = endpoint_id
        self.hostname = hostname
        self._queue: Deque[Dict[str, Any]] = deque(maxlen=policy.ring_buffer_max_events)
        self._ws: Optional[websockets.WebSocketClientProtocol] = None
        self._connected = asyncio.Event()
        self._stop = asyncio.Event()

    def enqueue(self, event_type: str, payload: Any) -> None:
        event = {
            "event_type": event_type,
            "endpoint_id": self.endpoint_id,
            "hostname": self.hostname,
            "ts": time.time(),
            "payload": _serialize(payload),
        }
        if len(self._queue) == self._queue.maxlen:
            logger.warning("Ring buffer full; dropping oldest queued event")
        self._queue.append(event)

    async def _drain_queue(self) -> None:
        while self._queue and self._ws is not None:
            event = self._queue[0]
            try:
                await self._ws.send(json.dumps(event))
                self._queue.popleft()
            except ConnectionClosed:
                logger.warning("Connection closed while draining queue")
                return

    async def _connect_and_enroll(self) -> bool:
        url = f"{self.policy.server_ws_url}?token={self.policy.enrollment_token}&endpoint_id={self.endpoint_id}"
        try:
            self._ws = await websockets.connect(url, ping_interval=20, ping_timeout=20)
            enrollment = {
                "event_type": "enrollment",
                "endpoint_id": self.endpoint_id,
                "hostname": self.hostname,
                "ts": time.time(),
                "payload": {"agent_version": "1.0.0"},
            }
            await self._ws.send(json.dumps(enrollment))
            self._connected.set()
            logger.info("Connected and enrolled with telemetry server at %s", self.policy.server_ws_url)
            return True
        except (OSError, websockets.InvalidURI, websockets.InvalidHandshake) as exc:
            logger.error("Failed to connect to telemetry server: %s", exc)
            self._ws = None
            self._connected.clear()
            return False

    async def _heartbeat_loop(self) -> None:
        while not self._stop.is_set():
            await asyncio.sleep(self.policy.heartbeat_interval_secs)
            self.enqueue("heartbeat", {"status": "alive"})

    async def _receive_loop(self) -> None:
        """Listens for inbound commands from the dashboard (e.g. manual quarantine)."""
        while not self._stop.is_set():
            if self._ws is None:
                await asyncio.sleep(1)
                continue
            try:
                raw = await self._ws.recv()
                yield json.loads(raw)
            except ConnectionClosed:
                self._connected.clear()
                self._ws = None
                await asyncio.sleep(1)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                logger.exception("Error receiving message from server")
                await asyncio.sleep(1)

    async def run(self, on_command=None) -> None:
        """
        Main shipper loop: maintains connection with exponential backoff,
        drains the ring buffer, and optionally dispatches inbound commands
        (e.g. {"command": "quarantine", "pid": 1234}) to on_command callback.
        """
        backoff = self.policy.reconnect_backoff_min_secs
        while not self._stop.is_set():
            if self._ws is None:
                connected = await self._connect_and_enroll()
                if not connected:
                    logger.info("Reconnecting in %.1fs", backoff)
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, self.policy.reconnect_backoff_max_secs)
                    continue
                backoff = self.policy.reconnect_backoff_min_secs

            try:
                await self._drain_queue()
                if self._ws is not None:
                    try:
                        raw = await asyncio.wait_for(self._ws.recv(), timeout=1.0)
                        message = json.loads(raw)
                        if on_command is not None:
                            await on_command(message)
                    except asyncio.TimeoutError:
                        pass
            except ConnectionClosed:
                logger.warning("Telemetry connection lost; will reconnect")
                self._ws = None
                self._connected.clear()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                logger.exception("Unexpected shipper error")
                self._ws = None
                await asyncio.sleep(1)

    async def stop(self) -> None:
        self._stop.set()
        if self._ws is not None:
            await self._ws.close()
