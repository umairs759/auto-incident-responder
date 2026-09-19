"""
agent/agent.py
Endpoint Daemon entrypoint. Wires Collector -> Detector -> ContainmentEngine
-> TelemetryShipper into a single asyncio event loop.

Run directly:
    sudo python3 -m agent.agent

Or via the systemd unit in deploy/micro-edr-agent.service
"""

from __future__ import annotations

import asyncio
import logging
import signal as sig
import sys
from typing import Any, Dict

from .collector import Collector
from .config import AgentPolicy, configure_logging
from .containment import ContainmentEngine
from .detector import Detector
from .shipper import TelemetryShipper

logger = logging.getLogger("edr.agent")


class EDRAgent:
    def __init__(self, policy: AgentPolicy) -> None:
        self.policy = policy
        self.collector = Collector()
        self.detector = Detector(policy.detection)
        self.containment = ContainmentEngine(policy.containment)
        self.shipper = TelemetryShipper(
            policy.shipper, policy.endpoint_id, policy.hostname
        )
        self._running = asyncio.Event()

    async def _process_network_loop(self) -> None:
        """Core detection loop: snapshot -> evaluate -> contain -> ship."""
        interval = self.policy.detection.process_poll_interval_secs
        while self._running.is_set():
            try:
                snapshot = self.collector.snapshot()
                alerts = self.detector.evaluate(snapshot)
                for alert in alerts:
                    logger.warning(
                        "ALERT [%s] %s (pid=%s) -> %s / %s",
                        alert.severity, alert.title, alert.pid,
                        alert.mitre_tactic, alert.mitre_technique_id,
                    )
                    self.shipper.enqueue("alert", alert)

                    if alert.requires_containment:
                        result = self.containment.respond(alert)
                        self.shipper.enqueue("containment_result", result)
            except Exception:  # noqa: BLE001
                logger.exception("Error in process/network detection loop")

            await asyncio.sleep(interval)

    async def _canary_loop(self) -> None:
        interval = self.policy.detection.canary_hash_interval_secs
        while self._running.is_set():
            try:
                alerts = self.detector.check_canary_integrity()
                for alert in alerts:
                    logger.warning(
                        "ALERT [%s] %s -> %s / %s",
                        alert.severity, alert.title,
                        alert.mitre_tactic, alert.mitre_technique_id,
                    )
                    self.shipper.enqueue("alert", alert)
            except Exception:  # noqa: BLE001
                logger.exception("Error in canary integrity loop")

            await asyncio.sleep(interval)

    async def _handle_server_command(self, message: Dict[str, Any]) -> None:
        command = message.get("command")
        if command == "quarantine":
            pid = message.get("pid")
            if isinstance(pid, int):
                logger.warning("Manual quarantine command received for pid=%s", pid)
                result = self.containment.manual_quarantine(pid)
                self.shipper.enqueue("containment_result", result)
        elif command == "ping":
            self.shipper.enqueue("pong", {"received_at": message.get("ts")})
        else:
            logger.info("Unknown command from server: %s", message)

    async def start(self) -> None:
        configure_logging(self.policy.log_level)
        logger.info(
            "Starting Micro-EDR Agent | endpoint_id=%s host=%s",
            self.policy.endpoint_id, self.policy.hostname,
        )
        self._running.set()

        tasks = [
            asyncio.create_task(self._process_network_loop(), name="detection_loop"),
            asyncio.create_task(self._canary_loop(), name="canary_loop"),
            asyncio.create_task(
                self.shipper.run(on_command=self._handle_server_command),
                name="shipper_loop",
            ),
        ]

        loop = asyncio.get_running_loop()
        for s in (sig.SIGINT, sig.SIGTERM):
            loop.add_signal_handler(s, lambda: asyncio.create_task(self.stop()))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def stop(self) -> None:
        logger.info("Shutting down Micro-EDR Agent...")
        self._running.clear()
        await self.shipper.stop()


def main() -> None:
    policy = AgentPolicy.load()
    agent = EDRAgent(policy)
    try:
        asyncio.run(agent.start())
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
