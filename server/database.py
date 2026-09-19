"""
server/database.py
SQLAlchemy engine/session management and ORM models for the Central
Telemetry Server. Defaults to SQLite (zero-config demo/dev); set
DATABASE_URL env var to point at PostgreSQL in production
(e.g. postgresql+psycopg2://user:pass@host/dbname).
"""

from __future__ import annotations

import os
import time
from typing import Generator, Optional

from sqlalchemy import (
    Boolean,
    Column,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, relationship, sessionmaker

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "sqlite:////var/lib/micro-edr/edr.db"
)

# SQLite needs this connect_arg for use across asyncio/threaded FastAPI workers
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args, echo=False)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


class Endpoint(Base):
    __tablename__ = "endpoints"

    endpoint_id = Column(String(64), primary_key=True)
    hostname = Column(String(255), nullable=False)
    agent_version = Column(String(32), nullable=True)
    enrolled_at = Column(Float, default=time.time)
    last_heartbeat_at = Column(Float, nullable=True)
    status = Column(String(16), default="online")  # online | offline | quarantined

    alerts = relationship("AlertRecord", back_populates="endpoint")
    incidents = relationship("Incident", back_populates="endpoint")


class AlertRecord(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(64), unique=True, nullable=False, index=True)
    endpoint_id = Column(String(64), ForeignKey("endpoints.endpoint_id"), index=True)
    rule_id = Column(String(64), nullable=False)
    severity = Column(String(16), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    mitre_tactic = Column(String(64), nullable=True)
    mitre_technique_id = Column(String(32), nullable=True, index=True)
    mitre_technique_name = Column(String(128), nullable=True)
    pid = Column(Integer, nullable=True)
    ppid = Column(Integer, nullable=True)
    process_name = Column(String(255), nullable=True)
    cmdline = Column(Text, nullable=True)
    raddr_ip = Column(String(64), nullable=True)
    raddr_port = Column(Integer, nullable=True)
    timestamp = Column(Float, default=time.time)
    status = Column(String(16), default="open")  # open | triaged | resolved | false_positive
    requires_containment = Column(Boolean, default=True)

    endpoint = relationship("Endpoint", back_populates="alerts")
    incident = relationship("Incident", back_populates="alert", uselist=False)


class Incident(Base):
    """A containment action taken in response to an Alert."""

    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(64), ForeignKey("alerts.alert_id"), unique=True)
    endpoint_id = Column(String(64), ForeignKey("endpoints.endpoint_id"), index=True)
    pid = Column(Integer, nullable=True)
    actions_taken = Column(Text, nullable=True)  # JSON-encoded list
    forensic_artifact_path = Column(String(512), nullable=True)
    blocked_ip = Column(String(64), nullable=True)
    success = Column(Boolean, default=True)
    error = Column(Text, nullable=True)
    timestamp = Column(Float, default=time.time)

    endpoint = relationship("Endpoint", back_populates="incidents")
    alert = relationship("AlertRecord", back_populates="incident")


def init_db() -> None:
    if DATABASE_URL.startswith("sqlite"):
        db_path = DATABASE_URL.replace("sqlite:///", "")
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
