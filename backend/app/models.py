from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from .db import Base


class TimestampMixin:
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class Organization(Base, TimestampMixin):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True, nullable=False)
    slug = Column(String(255), unique=True, nullable=False)
    description = Column(Text, nullable=True)


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    display_name = Column(String(255), nullable=False)
    role = Column(String(64), default="analyst", nullable=False)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=True)


class Target(Base, TimestampMixin):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True, nullable=False)
    scope = Column(Text, nullable=True)
    target_type = Column(String(64), default="domain", nullable=False)
    description = Column(Text, nullable=True)
    business_criticality = Column(Integer, default=3, nullable=False)
    priority = Column(Integer, default=3, nullable=False)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=True)
    monitoring_enabled = Column(Boolean, default=True, nullable=False)
    lifecycle = Column(String(64), default="active", nullable=False)
    last_intelligence_sync = Column(DateTime, nullable=True)
    last_scan_at = Column(DateTime, nullable=True)
    tags = Column(Text, nullable=True)


class Asset(Base, TimestampMixin):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("target_id", "kind", "value", name="uq_asset_target_kind_value"),
    )

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    kind = Column(String(64), nullable=False)
    value = Column(String(512), nullable=False)
    host = Column(String(512), nullable=True)
    ip = Column(String(128), nullable=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String(32), nullable=True)
    title = Column(String(512), nullable=True)
    tech_stack = Column(Text, nullable=True)
    exposure = Column(String(64), default="external", nullable=False)
    classification = Column(String(64), default="external_asm", nullable=False)
    sensitivity = Column(String(64), default="medium", nullable=False)
    lifecycle = Column(String(64), default="active", nullable=False)
    provider = Column(String(64), nullable=True)
    status_code = Column(Integer, nullable=True)
    risk_score = Column(Float, default=0.0, nullable=False)
    metadata_json = Column(Text, nullable=True)


class AssetSourceEvent(Base, TimestampMixin):
    __tablename__ = "asset_source_events"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    source = Column(String(128), nullable=False)
    asset_key = Column(String(512), nullable=False)
    asset_type = Column(String(64), nullable=False)
    confidence = Column(Float, default=0.5, nullable=False)
    trusted = Column(Boolean, default=False, nullable=False)
    raw_payload = Column(Text, nullable=True)
    observed_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class AssetRelationship(Base, TimestampMixin):
    __tablename__ = "asset_relationships"
    __table_args__ = (
        UniqueConstraint(
            "target_id",
            "source_asset_id",
            "target_asset_id",
            "relation",
            name="uq_asset_relationship",
        ),
    )

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    source_asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    target_asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    relation = Column(String(64), nullable=False)
    confidence = Column(Float, default=0.6, nullable=False)
    reason = Column(Text, nullable=True)


class IdentityExposure(Base, TimestampMixin):
    __tablename__ = "identity_exposures"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    principal = Column(String(255), nullable=False)
    kind = Column(String(64), nullable=False)
    secret_type = Column(String(64), nullable=True)
    privilege_level = Column(String(64), default="medium", nullable=False)
    source = Column(String(128), nullable=False)
    exposure = Column(String(64), default="external", nullable=False)
    status = Column(String(64), default="open", nullable=False)
    evidence = Column(Text, nullable=True)


class ThreatIntelRecord(Base, TimestampMixin):
    __tablename__ = "threat_intel_records"

    id = Column(Integer, primary_key=True)
    cve = Column(String(64), unique=True, nullable=False)
    cvss_v3 = Column(Float, default=0.0, nullable=False)
    cvss_v4 = Column(Float, default=0.0, nullable=False)
    epss = Column(Float, default=0.0, nullable=False)
    kev = Column(Boolean, default=False, nullable=False)
    exploit_maturity = Column(String(32), default="none", nullable=False)
    threat_context = Column(String(64), default="normal", nullable=False)
    ransomware = Column(Boolean, default=False, nullable=False)
    references_json = Column(Text, nullable=True)
    last_synced_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class ScannerNode(Base, TimestampMixin):
    __tablename__ = "scanner_nodes"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=True)
    node_name = Column(String(255), unique=True, nullable=False)
    status = Column(String(64), default="online", nullable=False)
    capabilities_json = Column(Text, nullable=True)
    current_load = Column(Integer, default=0, nullable=False)
    capacity = Column(Integer, default=4, nullable=False)
    cpu_percent = Column(Float, default=0.0, nullable=False)
    memory_percent = Column(Float, default=0.0, nullable=False)
    disk_percent = Column(Float, default=0.0, nullable=False)
    last_heartbeat = Column(DateTime, default=datetime.utcnow, nullable=False)


class ScanJob(Base, TimestampMixin):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    kind = Column(String(64), default="full_scan", nullable=False)
    trigger = Column(String(64), default="manual", nullable=False)
    cron = Column(String(64), nullable=True)
    priority = Column(Integer, default=3, nullable=False)
    status = Column(String(64), default="queued", nullable=False)
    progress = Column(Float, default=0.0, nullable=False)
    attempts = Column(Integer, default=0, nullable=False)
    max_retries = Column(Integer, default=2, nullable=False)
    scheduled_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    worker_hint = Column(String(255), nullable=True)
    last_error = Column(Text, nullable=True)


class ScanStage(Base):
    __tablename__ = "scan_stages"

    id = Column(Integer, primary_key=True)
    job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    status = Column(String(64), default="completed", nullable=False)
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    finished_at = Column(DateTime, nullable=True)
    duration_ms = Column(Integer, default=0, nullable=False)
    logs = Column(Text, nullable=True)


class ScanResult(Base, TimestampMixin):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True)
    job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False, index=True)
    tool = Column(String(128), nullable=False)
    stage = Column(String(128), nullable=False)
    status = Column(String(64), default="completed", nullable=False)
    exit_code = Column(Integer, default=0, nullable=False)
    fallback_used = Column(Boolean, default=False, nullable=False)
    stdout_sample = Column(Text, nullable=True)
    stderr_sample = Column(Text, nullable=True)
    payload = Column(Text, default="{}", nullable=False)
    artifact_json = Column(Text, nullable=True)


class Vulnerability(Base, TimestampMixin):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=True)
    fingerprint = Column(String(255), unique=True, nullable=False, index=True)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(32), default="info", nullable=False)
    status = Column(String(64), default="open", nullable=False)
    source = Column(String(128), nullable=False)
    host = Column(String(512), nullable=True)
    port = Column(Integer, nullable=True)
    cve = Column(String(64), nullable=True, index=True)
    cvss = Column(Float, default=0.0, nullable=False)
    epss = Column(Float, default=0.0, nullable=False)
    exploit_maturity = Column(String(32), default="none", nullable=False)
    exposure = Column(String(64), default="external", nullable=False)
    asset_criticality = Column(Integer, default=3, nullable=False)
    threat_context = Column(String(64), default="normal", nullable=False)
    kev = Column(Boolean, default=False, nullable=False)
    ransomware = Column(Boolean, default=False, nullable=False)
    risk_score = Column(Float, default=0.0, nullable=False)
    details_json = Column(Text, nullable=True)
    assigned_to = Column(String(255), nullable=True)
    notes = Column(Text, nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    sla_due_at = Column(DateTime, nullable=True)


class Ticket(Base, TimestampMixin):
    __tablename__ = "tickets"

    id = Column(Integer, primary_key=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False, index=True)
    provider = Column(String(64), default="internal", nullable=False)
    external_id = Column(String(255), nullable=True)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(64), default="open", nullable=False)


class ExceptionRequest(Base, TimestampMixin):
    __tablename__ = "exception_requests"

    id = Column(Integer, primary_key=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False, index=True)
    justification = Column(Text, nullable=False)
    status = Column(String(64), default="pending", nullable=False)
    requested_by = Column(String(255), nullable=True)
    approved_by = Column(String(255), nullable=True)
    expires_at = Column(DateTime, nullable=True)


class ApiKey(Base, TimestampMixin):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True)
    provider = Column(String(64), nullable=False)
    label = Column(String(255), nullable=False)
    key_value = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)


class BlacklistEntry(Base, TimestampMixin):
    __tablename__ = "blacklist_entries"

    id = Column(Integer, primary_key=True)
    pattern = Column(String(255), nullable=False, unique=True)
    scope = Column(String(64), default="global", nullable=False)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=True)
    reason = Column(Text, nullable=True)


class Notification(Base, TimestampMixin):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True)
    channel = Column(String(64), nullable=False)
    destination = Column(String(255), nullable=False)
    severity = Column(String(32), default="medium", nullable=False)
    subject = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    status = Column(String(64), default="queued", nullable=False)


class AssetSnapshot(Base, TimestampMixin):
    __tablename__ = "asset_snapshots"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=True)
    summary_json = Column(Text, nullable=False)


class MonitoringRule(Base, TimestampMixin):
    __tablename__ = "monitoring_rules"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    mode = Column(String(64), default="scheduled", nullable=False)
    cron = Column(String(64), nullable=True)
    event_type = Column(String(64), nullable=True)
    enabled = Column(Boolean, default=True, nullable=False)
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True)


class AutomationRule(Base, TimestampMixin):
    __tablename__ = "automation_rules"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    event = Column(String(64), nullable=False)
    action = Column(String(64), nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    configuration_json = Column(Text, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    actor = Column(String(255), nullable=True)
    action = Column(String(128), nullable=False)
    entity_type = Column(String(128), nullable=False)
    entity_id = Column(String(128), nullable=True)
    details_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


Organization.users = relationship("User", backref="organization")
Target.organization = relationship("Organization", backref="targets")
Target.assets = relationship("Asset", backref="target", cascade="all, delete-orphan")
Target.vulnerabilities = relationship("Vulnerability", backref="target", cascade="all, delete-orphan")
Target.jobs = relationship("ScanJob", backref="target", cascade="all, delete-orphan")
Asset.identity_exposures = relationship("IdentityExposure", backref="asset")
ScanJob.stages = relationship("ScanStage", backref="job", cascade="all, delete-orphan")
ScanJob.results = relationship("ScanResult", backref="job", cascade="all, delete-orphan")
Vulnerability.tickets = relationship("Ticket", backref="vulnerability", cascade="all, delete-orphan")
Vulnerability.exceptions = relationship("ExceptionRequest", backref="vulnerability", cascade="all, delete-orphan")
