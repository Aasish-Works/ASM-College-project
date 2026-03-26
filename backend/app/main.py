from __future__ import annotations

import json
from datetime import datetime, timedelta

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import desc, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import models
from .config import settings
from .db import SessionLocal, get_db, init_db
from .epss import epss_status, get_epss_score, refresh_epss_cache
from .graph import build_asset_graph, simulate_attack_paths
from .intelligence import guess_target_type, normalize_target_name
from .models import (
    ApiKey,
    Asset,
    AssetSnapshot,
    AssetSourceEvent,
    AutomationRule,
    BlacklistEntry,
    ExceptionRequest,
    IdentityExposure,
    MonitoringRule,
    Notification,
    Organization,
    ScanJob,
    ScanResult,
    ScanStage,
    ScannerNode,
    Target,
    ThreatIntelRecord,
    Ticket,
    Vulnerability,
)
from .orchestrator import orchestrator
from .schemas import (
    ApiKeyCreate,
    AssignmentRequest,
    AutomationRuleCreate,
    BlacklistEntryCreate,
    ExceptionCreate,
    IntelligenceRunRequest,
    MonitoringRuleCreate,
    NodeHeartbeat,
    NotificationCreate,
    OrganizationCreate,
    ScanCreate,
    ScanOrCreateRequest,
    TargetCreate,
    TargetUpdate,
    ThreatIntelRefreshRequest,
    TicketCreate,
    VulnerabilityUpdate,
)
from .threat_intel import lookup_threat_context, refresh_threat_feeds
from .tools import stage_tool_plan


app = FastAPI(
    title="Enterprise ASM Platform",
    version="2.0.0",
    description="Enterprise-grade Attack Surface Management platform with graph correlation, EPSS enrichment, contextual risk, distributed scanning, and detailed reporting.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()


def ensure_default_automation_rules() -> None:
    db = SessionLocal()
    try:
        existing = {(rule.event, rule.action) for rule in db.query(AutomationRule).all()}
        defaults = [
            ("High Risk Notify", "high_risk_vulnerability", "notify"),
            ("High Risk Ticket", "high_risk_vulnerability", "create_ticket"),
            ("Scan Completed Notify", "scan_completed", "notify"),
        ]
        created = False
        for name, event, action in defaults:
            if (event, action) in existing:
                continue
            db.add(
                AutomationRule(
                    name=name,
                    event=event,
                    action=action,
                    enabled=True,
                    configuration_json=json.dumps({"seeded": True}),
                )
            )
            created = True
        if created:
            db.commit()
    finally:
        db.close()


@app.on_event("startup")
def on_startup() -> None:
    ensure_default_automation_rules()
    orchestrator.start()


@app.on_event("shutdown")
def on_shutdown() -> None:
    orchestrator.stop()


def _json_load(value: str | None) -> dict | list | None:
    if not value:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return None


def normalize_name(value: str) -> str:
    normalized = normalize_target_name(value)
    if not normalized:
        raise HTTPException(status_code=400, detail="Target name is required")
    return normalized


def payload_dump(model) -> dict[str, object]:
    if hasattr(model, "model_dump"):
        return model.model_dump(exclude_none=True)
    return model.dict(exclude_none=True)


def serialize_target(db: Session, target: Target) -> dict[str, object]:
    asset_count = db.query(Asset).filter(Asset.target_id == target.id).count()
    vuln_count = db.query(Vulnerability).filter(Vulnerability.target_id == target.id).count()
    exposure_count = (
        db.query(Asset)
        .filter(Asset.target_id == target.id, Asset.exposure.in_(["external", "public", "api", "cloud"]))
        .count()
    )
    identity_count = db.query(IdentityExposure).filter(IdentityExposure.target_id == target.id).count()
    latest_job = db.query(ScanJob).filter(ScanJob.target_id == target.id).order_by(desc(ScanJob.created_at)).first()
    return {
        "id": target.id,
        "name": target.name,
        "scope": target.scope,
        "target_type": target.target_type,
        "description": target.description,
        "business_criticality": target.business_criticality,
        "priority": target.priority,
        "organization_id": target.organization_id,
        "monitoring_enabled": target.monitoring_enabled,
        "lifecycle": target.lifecycle,
        "tags": target.tags,
        "last_intelligence_sync": target.last_intelligence_sync,
        "last_scan_at": target.last_scan_at,
        "created_at": target.created_at,
        "updated_at": target.updated_at,
        "asset_count": asset_count,
        "vulnerability_count": vuln_count,
        "exposure_count": exposure_count,
        "identity_count": identity_count,
        "latest_job_status": latest_job.status if latest_job else None,
    }


def serialize_asset(asset: Asset) -> dict[str, object]:
    return {
        "id": asset.id,
        "target_id": asset.target_id,
        "kind": asset.kind,
        "value": asset.value,
        "host": asset.host,
        "ip": asset.ip,
        "port": asset.port,
        "protocol": asset.protocol,
        "title": asset.title,
        "tech_stack": _json_load(asset.tech_stack) or asset.tech_stack,
        "exposure": asset.exposure,
        "classification": asset.classification,
        "sensitivity": asset.sensitivity,
        "lifecycle": asset.lifecycle,
        "provider": asset.provider,
        "status_code": asset.status_code,
        "risk_score": asset.risk_score,
        "metadata": _json_load(asset.metadata_json) or {},
        "created_at": asset.created_at,
        "updated_at": asset.updated_at,
    }


def serialize_vulnerability(vulnerability: Vulnerability) -> dict[str, object]:
    return {
        "id": vulnerability.id,
        "target_id": vulnerability.target_id,
        "asset_id": vulnerability.asset_id,
        "scan_job_id": vulnerability.scan_job_id,
        "fingerprint": vulnerability.fingerprint,
        "title": vulnerability.title,
        "description": vulnerability.description,
        "severity": vulnerability.severity,
        "status": vulnerability.status,
        "source": vulnerability.source,
        "host": vulnerability.host,
        "port": vulnerability.port,
        "cve": vulnerability.cve,
        "cvss": vulnerability.cvss,
        "epss": vulnerability.epss,
        "exploit_maturity": vulnerability.exploit_maturity,
        "exposure": vulnerability.exposure,
        "asset_criticality": vulnerability.asset_criticality,
        "threat_context": vulnerability.threat_context,
        "kev": vulnerability.kev,
        "ransomware": vulnerability.ransomware,
        "risk_score": vulnerability.risk_score,
        "details": _json_load(vulnerability.details_json) or {},
        "assigned_to": vulnerability.assigned_to,
        "notes": vulnerability.notes,
        "first_seen": vulnerability.first_seen,
        "last_seen": vulnerability.last_seen,
        "sla_due_at": vulnerability.sla_due_at,
        "tickets": [
            {
                "id": ticket.id,
                "provider": ticket.provider,
                "external_id": ticket.external_id,
                "title": ticket.title,
                "status": ticket.status,
            }
            for ticket in vulnerability.tickets
        ],
        "exceptions": [
            {
                "id": exception.id,
                "status": exception.status,
                "justification": exception.justification,
                "expires_at": exception.expires_at,
            }
            for exception in vulnerability.exceptions
        ],
    }


def serialize_job(job: ScanJob) -> dict[str, object]:
    return {
        "id": job.id,
        "target_id": job.target_id,
        "kind": job.kind,
        "trigger": job.trigger,
        "cron": job.cron,
        "priority": job.priority,
        "status": job.status,
        "progress": job.progress,
        "attempts": job.attempts,
        "max_retries": job.max_retries,
        "scheduled_at": job.scheduled_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "next_run_at": job.next_run_at,
        "worker_hint": job.worker_hint,
        "last_error": job.last_error,
        "created_at": job.created_at,
        "updated_at": job.updated_at,
    }


def serialize_stage(stage: ScanStage) -> dict[str, object]:
    return {
        "id": stage.id,
        "job_id": stage.job_id,
        "name": stage.name,
        "status": stage.status,
        "started_at": stage.started_at,
        "finished_at": stage.finished_at,
        "duration_ms": stage.duration_ms,
        "logs": stage.logs,
    }


def serialize_result(result: ScanResult) -> dict[str, object]:
    return {
        "id": result.id,
        "job_id": result.job_id,
        "tool": result.tool,
        "stage": result.stage,
        "status": result.status,
        "exit_code": result.exit_code,
        "fallback_used": result.fallback_used,
        "stdout_sample": result.stdout_sample,
        "stderr_sample": result.stderr_sample,
        "artifact": _json_load(result.artifact_json) or {},
        "created_at": result.created_at,
    }


def serialize_node(node: ScannerNode) -> dict[str, object]:
    return {
        "id": node.id,
        "node_name": node.node_name,
        "status": node.status,
        "capabilities": _json_load(node.capabilities_json) or [],
        "current_load": node.current_load,
        "capacity": node.capacity,
        "cpu_percent": node.cpu_percent,
        "memory_percent": node.memory_percent,
        "disk_percent": node.disk_percent,
        "last_heartbeat": node.last_heartbeat,
    }


def serialize_monitoring(rule: MonitoringRule) -> dict[str, object]:
    return {
        "id": rule.id,
        "target_id": rule.target_id,
        "name": rule.name,
        "mode": rule.mode,
        "cron": rule.cron,
        "event_type": rule.event_type,
        "enabled": rule.enabled,
        "last_run_at": rule.last_run_at,
        "next_run_at": rule.next_run_at,
        "created_at": rule.created_at,
        "updated_at": rule.updated_at,
    }


def serialize_identity(identity: IdentityExposure) -> dict[str, object]:
    return {
        "id": identity.id,
        "target_id": identity.target_id,
        "asset_id": identity.asset_id,
        "principal": identity.principal,
        "kind": identity.kind,
        "secret_type": identity.secret_type,
        "privilege_level": identity.privilege_level,
        "source": identity.source,
        "exposure": identity.exposure,
        "status": identity.status,
        "evidence": identity.evidence,
        "created_at": identity.created_at,
    }


def queue_scan_job(db: Session, target: Target, payload: ScanCreate | ScanOrCreateRequest) -> ScanJob:
    orchestrator.ensure_default_monitor(db, target)
    if isinstance(payload, ScanOrCreateRequest):
        return orchestrator.create_job(
            db,
            target,
            kind=payload.scan_kind,
            priority=payload.priority,
            trigger=payload.trigger,
            max_retries=payload.max_retries,
        )
    return orchestrator.create_job(
        db,
        target,
        kind=payload.kind,
        priority=payload.priority,
        trigger=payload.trigger,
        max_retries=payload.max_retries,
        cron=payload.cron,
    )


def target_report(db: Session, target: Target) -> dict[str, object]:
    assets = db.query(Asset).filter(Asset.target_id == target.id).all()
    vulnerabilities = db.query(Vulnerability).filter(Vulnerability.target_id == target.id).all()
    identities = db.query(IdentityExposure).filter(IdentityExposure.target_id == target.id).all()
    jobs = db.query(ScanJob).filter(ScanJob.target_id == target.id).order_by(desc(ScanJob.created_at)).limit(10).all()
    snapshots = (
        db.query(AssetSnapshot)
        .filter(AssetSnapshot.target_id == target.id)
        .order_by(desc(AssetSnapshot.created_at))
        .limit(10)
        .all()
    )

    classification_counts: dict[str, int] = {}
    exposure_counts: dict[str, int] = {}
    kind_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    for asset in assets:
        classification_counts[asset.classification] = classification_counts.get(asset.classification, 0) + 1
        exposure_counts[asset.exposure] = exposure_counts.get(asset.exposure, 0) + 1
        kind_counts[asset.kind] = kind_counts.get(asset.kind, 0) + 1
    for vulnerability in vulnerabilities:
        severity_counts[vulnerability.severity] = severity_counts.get(vulnerability.severity, 0) + 1

    graph = build_asset_graph(db, target.id)
    attack_paths = simulate_attack_paths(db, target.id)
    raw_streams = (
        db.query(AssetSourceEvent)
        .filter(AssetSourceEvent.target_id == target.id)
        .order_by(desc(AssetSourceEvent.observed_at))
        .limit(30)
        .all()
    )
    top_risk = sorted(vulnerabilities, key=lambda item: item.risk_score or 0.0, reverse=True)[:10]
    epss_top = sorted(vulnerabilities, key=lambda item: item.epss or 0.0, reverse=True)[:5]

    return {
        "target": serialize_target(db, target),
        "summary": {
            "asset_count": len(assets),
            "vulnerability_count": len(vulnerabilities),
            "identity_exposure_count": len(identities),
            "job_count": len(jobs),
            "classification_counts": classification_counts,
            "exposure_counts": exposure_counts,
            "kind_counts": kind_counts,
            "severity_counts": severity_counts,
            "average_risk": round(sum(item.risk_score or 0.0 for item in vulnerabilities) / max(len(vulnerabilities), 1), 2),
            "max_risk": round(max((item.risk_score or 0.0) for item in vulnerabilities), 2) if vulnerabilities else 0.0,
            "average_epss": round(sum(item.epss or 0.0 for item in vulnerabilities) / max(len(vulnerabilities), 1), 4),
        },
        "assets": [serialize_asset(asset) for asset in assets],
        "vulnerabilities": [serialize_vulnerability(vulnerability) for vulnerability in top_risk],
        "identity_exposures": [serialize_identity(identity) for identity in identities],
        "graph": graph,
        "attack_paths": attack_paths,
        "jobs": [serialize_job(job) for job in jobs],
        "snapshots": [
            {"id": snapshot.id, "created_at": snapshot.created_at, "summary": _json_load(snapshot.summary_json) or {}}
            for snapshot in snapshots
        ],
        "raw_asset_streams": [
            {
                "id": event.id,
                "source": event.source,
                "asset_key": event.asset_key,
                "asset_type": event.asset_type,
                "confidence": event.confidence,
                "trusted": event.trusted,
                "payload": _json_load(event.raw_payload) or {},
                "observed_at": event.observed_at,
            }
            for event in raw_streams
        ],
        "epss_top": [serialize_vulnerability(vulnerability) for vulnerability in epss_top],
    }


def job_report(db: Session, job: ScanJob) -> dict[str, object]:
    target = db.query(Target).filter(Target.id == job.target_id).one()
    stages = db.query(ScanStage).filter(ScanStage.job_id == job.id).order_by(ScanStage.id).all()
    results = db.query(ScanResult).filter(ScanResult.job_id == job.id).order_by(ScanResult.id).all()
    vulnerabilities = (
        db.query(Vulnerability)
        .filter(Vulnerability.scan_job_id == job.id)
        .order_by(desc(Vulnerability.risk_score))
        .all()
    )
    assets = db.query(Asset).filter(Asset.target_id == target.id).all()
    snapshots = (
        db.query(AssetSnapshot)
        .filter(AssetSnapshot.scan_job_id == job.id)
        .order_by(desc(AssetSnapshot.created_at))
        .all()
    )

    severity_counts: dict[str, int] = {}
    exposure_counts: dict[str, int] = {}
    tech_counts: dict[str, int] = {}
    for vulnerability in vulnerabilities:
        severity_counts[vulnerability.severity] = severity_counts.get(vulnerability.severity, 0) + 1
        exposure_counts[vulnerability.exposure] = exposure_counts.get(vulnerability.exposure, 0) + 1
    for asset in assets:
        metadata = _json_load(asset.metadata_json) or {}
        for tech in metadata.get("tech", []):
            tech_counts[tech] = tech_counts.get(tech, 0) + 1

    overdue = [
        vulnerability
        for vulnerability in vulnerabilities
        if vulnerability.sla_due_at and vulnerability.sla_due_at < datetime.utcnow() and vulnerability.status != "resolved"
    ]
    return {
        "job": serialize_job(job),
        "target": serialize_target(db, target),
        "summary": {
            "asset_count": len(assets),
            "vulnerability_count": len(vulnerabilities),
            "severity_counts": severity_counts,
            "exposure_counts": exposure_counts,
            "tech_counts": tech_counts,
            "overdue_count": len(overdue),
            "average_epss": round(sum(item.epss or 0.0 for item in vulnerabilities) / max(len(vulnerabilities), 1), 4),
            "max_epss": round(max((item.epss or 0.0) for item in vulnerabilities), 4) if vulnerabilities else 0.0,
            "top_epss": [serialize_vulnerability(item) for item in sorted(vulnerabilities, key=lambda row: row.epss or 0.0, reverse=True)[:5]],
        },
        "stages": [serialize_stage(stage) for stage in stages],
        "results": [serialize_result(result) for result in results],
        "vulnerabilities": [serialize_vulnerability(vulnerability) for vulnerability in vulnerabilities],
        "assets": [serialize_asset(asset) for asset in assets],
        "snapshots": [
            {"id": snapshot.id, "created_at": snapshot.created_at, "summary": _json_load(snapshot.summary_json) or {}}
            for snapshot in snapshots
        ],
    }


@app.get("/")
def root() -> dict[str, object]:
    return {"name": "Enterprise ASM Platform", "status": "ok", "docs": "/docs", "health": "/health", "dashboard": "/dashboard"}


@app.get("/health")
def health(db: Session = Depends(get_db)) -> dict[str, object]:
    return {
        "status": "ok",
        "database": "connected",
        "targets": db.query(Target).count(),
        "jobs": db.query(ScanJob).count(),
        "epss": epss_status(),
    }


@app.post("/orgs")
def create_org(payload: OrganizationCreate, db: Session = Depends(get_db)) -> dict[str, object]:
    org = Organization(name=payload.name.strip(), slug=payload.slug.strip(), description=payload.description)
    db.add(org)
    db.commit()
    db.refresh(org)
    return {"organization": {"id": org.id, "name": org.name, "slug": org.slug, "description": org.description}}


@app.get("/orgs")
def list_orgs(db: Session = Depends(get_db)) -> list[dict[str, object]]:
    return [
        {"id": org.id, "name": org.name, "slug": org.slug, "description": org.description, "created_at": org.created_at}
        for org in db.query(Organization).order_by(Organization.name).all()
    ]


@app.get("/orgs/{org_id}")
def get_org(org_id: int, db: Session = Depends(get_db)) -> dict[str, object]:
    org = db.query(Organization).filter(Organization.id == org_id).one_or_none()
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    targets = db.query(Target).filter(Target.organization_id == org.id).all()
    return {
        "organization": {"id": org.id, "name": org.name, "slug": org.slug, "description": org.description},
        "targets": [serialize_target(db, target) for target in targets],
    }


@app.post("/targets")
def create_target(payload: TargetCreate, db: Session = Depends(get_db)) -> dict[str, object]:
    normalized = normalize_name(payload.name)
    target = Target(
        name=normalized,
        scope=payload.scope,
        target_type=payload.target_type or guess_target_type(normalized),
        description=payload.description,
        business_criticality=payload.business_criticality,
        priority=payload.priority,
        organization_id=payload.organization_id,
    )
    db.add(target)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.query(Target).filter(Target.name == normalized).one_or_none()
        raise HTTPException(status_code=409, detail={"message": "Target already exists", "target_id": existing.id if existing else None})
    db.refresh(target)
    orchestrator.ensure_default_monitor(db, target)
    db.commit()
    return {"target": serialize_target(db, target)}


@app.get("/targets")
def list_targets(q: str | None = None, db: Session = Depends(get_db)) -> list[dict[str, object]]:
    query = db.query(Target)
    if q:
        query = query.filter(Target.name.ilike(f"%{q.strip().lower()}%"))
    return [serialize_target(db, target) for target in query.order_by(desc(Target.updated_at)).all()]


@app.get("/targets/search")
def search_targets(query: str = Query(...), db: Session = Depends(get_db)) -> list[dict[str, object]]:
    targets = db.query(Target).filter(Target.name.ilike(f"%{query.strip().lower()}%")).all()
    return [serialize_target(db, target) for target in targets]


@app.get("/targets/{target_id}")
def get_target(target_id: int, db: Session = Depends(get_db)) -> dict[str, object]:
    target = db.query(Target).filter(Target.id == target_id).one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return {"target": serialize_target(db, target)}


@app.patch("/targets/{target_id}")
def update_target(target_id: int, payload: TargetUpdate, db: Session = Depends(get_db)) -> dict[str, object]:
    target = db.query(Target).filter(Target.id == target_id).one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    for field, value in payload_dump(payload).items():
        setattr(target, field, value)
    db.commit()
    db.refresh(target)
    return {"target": serialize_target(db, target)}


@app.post("/targets/{target_id}/scan")
def scan_target(target_id: int, payload: ScanCreate, db: Session = Depends(get_db)) -> dict[str, object]:
    target = db.query(Target).filter(Target.id == target_id).one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    job = queue_scan_job(db, target, payload)
    db.commit()
    db.refresh(job)
    return {"target": serialize_target(db, target), "job": serialize_job(job)}


@app.post("/targets/scan-or-create")
def scan_or_create(payload: ScanOrCreateRequest, db: Session = Depends(get_db)) -> dict[str, object]:
    normalized = normalize_name(payload.name)
    target = db.query(Target).filter(Target.name == normalized).one_or_none()
    created = False
    if target is None:
        target = Target(
            name=normalized,
            scope=payload.scope,
            target_type=payload.target_type or guess_target_type(normalized),
            description=payload.description,
            business_criticality=payload.business_criticality,
            priority=payload.priority,
            organization_id=payload.organization_id,
        )
        db.add(target)
        db.flush()
        orchestrator.ensure_default_monitor(db, target)
        created = True
    else:
        target.scope = payload.scope or target.scope
        target.business_criticality = payload.business_criticality or target.business_criticality
        target.priority = payload.priority or target.priority
    job = queue_scan_job(db, target, payload)
    db.commit()
    db.refresh(target)
    db.refresh(job)
    return {"created": created, "target": serialize_target(db, target), "job": serialize_job(job)}


@app.post("/targets/{target_id}/intelligence")
def run_target_intelligence(target_id: int, payload: IntelligenceRunRequest, db: Session = Depends(get_db)) -> dict[str, object]:
    target = db.query(Target).filter(Target.id == target_id).one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    job = orchestrator.create_job(
        db,
        target,
        kind="intelligence_refresh",
        priority=max(1, target.priority - 1),
        trigger="event",
        max_retries=2,
    )
    db.commit()
    return {"message": "Intelligence refresh queued", "job": serialize_job(job), "requested_sources": payload.sources}


@app.get("/targets/{target_id}/jobs")
def target_jobs(target_id: int, db: Session = Depends(get_db)) -> list[dict[str, object]]:
    jobs = db.query(ScanJob).filter(ScanJob.target_id == target_id).order_by(desc(ScanJob.created_at)).all()
    return [serialize_job(job) for job in jobs]


@app.get("/targets/{target_id}/intel")
def target_intel(target_id: int, db: Session = Depends(get_db)) -> dict[str, object]:
    target = db.query(Target).filter(Target.id == target_id).one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return target_report(db, target)


@app.get("/targets/{target_id}/graph")
def target_graph(target_id: int, db: Session = Depends(get_db)) -> dict[str, object]:
    target = db.query(Target).filter(Target.id == target_id).one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return {"graph": build_asset_graph(db, target.id)}


@app.get("/targets/{target_id}/attack-paths")
def target_attack_paths(target_id: int, db: Session = Depends(get_db)) -> dict[str, object]:
    target = db.query(Target).filter(Target.id == target_id).one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return {"paths": simulate_attack_paths(db, target.id)}


@app.get("/targets/{target_id}/exposures")
def target_exposures(target_id: int, db: Session = Depends(get_db)) -> dict[str, object]:
    exposures = (
        db.query(Vulnerability)
        .filter(Vulnerability.target_id == target_id)
        .filter(or_(Vulnerability.source == "exposure_engine", Vulnerability.exposure != "internal"))
        .order_by(desc(Vulnerability.risk_score))
        .all()
    )
    return {"items": [serialize_vulnerability(item) for item in exposures]}


@app.get("/targets/{target_id}/identities")
def target_identities(target_id: int, db: Session = Depends(get_db)) -> dict[str, object]:
    identities = db.query(IdentityExposure).filter(IdentityExposure.target_id == target_id).all()
    return {"items": [serialize_identity(identity) for identity in identities]}


@app.get("/targets/{target_id}/monitoring")
def get_monitoring(target_id: int, db: Session = Depends(get_db)) -> dict[str, object]:
    rules = db.query(MonitoringRule).filter(MonitoringRule.target_id == target_id).order_by(MonitoringRule.id).all()
    return {"items": [serialize_monitoring(rule) for rule in rules]}


@app.post("/targets/{target_id}/monitoring")
def create_monitoring(target_id: int, payload: MonitoringRuleCreate, db: Session = Depends(get_db)) -> dict[str, object]:
    target = db.query(Target).filter(Target.id == target_id).one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    rule = MonitoringRule(
        target_id=target.id,
        name=payload.name,
        mode=payload.mode,
        cron=payload.cron,
        event_type=payload.event_type,
        enabled=payload.enabled,
        next_run_at=datetime.utcnow() + timedelta(minutes=5) if payload.mode == "event" else datetime.utcnow() + timedelta(hours=1),
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return {"rule": serialize_monitoring(rule)}


@app.post("/events/targets/{target_id}")
def trigger_target_event(target_id: int, event_type: str = Query("new_asset_detected"), db: Session = Depends(get_db)) -> dict[str, object]:
    target = db.query(Target).filter(Target.id == target_id).one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    job = orchestrator.create_job(
        db,
        target,
        kind=f"event_{event_type}",
        priority=max(1, target.priority - 1),
        trigger="event",
        max_retries=2,
    )
    db.commit()
    db.refresh(job)
    return {"message": f"Event-driven scan queued for {event_type}", "job": serialize_job(job)}


@app.get("/jobs")
def list_jobs(status: str | None = None, db: Session = Depends(get_db)) -> list[dict[str, object]]:
    query = db.query(ScanJob)
    if status:
        query = query.filter(ScanJob.status == status)
    return [serialize_job(job) for job in query.order_by(desc(ScanJob.created_at)).all()]


@app.get("/jobs/search")
def search_jobs(query: str = Query(...), db: Session = Depends(get_db)) -> list[dict[str, object]]:
    jobs = (
        db.query(ScanJob)
        .join(Target, Target.id == ScanJob.target_id)
        .filter(Target.name.ilike(f"%{query.strip().lower()}%"))
        .order_by(desc(ScanJob.created_at))
        .all()
    )
    return [serialize_job(job) for job in jobs]


@app.get("/jobs/{job_id}")
def get_job(job_id: int, db: Session = Depends(get_db)) -> dict[str, object]:
    job = db.query(ScanJob).filter(ScanJob.id == job_id).one_or_none()
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"job": serialize_job(job)}


@app.get("/jobs/{job_id}/stages")
def get_job_stages(job_id: int, db: Session = Depends(get_db)) -> list[dict[str, object]]:
    stages = db.query(ScanStage).filter(ScanStage.job_id == job_id).order_by(ScanStage.id).all()
    return [serialize_stage(stage) for stage in stages]


@app.get("/jobs/{job_id}/results")
def get_job_results(job_id: int, db: Session = Depends(get_db)) -> list[dict[str, object]]:
    results = db.query(ScanResult).filter(ScanResult.job_id == job_id).order_by(ScanResult.id).all()
    return [serialize_result(result) for result in results]


@app.get("/reports/jobs/{job_id}")
def get_job_report(job_id: int, db: Session = Depends(get_db)) -> dict[str, object]:
    job = db.query(ScanJob).filter(ScanJob.id == job_id).one_or_none()
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return job_report(db, job)


@app.get("/reports/targets/{target_id}")
def get_target_report(target_id: int, db: Session = Depends(get_db)) -> dict[str, object]:
    target = db.query(Target).filter(Target.id == target_id).one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return target_report(db, target)


@app.post("/nodes/heartbeat")
def heartbeat(payload: NodeHeartbeat, db: Session = Depends(get_db)) -> dict[str, object]:
    node = orchestrator.register_heartbeat(
        db,
        node_name=payload.node_name,
        capabilities=payload.capabilities,
        current_load=payload.current_load,
        capacity=payload.capacity,
        cpu_percent=payload.cpu_percent,
        memory_percent=payload.memory_percent,
        disk_percent=payload.disk_percent,
    )
    db.commit()
    return {"node": serialize_node(node)}


@app.get("/nodes")
def list_nodes(db: Session = Depends(get_db)) -> list[dict[str, object]]:
    nodes = db.query(ScannerNode).order_by(ScannerNode.node_name).all()
    return [serialize_node(node) for node in nodes]


@app.get("/assets")
def list_assets(target_id: int | None = None, kind: str | None = None, exposure: str | None = None, db: Session = Depends(get_db)) -> list[dict[str, object]]:
    query = db.query(Asset)
    if target_id is not None:
        query = query.filter(Asset.target_id == target_id)
    if kind:
        query = query.filter(Asset.kind == kind)
    if exposure:
        query = query.filter(Asset.exposure == exposure)
    return [serialize_asset(asset) for asset in query.order_by(desc(Asset.risk_score), Asset.value).all()]


@app.get("/assets/search")
def search_assets(query: str = Query(...), db: Session = Depends(get_db)) -> list[dict[str, object]]:
    value = query.strip()
    assets = db.query(Asset).filter(
        or_(
            Asset.value.ilike(f"%{value}%"),
            Asset.host.ilike(f"%{value}%"),
            Asset.title.ilike(f"%{value}%"),
            Asset.classification.ilike(f"%{value}%"),
        )
    )
    return [serialize_asset(asset) for asset in assets.order_by(desc(Asset.risk_score)).all()]


@app.get("/assets/export")
def export_assets(db: Session = Depends(get_db)) -> dict[str, object]:
    return {"items": [serialize_asset(asset) for asset in db.query(Asset).order_by(Asset.id).all()]}


@app.get("/targets/{target_id}/snapshots")
def list_snapshots(target_id: int, db: Session = Depends(get_db)) -> list[dict[str, object]]:
    snapshots = (
        db.query(AssetSnapshot)
        .filter(AssetSnapshot.target_id == target_id)
        .order_by(desc(AssetSnapshot.created_at))
        .all()
    )
    return [
        {"id": snapshot.id, "created_at": snapshot.created_at, "summary": _json_load(snapshot.summary_json) or {}}
        for snapshot in snapshots
    ]


@app.get("/targets/{target_id}/snapshots/compare")
def compare_snapshots(target_id: int, db: Session = Depends(get_db)) -> dict[str, object]:
    snapshots = (
        db.query(AssetSnapshot)
        .filter(AssetSnapshot.target_id == target_id)
        .order_by(desc(AssetSnapshot.created_at))
        .limit(2)
        .all()
    )
    if len(snapshots) < 2:
        return {"current": _json_load(snapshots[0].summary_json) if snapshots else {}, "previous": {}, "delta": {}}
    current = _json_load(snapshots[0].summary_json) or {}
    previous = _json_load(snapshots[1].summary_json) or {}
    delta = {
        key: current.get(key, 0) - previous.get(key, 0)
        for key in set(current.keys()) | set(previous.keys())
        if isinstance(current.get(key, 0), (int, float)) and isinstance(previous.get(key, 0), (int, float))
    }
    return {"current": current, "previous": previous, "delta": delta}


@app.get("/vulns")
def list_vulns(target_id: int | None = None, status: str | None = None, severity: str | None = None, db: Session = Depends(get_db)) -> list[dict[str, object]]:
    query = db.query(Vulnerability)
    if target_id is not None:
        query = query.filter(Vulnerability.target_id == target_id)
    if status:
        query = query.filter(Vulnerability.status == status)
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    vulns = query.order_by(desc(Vulnerability.risk_score), desc(Vulnerability.epss)).all()
    return [serialize_vulnerability(vulnerability) for vulnerability in vulns]


@app.post("/vulns/{vuln_id}/assign")
def assign_vuln(vuln_id: int, payload: AssignmentRequest, db: Session = Depends(get_db)) -> dict[str, object]:
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).one_or_none()
    if vuln is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    vuln.assigned_to = payload.assignee
    db.commit()
    db.refresh(vuln)
    return {"vulnerability": serialize_vulnerability(vuln)}


@app.patch("/vulns/{vuln_id}")
def update_vuln(vuln_id: int, payload: VulnerabilityUpdate, db: Session = Depends(get_db)) -> dict[str, object]:
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).one_or_none()
    if vuln is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    for field, value in payload_dump(payload).items():
        setattr(vuln, field, value)
    db.commit()
    db.refresh(vuln)
    return {"vulnerability": serialize_vulnerability(vuln)}


@app.post("/vulns/{vuln_id}/ticket")
def create_ticket(vuln_id: int, payload: TicketCreate, db: Session = Depends(get_db)) -> dict[str, object]:
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).one_or_none()
    if vuln is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    ticket = Ticket(
        vulnerability_id=vuln.id,
        provider=payload.provider,
        external_id=payload.external_id,
        title=payload.title,
        description=payload.description,
        status="open",
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)
    return {
        "ticket": {
            "id": ticket.id,
            "provider": ticket.provider,
            "external_id": ticket.external_id,
            "title": ticket.title,
            "description": ticket.description,
            "status": ticket.status,
        }
    }


@app.post("/vulns/{vuln_id}/exception")
def create_exception(vuln_id: int, payload: ExceptionCreate, db: Session = Depends(get_db)) -> dict[str, object]:
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).one_or_none()
    if vuln is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    request = ExceptionRequest(
        vulnerability_id=vuln.id,
        justification=payload.justification,
        requested_by=payload.requested_by,
        expires_at=payload.expires_at,
        status="pending",
    )
    db.add(request)
    db.commit()
    db.refresh(request)
    return {
        "exception": {
            "id": request.id,
            "status": request.status,
            "requested_by": request.requested_by,
            "expires_at": request.expires_at,
            "justification": request.justification,
        }
    }


@app.post("/exceptions/{exception_id}/approve")
def approve_exception(exception_id: int, approver: str = Query("security-lead"), db: Session = Depends(get_db)) -> dict[str, object]:
    exception = db.query(ExceptionRequest).filter(ExceptionRequest.id == exception_id).one_or_none()
    if exception is None:
        raise HTTPException(status_code=404, detail="Exception request not found")
    exception.status = "approved"
    exception.approved_by = approver
    db.commit()
    db.refresh(exception)
    return {"exception": {"id": exception.id, "status": exception.status, "approved_by": exception.approved_by, "expires_at": exception.expires_at}}


@app.get("/vulns/overdue")
def overdue_vulns(db: Session = Depends(get_db)) -> list[dict[str, object]]:
    now = datetime.utcnow()
    vulns = db.query(Vulnerability).filter(Vulnerability.sla_due_at < now, Vulnerability.status != "resolved").all()
    return [serialize_vulnerability(vulnerability) for vulnerability in vulns]


@app.post("/automation/rules")
def create_automation(payload: AutomationRuleCreate, db: Session = Depends(get_db)) -> dict[str, object]:
    rule = AutomationRule(
        name=payload.name,
        event=payload.event,
        action=payload.action,
        enabled=payload.enabled,
        configuration_json=json.dumps(payload.configuration, default=str),
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return {
        "rule": {
            "id": rule.id,
            "name": rule.name,
            "event": rule.event,
            "action": rule.action,
            "enabled": rule.enabled,
            "configuration": _json_load(rule.configuration_json) or {},
        }
    }


@app.get("/automation/rules")
def list_automation(db: Session = Depends(get_db)) -> list[dict[str, object]]:
    rules = db.query(AutomationRule).order_by(AutomationRule.id).all()
    return [
        {
            "id": rule.id,
            "name": rule.name,
            "event": rule.event,
            "action": rule.action,
            "enabled": rule.enabled,
            "configuration": _json_load(rule.configuration_json) or {},
        }
        for rule in rules
    ]


@app.post("/apikeys")
def create_apikey(payload: ApiKeyCreate, db: Session = Depends(get_db)) -> dict[str, object]:
    key = ApiKey(provider=payload.provider, label=payload.label, key_value=payload.key_value, is_active=payload.is_active)
    db.add(key)
    db.commit()
    db.refresh(key)
    return {"key": {"id": key.id, "provider": key.provider, "label": key.label, "is_active": key.is_active}}


@app.get("/apikeys")
def list_apikeys(db: Session = Depends(get_db)) -> list[dict[str, object]]:
    return [
        {"id": key.id, "provider": key.provider, "label": key.label, "is_active": key.is_active, "created_at": key.created_at}
        for key in db.query(ApiKey).order_by(ApiKey.provider, ApiKey.label).all()
    ]


@app.delete("/apikeys/{key_id}")
def delete_apikey(key_id: int, db: Session = Depends(get_db)) -> dict[str, object]:
    key = db.query(ApiKey).filter(ApiKey.id == key_id).one_or_none()
    if key is None:
        raise HTTPException(status_code=404, detail="API key not found")
    db.delete(key)
    db.commit()
    return {"deleted": True}


@app.post("/blacklist")
def create_blacklist(payload: BlacklistEntryCreate, db: Session = Depends(get_db)) -> dict[str, object]:
    entry = BlacklistEntry(pattern=payload.pattern, scope=payload.scope, target_id=payload.target_id, reason=payload.reason)
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return {"entry": {"id": entry.id, "pattern": entry.pattern, "scope": entry.scope, "target_id": entry.target_id, "reason": entry.reason}}


@app.get("/blacklist")
def list_blacklist(db: Session = Depends(get_db)) -> list[dict[str, object]]:
    return [
        {"id": entry.id, "pattern": entry.pattern, "scope": entry.scope, "target_id": entry.target_id, "reason": entry.reason}
        for entry in db.query(BlacklistEntry).order_by(BlacklistEntry.pattern).all()
    ]


@app.delete("/blacklist/{entry_id}")
def delete_blacklist(entry_id: int, db: Session = Depends(get_db)) -> dict[str, object]:
    entry = db.query(BlacklistEntry).filter(BlacklistEntry.id == entry_id).one_or_none()
    if entry is None:
        raise HTTPException(status_code=404, detail="Blacklist entry not found")
    db.delete(entry)
    db.commit()
    return {"deleted": True}


@app.post("/notifications")
def create_notification(payload: NotificationCreate, db: Session = Depends(get_db)) -> dict[str, object]:
    item = Notification(
        channel=payload.channel,
        destination=payload.destination,
        severity=payload.severity,
        subject=payload.subject,
        message=payload.message,
        status="queued",
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return {"notification": {"id": item.id, "status": item.status}}


@app.get("/notifications")
def list_notifications(db: Session = Depends(get_db)) -> list[dict[str, object]]:
    items = db.query(Notification).order_by(desc(Notification.created_at)).all()
    return [
        {
            "id": item.id,
            "channel": item.channel,
            "destination": item.destination,
            "severity": item.severity,
            "subject": item.subject,
            "message": item.message,
            "status": item.status,
            "created_at": item.created_at,
        }
        for item in items
    ]


@app.get("/stats")
def stats(db: Session = Depends(get_db)) -> dict[str, object]:
    return {
        "targets": db.query(Target).count(),
        "assets": db.query(Asset).count(),
        "vulnerabilities": db.query(Vulnerability).count(),
        "open_jobs": db.query(ScanJob).filter(ScanJob.status.in_(["queued", "running"])).count(),
        "nodes": db.query(ScannerNode).count(),
        "identity_exposures": db.query(IdentityExposure).count(),
    }


@app.get("/dashboard")
def dashboard(db: Session = Depends(get_db)) -> dict[str, object]:
    recent_targets = db.query(Target).order_by(desc(Target.updated_at)).limit(8).all()
    recent_jobs = db.query(ScanJob).order_by(desc(ScanJob.created_at)).limit(12).all()
    nodes = db.query(ScannerNode).order_by(ScannerNode.node_name).all()
    top_risky_assets = db.query(Asset).order_by(desc(Asset.risk_score)).limit(8).all()
    trending_vulns = db.query(Vulnerability).order_by(desc(Vulnerability.epss), desc(Vulnerability.risk_score)).limit(8).all()
    monitoring = db.query(MonitoringRule).filter(MonitoringRule.enabled.is_(True)).order_by(MonitoringRule.next_run_at).limit(8).all()

    risk_heatmap: dict[str, dict[str, int]] = {}
    for vulnerability in db.query(Vulnerability).all():
        risk_heatmap.setdefault(vulnerability.severity, {})
        risk_heatmap[vulnerability.severity][vulnerability.exposure] = risk_heatmap[vulnerability.severity].get(vulnerability.exposure, 0) + 1

    trends = []
    for days_back in range(6, -1, -1):
        day = (datetime.utcnow() - timedelta(days=days_back)).date()
        day_start = datetime.combine(day, datetime.min.time())
        day_end = day_start + timedelta(days=1)
        trends.append(
            {
                "date": day.isoformat(),
                "assets": db.query(Asset).filter(Asset.created_at >= day_start, Asset.created_at < day_end).count(),
                "vulnerabilities": db.query(Vulnerability).filter(Vulnerability.created_at >= day_start, Vulnerability.created_at < day_end).count(),
                "scans": db.query(ScanJob).filter(ScanJob.created_at >= day_start, ScanJob.created_at < day_end).count(),
            }
        )

    return {
        "stats": stats(db),
        "recent_targets": [serialize_target(db, target) for target in recent_targets],
        "recent_jobs": [serialize_job(job) for job in recent_jobs],
        "nodes": [serialize_node(node) for node in nodes],
        "top_risky_assets": [serialize_asset(asset) for asset in top_risky_assets],
        "trending_vulnerabilities": [serialize_vulnerability(vulnerability) for vulnerability in trending_vulns],
        "monitoring": [serialize_monitoring(rule) for rule in monitoring],
        "risk_heatmap": risk_heatmap,
        "trends": trends,
    }


@app.get("/analytics/trend")
def analytics_trend(db: Session = Depends(get_db)) -> dict[str, object]:
    return {"items": dashboard(db)["trends"]}


@app.get("/analytics/risk")
def analytics_risk(db: Session = Depends(get_db)) -> dict[str, object]:
    counts: dict[str, int] = {}
    exposure: dict[str, int] = {}
    for vulnerability in db.query(Vulnerability).all():
        counts[vulnerability.severity] = counts.get(vulnerability.severity, 0) + 1
        exposure[vulnerability.exposure] = exposure.get(vulnerability.exposure, 0) + 1
    return {"severity": counts, "exposure": exposure}


@app.get("/threat-intel")
def threat_intelligence(cve: str | None = None, db: Session = Depends(get_db)) -> dict[str, object]:
    if cve:
        return lookup_threat_context(cve)
    records = db.query(ThreatIntelRecord).order_by(desc(ThreatIntelRecord.last_synced_at)).limit(25).all()
    return {
        "items": [
            {
                "cve": record.cve,
                "cvss_v3": record.cvss_v3,
                "epss": record.epss,
                "kev": record.kev,
                "exploit_maturity": record.exploit_maturity,
                "threat_context": record.threat_context,
                "ransomware": record.ransomware,
                "last_synced_at": record.last_synced_at,
            }
            for record in records
        ]
    }


@app.post("/threat-intel/refresh")
def refresh_threat_intel(_: ThreatIntelRefreshRequest, db: Session = Depends(get_db)) -> dict[str, object]:
    del db
    return refresh_threat_feeds()


@app.get("/epss/lookup")
def epss_lookup(cve: str = Query(...)) -> dict[str, object]:
    return {"cve": cve.upper(), "epss": get_epss_score(cve)}


@app.post("/epss/refresh")
def epss_refresh() -> dict[str, int | str]:
    return refresh_epss_cache()


def _recent_reports_payload(db: Session, limit: int = 20) -> list[dict[str, object]]:
    jobs = db.query(ScanJob).order_by(desc(ScanJob.created_at)).limit(limit).all()
    payload: list[dict[str, object]] = []
    for job in jobs:
        target = db.query(Target).filter(Target.id == job.target_id).one_or_none()
        vuln_count = db.query(Vulnerability).filter(Vulnerability.scan_job_id == job.id).count()
        payload.append(
            {
                "id": job.id,
                "job_id": job.id,
                "target_id": job.target_id,
                "target": target.name if target else f"target-{job.target_id}",
                "kind": job.kind,
                "status": job.status,
                "priority": job.priority,
                "progress": job.progress,
                "vulnerability_count": vuln_count,
                "created_at": job.created_at,
                "updated_at": job.updated_at,
            }
        )
    return payload


@app.get("/api/version")
def legacy_api_version() -> dict[str, object]:
    return {
        "name": "Enterprise ASM Platform",
        "version": app.version,
        "api_version": "compat-v1",
        "status": "ok",
    }


@app.get("/api/summary")
def legacy_api_summary(db: Session = Depends(get_db)) -> dict[str, object]:
    board = dashboard(db)
    return {
        "stats": board["stats"],
        "recent_targets": board["recent_targets"],
        "recent_jobs": board["recent_jobs"],
        "risk_heatmap": board["risk_heatmap"],
        "trends": board["trends"],
    }


@app.get("/api/reports")
def legacy_api_reports(limit: int = Query(20, ge=1, le=200), db: Session = Depends(get_db)) -> list[dict[str, object]]:
    return _recent_reports_payload(db, limit=limit)


@app.get("/api/reporting/portfolio")
def legacy_reporting_portfolio(db: Session = Depends(get_db)) -> dict[str, object]:
    board = dashboard(db)
    return {
        "summary": board["stats"],
        "trends": board["trends"],
        "top_risky_assets": board["top_risky_assets"],
        "trending_vulnerabilities": board["trending_vulnerabilities"],
    }


@app.get("/api/monitor-targets")
def legacy_monitor_targets(db: Session = Depends(get_db)) -> list[dict[str, object]]:
    targets = db.query(Target).order_by(desc(Target.updated_at)).all()
    payload: list[dict[str, object]] = []
    for target in targets:
        rules = db.query(MonitoringRule).filter(MonitoringRule.target_id == target.id).all()
        serialized = serialize_target(db, target)
        serialized["monitoring_rules"] = [serialize_monitoring(rule) for rule in rules]
        payload.append(serialized)
    return payload


@app.get("/api/automation")
def legacy_automation(db: Session = Depends(get_db)) -> list[dict[str, object]]:
    return list_automation(db)


@app.get("/api/scanner-environment")
def legacy_scanner_environment(db: Session = Depends(get_db)) -> dict[str, object]:
    return {
        "nodes": [serialize_node(node) for node in db.query(ScannerNode).order_by(ScannerNode.node_name).all()],
        "tool_plan": stage_tool_plan(),
        "worker_count": settings.worker_count,
        "scheduler_interval_seconds": settings.scheduler_interval_seconds,
    }


@app.get("/api/exposures")
def legacy_exposures(limit: int = Query(200, ge=1, le=1000), db: Session = Depends(get_db)) -> list[dict[str, object]]:
    vulnerabilities = (
        db.query(Vulnerability)
        .filter(or_(Vulnerability.source == "exposure_engine", Vulnerability.exposure != "internal"))
        .order_by(desc(Vulnerability.risk_score))
        .limit(limit)
        .all()
    )
    return [serialize_vulnerability(vulnerability) for vulnerability in vulnerabilities]


@app.get("/api/assets/by-url")
def legacy_assets_by_url(limit: int = Query(200, ge=1, le=1000), db: Session = Depends(get_db)) -> list[dict[str, object]]:
    assets = (
        db.query(Asset)
        .filter(Asset.kind.in_(["application", "domain", "service"]))
        .order_by(desc(Asset.risk_score), Asset.value)
        .limit(limit)
        .all()
    )
    return [
        {
            "id": asset.id,
            "target_id": asset.target_id,
            "url": asset.value if asset.kind == "application" else None,
            "host": asset.host or asset.value,
            "kind": asset.kind,
            "title": asset.title,
            "exposure": asset.exposure,
            "classification": asset.classification,
            "risk_score": asset.risk_score,
            "status_code": asset.status_code,
            "tech": _json_load(asset.tech_stack) or [],
        }
        for asset in assets
    ]
