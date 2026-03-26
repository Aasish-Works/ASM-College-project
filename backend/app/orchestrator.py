from __future__ import annotations

import fnmatch
import json
import threading
from datetime import datetime, timedelta
from queue import Empty, PriorityQueue

from sqlalchemy import or_
from sqlalchemy.orm import Session

from .config import settings
from .db import SessionLocal, session_scope
from .graph import simulate_attack_paths
from .intelligence import RawAssetStream, persist_asset_graph
from .models import (
    Asset,
    AssetSnapshot,
    AutomationRule,
    BlacklistEntry,
    MonitoringRule,
    Notification,
    ScanJob,
    ScanResult,
    ScanStage,
    ScannerNode,
    Target,
    ThreatIntelRecord,
    Ticket,
    Vulnerability,
)
from .pipeline import PipelineResult, execute_scan_pipeline


def _json_dumps(payload: object) -> str:
    return json.dumps(payload, default=str)


def _now() -> datetime:
    return datetime.utcnow()


def _compute_next_run(cron: str | None) -> datetime:
    if not cron:
        return _now() + timedelta(hours=24)
    parts = cron.split()
    if len(parts) != 5:
        return _now() + timedelta(hours=24)
    minute, hour = parts[0], parts[1]
    if hour.startswith("*/"):
        try:
            step = max(1, int(hour[2:]))
        except ValueError:
            step = 6
        return _now() + timedelta(hours=step)
    if minute == "0" and hour == "*":
        return _now() + timedelta(hours=1)
    return _now() + timedelta(hours=24)


def _matches_blacklist(patterns: list[BlacklistEntry], value: str) -> bool:
    lowered = value.lower()
    for entry in patterns:
        pattern = (entry.pattern or "").lower()
        if not pattern:
            continue
        if fnmatch.fnmatch(lowered, pattern) or pattern in lowered:
            return True
    return False


def _apply_blacklist(
    db: Session, target: Target, streams: list[RawAssetStream], vulnerabilities: list[dict[str, object]]
) -> tuple[list[RawAssetStream], list[dict[str, object]]]:
    patterns = (
        db.query(BlacklistEntry)
        .filter((BlacklistEntry.scope == "global") | (BlacklistEntry.target_id == target.id))
        .all()
    )
    if not patterns:
        return streams, vulnerabilities

    allowed_streams = [stream for stream in streams if not _matches_blacklist(patterns, stream.value)]
    allowed_hosts = {stream.host or stream.value for stream in allowed_streams}
    allowed_vulnerabilities = [
        vulnerability
        for vulnerability in vulnerabilities
        if not vulnerability.get("host") or vulnerability["host"] in allowed_hosts
    ]
    return allowed_streams, allowed_vulnerabilities


def _asset_lookup_by_host(asset_map: dict[str, Asset]) -> dict[str, Asset]:
    lookup: dict[str, Asset] = {}
    for asset in asset_map.values():
        if asset.host:
            lookup[asset.host] = asset
        lookup[asset.value] = asset
    return lookup


def _stable_fingerprint(vuln_data: dict[str, object]) -> str:
    raw = "|".join(
        [
            str(vuln_data.get("host") or ""),
            str(vuln_data.get("port") or ""),
            str(vuln_data.get("source") or ""),
            str(vuln_data.get("title") or ""),
            str(vuln_data.get("cve") or ""),
        ]
    )
    return raw


class ASMOrchestrator:
    def __init__(self) -> None:
        self.queue: PriorityQueue[tuple[int, float, int]] = PriorityQueue()
        self.stop_event = threading.Event()
        self.threads: list[threading.Thread] = []
        self.scheduler_thread: threading.Thread | None = None
        self.pending_job_ids: set[int] = set()
        self.lock = threading.Lock()

    def start(self) -> None:
        if self.threads:
            return
        self.stop_event.clear()
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop, name="asm-scheduler", daemon=True)
        self.scheduler_thread.start()
        for index in range(settings.worker_count):
            thread = threading.Thread(target=self._worker_loop, args=(index + 1,), daemon=True)
            thread.start()
            self.threads.append(thread)

    def stop(self) -> None:
        self.stop_event.set()
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=2)
        for thread in self.threads:
            thread.join(timeout=2)
        self.threads.clear()

    def enqueue_job(self, job_id: int, priority: int) -> None:
        with self.lock:
            if job_id in self.pending_job_ids:
                return
            self.pending_job_ids.add(job_id)
        self.queue.put((priority, _now().timestamp(), job_id))

    def create_job(
        self,
        db: Session,
        target: Target,
        *,
        kind: str = "full_scan",
        priority: int = 3,
        trigger: str = "manual",
        max_retries: int = 2,
        cron: str | None = None,
    ) -> ScanJob:
        job = ScanJob(
            target_id=target.id,
            kind=kind,
            priority=priority,
            trigger=trigger,
            max_retries=max_retries,
            cron=cron,
            scheduled_at=_now(),
            next_run_at=_now(),
            status="queued",
            progress=0.0,
        )
        db.add(job)
        db.flush()
        self.enqueue_job(job.id, priority)
        return job

    def ensure_default_monitor(self, db: Session, target: Target) -> None:
        exists = db.query(MonitoringRule).filter(MonitoringRule.target_id == target.id).first()
        if exists:
            return
        db.add(
            MonitoringRule(
                target_id=target.id,
                name="Continuous monitoring",
                mode="scheduled",
                cron=settings.default_monitor_cron,
                enabled=True,
                next_run_at=_compute_next_run(settings.default_monitor_cron),
            )
        )

    def register_heartbeat(
        self,
        db: Session,
        *,
        node_name: str,
        capabilities: list[str],
        current_load: int,
        capacity: int,
        cpu_percent: float,
        memory_percent: float,
        disk_percent: float,
    ) -> ScannerNode:
        node = db.query(ScannerNode).filter(or_(ScannerNode.node_name == node_name, ScannerNode.name == node_name)).one_or_none()
        if node is None:
            node = ScannerNode(node_name=node_name)
            db.add(node)
        node.name = node_name
        node.node_name = node_name
        node.capabilities_json = _json_dumps(capabilities)
        node.current_load = current_load
        node.capacity = capacity
        node.cpu_percent = cpu_percent
        node.memory_percent = memory_percent
        node.disk_percent = disk_percent
        node.last_heartbeat = _now()
        node.status = "online"
        db.flush()
        return node

    def _scheduler_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                with session_scope() as db:
                    self._queue_existing_jobs(db)
                    self._queue_due_monitoring(db)
                    self._mark_offline_nodes(db)
            except Exception:
                pass
            self.stop_event.wait(settings.scheduler_interval_seconds)

    def _queue_existing_jobs(self, db: Session) -> None:
        now = _now()
        jobs = (
            db.query(ScanJob)
            .filter(ScanJob.status == "queued")
            .filter((ScanJob.next_run_at.is_(None)) | (ScanJob.next_run_at <= now))
            .all()
        )
        for job in jobs:
            self.enqueue_job(job.id, job.priority)

    def _queue_due_monitoring(self, db: Session) -> None:
        now = _now()
        rules = (
            db.query(MonitoringRule)
            .filter(MonitoringRule.enabled.is_(True))
            .filter(MonitoringRule.mode == "scheduled")
            .filter((MonitoringRule.next_run_at.is_(None)) | (MonitoringRule.next_run_at <= now))
            .all()
        )
        for rule in rules:
            target = db.query(Target).filter(Target.id == rule.target_id).one_or_none()
            if target is None:
                continue
            self.create_job(
                db,
                target,
                kind="continuous_monitoring",
                priority=max(1, target.priority - 1),
                trigger="scheduled",
                max_retries=2,
                cron=rule.cron,
            )
            rule.last_run_at = now
            rule.next_run_at = _compute_next_run(rule.cron)

    def _mark_offline_nodes(self, db: Session) -> None:
        stale_cutoff = _now() - timedelta(minutes=2)
        nodes = db.query(ScannerNode).all()
        for node in nodes:
            node.status = "offline" if node.last_heartbeat < stale_cutoff else "online"

    def _worker_loop(self, worker_index: int) -> None:
        worker_name = f"{settings.local_node_name}-w{worker_index}"
        while not self.stop_event.is_set():
            try:
                _, _, job_id = self.queue.get(timeout=1)
            except Empty:
                continue
            try:
                with session_scope() as db:
                    self._process_job(db, job_id, worker_name)
            except Exception:
                continue
            finally:
                with self.lock:
                    self.pending_job_ids.discard(job_id)

    def _persist_threat_record(self, db: Session, vulnerability: Vulnerability) -> None:
        if not vulnerability.cve:
            return
        record = db.query(ThreatIntelRecord).filter(ThreatIntelRecord.cve == vulnerability.cve).one_or_none()
        if record is None:
            record = ThreatIntelRecord(cve=vulnerability.cve)
            db.add(record)
        record.cvss_v3 = vulnerability.cvss
        record.epss = vulnerability.epss
        record.kev = vulnerability.kev
        record.exploit_maturity = vulnerability.exploit_maturity
        record.threat_context = vulnerability.threat_context
        record.ransomware = vulnerability.ransomware
        record.references_json = vulnerability.details_json
        record.last_synced_at = _now()

    def _persist_results(
        self, db: Session, job: ScanJob, result: PipelineResult, asset_map: dict[str, Asset]
    ) -> list[Vulnerability]:
        asset_lookup = _asset_lookup_by_host(asset_map)
        persisted: list[Vulnerability] = []

        for stage in result.stage_logs:
            db.add(
                ScanStage(
                    job_id=job.id,
                    name=str(stage["name"]),
                    status=str(stage["status"]),
                    started_at=stage["started_at"],
                    finished_at=stage["finished_at"],
                    duration_ms=int(stage["duration_ms"]),
                    logs=str(stage.get("logs") or ""),
                )
            )

        for tool_result in result.tool_results:
            db.add(
                ScanResult(
                    job_id=job.id,
                    tool=str(tool_result["tool"]),
                    stage=str(tool_result["stage"]),
                    status=str(tool_result["status"]),
                    exit_code=int(tool_result["exit_code"]),
                    fallback_used=bool(tool_result["fallback_used"]),
                    stdout_sample=str(tool_result.get("stdout") or "")[:4000],
                    stderr_sample=str(tool_result.get("stderr") or "")[:4000],
                    artifact_json=_json_dumps({"command": tool_result.get("command")}),
                )
            )

        for vuln_data in result.vulnerabilities:
            asset = asset_lookup.get(str(vuln_data.get("host") or ""))
            fingerprint = str(vuln_data.get("fingerprint") or _stable_fingerprint(vuln_data))
            existing = (
                db.query(Vulnerability)
                .filter(Vulnerability.fingerprint == fingerprint)
                .one_or_none()
            )
            if existing is None:
                vulnerability = Vulnerability(
                    target_id=job.target_id,
                    asset_id=asset.id if asset else None,
                    scan_job_id=job.id,
                    fingerprint=fingerprint,
                    title=str(vuln_data["title"]),
                    description=str(vuln_data.get("description") or ""),
                    severity=str(vuln_data["severity"]),
                    status="open",
                    source=str(vuln_data["source"]),
                    host=str(vuln_data.get("host") or ""),
                    port=vuln_data.get("port"),
                    cve=vuln_data.get("cve"),
                    cvss=float(vuln_data.get("cvss") or 0.0),
                    epss=float(vuln_data.get("epss") or 0.0),
                    exploit_maturity=str(vuln_data.get("exploit_maturity") or "none"),
                    exposure=str(vuln_data.get("exposure") or "external"),
                    asset_criticality=int(vuln_data.get("asset_criticality") or 3),
                    threat_context=str(vuln_data.get("threat_context") or "normal"),
                    kev=bool(vuln_data.get("kev")),
                    ransomware=bool(vuln_data.get("ransomware")),
                    risk_score=float(vuln_data.get("risk_score") or 0.0),
                    details_json=_json_dumps(vuln_data.get("details") or {}),
                    first_seen=_now(),
                    last_seen=_now(),
                    sla_due_at=_now() + timedelta(days=7 if vuln_data.get("severity") in {"critical", "high"} else 30),
                )
                db.add(vulnerability)
                db.flush()
            else:
                vulnerability = existing
                vulnerability.last_seen = _now()
                vulnerability.scan_job_id = job.id
                vulnerability.asset_id = asset.id if asset else vulnerability.asset_id
                vulnerability.description = str(vuln_data.get("description") or vulnerability.description or "")
                vulnerability.severity = str(vuln_data["severity"])
                vulnerability.source = str(vuln_data["source"])
                vulnerability.host = str(vuln_data.get("host") or vulnerability.host or "")
                vulnerability.port = vuln_data.get("port") or vulnerability.port
                vulnerability.cve = vuln_data.get("cve") or vulnerability.cve
                vulnerability.cvss = float(vuln_data.get("cvss") or vulnerability.cvss or 0.0)
                vulnerability.epss = float(vuln_data.get("epss") or vulnerability.epss or 0.0)
                vulnerability.exploit_maturity = str(vuln_data.get("exploit_maturity") or vulnerability.exploit_maturity)
                vulnerability.exposure = str(vuln_data.get("exposure") or vulnerability.exposure)
                vulnerability.asset_criticality = int(vuln_data.get("asset_criticality") or vulnerability.asset_criticality)
                vulnerability.threat_context = str(vuln_data.get("threat_context") or vulnerability.threat_context)
                vulnerability.kev = bool(vuln_data.get("kev") or vulnerability.kev)
                vulnerability.ransomware = bool(vuln_data.get("ransomware") or vulnerability.ransomware)
                vulnerability.risk_score = float(vuln_data.get("risk_score") or vulnerability.risk_score or 0.0)
                vulnerability.details_json = _json_dumps(vuln_data.get("details") or {})
            persisted.append(vulnerability)
            self._persist_threat_record(db, vulnerability)

        for asset in asset_map.values():
            related_scores = [v.risk_score for v in persisted if v.asset_id == asset.id]
            asset.risk_score = round(max(related_scores, default=asset.risk_score or 0.0), 2)

        db.add(AssetSnapshot(target_id=job.target_id, scan_job_id=job.id, summary_json=_json_dumps(result.snapshot)))
        return persisted

    def _run_automations(self, db: Session, job: ScanJob, vulnerabilities: list[Vulnerability]) -> None:
        if not vulnerabilities:
            return

        high_risk = [vulnerability for vulnerability in vulnerabilities if vulnerability.risk_score >= 70]
        rules = db.query(AutomationRule).filter(AutomationRule.enabled.is_(True)).all()
        for rule in rules:
            if rule.event == "high_risk_vulnerability" and high_risk:
                if rule.action == "notify":
                    top = sorted(high_risk, key=lambda item: item.risk_score, reverse=True)[0]
                    db.add(
                        Notification(
                            channel="dashboard",
                            destination="security-ops",
                            severity="high",
                            subject=f"High-risk issue on {job.target.name}",
                            message=f"{top.title} scored {top.risk_score} and requires attention.",
                            status="queued",
                        )
                    )
                if rule.action == "create_ticket":
                    for vulnerability in high_risk[:3]:
                        if vulnerability.tickets:
                            continue
                        db.add(
                            Ticket(
                                vulnerability_id=vulnerability.id,
                                provider="internal",
                                title=f"Remediate {vulnerability.title}",
                                description=f"Auto-created from automation rule {rule.name}",
                                status="open",
                            )
                        )
            if rule.event == "scan_completed" and rule.action == "notify":
                db.add(
                    Notification(
                        channel="dashboard",
                        destination="security-ops",
                        severity="medium",
                        subject=f"Scan completed for {job.target.name}",
                        message=f"Job #{job.id} completed with {len(vulnerabilities)} findings.",
                        status="queued",
                    )
                )

    def _process_job(self, db: Session, job_id: int, worker_name: str) -> None:
        job = db.query(ScanJob).filter(ScanJob.id == job_id).one_or_none()
        if job is None or job.status not in {"queued", "retry_pending"}:
            return
        target = db.query(Target).filter(Target.id == job.target_id).one_or_none()
        if target is None:
            return

        self.register_heartbeat(
            db,
            node_name=worker_name,
            capabilities=["nuclei", "nmap", "httpx", "correlation", "graph"],
            current_load=1,
            capacity=4,
            cpu_percent=12.0,
            memory_percent=28.0,
            disk_percent=33.0,
        )

        job.status = "running"
        job.started_at = _now()
        job.progress = 10.0
        job.attempts += 1
        job.worker_hint = worker_name
        db.flush()
        db.commit()
        job = db.query(ScanJob).filter(ScanJob.id == job_id).one()
        target = db.query(Target).filter(Target.id == job.target_id).one()

        try:
            result = execute_scan_pipeline(target)
            allowed_streams, allowed_vulnerabilities = _apply_blacklist(db, target, result.streams, result.vulnerabilities)
            result.streams = allowed_streams
            result.vulnerabilities = allowed_vulnerabilities
            asset_map = persist_asset_graph(db, target, result.streams, result.relationships, result.identities)
            job.progress = 75.0
            persisted_vulnerabilities = self._persist_results(db, job, result, asset_map)
            target.last_scan_at = _now()
            target.last_intelligence_sync = _now()
            job.progress = 100.0
            job.status = "completed"
            job.finished_at = _now()
            self._run_automations(db, job, persisted_vulnerabilities)
            simulate_attack_paths(db, target.id)
        except Exception as exc:
            job.last_error = str(exc)
            if job.attempts <= job.max_retries:
                job.status = "retry_pending"
                job.next_run_at = _now() + timedelta(minutes=2 ** job.attempts)
                job.progress = 0.0
            else:
                job.status = "failed"
                job.finished_at = _now()
        finally:
            node = db.query(ScannerNode).filter(ScannerNode.node_name == worker_name).one_or_none()
            if node is not None:
                node.current_load = 0
                node.last_heartbeat = _now()


orchestrator = ASMOrchestrator()
