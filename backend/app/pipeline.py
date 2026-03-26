from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime

from .intelligence import (
    RawAssetStream,
    RawIdentityExposure,
    collect_multi_source_intelligence,
    generate_exposure_findings,
    infer_asset_relationships,
)
from .risk import compute_enterprise_risk
from .threat_intel import enrich_vulnerability
from .tools import ToolResult, run_tool, stage_tool_plan


CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


@dataclass(slots=True)
class StageLog:
    name: str
    status: str
    started_at: datetime
    finished_at: datetime
    duration_ms: int
    logs: str = ""

    def to_record(self) -> dict[str, object]:
        return {
            "name": self.name,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
            "logs": self.logs,
        }


@dataclass(slots=True)
class PipelineResult:
    streams: list[RawAssetStream] = field(default_factory=list)
    relationships: list[dict[str, object]] = field(default_factory=list)
    identities: list[RawIdentityExposure] = field(default_factory=list)
    vulnerabilities: list[dict[str, object]] = field(default_factory=list)
    tool_results: list[dict[str, object]] = field(default_factory=list)
    stage_logs: list[dict[str, object]] = field(default_factory=list)
    snapshot: dict[str, object] = field(default_factory=dict)
    raw_log: str = ""


def _severity_rank(severity: str) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(severity, 1)


def _normalize_severity(raw: str | None) -> str:
    value = (raw or "info").strip().lower()
    aliases = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
    }
    return aliases.get(value, "info")


def _extract_cve(*values: str | None) -> str | None:
    for value in values:
        if not value:
            continue
        match = CVE_PATTERN.search(value)
        if match:
            return match.group(0).upper()
    return None


def _fingerprint(payload: str) -> str:
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()


def _url_host(value: str) -> str:
    return value.replace("https://", "").replace("http://", "").split("/")[0]


def _parse_subdomains(stdout: str, source: str) -> list[RawAssetStream]:
    streams: list[RawAssetStream] = []
    for line in stdout.splitlines():
        host = line.strip().lower()
        if host and "." in host:
            streams.append(
                RawAssetStream(
                    kind="domain",
                    value=host,
                    host=host,
                    source=source,
                    confidence=0.65,
                    trusted=False,
                    classification="external_asm",
                )
            )
    return streams


def _parse_dnsx(stdout: str) -> tuple[list[RawAssetStream], list[dict[str, object]]]:
    streams: list[RawAssetStream] = []
    relationships: list[dict[str, object]] = []
    for line in stdout.splitlines():
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        host, ip = parts[0].lower(), parts[1]
        streams.append(
            RawAssetStream(
                kind="domain",
                value=host,
                host=host,
                source="dnsx",
                confidence=0.8,
                trusted=False,
                classification="external_asm",
            )
        )
        streams.append(
            RawAssetStream(
                kind="ip",
                value=ip,
                host=host,
                ip=ip,
                source="dnsx",
                confidence=0.8,
                trusted=False,
                classification="external_asm",
            )
        )
        relationships.append(
            {
                "source_kind": "domain",
                "source_value": host,
                "target_kind": "ip",
                "target_value": ip,
                "relation": "resolves_to",
                "confidence": 0.85,
                "reason": "dnsx resolution",
            }
        )
    return streams, relationships


def _parse_ports(stdout: str, host: str, source: str) -> list[RawAssetStream]:
    streams: list[RawAssetStream] = []
    for line in stdout.splitlines():
        text = line.strip()
        if not text:
            continue
        port = None
        if ":" in text and text.count(":") == 1:
            try:
                port = int(text.split(":")[1])
            except ValueError:
                port = None
        elif "/tcp" in text:
            try:
                port = int(text.split("/tcp")[0])
            except ValueError:
                port = None
        elif " tcp " in text:
            numbers = [item for item in text.split() if item.isdigit()]
            if numbers:
                port = int(numbers[0])
        if port is None:
            continue
        protocol = "https" if port in {443, 8443} else "http" if port in {80, 8080} else "tcp"
        streams.append(
            RawAssetStream(
                kind="service",
                value=f"{host}:{port}",
                host=host,
                port=port,
                protocol=protocol,
                source=source,
                confidence=0.85,
                trusted=False,
                exposure="external",
                classification="external_asm",
            )
        )
    return streams


def _parse_http(stdout: str, source: str) -> list[RawAssetStream]:
    streams: list[RawAssetStream] = []
    for line in stdout.splitlines():
        parts = [item.strip() for item in line.split("|")]
        if len(parts) < 4:
            continue
        url, status_code, title, tech = parts[:4]
        host = _url_host(url)
        try:
            status = int(status_code)
        except ValueError:
            status = None
        classification = "api_attack_surface" if any(token in url.lower() for token in ("api", "graphql", "swagger", "openapi")) else "external_asm"
        streams.append(
            RawAssetStream(
                kind="application",
                value=url,
                host=host,
                protocol="https" if url.startswith("https://") else "http",
                title=title,
                source=source,
                confidence=0.8,
                trusted=False,
                classification=classification,
                exposure="external",
                metadata={"status_code": status, "tech": tech.split(",")},
            )
        )
    return streams


def _parse_tlsx(stdout: str) -> list[RawAssetStream]:
    streams: list[RawAssetStream] = []
    for line in stdout.splitlines():
        parts = [item.strip() for item in line.split("|")]
        if len(parts) < 3:
            continue
        host, tls_version, weak_flag = parts[:3]
        streams.append(
            RawAssetStream(
                kind="service",
                value=f"{host}:443",
                host=host,
                port=443,
                protocol="https",
                source="tlsx",
                confidence=0.75,
                trusted=False,
                classification="external_asm",
                metadata={"tls_version": tls_version, "tls_weak": weak_flag.endswith("true")},
            )
        )
    return streams


def _parse_tech(stdout: str, source: str) -> list[RawAssetStream]:
    streams: list[RawAssetStream] = []
    for line in stdout.splitlines():
        parts = [item.strip() for item in line.split("|")]
        if len(parts) < 2:
            continue
        url = parts[0]
        host = _url_host(url)
        streams.append(
            RawAssetStream(
                kind="application",
                value=url,
                host=host,
                source=source,
                confidence=0.65,
                trusted=False,
                classification="external_asm",
                metadata={"tech": parts[1:]},
            )
        )
    return streams


def _parse_urls(stdout: str, source: str) -> list[RawAssetStream]:
    streams: list[RawAssetStream] = []
    for line in stdout.splitlines():
        url = line.strip()
        if not url.startswith(("http://", "https://")):
            continue
        host = _url_host(url)
        classification = "api_attack_surface" if any(token in url.lower() for token in ("api", "graphql", "swagger", "openapi")) else "external_asm"
        streams.append(
            RawAssetStream(
                kind="application",
                value=url,
                host=host,
                source=source,
                confidence=0.55,
                trusted=False,
                classification=classification,
                exposure="api" if classification == "api_attack_surface" else "external",
            )
        )
    return streams


def _vulnerability_payload(
    *,
    title: str,
    severity: str,
    source: str,
    host: str | None,
    port: int | None,
    business_criticality: int,
    cve: str | None = None,
    description: str | None = None,
    exposure: str = "external",
    details: dict[str, object] | None = None,
) -> dict[str, object]:
    enrichment = enrich_vulnerability(cve, severity, title, description)
    risk = compute_enterprise_risk(
        cvss=float(enrichment["cvss"]),
        epss=float(enrichment["epss"]),
        exploit_maturity=str(enrichment["exploit_maturity"]),
        exposure=exposure,
        asset_criticality=business_criticality,
        threat_context=str(enrichment["threat_context"]),
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
    )
    return {
        "fingerprint": _fingerprint(f"{host}|{port}|{source}|{title}|{cve or ''}"),
        "title": title,
        "description": description or title,
        "severity": _normalize_severity(severity),
        "source": source,
        "host": host,
        "port": port,
        "cve": enrichment["cve"],
        "cvss": enrichment["cvss"],
        "epss": enrichment["epss"],
        "exploit_maturity": enrichment["exploit_maturity"],
        "exposure": exposure,
        "asset_criticality": business_criticality,
        "threat_context": enrichment["threat_context"],
        "kev": enrichment["kev"],
        "ransomware": enrichment["ransomware"],
        "risk_score": risk["score"],
        "risk_factors": risk["factors"],
        "details": {
            **(details or {}),
            "references": enrichment["references"],
            "risk": risk,
        },
    }


def _parse_nuclei(stdout: str, business_criticality: int) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for line in stdout.splitlines():
        text = line.strip()
        if not text:
            continue
        severity_match = re.search(r"\[(critical|high|medium|low|info)\]", text, re.IGNORECASE)
        severity = severity_match.group(1).lower() if severity_match else "medium"
        cve = _extract_cve(text)
        title = re.sub(r"\[[^\]]+\]\s*", "", text).split("|")[0].strip()
        host_match = re.search(r"host=([^\s]+)", text, re.IGNORECASE)
        host = _url_host(host_match.group(1)) if host_match else None
        findings.append(
            _vulnerability_payload(
                title=title,
                severity=severity,
                source="nuclei",
                host=host,
                port=443,
                cve=cve,
                business_criticality=business_criticality,
            )
        )
    return findings


def _parse_structured_finding(stdout: str, source: str, business_criticality: int) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for line in stdout.splitlines():
        parts = [item.strip() for item in line.split("|")]
        if len(parts) < 3:
            continue
        severity, location, title = parts[:3]
        host = _url_host(location) if location.startswith(("http://", "https://")) else location
        port = 443 if location.startswith("https://") else 80 if location.startswith("http://") else None
        cve = _extract_cve(title)
        findings.append(
            _vulnerability_payload(
                title=title,
                severity=severity,
                source=source,
                host=host,
                port=port,
                cve=cve,
                business_criticality=business_criticality,
            )
        )
    return findings


def _deduplicate_streams(streams: list[RawAssetStream]) -> list[RawAssetStream]:
    best: dict[str, RawAssetStream] = {}
    for stream in streams:
        key = stream.asset_key()
        existing = best.get(key)
        if existing is None or stream.confidence > existing.confidence:
            best[key] = stream
    return list(best.values())


def _deduplicate_vulns(vulnerabilities: list[dict[str, object]]) -> list[dict[str, object]]:
    best: dict[str, dict[str, object]] = {}
    for vuln in vulnerabilities:
        fingerprint = str(vuln["fingerprint"])
        existing = best.get(fingerprint)
        if existing is None or _severity_rank(str(vuln["severity"])) > _severity_rank(str(existing["severity"])):
            best[fingerprint] = vuln
    return list(best.values())


def execute_scan_pipeline(target) -> PipelineResult:
    result = PipelineResult()
    raw_logs: list[str] = []

    stage_started = datetime.utcnow()
    intelligence = collect_multi_source_intelligence(target)
    result.streams.extend(intelligence["streams"])
    result.identities.extend(intelligence["identities"])
    result.relationships.extend(intelligence["relationships"])
    result.stage_logs.append(
        StageLog(
            name="multi_source_intelligence",
            status="completed",
            started_at=stage_started,
            finished_at=datetime.utcnow(),
            duration_ms=int((datetime.utcnow() - stage_started).total_seconds() * 1000),
            logs=f"Collected {len(intelligence['streams'])} raw asset streams and {len(intelligence['identities'])} identity observations.",
        ).to_record()
    )

    for stage, tools in stage_tool_plan().items():
        stage_start = datetime.utcnow()
        stage_logs: list[str] = []
        for tool in tools:
            tool_result: ToolResult = run_tool(tool, target.name, stage)
            result.tool_results.append(tool_result.to_record())
            raw_logs.append(f"## {tool}\n{tool_result.stdout}")
            stage_logs.append(f"{tool}: {'fallback' if tool_result.fallback_used else 'native'}")

            if tool in {"subfinder", "amass", "assetfinder", "puredns"}:
                result.streams.extend(_parse_subdomains(tool_result.stdout, tool))
            elif tool == "dnsx":
                streams, relationships = _parse_dnsx(tool_result.stdout)
                result.streams.extend(streams)
                result.relationships.extend(relationships)
            elif tool in {"naabu", "masscan", "nmap"}:
                result.streams.extend(_parse_ports(tool_result.stdout, target.name, tool))
            elif tool == "httpx":
                result.streams.extend(_parse_http(tool_result.stdout, tool))
            elif tool == "tlsx":
                result.streams.extend(_parse_tlsx(tool_result.stdout))
            elif tool in {"whatweb", "xingfinger"}:
                result.streams.extend(_parse_tech(tool_result.stdout, tool))
            elif tool in {"gau", "waybackurls", "waymore", "katana", "hakrawler"}:
                result.streams.extend(_parse_urls(tool_result.stdout, tool))
            elif tool == "nuclei":
                result.vulnerabilities.extend(_parse_nuclei(tool_result.stdout, target.business_criticality))
            elif tool in {"kxss", "dalfox", "nikto"}:
                result.vulnerabilities.extend(_parse_structured_finding(tool_result.stdout, tool, target.business_criticality))
            elif tool in {"ffuf", "dirsearch"}:
                for line in tool_result.stdout.splitlines():
                    parts = [item.strip() for item in line.split("|")]
                    if len(parts) < 2:
                        continue
                    status, path = parts[:2]
                    severity = "high" if path in {"/.env", "/backup", "/backup.zip"} else "medium"
                    result.vulnerabilities.append(
                        _vulnerability_payload(
                            title=f"Sensitive path discovered: {path}",
                            severity=severity,
                            source=tool,
                            host=target.name,
                            port=443,
                            business_criticality=target.business_criticality,
                            exposure="external",
                            details={"status": status, "path": path},
                        )
                    )

        stage_finish = datetime.utcnow()
        result.stage_logs.append(
            StageLog(
                name=stage,
                status="completed",
                started_at=stage_start,
                finished_at=stage_finish,
                duration_ms=int((stage_finish - stage_start).total_seconds() * 1000),
                logs="; ".join(stage_logs),
            ).to_record()
        )

    result.streams = _deduplicate_streams(result.streams)
    result.relationships.extend(infer_asset_relationships(result.streams))
    result.vulnerabilities.extend(generate_exposure_findings(result.streams, target.business_criticality))
    result.vulnerabilities = _deduplicate_vulns(result.vulnerabilities)

    summary = {
        "assets": len(result.streams),
        "vulnerabilities": len(result.vulnerabilities),
        "identities": len(result.identities),
        "external_assets": sum(1 for item in result.streams if item.exposure in {"external", "public", "api", "cloud"}),
        "classifications": {},
    }
    for stream in result.streams:
        summary["classifications"][stream.classification] = summary["classifications"].get(stream.classification, 0) + 1
    result.snapshot = summary
    result.raw_log = "\n\n".join(raw_logs)
    return result
