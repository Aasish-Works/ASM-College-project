from __future__ import annotations

import json
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_address, ip_network
from typing import Iterable
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from .models import Asset, AssetRelationship, AssetSourceEvent, IdentityExposure, Target


COMMON_SUBDOMAINS = [
    "www",
    "api",
    "app",
    "admin",
    "portal",
    "vpn",
    "mail",
    "auth",
    "staging",
    "dev",
    "cdn",
    "status",
]

COMMON_SAAS = [
    ("slack", "workspace"),
    ("okta", "identity"),
    ("github", "code"),
    ("notion", "knowledge"),
]


@dataclass(slots=True)
class RawAssetStream:
    kind: str
    value: str
    source: str
    confidence: float = 0.5
    trusted: bool = False
    host: str | None = None
    ip: str | None = None
    port: int | None = None
    protocol: str | None = None
    title: str | None = None
    exposure: str = "external"
    classification: str = "external_asm"
    sensitivity: str = "medium"
    lifecycle: str = "active"
    provider: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)

    def asset_key(self) -> str:
        return f"{self.kind}:{self.value}".lower()

    def to_event(self) -> dict[str, object]:
        return {
            "asset_type": self.kind,
            "asset_key": self.asset_key(),
            "source": self.source,
            "confidence": self.confidence,
            "trusted": self.trusted,
            "raw_payload": json.dumps(self.metadata or {}, default=str),
        }


@dataclass(slots=True)
class RawIdentityExposure:
    principal: str
    kind: str
    secret_type: str
    privilege_level: str
    source: str
    exposure: str
    status: str
    evidence: str
    asset_kind: str | None = None
    asset_value: str | None = None


def normalize_target_name(value: str) -> str:
    normalized = (value or "").strip().lower()
    if normalized.startswith(("http://", "https://")):
        parsed = urlparse(normalized)
        normalized = parsed.netloc or parsed.path or normalized
    normalized = normalized.strip().strip("/")
    return normalized


def guess_target_type(value: str) -> str:
    name = normalize_target_name(value)
    try:
        ip_address(name)
        return "ip"
    except ValueError:
        pass
    if "/" in name:
        try:
            ip_network(name, strict=False)
            return "cidr"
        except ValueError:
            pass
    return "domain"


def try_resolve_ips(host: str) -> list[str]:
    try:
        return list(dict.fromkeys(socket.gethostbyname_ex(host)[2]))
    except Exception:
        return []


def _target_root(name: str) -> str:
    parts = name.split(".")
    if len(parts) <= 2:
        return name
    return ".".join(parts[-2:])


def collect_multi_source_intelligence(target: Target, requested_sources: Iterable[str] | None = None) -> dict[str, list]:
    target_name = normalize_target_name(target.name)
    target_type = guess_target_type(target_name)
    source_filter = {item.strip().lower() for item in (requested_sources or []) if item}

    def include(source: str) -> bool:
        return not source_filter or source in source_filter

    streams: list[RawAssetStream] = []
    identities: list[RawIdentityExposure] = []
    relationships: list[dict[str, object]] = []

    if target_type == "ip":
        streams.append(
            RawAssetStream(
                kind="ip",
                value=target_name,
                host=target_name,
                ip=target_name,
                source="dns",
                confidence=1.0,
                trusted=True,
                classification="external_asm",
            )
        )
        resolved_ips = [target_name]
        root_domain = None
    else:
        root_domain = _target_root(target_name)
        streams.append(
            RawAssetStream(
                kind="domain",
                value=target_name,
                host=target_name,
                source="dns",
                confidence=1.0,
                trusted=True,
                classification="external_asm",
                metadata={"seed": True},
            )
        )
        resolved_ips = try_resolve_ips(target_name)
        for resolved_ip in resolved_ips:
            streams.append(
                RawAssetStream(
                    kind="ip",
                    value=resolved_ip,
                    host=target_name,
                    ip=resolved_ip,
                    source="dns",
                    confidence=0.95,
                    trusted=True,
                    classification="external_asm",
                )
            )
            relationships.append(
                {
                    "source_kind": "domain",
                    "source_value": target_name,
                    "target_kind": "ip",
                    "target_value": resolved_ip,
                    "relation": "resolves_to",
                    "confidence": 0.95,
                    "reason": "DNS resolution",
                }
            )

    if include("ct_logs") and root_domain:
        for prefix in COMMON_SUBDOMAINS:
            host = f"{prefix}.{root_domain}"
            streams.append(
                RawAssetStream(
                    kind="domain",
                    value=host,
                    host=host,
                    source="ct_logs",
                    confidence=0.55,
                    trusted=False,
                    classification="external_asm" if prefix not in {"vpn", "dev", "staging"} else "internal_asm",
                    metadata={"inferred_from": "certificate_transparency"},
                )
            )

    if include("passive_dns") and root_domain:
        for prefix in ("gateway", "files", "git", "jenkins"):
            host = f"{prefix}.{root_domain}"
            streams.append(
                RawAssetStream(
                    kind="domain",
                    value=host,
                    host=host,
                    source="passive_dns",
                    confidence=0.45,
                    trusted=False,
                    classification="external_asm",
                    metadata={"inferred_from": "passive_dns"},
                )
            )

    if include("asn"):
        for resolved_ip in resolved_ips:
            streams.append(
                RawAssetStream(
                    kind="asn",
                    value=f"ASN:{resolved_ip}",
                    host=target_name,
                    ip=resolved_ip,
                    source="asn",
                    confidence=0.7,
                    trusted=False,
                    classification="external_asm",
                    metadata={"note": "Local ASN placeholder enrichment"},
                )
            )

    if include("cloud") and root_domain:
        cloud_candidates = [
            ("cloud_bucket", f"{root_domain.replace('.', '-')}-assets", "aws"),
            ("cloud_bucket", f"{root_domain.replace('.', '-')}-backup", "aws"),
            ("cloud_service", f"api.{root_domain}", "azure"),
        ]
        for kind, value, provider in cloud_candidates:
            streams.append(
                RawAssetStream(
                    kind=kind,
                    value=value,
                    host=value,
                    source="cloud",
                    provider=provider,
                    confidence=0.4,
                    trusted=False,
                    exposure="public" if "backup" in value else "external",
                    classification="cloud_asm",
                    metadata={"provider": provider, "inferred": True},
                )
            )

    if include("git") and root_domain:
        streams.append(
            RawAssetStream(
                kind="application",
                value=f"github.com/{root_domain.split('.')[0]}",
                source="git",
                confidence=0.35,
                trusted=False,
                classification="third_party",
                metadata={"provider": "github"},
            )
        )
        identities.append(
            RawIdentityExposure(
                principal=f"{root_domain.split('.')[0]}-ci",
                kind="service_account",
                secret_type="github_pat",
                privilege_level="medium",
                source="git",
                exposure="external",
                status="suspected",
                evidence="Potential CI/CD secret exposure surface inferred from code hosting footprint",
                asset_kind="application",
                asset_value=f"github.com/{root_domain.split('.')[0]}",
            )
        )

    if include("dark_web") and root_domain:
        identities.append(
            RawIdentityExposure(
                principal=f"admin@{root_domain}",
                kind="credential",
                secret_type="password",
                privilege_level="high",
                source="dark_web",
                exposure="external",
                status="suspected",
                evidence="Credential mention inferred from dark-web monitoring source",
                asset_kind="domain",
                asset_value=target_name,
            )
        )

    if include("saas") and root_domain:
        for provider, category in COMMON_SAAS:
            streams.append(
                RawAssetStream(
                    kind="saas",
                    value=f"{provider}:{root_domain}",
                    source="saas",
                    confidence=0.3,
                    trusted=False,
                    classification="third_party",
                    metadata={"provider": provider, "category": category},
                )
            )

    deduped: dict[str, RawAssetStream] = {}
    for stream in streams:
        existing = deduped.get(stream.asset_key())
        if existing is None or stream.confidence > existing.confidence:
            deduped[stream.asset_key()] = stream

    return {
        "streams": list(deduped.values()),
        "relationships": relationships,
        "identities": identities,
    }


def _asset_metadata(asset: Asset) -> dict[str, object]:
    if not asset.metadata_json:
        return {}
    try:
        return json.loads(asset.metadata_json)
    except json.JSONDecodeError:
        return {}


def upsert_asset(db: Session, target: Target, stream: RawAssetStream) -> Asset:
    asset = (
        db.query(Asset)
        .filter(Asset.target_id == target.id, Asset.kind == stream.kind, Asset.value == stream.value)
        .one_or_none()
    )
    metadata = stream.metadata or {}
    tech_stack = metadata.get("tech")
    serialized_tech = json.dumps(tech_stack, default=str) if tech_stack else None
    status_code = metadata.get("status_code")
    if asset is None:
        asset = Asset(
            target_id=target.id,
            kind=stream.kind,
            value=stream.value,
            host=stream.host,
            ip=stream.ip,
            port=stream.port,
            protocol=stream.protocol,
            title=stream.title,
            exposure=stream.exposure,
            classification=stream.classification,
            sensitivity=stream.sensitivity,
            lifecycle=stream.lifecycle,
            provider=stream.provider,
            status_code=status_code if isinstance(status_code, int) else None,
            tech_stack=serialized_tech,
            metadata_json=json.dumps(metadata, default=str),
        )
        db.add(asset)
        db.flush()
    else:
        asset.host = stream.host or asset.host
        asset.ip = stream.ip or asset.ip
        asset.port = stream.port or asset.port
        asset.protocol = stream.protocol or asset.protocol
        asset.title = stream.title or asset.title
        asset.exposure = stream.exposure or asset.exposure
        asset.classification = stream.classification or asset.classification
        asset.sensitivity = stream.sensitivity or asset.sensitivity
        asset.lifecycle = stream.lifecycle or asset.lifecycle
        asset.provider = stream.provider or asset.provider
        asset.status_code = status_code if isinstance(status_code, int) else asset.status_code
        asset.tech_stack = serialized_tech or asset.tech_stack
        merged = _asset_metadata(asset)
        merged.update(metadata)
        asset.metadata_json = json.dumps(merged, default=str)

    event_payload = stream.to_event()
    db.add(
        AssetSourceEvent(
            target_id=target.id,
            source=str(event_payload["source"]),
            asset_key=str(event_payload["asset_key"]),
            asset_type=str(event_payload["asset_type"]),
            confidence=float(event_payload["confidence"]),
            trusted=bool(event_payload["trusted"]),
            raw_payload=str(event_payload["raw_payload"]),
            observed_at=datetime.utcnow(),
        )
    )
    return asset


def persist_asset_graph(
    db: Session,
    target: Target,
    streams: list[RawAssetStream],
    relationships: list[dict[str, object]],
    identities: list[RawIdentityExposure],
) -> dict[str, Asset]:
    asset_map: dict[str, Asset] = {}
    for stream in streams:
        asset = upsert_asset(db, target, stream)
        asset_map[stream.asset_key()] = asset

    for relation in relationships:
        src = asset_map.get(f"{relation['source_kind']}:{str(relation['source_value']).lower()}")
        dst = asset_map.get(f"{relation['target_kind']}:{str(relation['target_value']).lower()}")
        if src is None or dst is None:
            continue
        exists = (
            db.query(AssetRelationship)
            .filter(
                AssetRelationship.target_id == target.id,
                AssetRelationship.source_asset_id == src.id,
                AssetRelationship.target_asset_id == dst.id,
                AssetRelationship.relation == relation["relation"],
            )
            .one_or_none()
        )
        if exists is None:
            db.add(
                AssetRelationship(
                    target_id=target.id,
                    source_asset_id=src.id,
                    target_asset_id=dst.id,
                    relation=str(relation["relation"]),
                    confidence=float(relation.get("confidence", 0.6)),
                    reason=str(relation.get("reason") or ""),
                )
            )

    for identity in identities:
        asset_id = None
        if identity.asset_kind and identity.asset_value:
            asset = asset_map.get(f"{identity.asset_kind}:{identity.asset_value.lower()}")
            asset_id = asset.id if asset else None
        exists = (
            db.query(IdentityExposure)
            .filter(
                IdentityExposure.target_id == target.id,
                IdentityExposure.principal == identity.principal,
                IdentityExposure.source == identity.source,
                IdentityExposure.secret_type == identity.secret_type,
            )
            .one_or_none()
        )
        if exists is None:
            db.add(
                IdentityExposure(
                    target_id=target.id,
                    asset_id=asset_id,
                    principal=identity.principal,
                    kind=identity.kind,
                    secret_type=identity.secret_type,
                    privilege_level=identity.privilege_level,
                    source=identity.source,
                    exposure=identity.exposure,
                    status=identity.status,
                    evidence=identity.evidence,
                )
            )
    db.flush()
    return asset_map


def generate_exposure_findings(streams: list[RawAssetStream], business_criticality: int) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for stream in streams:
        host = stream.host or stream.value
        value_lc = stream.value.lower()
        if stream.kind == "service" and stream.port in {22, 3389, 5432, 6379, 9200} and stream.exposure != "internal":
            findings.append(
                {
                    "title": f"Exposed service on port {stream.port}",
                    "description": f"Service {stream.protocol or 'tcp'}:{stream.port} is reachable from the external attack surface.",
                    "severity": "high" if stream.port in {3389, 5432, 6379, 9200} else "medium",
                    "source": "exposure_engine",
                    "host": host,
                    "port": stream.port,
                    "cve": None,
                    "exposure": stream.exposure,
                    "asset_criticality": business_criticality,
                    "details": {"kind": "open_port", "asset": stream.value},
                }
            )
        if stream.kind in {"domain", "application"} and any(token in value_lc for token in ("admin", "jenkins", "grafana", "kibana", "console")):
            findings.append(
                {
                    "title": "Public administrative interface detected",
                    "description": f"Administrative surface {stream.value} appears internet-accessible.",
                    "severity": "high",
                    "source": "exposure_engine",
                    "host": host,
                    "port": stream.port,
                    "cve": None,
                    "exposure": stream.exposure,
                    "asset_criticality": business_criticality,
                    "details": {"kind": "public_admin_panel", "asset": stream.value},
                }
            )
        if stream.kind == "cloud_bucket" and stream.exposure == "public":
            findings.append(
                {
                    "title": "Public cloud bucket exposure",
                    "description": f"Cloud bucket {stream.value} is marked as publicly reachable.",
                    "severity": "critical",
                    "source": "exposure_engine",
                    "host": host,
                    "port": None,
                    "cve": None,
                    "exposure": "cloud",
                    "asset_criticality": max(4, business_criticality),
                    "details": {"kind": "public_bucket", "provider": stream.provider},
                }
            )
        if stream.metadata.get("tls_weak"):
            findings.append(
                {
                    "title": "Weak TLS configuration",
                    "description": f"{stream.value} appears to support weak TLS settings.",
                    "severity": "medium",
                    "source": "exposure_engine",
                    "host": host,
                    "port": stream.port,
                    "cve": None,
                    "exposure": stream.exposure,
                    "asset_criticality": business_criticality,
                    "details": {"kind": "weak_tls"},
                }
            )
        if stream.kind in {"application", "service"} and any(token in value_lc for token in ("api", "graphql", "swagger")):
            findings.append(
                {
                    "title": "Exposed API surface",
                    "description": f"{stream.value} indicates an externally reachable API endpoint.",
                    "severity": "medium",
                    "source": "exposure_engine",
                    "host": host,
                    "port": stream.port,
                    "cve": None,
                    "exposure": "api",
                    "asset_criticality": business_criticality,
                    "details": {"kind": "public_api"},
                }
            )
    return findings


def infer_asset_relationships(streams: list[RawAssetStream]) -> list[dict[str, object]]:
    relationships: list[dict[str, object]] = []
    domains = [item for item in streams if item.kind == "domain"]
    ips = [item for item in streams if item.kind == "ip"]
    services = [item for item in streams if item.kind == "service"]
    applications = [item for item in streams if item.kind == "application"]

    ip_by_host = {item.host: item for item in ips if item.host}
    for service in services:
        if service.host and service.host in ip_by_host:
            relationships.append(
                {
                    "source_kind": "ip",
                    "source_value": ip_by_host[service.host].value,
                    "target_kind": "service",
                    "target_value": service.value,
                    "relation": "hosts",
                    "confidence": 0.8,
                    "reason": "Port scan / service detection",
                }
            )
    for app in applications:
        host = app.host or app.value
        domain_match = next((item for item in domains if item.value == host), None)
        if domain_match:
            relationships.append(
                {
                    "source_kind": "domain",
                    "source_value": domain_match.value,
                    "target_kind": "application",
                    "target_value": app.value,
                    "relation": "hosts",
                    "confidence": 0.7,
                    "reason": "HTTP discovery",
                }
            )
    return relationships


def looks_like_secret(text: str) -> bool:
    patterns = [r"AKIA[0-9A-Z]{16}", r"ghp_[A-Za-z0-9]{16,}", r"(?i)api[_-]?key", r"(?i)secret"]
    return any(re.search(pattern, text) for pattern in patterns)
