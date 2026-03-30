from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class OrganizationCreate(BaseModel):
    name: str
    slug: str
    description: str | None = None


class TargetCreate(BaseModel):
    name: str
    scope: str | None = None
    target_type: str = "domain"
    description: str | None = None
    business_criticality: int = Field(default=3, ge=1, le=5)
    priority: int = Field(default=3, ge=1, le=5)
    organization_id: int | None = None


class TargetUpdate(BaseModel):
    scope: str | None = None
    description: str | None = None
    business_criticality: int | None = Field(default=None, ge=1, le=5)
    priority: int | None = Field(default=None, ge=1, le=5)
    monitoring_enabled: bool | None = None
    lifecycle: str | None = None
    tags: str | None = None


class ScanCreate(BaseModel):
    kind: str = "full_scan"
    trigger: str = "manual"
    cron: str | None = None
    priority: int = Field(default=3, ge=1, le=5)
    max_retries: int = Field(default=2, ge=0, le=10)


class ScanOrCreateRequest(BaseModel):
    name: str
    scope: str | None = None
    target_type: str = "domain"
    description: str | None = None
    business_criticality: int = Field(default=3, ge=1, le=5)
    priority: int = Field(default=3, ge=1, le=5)
    organization_id: int | None = None
    scan_kind: str = "full_scan"
    trigger: str = "manual"
    max_retries: int = Field(default=2, ge=0, le=10)


class MonitoringRuleCreate(BaseModel):
    name: str
    mode: str = "scheduled"
    cron: str | None = None
    event_type: str | None = None
    enabled: bool = True


class AutomationRuleCreate(BaseModel):
    name: str
    event: str
    action: str
    enabled: bool = True
    configuration: dict[str, Any] = Field(default_factory=dict)


class NodeHeartbeat(BaseModel):
    node_name: str
    capabilities: list[str] = Field(default_factory=list)
    current_load: int = 0
    capacity: int = 4
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    disk_percent: float = 0.0


class VulnerabilityUpdate(BaseModel):
    status: str | None = None
    notes: str | None = None
    asset_criticality: int | None = Field(default=None, ge=1, le=5)


class AssignmentRequest(BaseModel):
    assignee: str


class TicketCreate(BaseModel):
    provider: str = "internal"
    external_id: str | None = None
    title: str
    description: str | None = None


class ExceptionCreate(BaseModel):
    justification: str
    requested_by: str | None = None
    expires_at: datetime | None = None


class ApiKeyCreate(BaseModel):
    provider: str
    label: str
    key_value: str
    is_active: bool = True


class BlacklistEntryCreate(BaseModel):
    pattern: str
    scope: str = "global"
    target_id: int | None = None
    reason: str | None = None


class NotificationCreate(BaseModel):
    channel: str
    destination: str
    severity: str = "medium"
    subject: str
    message: str


class IntelligenceRunRequest(BaseModel):
    sources: list[str] = Field(default_factory=list)
    include_dark_web: bool = True
    include_git: bool = True


class ThreatIntelRefreshRequest(BaseModel):
    cve: str | None = None


class ToolExecutionRequest(BaseModel):
    tool: str
    target: str
    stage: str | None = None
    timeout_seconds: int | None = Field(default=None, ge=1, le=300)
