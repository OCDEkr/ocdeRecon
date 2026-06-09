"""Domain models — the unified data model shared across every tool.

These Pydantic models mirror the SQLite schema in ``pentui.persistence.db`` (see
PROJECT.md §8). Persisted entities carry an optional ``id`` that is ``None`` until
written. ``ScanResult`` is the (unpersisted) container a parser returns.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #
class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"
    CANCELLED = "cancelled"


class WorkflowStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"
    CANCELLED = "cancelled"


class GateState(StrEnum):
    AUTO = "auto"  # ran without a gate
    PENDING = "pending"  # waiting for operator approval
    APPROVED = "approved"  # operator approved a gated step
    SKIPPED = "skipped"  # branch skipped (failure or out-of-scope)


class ScopeKind(StrEnum):
    INCLUDE = "include"
    EXCLUDE = "exclude"


class TargetSource(StrEnum):
    MANUAL = "manual"
    FILE = "file"
    CHAINED = "chained"  # produced by an upstream workflow step
    PROJECT = "project"


class Severity(StrEnum):
    UNKNOWN = "unknown"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# --------------------------------------------------------------------------- #
# Engagement / scope / targets
# --------------------------------------------------------------------------- #
class Project(BaseModel):
    id: int | None = None
    name: str
    client: str | None = None
    notes: str | None = None
    created_at: datetime | None = None


class ScopeRule(BaseModel):
    id: int | None = None
    project_id: int
    value: str  # CIDR or single host/IP
    kind: ScopeKind


class Target(BaseModel):
    id: int | None = None
    project_id: int
    value: str
    source: TargetSource = TargetSource.MANUAL
    added_at: datetime | None = None


# --------------------------------------------------------------------------- #
# Scans and normalized results
# --------------------------------------------------------------------------- #
class Scan(BaseModel):
    id: int | None = None
    project_id: int
    tool: str
    profile: str | None = None
    command_str: str | None = None
    args: list[str] = Field(default_factory=list)
    status: ScanStatus = ScanStatus.QUEUED
    exit_code: int | None = None
    ran_as_root: bool = False
    started_at: datetime | None = None
    finished_at: datetime | None = None
    raw_output_path: str | None = None
    artifact_path: str | None = None
    step_run_id: int | None = None  # set when produced by a workflow step


class Service(BaseModel):
    id: int | None = None
    port_id: int | None = None
    name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    cpe: str | None = None


class Port(BaseModel):
    id: int | None = None
    host_id: int | None = None
    discovered_by_scan_id: int | None = None
    number: int
    protocol: str = "tcp"
    state: str = "open"
    reason: str | None = None
    service: Service | None = None


class Host(BaseModel):
    id: int | None = None
    project_id: int | None = None
    ip: str
    hostname: str | None = None
    state: str = "up"
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    ports: list[Port] = Field(default_factory=list)


class Finding(BaseModel):
    id: int | None = None
    project_id: int | None = None
    host_id: int | None = None
    scan_id: int | None = None
    source_tool: str
    severity: Severity = Severity.UNKNOWN
    title: str
    detail: str | None = None
    created_at: datetime | None = None
    #: Transient — set by parsers to resolve host_id at merge time; not persisted.
    host_ip: str | None = None


class ScanResult(BaseModel):
    """Normalized output a parser returns; merged into the engagement DB by core."""

    hosts: list[Host] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Workflow runs (orchestration — PROJECT.md §7)
# --------------------------------------------------------------------------- #
class WorkflowRun(BaseModel):
    id: int | None = None
    project_id: int
    workflow_name: str
    definition_json: str | None = None  # snapshot of the workflow definition
    status: WorkflowStatus = WorkflowStatus.QUEUED
    unattended: bool = False
    started_at: datetime | None = None
    finished_at: datetime | None = None


class StepRun(BaseModel):
    id: int | None = None
    workflow_run_id: int
    step_id: str  # the step's id within the workflow definition
    tool: str
    scan_id: int | None = None
    status: ScanStatus = ScanStatus.QUEUED
    gate_state: GateState = GateState.AUTO
    started_at: datetime | None = None
    finished_at: datetime | None = None
