"""Data models shared across the pipeline, DB, web dashboard and bot."""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class Verdict(str, Enum):
    UNVERIFIED = "unverified"
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"


@dataclass
class ScopeRule:
    pattern: str  # e.g. "*.example.com" or "192.168.1.0/24"
    included: bool = True  # False = explicitly out of scope


@dataclass
class Target:
    name: str  # canonical folder-safe name, e.g. "example-com"
    root_domain: str
    scope: list[ScopeRule] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class Finding:
    id: int | None
    target: str
    tool: str
    kind: str  # e.g. "nuclei", "dalfox-xss", "port"
    severity: str
    title: str
    matched_url: str
    evidence: str
    verdict: Verdict = Verdict.UNVERIFIED
    ai_summary: str = ""
    ai_confidence: float = 0.0
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class Job:
    id: int | None
    target: str
    status: JobStatus
    created_at: datetime = field(default_factory=datetime.utcnow)
    finished_at: datetime | None = None
    summary: str = ""
