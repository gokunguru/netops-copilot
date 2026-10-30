"""Core data structures shared across the pipeline."""

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class Vendor(str, Enum):
    CISCO_IOS = "cisco_ios"
    HUAWEI_VRP = "huawei_vrp"


class ChangeType(str, Enum):
    VLAN_PROVISION = "vlan_provision"
    ACL_AUDIT = "acl_audit"
    ACL_REMEDIATE = "acl_remediate"


class Device(BaseModel):
    hostname: str
    vendor: Vendor
    config: str
    # Interfaces the ACL policy applies to. None: every interface that has an inbound filter.
    edge: list[str] | None = None
    # Interfaces the agent must never modify (management, uplinks to the jump host...).
    protected: list[str] = Field(default_factory=list)
    # Live device connection settings (see drivers.py). None: offline lab model.
    driver: dict | None = None

    @property
    def live(self) -> bool:
        return self.driver is not None


class VlanParams(BaseModel):
    vlan_id: int = Field(ge=1, le=4094)
    name: str = Field(min_length=1, max_length=31, pattern=r"^[A-Za-z0-9_-]+$")


class Flow(BaseModel):
    """A test flow (any source to any destination) and the action policy expects for it."""

    label: str
    protocol: Literal["tcp", "udp", "icmp", "ip"]
    dst_port: int | None = Field(default=None, ge=1, le=65535)
    expected: Literal["permit", "deny"]


class AclAuditParams(BaseModel):
    flows: list[Flow] = Field(min_length=1, max_length=20)


class Intent(BaseModel):
    """Structured version of a plain-language change request."""

    change_type: ChangeType
    targets: list[str] = Field(min_length=1, description="Device hostnames in scope")
    params: dict = Field(default_factory=dict)
    summary: str


class ProposedChange(BaseModel):
    """Config generated for one device, in configuration-mode commands."""

    device: str
    vendor: Vendor
    commands: list[str]


class Verdict(str, Enum):
    PASS = "PASS"  # nosec B105
    REJECT = "REJECT"


class GateResult(BaseModel):
    verdict: Verdict
    violations: list[str] = Field(default_factory=list)


class Attempt(BaseModel):
    """One generate -> gate -> dry-run round."""

    number: int
    changes: list[ProposedChange]
    gate: GateResult
    dry_run_errors: list[str] = Field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.gate.verdict == Verdict.PASS and not self.dry_run_errors


class Finding(BaseModel):
    """Result of evaluating one flow against the inbound filter of one interface."""

    device: str
    interface: str
    acl: str
    flow: Flow
    actual: Literal["permit", "deny"]
    matched: str

    @property
    def compliant(self) -> bool:
        return self.actual == self.flow.expected


class Step(BaseModel):
    """Progress event emitted by the pipeline after each step (used by the web UI)."""

    name: Literal["parse", "generate", "gate", "dry_run", "explain", "audit"]
    ok: bool
    attempt: int | None = None
    detail: str = ""


class RunResult(BaseModel):
    request: str
    intent: Intent | None = None
    attempts: list[Attempt] = Field(default_factory=list)
    diffs: dict[str, str] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    explanation: str = ""
    error: str = ""

    @property
    def is_audit(self) -> bool:
        return self.intent is not None and self.intent.change_type == ChangeType.ACL_AUDIT

    @property
    def compliant(self) -> bool:
        return bool(self.findings) and all(f.compliant for f in self.findings)

    @property
    def ready_for_approval(self) -> bool:
        return bool(self.attempts) and self.attempts[-1].ok and not self.error

    @property
    def final_changes(self) -> list[ProposedChange]:
        return self.attempts[-1].changes if self.ready_for_approval else []
