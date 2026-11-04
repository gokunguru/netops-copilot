"""Data model of a change: what was asked (Intent), what is proposed (ProposedChange), what the
gate decided (GateResult), and the record of a run. Every model output is validated against it."""

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class Vendor(str, Enum):
    """Network OS families the generator, the config models and the drivers understand."""

    CISCO_IOS = "cisco_ios"
    HUAWEI_VRP = "huawei_vrp"


class ChangeType(str, Enum):
    VLAN_PROVISION = "vlan_provision"  # add a VLAN (never remove or rename one)
    ACL_AUDIT = "acl_audit"  # read-only compliance report
    ACL_REMEDIATE = "acl_remediate"  # add rules or bind a filter, only where non-compliant


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
    """The request once parsed: a change type, the devices it may touch, and its parameters."""

    change_type: ChangeType
    targets: list[str] = Field(min_length=1, description="hostnames the change is allowed to touch")
    params: dict = Field(default_factory=dict)
    summary: str


class ProposedChange(BaseModel):
    """Commands for one device, as typed in configuration mode."""

    device: str
    vendor: Vendor
    commands: list[str]


class Verdict(str, Enum):
    PASS = "PASS"  # nosec B105
    REJECT = "REJECT"


class GateResult(BaseModel):
    """Verdict of the safety gate and, when it rejects, every reason found."""

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

    name: Literal["read", "tool", "investigate", "parse", "generate", "gate", "dry_run",
                  "policy", "review_tool", "review", "explain", "audit"]
    ok: bool
    attempt: int | None = None
    detail: str = ""


class Reading(BaseModel):
    """What the model read from the attached images. Data, never instructions: the request
    still goes through parse, gate, dry-run and human approval."""

    request: str = Field(min_length=1, max_length=500)
    seen: str = Field(default="", max_length=1000)
    confidence: Literal["high", "medium", "low"]
    images: list[str] = Field(default_factory=list)


class Risk(BaseModel):
    """Minimum risk level computed from the validated change, without any model."""

    level: Literal["low", "medium", "high"]
    reasons: list[str] = Field(default_factory=list)
    human: bool = False  # a deterministic rule requires a human decision (never auto-approved)


class ToolCall(BaseModel):
    name: str
    arguments: dict = Field(default_factory=dict)
    ok: bool
    output: str


class Investigation(BaseModel):
    """What the agent looked at with its read-only tools, and what it concluded."""

    goal: str
    calls: list[ToolCall] = Field(default_factory=list)
    answer: str = ""
    request: str | None = None  # the change it asks for, still to be parsed, gated and approved


class Concern(BaseModel):
    severity: Literal["low", "medium", "high"]
    device: str = ""
    text: str = Field(min_length=1, max_length=500)


class Review(BaseModel):
    """Verdict of the independent reviewer: a separate model session that only sees the change,
    never the generator's prompts or reasoning, and can only escalate to the human."""

    verdict: Literal["approve", "escalate"]
    summary: str = ""
    concerns: list[Concern] = Field(default_factory=list)
    calls: list[ToolCall] = Field(default_factory=list)
    model: str = ""

    @property
    def escalated(self) -> bool:
        return self.verdict == "escalate"


class RunResult(BaseModel):
    request: str
    reading: Reading | None = None
    investigation: Investigation | None = None
    intent: Intent | None = None
    attempts: list[Attempt] = Field(default_factory=list)
    diffs: dict[str, str] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    explanation: str = ""
    risk: Risk | None = None
    review: Review | None = None
    policy: str | None = None  # set when the intent comes from a versioned policy
    error: str = ""

    @property
    def answered(self) -> bool:
        """Investigation that ended with an answer and no change to propose."""
        return (self.investigation is not None and self.investigation.request is None
                and not self.error)

    @property
    def escalated(self) -> bool:
        """The reviewer or a deterministic rule asks for a human decision: never auto-approved."""
        return ((self.review is not None and self.review.escalated)
                or (self.risk is not None and self.risk.human))

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
