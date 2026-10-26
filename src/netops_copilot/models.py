"""Core data structures shared across the pipeline."""

from enum import Enum

from pydantic import BaseModel, Field


class Vendor(str, Enum):
    CISCO_IOS = "cisco_ios"
    HUAWEI_VRP = "huawei_vrp"


class ChangeType(str, Enum):
    VLAN_PROVISION = "vlan_provision"
    ACL_AUDIT = "acl_audit"
    QOS_CHECK = "qos_check"


class Intent(BaseModel):
    """Structured version of a plain-language change request."""

    change_type: ChangeType
    targets: list[str] = Field(min_length=1, description="Device hostnames in scope")
    params: dict = Field(default_factory=dict)
    summary: str


class ProposedChange(BaseModel):
    """Config generated for one device."""

    device: str
    vendor: Vendor
    commands: list[str]


class Verdict(str, Enum):
    PASS = "PASS"
    REJECT = "REJECT"


class GateResult(BaseModel):
    verdict: Verdict
    violations: list[str] = Field(default_factory=list)
