"""Policy as code: versioned YAML policies, checked without any model.

A policy is reviewed in a pull request like code. `--check-policies` evaluates every policy
against the inventory (exit code 3 on drift), the scheduled CI workflow turns drift into a
GitHub issue, and `--enforce <policy>` turns a policy into a structured intent directly (no
parse step): the fix still goes through generate, gate, dry-run, risk floor and approval.
"""

import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, ValidationError, model_validator

from netops_copilot.audit import acl
from netops_copilot.lab import simulator
from netops_copilot.models import ChangeType, Device, Flow, Intent, VlanParams

DEFAULT_DIR = Path(os.getenv("NETOPS_POLICIES")
                   or Path(__file__).resolve().parents[2] / "policies")


class PolicyError(ValueError):
    pass


class Policy(BaseModel):
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")
    description: str = ""
    owner: str = ""
    severity: Literal["low", "medium", "high"] = "medium"
    devices: Literal["all"] | list[str] = "all"
    flows: list[Flow] | None = Field(default=None, min_length=1, max_length=20)
    vlans: list[VlanParams] | None = Field(default=None, min_length=1, max_length=50)
    file: str = ""

    @model_validator(mode="after")
    def one_kind(self) -> "Policy":
        if (self.flows is None) == (self.vlans is None):
            raise ValueError("a policy defines either `flows` (ACL) or `vlans`, not both")
        return self

    @property
    def kind(self) -> str:
        return "acl" if self.flows else "vlan"

    def scope(self, devices: dict[str, Device]) -> list[str]:
        return list(devices) if self.devices == "all" else self.devices


class Row(BaseModel):
    """One checked item: an interface and flow for ACL policies, a VLAN for VLAN policies."""

    device: str
    subject: str
    expected: str
    actual: str
    detail: str = ""

    @property
    def compliant(self) -> bool:
        return self.expected == self.actual


class PolicyResult(BaseModel):
    policy: Policy
    rows: list[Row]

    @property
    def failed(self) -> list[Row]:
        return [r for r in self.rows if not r.compliant]

    @property
    def compliant(self) -> bool:
        return not self.failed


def load(directory: str | Path = DEFAULT_DIR) -> list[Policy]:
    directory = Path(directory)
    files = sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")])
    if not files:
        raise PolicyError(f"no policy file (*.yml) in {directory}")
    policies: list[Policy] = []
    for path in files:
        try:
            policy = Policy(**(yaml.safe_load(path.read_text()) or {}), file=path.name)
        except (ValidationError, TypeError, yaml.YAMLError) as exc:
            raise PolicyError(f"{path.name}: {exc}") from exc
        if policy.name in {p.name for p in policies}:
            raise PolicyError(f"{path.name}: duplicate policy name '{policy.name}'")
        policies.append(policy)
    return policies


def check(policy: Policy, devices: dict[str, Device]) -> PolicyResult:
    unknown = [h for h in policy.scope(devices) if h not in devices]
    if unknown:
        raise PolicyError(f"policy {policy.name}: unknown devices {unknown}")
    rows: list[Row] = []
    for host in policy.scope(devices):
        if policy.flows:
            rows += [Row(device=host, subject=f"{f.interface} {f.flow.label}",
                         expected=f.flow.expected, actual=f.actual, detail=f.matched)
                     for f in acl.audit(devices[host], policy.flows)]
        else:
            present = simulator.parse_vlans(devices[host].config)
            for v in policy.vlans:
                name = present.get(v.vlan_id)
                actual = "missing" if name is None else (name or "(no name)")
                rows.append(Row(device=host, subject=f"vlan {v.vlan_id}", expected=v.name,
                                actual=actual))
    return PolicyResult(policy=policy, rows=rows)


def check_all(policies: list[Policy], devices: dict[str, Device]) -> list[PolicyResult]:
    return [check(p, devices) for p in policies]


def intent(result: PolicyResult) -> Intent | None:
    """Structured intent that enforces the policy, or None if nothing can be enforced."""
    policy = result.policy
    failing = list(dict.fromkeys(r.device for r in result.failed))
    if not failing:
        return None
    if policy.flows:
        return Intent(change_type=ChangeType.ACL_REMEDIATE, targets=failing,
                      params={"flows": [f.model_dump() for f in policy.flows]},
                      summary=f"Enforce policy {policy.name} on {', '.join(failing)}")
    # One VLAN per change: the first one missing somewhere. Renames are left to an operator.
    for v in policy.vlans:
        missing = [r.device for r in result.failed
                   if r.subject == f"vlan {v.vlan_id}" and r.actual == "missing"]
        if missing:
            return Intent(change_type=ChangeType.VLAN_PROVISION, targets=missing,
                          params=v.model_dump(),
                          summary=f"Enforce policy {policy.name}: VLAN {v.vlan_id} "
                                  f"{v.name} on {', '.join(missing)}")
    return None


def fingerprint(results: list[PolicyResult]) -> str:
    """Stable id of the drift itself (not of the time it was seen): same drift, same id."""
    rows = sorted(f"{r.policy.name}|{x.device}|{x.subject}|{x.actual}"
                  for r in results for x in r.failed)
    return hashlib.sha256("\n".join(rows).encode()).hexdigest()[:16]


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def report(results: list[PolicyResult], inventory: str, limit: int = 30) -> str:
    """Markdown report, used as the body of the drift issue."""
    drift = [r for r in results if not r.compliant]
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    out = [f"## {'Policy drift detected' if drift else 'All policies compliant'}", "",
           f"Inventory `{inventory}` · checked {now}"
           + (f" · commit `{os.environ['GITHUB_SHA'][:7]}`" if os.getenv("GITHUB_SHA") else ""),
           "", "| Policy | Severity | Owner | Result |", "|---|---|---|---|"]
    for r in results:
        status = ("compliant" if r.compliant
                  else f"**{len(r.failed)} of {len(r.rows)} checks failed**")
        out.append(f"| `{r.policy.name}` | {r.policy.severity} | {r.policy.owner or '-'} "
                   f"| {status} |")
    for r in drift:
        out += ["", f"### `{r.policy.name}`", "", r.policy.description, "",
                "| Device | Checked | Expected | Actual | Decided by |", "|---|---|---|---|---|"]
        out += [f"| {_cell(x.device)} | {_cell(x.subject)} | {x.expected} | {_cell(x.actual)} "
                f"| {_cell(x.detail or '-')} |" for x in r.failed[:limit]]
        if len(r.failed) > limit:
            out.append(f"| … | {len(r.failed) - limit} more | | | |")
        out += ["", f"Fix with validation and approval: `netops-copilot --enforce {r.policy.name}`"]
    out += ["", "_Generated by NetOps Copilot. Deterministic check, no model involved._",
            f"<!-- fingerprint: {fingerprint(results)} -->"]
    return "\n".join(out)
