"""Read-only tools the agent can call to investigate before proposing a change.

There is no write tool: the agent can only look. Whatever it concludes leaves as a plain-language
request that goes through parse, gate, dry-run and human approval like a typed one.
Every tool reads the device snapshot the run validates against (no extra SSH session), so the
agent and the deterministic checks see the same state. Tool output is data, never instructions.
"""

import json
import re
from collections.abc import Callable

from pydantic import BaseModel, Field, ValidationError

from netops_copilot.audit import acl
from netops_copilot.lab import config_editor, simulator
from netops_copilot.models import Device, Flow

MAX_CALLS = 8
MAX_OUTPUT = 6000  # characters per tool result sent back to the model


class ToolError(ValueError):
    pass


class _NoArgs(BaseModel):
    pass


class _Device(BaseModel):
    device: str


class _ShowConfig(BaseModel):
    device: str
    section: str | None = Field(default=None, max_length=60)


class _Vlans(BaseModel):
    device: str | None = None


class _Audit(BaseModel):
    flows: list[Flow] = Field(min_length=1, max_length=20)
    devices: list[str] | None = None


class Finish(BaseModel):
    answer: str = Field(min_length=1, max_length=2000)
    request: str | None = Field(default=None, max_length=500)


def _device(devices: dict[str, Device], name: str) -> Device:
    if name not in devices:
        raise ToolError(f"unknown device '{name}', known: {', '.join(devices)}")
    return devices[name]


def list_devices(devices: dict[str, Device], _: BaseModel) -> list[dict]:
    return [{"hostname": d.hostname, "vendor": d.vendor.value, "live": d.live,
             "edge_interfaces": d.edge, "protected_interfaces": d.protected}
            for d in devices.values()]


def show_config(devices: dict[str, Device], args: _ShowConfig) -> str:
    config = _device(devices, args.device).config
    if not args.section:
        return config
    blocks = [b for b in config_editor._split(config)
              if b[0].lower().startswith(args.section.lower().strip())]
    if not blocks:
        raise ToolError(f"no top-level block starting with '{args.section}' on {args.device}")
    return "\n".join(line for block in blocks for line in block)


def list_interfaces(devices: dict[str, Device], args: _Device) -> list[dict]:
    device = _device(devices, args.device)
    filters = acl.inbound_filters(device)
    result = []
    for block in config_editor._split(device.config):
        if m := re.match(r"^interface (\S+)", block[0]):
            name = m.group(1)
            desc = next((ln.split(None, 1)[1] for ln in block[1:]
                         if ln.strip().startswith("description ")), "")
            result.append({"interface": name, "description": desc,
                           "inbound_filter": filters.get(name),
                           "edge": None if device.edge is None else name in device.edge,
                           "protected": name in device.protected})
    return result


def list_vlans(devices: dict[str, Device], args: _Vlans) -> dict:
    scope = [_device(devices, args.device)] if args.device else list(devices.values())
    return {d.hostname: {str(k): v for k, v in simulator.parse_vlans(d.config).items()}
            for d in scope}


def audit_acls(devices: dict[str, Device], args: _Audit) -> dict:
    scope = [_device(devices, h) for h in (args.devices or devices)]
    findings = [f for d in scope for f in acl.audit(d, args.flows)]
    return {"checks": len(findings),
            "non_compliant": [{"device": f.device, "interface": f.interface, "acl": f.acl,
                               "flow": f.flow.label, "expected": f.flow.expected,
                               "actual": f.actual, "decided_by": f.matched}
                              for f in findings if not f.compliant]}


TOOLS: dict[str, tuple[type[BaseModel], Callable, str]] = {
    "list_devices": (_NoArgs, list_devices,
                     ("Inventory: hostname, vendor, live or lab, edge and protected interfaces "
                      "(edge null: not declared, every interface is audited).")),
    "show_config": (_ShowConfig, show_config,
                    ("Current config of one device, or only the top-level blocks whose first "
                     "line starts with `section` (e.g. 'interface', 'ip access-list', 'acl').")),
    "list_interfaces": (_Device, list_interfaces,
                        "Interfaces of one device: description, inbound ACL, edge (null if not declared), protected."),
    "list_vlans": (_Vlans, list_vlans, "VLAN ids and names, on one device or on all devices."),
    "audit_acls": (_Audit, audit_acls,
                   ("Deterministic inbound ACL audit: for each flow, the action each edge "
                    "interface actually applies (first match, vendor defaults) vs the expected one.")),
}

_FLOW = {"type": "object", "required": ["label", "protocol", "expected"], "properties": {
    "label": {"type": "string", "description": "service name, e.g. telnet"},
    "protocol": {"type": "string", "enum": ["tcp", "udp", "icmp", "ip"]},
    "dst_port": {"type": ["integer", "null"]},
    "expected": {"type": "string", "enum": ["permit", "deny"]}}}
_PARAMS = {
    "list_devices": {},
    "show_config": {"device": {"type": "string"}, "section": {"type": "string"}},
    "list_interfaces": {"device": {"type": "string"}},
    "list_vlans": {"device": {"type": "string", "description": "omit for every device"}},
    "audit_acls": {"flows": {"type": "array", "items": _FLOW},
                   "devices": {"type": "array", "items": {"type": "string"},
                               "description": "omit for every device"}},
    "finish": {"answer": {"type": "string", "description": "what you found, grounded in tool results"},
               "request": {"type": ["string", "null"],
                           "description": "one plain-language change request, or null"}},
}
_REQUIRED = {"show_config": ["device"], "list_interfaces": ["device"], "audit_acls": ["flows"],
             "finish": ["answer"]}
FINISH_DOC = "End the investigation: your answer, and the change request if one is needed."


def specs() -> list[dict]:
    """OpenAI-compatible tool definitions (the Meta Model API uses the same format)."""
    docs = {name: doc for name, (_, _, doc) in TOOLS.items()} | {"finish": FINISH_DOC}
    return [{"type": "function", "function": {
        "name": name, "description": docs[name],
        "parameters": {"type": "object", "properties": props,
                       "required": _REQUIRED.get(name, [])}}}
        for name, props in _PARAMS.items()]


def call(name: str, arguments: dict, devices: dict[str, Device]) -> str:
    """Run one tool. Raises ToolError with a message meant for the model."""
    if name not in TOOLS:
        raise ToolError(f"unknown tool '{name}', available: {', '.join(TOOLS)}, finish")
    model, fn, _ = TOOLS[name]
    try:
        args = model(**arguments)
    except ValidationError as exc:
        raise ToolError(f"invalid arguments for {name}: {exc.errors()[0]['msg']}") from exc
    out = fn(devices, args)
    text = out if isinstance(out, str) else json.dumps(out)
    return text if len(text) <= MAX_OUTPUT else text[:MAX_OUTPUT] + "\n... (truncated)"
