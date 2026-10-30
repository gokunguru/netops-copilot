"""Offline dry-run: applies generated commands to a model of each device's config
and runs pre/post checks. Scope: VLAN objects.
"""

import difflib
import re

from netops_copilot.models import Device, Intent, ProposedChange, Vendor, VlanParams


class SimulationError(Exception):
    pass


def parse_vlans(config: str) -> dict[int, str]:
    """Extract {vlan_id: name} from a Cisco IOS or Huawei VRP config."""
    vlans: dict[int, str] = {}
    current: int | None = None
    for raw in config.splitlines():
        line = raw.rstrip()
        if m := re.match(r"^vlan batch ([\d ]+(?:to [\d ]+)*)$", line):
            for vid in _expand_batch(m.group(1)):
                vlans.setdefault(vid, "")
            current = None
        elif m := re.match(r"^vlan (\d+)$", line):
            current = int(m.group(1))
            vlans.setdefault(current, "")
        elif current is not None and (m := re.match(r"^\s+(?:name|description) (\S+)$", line)):
            vlans[current] = m.group(1)
        elif not line.startswith(" "):
            current = None
    return vlans


def _expand_batch(spec: str) -> list[int]:
    ids, tokens = [], spec.split()
    i = 0
    while i < len(tokens):
        if i + 2 < len(tokens) and tokens[i + 1] == "to":
            ids.extend(range(int(tokens[i]), int(tokens[i + 2]) + 1))
            i += 3
        else:
            ids.append(int(tokens[i]))
            i += 1
    return ids


def apply(vendor: Vendor, vlans: dict[int, str], commands: list[str]) -> dict[int, str]:
    """Apply VLAN commands with vendor-specific grammar. Unknown commands raise."""
    state = dict(vlans)
    neg = "no" if vendor == Vendor.CISCO_IOS else "undo"
    current: int | None = None
    for raw in commands:
        cmd = raw.strip()
        if not cmd or cmd in ("!", "#", "exit", "quit"):
            current = None
            continue
        if m := re.fullmatch(r"vlan (\d+)", cmd):
            current = int(m.group(1))
            state.setdefault(current, "")
        elif vendor == Vendor.HUAWEI_VRP and (m := re.fullmatch(r"vlan batch ([\d ]+(?:to [\d ]+)*)", cmd)):
            for vid in _expand_batch(m.group(1)):
                state.setdefault(vid, "")
            current = None
        elif current is not None and (m := re.fullmatch(r"name (\S+)", cmd)) or vendor == Vendor.HUAWEI_VRP and current is not None and (
            m := re.fullmatch(r"description (\S+)", cmd)
        ):
            state[current] = m.group(1)
        elif m := re.fullmatch(rf"{neg} vlan (\d+)", cmd):
            state.pop(int(m.group(1)), None)
        else:
            raise SimulationError(f"unrecognized or wrong-vendor command for {vendor.value}: '{cmd}'")
    return state


def render_vlans(vlans: dict[int, str]) -> str:
    return "\n".join(f"vlan {vid}" + (f"\n name {name}" if name else "")
                     for vid, name in sorted(vlans.items()))


def dry_run(intent: Intent, changes: list[ProposedChange],
            devices: dict[str, Device]) -> tuple[list[str], dict[str, str]]:
    """Return (errors, per-device unified diff of the VLAN table). No errors = safe to propose."""
    errors: list[str] = []
    diffs: dict[str, str] = {}
    params = VlanParams(**intent.params)
    by_device = {c.device: c for c in changes}

    for host in intent.targets:
        if host not in by_device:
            errors.append(f"{host}: no change generated for a target device")
    for change in changes:
        device = devices[change.device]
        before = parse_vlans(device.config)
        try:
            after = apply(change.vendor, before, change.commands)
        except SimulationError as exc:
            errors.append(f"{change.device}: {exc}")
            continue
        # Post-check 1: the requested VLAN exists with the requested name.
        if after.get(params.vlan_id) != params.name:
            errors.append(f"{change.device}: post-check failed, VLAN {params.vlan_id} "
                          f"'{params.name}' not present after change")
        # Post-check 2: nothing pre-existing was removed or renamed.
        for vid, name in before.items():
            if vid not in after:
                errors.append(f"{change.device}: post-check failed, existing VLAN {vid} removed")
            elif name and after[vid] != name and vid != params.vlan_id:
                errors.append(f"{change.device}: post-check failed, VLAN {vid} renamed")
        # Post-check 3: no collateral VLANs created.
        extra = set(after) - set(before) - {params.vlan_id}
        if extra:
            errors.append(f"{change.device}: post-check failed, unexpected VLANs {sorted(extra)}")
        diffs[change.device] = "\n".join(difflib.unified_diff(
            render_vlans(before).splitlines(), render_vlans(after).splitlines(),
            "running", "candidate", lineterm=""))
    return errors, diffs
