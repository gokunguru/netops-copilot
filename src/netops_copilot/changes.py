"""What happens after "Approve": apply to the lab state, emit Ansible artefacts, journal it.

Guarantees, all deterministic:
- The applied config is produced by the same editor the dry-run trusts; for VLAN changes it is
  cross-checked against the simulator, so what was validated is what gets applied.
- No change is applied without a rollback that was derived, replayed on the new config and
  proven to restore the original exactly.
- A change is refused if the lab moved since the run was validated (no stale approvals).
- Every apply and rollback is appended to a hash-chained journal (tamper-evident).
"""

import getpass
import hashlib
import json
import os
import re
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import yaml

from netops_copilot import drivers
from netops_copilot.audit.acl import SERVICES
from netops_copilot.lab import config_editor, simulator
from netops_copilot.models import ChangeType, Device, RunResult, Vendor

NETWORK_OS = {Vendor.CISCO_IOS: "cisco.ios.ios", Vendor.HUAWEI_VRP: "community.network.ce"}
ARTEFACTS = ("playbook.yml", "rollback.yml", "inventory.yml")
SEPARATORS = {"", "!", "#"}


class ChangeError(Exception):
    pass


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def operator() -> str:
    return os.getenv("NETOPS_OPERATOR") or getpass.getuser()


# ---------------------------------------------------------------- state store

class Store:
    """Lab state (configs overriding the inventory), change artefacts and the journal."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root or os.getenv("NETOPS_STATE_DIR") or Path.cwd() / ".netops")
        self.configs = self.root / "configs"
        self.changes = self.root / "changes"
        self.journal_path = self.root / "journal.jsonl"

    def config(self, host: str) -> str | None:
        path = self.configs / f"{host}.cfg"
        return path.read_text() if path.exists() else None

    def write_config(self, host: str, text: str) -> None:
        self.configs.mkdir(parents=True, exist_ok=True)
        (self.configs / f"{host}.cfg").write_text(text)

    def journal(self) -> list[dict]:
        if not self.journal_path.exists():
            return []
        return [json.loads(line) for line in self.journal_path.read_text().splitlines() if line]

    def append(self, entry: dict) -> dict:
        entries = self.journal()
        entry = {"seq": len(entries) + 1, "time": datetime.now(UTC).isoformat(timespec="seconds"),
                 **entry, "prev": entries[-1]["hash"] if entries else "0" * 64}
        entry["hash"] = sha(json.dumps(entry, sort_keys=True))
        self.root.mkdir(parents=True, exist_ok=True)
        with self.journal_path.open("a") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def verify_journal(self) -> bool:
        prev = "0" * 64
        for entry in self.journal():
            body = {k: v for k, v in entry.items() if k != "hash"}
            if entry["prev"] != prev or sha(json.dumps(body, sort_keys=True)) != entry["hash"]:
                return False
            prev = entry["hash"]
        return True

    def record(self, change_id: str) -> dict:
        if not re.fullmatch(r"[0-9a-f]{10}", change_id):
            raise ChangeError(f"invalid change id '{change_id}'")
        path = self.changes / change_id / "change.json"
        if not path.exists():
            raise ChangeError(f"unknown change '{change_id}'")
        return json.loads(path.read_text())

    def artefact(self, change_id: str, name: str) -> str:
        self.record(change_id)  # validates the id
        if name not in ARTEFACTS:
            raise ChangeError(f"unknown artefact '{name}'")
        return (self.changes / change_id / name).read_text()

    def reset(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


# ---------------------------------------------------------------- rollback

def _norm(config: str) -> list[str]:
    return [line.rstrip() for line in config.splitlines() if line.strip() not in SEPARATORS]


def norm_sha(config: str) -> str:
    """Hash of the config ignoring separator lines: what matters for equivalence."""
    return sha("\n".join(_norm(config)))


def _blocks(config: str) -> dict[str, list[str]]:
    blocks: dict[str, list[str]] = {}
    header = None
    for line in config.splitlines():
        if line.startswith(" ") and header is not None:
            blocks[header].append(line)
        elif line.strip() not in SEPARATORS:
            header = line.strip()
            blocks.setdefault(header, [])
    return blocks


def _negate(vendor: Vendor, header: str, line: str) -> str:
    cisco = vendor == Vendor.CISCO_IOS
    patterns = ([(r"^\s+(\d+)\s+(?:permit|deny)\s", "no {}"), (r"^\s+(ip access-group \S+ in)$", "no {}")]
                if cisco else
                [(r"^\s+rule (\d+)\s", "undo rule {}"),
                 (r"^\s+(traffic-filter inbound acl (?:name )?\S+)$", "undo {}")])
    for pattern, template in patterns:
        if m := re.match(pattern, line):
            return " " + template.format(m.group(1))
    raise ChangeError(f"no safe inverse for '{line.strip()}' under '{header}'")


def derive_rollback(vendor: Vendor, before: str, after: str) -> list[str]:
    """Inverse commands, ordered for a live device: unbind, then remove rules, then objects."""
    old, new = _blocks(before), _blocks(after)
    if missing := [h for h in old if h not in new]:
        raise ChangeError(f"change removed '{missing[0]}': no automatic rollback")
    neg = "no" if vendor == Vendor.CISCO_IOS else "undo"
    unbind, entries, removals = [], [], []
    for header, children in new.items():
        if header in ("end", "return"):
            continue
        if header not in old:
            removals.append(f"{neg} {header}")
            continue
        if removed := [c for c in old[header] if c not in children]:
            raise ChangeError(f"change modified '{removed[0].strip()}' under '{header}': "
                              "no automatic rollback")
        added = [c for c in children if c not in old[header]]
        if added:
            target = unbind if header.startswith("interface ") else entries
            target += [header, *(_negate(vendor, header, c) for c in added)]
    return unbind + entries + removals


# ---------------------------------------------------------------- prepare / apply

@dataclass
class DeviceChange:
    device: str
    vendor: Vendor
    commands: list[str]
    rollback: list[str]
    before: str
    after: str


def prepare(result: RunResult, devices: dict[str, Device]) -> list[DeviceChange]:
    if not result.ready_for_approval:
        raise ChangeError("nothing validated to apply")
    prepared = []
    for change in result.final_changes:
        device = devices[change.device]
        try:
            after = config_editor.apply(change.vendor, device.config, change.commands)
        except config_editor.EditError as exc:
            raise ChangeError(f"{change.device}: {exc}") from exc
        if result.intent.change_type == ChangeType.VLAN_PROVISION:
            expected = simulator.apply(change.vendor, simulator.parse_vlans(device.config),
                                       change.commands)
            if simulator.parse_vlans(after) != expected:
                raise ChangeError(f"{change.device}: applied config differs from the dry-run")
        rollback = derive_rollback(change.vendor, device.config, after)
        restored = config_editor.apply(change.vendor, after, rollback)
        if _norm(restored) != _norm(device.config):
            raise ChangeError(f"{change.device}: rollback replay does not restore the original")
        prepared.append(DeviceChange(change.device, change.vendor, change.commands, rollback,
                                     device.config, after))
    return prepared


class _Dumper(yaml.SafeDumper):
    """Multi-line strings as literal blocks: the config reads like on the device."""


_Dumper.add_representer(str, lambda d, v: d.represent_scalar(
    "tag:yaml.org,2002:str", v, style="|" if "\n" in v else None))


def _playbook(title: str, items: list[tuple[str, Vendor, list[str]]]) -> str:
    plays = [{
        "name": f"{title} [{host}]",
        "hosts": host,
        "gather_facts": False,
        "tasks": [{
            "name": "Apply (running config backed up first)",
            "ansible.netcommon.cli_config": {"config": "\n".join(cmds), "backup": True},
        }],
    } for host, _vendor, cmds in items]
    return ("# Generated by NetOps Copilot. Validated offline: review, then run with\n"
            "#   ansible-playbook -i inventory.yml <this file>\n"
            + yaml.dump(plays, Dumper=_Dumper, sort_keys=False, width=120))


def _inventory(items: list[tuple[str, Vendor, list[str]]]) -> str:
    return yaml.safe_dump({"all": {
        "vars": {"ansible_connection": "ansible.netcommon.network_cli"},
        "hosts": {host: {"ansible_host": host, "ansible_network_os": NETWORK_OS[vendor]}
                  for host, vendor, _ in items},
    }}, sort_keys=False)


# ---------------------------------------------------------------- live devices

def _canon(line: str) -> str:
    """Semantic form of a config line: IOS shows 'eq 23' as 'eq telnet', 'eq 80' as 'eq www'."""
    line = " ".join(line.split())
    return re.sub(r"\b(eq|gt|lt|neq) (\S+)",
                  lambda m: f"{m.group(1)} {SERVICES.get(m.group(2).lower(), m.group(2))}", line)


def touched_headers(before: str, after: str) -> list[str]:
    old, new = _blocks(before), _blocks(after)
    return [h for h, children in new.items() if h not in old or children != old[h]]


def blocks_of(config: str, headers: list[str]) -> dict[str, list[str] | None]:
    """Touched blocks in comparable form. Order-insensitive: IOS re-orders interface lines
    (it puts 'ip access-group' before 'shutdown'); ACL order is kept by sequence numbers."""
    blocks = _blocks(config)
    return {h: (sorted(_canon(c) for c in blocks[h]) if h in blocks else None) for h in headers}


def only(config: str, headers: list[str]) -> str:
    """The config reduced to some blocks: never reason about objects we did not touch."""
    blocks = _blocks(config)
    return "".join(f"{h}\n" + "".join(f"{c}\n" for c in blocks[h]) for h in headers if h in blocks)


def _push_and_verify(session: "drivers.Session", commands: list[str], expected: dict) -> str:
    """Push, read the running config back, compare the touched blocks to what was validated."""
    session.push(commands)
    running = session.fetch()
    got = blocks_of(running, list(expected))
    if got != expected:
        diff = next(h for h in expected if got[h] != expected[h])
        raise ChangeError(f"{session.device.hostname}: running config differs from the validated "
                          f"candidate after the push (block '{diff}')")
    return running


def _restore(p: "DeviceChange", device: Device, headers: list[str], expected_before: dict) -> None:
    """Put the touched blocks back as they were, from what is really on the device."""
    with drivers.Session(device) as s:
        running = s.fetch()
        if blocks_of(running, headers) == expected_before:
            return
        # The push may have stopped half-way: invert what is really there, touched blocks only.
        inverse = derive_rollback(p.vendor, only(p.before, headers), only(running, headers))
        _push_and_verify(s, inverse, expected_before)


def _apply_live(prepared: list["DeviceChange"], devices: dict[str, Device],
                folder: Path) -> dict[str, dict]:
    """All-or-nothing across devices: any failure rolls back every device already changed."""
    done: list[tuple[DeviceChange, list[str], dict]] = []
    evidence = {}
    try:
        for p in prepared:
            device = devices[p.device]
            headers = touched_headers(p.before, p.after)
            expected_before, expected_after = blocks_of(p.before, headers), blocks_of(p.after, headers)
            with drivers.Session(device) as s:
                running = s.fetch()
                (folder / f"{p.device}.before.cfg").write_text(running)
                if blocks_of(running, headers) != expected_before:
                    raise ChangeError(f"{p.device} changed on the device since this run was "
                                      "validated: run it again")
                done.append((p, headers, expected_before))
                after = _push_and_verify(s, p.commands, expected_after)
            (folder / f"{p.device}.after.cfg").write_text(after)
            evidence[p.device] = {"headers": headers, "blocks_before": expected_before,
                                  "blocks_after": expected_after}
    except (ChangeError, drivers.DriverError) as exc:
        restored, failed = [], []
        for p, headers, expected_before in reversed(done):
            try:
                _restore(p, devices[p.device], headers, expected_before)
                restored.append(p.device)
            except (ChangeError, drivers.DriverError) as rb_exc:
                failed.append(f"{p.device} ({rb_exc})")
        note = f" Rolled back automatically on: {', '.join(restored)}." if restored else ""
        if failed:
            note += f" AUTOMATIC ROLLBACK FAILED, check manually: {'; '.join(failed)}."
        raise ChangeError(f"{exc}.{note}") from exc
    return evidence


# ---------------------------------------------------------------- commit / rollback

def commit(result: RunResult, devices: dict[str, Device], inventory: str | Path,
           store: Store, who: str | None = None) -> dict:
    """Apply an approved run: lab state for lab devices, SSH push for live ones."""
    from netops_copilot.agent.pipeline import load_inventory

    prepared = prepare(result, devices)
    lab = [p for p in prepared if not devices[p.device].live]
    live = [p for p in prepared if devices[p.device].live]
    if lab:
        current = load_inventory(inventory, store, live=False)
        for p in lab:
            if sha(current[p.device].config) != sha(p.before):
                raise ChangeError(f"{p.device} changed since this run was validated: run it again")

    who = who or operator()
    change_id = sha(json.dumps([result.request, [p.commands for p in prepared],
                                datetime.now(UTC).isoformat()]))[:10]
    folder = store.changes / change_id
    folder.mkdir(parents=True, exist_ok=True)
    evidence = _apply_live(live, devices, folder) if live else {}

    title = f"NetOps Copilot change {change_id}: {result.intent.summary}"
    (folder / "playbook.yml").write_text(
        _playbook(title, [(p.device, p.vendor, p.commands) for p in prepared]))
    (folder / "rollback.yml").write_text(
        _playbook(f"Rollback of {change_id}", [(p.device, p.vendor, p.rollback) for p in prepared]))
    (folder / "inventory.yml").write_text(
        _inventory([(p.device, p.vendor, p.commands) for p in prepared]))
    (folder / "change.json").write_text(json.dumps({
        "id": change_id, "request": result.request, "summary": result.intent.summary,
        "operator": who, "devices": {p.device: {
            "vendor": p.vendor.value, "commands": p.commands, "rollback": p.rollback,
            "target": "live" if p.device in evidence else "lab",
            "before_sha256": norm_sha(p.before), "after_sha256": sha(p.after),
            **evidence.get(p.device, {})} for p in prepared},
    }, indent=2))

    for p in lab:
        store.write_config(p.device, p.after)
    return store.append({"type": "apply", "change": change_id, "operator": who,
                         "request": result.request, "devices": [p.device for p in prepared],
                         "live": sorted(evidence)})


def rollback(change_id: str, inventory: str | Path, store: Store, who: str | None = None) -> dict:
    """Undo a change. On a live device, three states are told apart:
    - as left by the change: roll it back;
    - already back to the state before the change (someone reverted it outside the tool):
      nothing to push, the fact is recorded in the journal;
    - anything else: refuse, and say which block moved.
    """
    from netops_copilot.agent.pipeline import load_inventory

    record = store.record(change_id)
    if any(e["type"] in ("rollback", "reconcile") and e["change"] == change_id
           for e in store.journal()):
        raise ChangeError(f"change {change_id} was already rolled back")
    current = load_inventory(inventory, store, live=False)
    restored, live, reverted = {}, [], []
    for host, info in record["devices"].items():
        if info.get("target") == "live":
            device = current[host]
            now = blocks_of(drivers.fetch_config(device), info["headers"])
            if now == info["blocks_before"]:
                reverted.append(host)
            elif now == info["blocks_after"]:
                live.append((device, info))
            else:
                moved = [h for h in info["headers"] if now[h] != info["blocks_after"][h]]
                raise ChangeError(f"{host}: '{moved[0]}' was changed outside NetOps Copilot after "
                                  f"{change_id} (neither the state it left nor the one before): "
                                  "refusing to roll back over it")
            continue
        config = current[host].config
        if sha(config) != info["after_sha256"]:
            raise ChangeError(f"{host} changed after {change_id}: refusing to roll back over it")
        restored[host] = config_editor.apply(Vendor(info["vendor"]), config, info["rollback"])
        if norm_sha(restored[host]) != info["before_sha256"]:
            raise ChangeError(f"{host}: rollback did not restore the original")
    for device, info in live:
        try:
            with drivers.Session(device) as session:
                _push_and_verify(session, info["rollback"], info["blocks_before"])
        except drivers.DriverError as exc:
            raise ChangeError(str(exc)) from exc
    for host, text in restored.items():
        store.write_config(host, text)
    rolled_back = list(restored) + [d.hostname for d, _ in live]
    return store.append({"type": "rollback" if rolled_back else "reconcile",
                         "change": change_id, "operator": who or operator(),
                         "request": record["request"], "devices": rolled_back or reverted,
                         "live": sorted(d.hostname for d, _ in live),
                         "already_reverted": reverted})
