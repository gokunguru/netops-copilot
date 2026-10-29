"""Offline ACL editor: applies configuration-mode ACL commands to a device config and returns
the candidate config. Used by the remediation dry-run, which then re-audits the candidate.

Supported grammar (anything else raises EditError, so a hallucinated command never passes):
- Cisco IOS:  ip access-list extended NAME / [seq] permit|deny ... / no <seq>
              interface X / ip access-group NAME in
- Huawei VRP: acl number N | acl name X / rule [id] permit|deny ... / undo rule <id>
              interface X / traffic-filter inbound acl N
"""

import re

from netops_copilot.audit.acl import _parse_cisco_ace, _parse_huawei_rule
from netops_copilot.models import Vendor


class EditError(Exception):
    pass


Block = list[str]  # header line followed by its indented child lines


def _split(config: str) -> list[Block]:
    blocks: list[Block] = []
    for line in config.rstrip("\n").splitlines():
        if line.startswith(" ") and blocks:
            blocks[-1].append(line)
        else:
            blocks.append([line])
    return blocks


def _join(blocks: list[Block]) -> str:
    return "\n".join(line for block in blocks for line in block) + "\n"


def _find(blocks: list[Block], header: str) -> Block | None:
    return next((b for b in blocks if b[0].strip() == header), None)


def _new_block(blocks: list[Block], header: str, vendor: Vendor) -> Block:
    """Create a top-level block just before the final 'end' / 'return'."""
    sep, end = ("!", "end") if vendor == Vendor.CISCO_IOS else ("#", "return")
    block: Block = [header]
    idx = next((i for i, b in enumerate(blocks) if b[0].strip() == end), len(blocks))
    blocks[idx:idx] = [block, [sep]]
    return block


def _entry_number(line: str, vendor: Vendor) -> int | None:
    pattern = r"^\s+(\d+)\s" if vendor == Vendor.CISCO_IOS else r"^\s+rule\s+(\d+)\s"
    m = re.match(pattern, line)
    return int(m.group(1)) if m else None


def _insert_entry(block: Block, number: int | None, text: str, vendor: Vendor) -> None:
    numbers = [n for n in (_entry_number(line, vendor) for line in block[1:]) if n is not None]
    if number is None:  # no sequence given: append with the vendor's default step
        number = (max(numbers) if numbers else 0) + (10 if vendor == Vendor.CISCO_IOS else 5)
    if number in numbers:
        raise EditError(f"entry {number} already exists in '{block[0].strip()}'")
    line = f" {number} {text}" if vendor == Vendor.CISCO_IOS else f" rule {number} {text}"
    pos = next((i for i, existing in enumerate(block) if i > 0
                and (_entry_number(existing, vendor) or 0) > number), len(block))
    block.insert(pos, line)


def _delete_entry(block: Block, number: int, vendor: Vendor) -> None:
    for i, line in enumerate(block[1:], start=1):
        if _entry_number(line, vendor) == number:
            del block[i]
            return
    raise EditError(f"entry {number} not found in '{block[0].strip()}'")


def apply(vendor: Vendor, config: str, commands: list[str]) -> str:
    blocks = _split(config)
    ctx: tuple[str, Block] | None = None  # ("acl" | "interface", block)
    cisco = vendor == Vendor.CISCO_IOS

    for raw in commands:
        cmd = raw.strip()
        if not cmd or cmd in ("!", "#", "exit", "quit"):
            ctx = None
            continue

        # Enter an ACL (created if missing).
        acl_header = (re.fullmatch(r"ip access-list extended (\S+)", cmd) if cisco
                      else re.fullmatch(r"acl (?:number \d+|name \S+(?: \d+)?)", cmd))
        if acl_header:
            block = _find(blocks, cmd) or _new_block(blocks, cmd, vendor)
            ctx = ("acl", block)
            continue

        # Enter an existing interface (never create one).
        if m := re.fullmatch(r"interface (\S+)", cmd):
            block = _find(blocks, cmd)
            if block is None:
                raise EditError(f"interface {m.group(1)} does not exist on this device")
            ctx = ("interface", block)
            continue

        if ctx and ctx[0] == "acl":
            block = ctx[1]
            if cisco and (m := re.fullmatch(r"no (\d+)", cmd)):
                _delete_entry(block, int(m.group(1)), vendor)
                continue
            if not cisco and (m := re.fullmatch(r"undo rule (\d+)", cmd)):
                _delete_entry(block, int(m.group(1)), vendor)
                continue
            if cisco and (m := re.fullmatch(r"(?:(\d+)\s+)?((?:permit|deny)\s+.+)", cmd)):
                if _parse_cisco_ace(m.group(2)) is None:
                    raise EditError(f"invalid Cisco ACE: '{cmd}'")
                _insert_entry(block, int(m.group(1)) if m.group(1) else None, m.group(2), vendor)
                continue
            if not cisco and (m := re.fullmatch(r"rule(?:\s+(\d+))?\s+((?:permit|deny)\s+.+)", cmd)):
                if _parse_huawei_rule(f" rule {m.group(2)}") is None:
                    raise EditError(f"invalid Huawei rule: '{cmd}'")
                _insert_entry(block, int(m.group(1)) if m.group(1) else None, m.group(2), vendor)
                continue

        if ctx and ctx[0] == "interface":
            block = ctx[1]
            bind = (re.fullmatch(r"ip access-group (\S+) in", cmd) if cisco
                    else re.fullmatch(r"traffic-filter inbound acl (?:name )?(\S+)", cmd))
            if bind:
                prefix = " ip access-group " if cisco else " traffic-filter inbound "
                block[1:] = [line for line in block[1:] if not line.startswith(prefix)]
                block.append(f" {cmd}")
                continue

        raise EditError(f"unrecognized or wrong-vendor command for {vendor.value}: '{cmd}'")

    return _join(blocks)


def interfaces(config: str) -> list[str]:
    return re.findall(r"^interface (\S+)", config, re.MULTILINE)
