"""Live device access over SSH (Netmiko). Only used for inventory entries with a `driver`.

Credentials never live in the repo: the inventory names an environment-variable prefix
(credentials_env: DEVNET -> DEVNET_USERNAME / DEVNET_PASSWORD).
"""

import os
import re
from typing import Protocol

from netops_copilot.models import Device, Vendor

DEVICE_TYPES = {Vendor.CISCO_IOS: "cisco_xe", Vendor.HUAWEI_VRP: "huawei_vrp"}
SHOW_CONFIG = {Vendor.CISCO_IOS: "show running-config", Vendor.HUAWEI_VRP: "display current-configuration"}
# The device answers with one of these when a command is rejected: abort, never half-apply.
ERROR_PATTERN = {Vendor.CISCO_IOS: r"% (?:Invalid|Incomplete|Ambiguous|Unknown)",
                 Vendor.HUAWEI_VRP: r"Error:"}
# Lines that change on their own and say nothing about the configuration.
VOLATILE = re.compile(r"^(Building configuration|Current configuration :|! Last configuration change"
                      r"|! NVRAM config last updated|! No configuration change since|ntp clock-period)")


class DriverError(Exception):
    pass


class Connection(Protocol):
    def send_command(self, command_string: str, **kwargs) -> str: ...
    def send_config_set(self, config_commands: list[str], **kwargs) -> str: ...
    def disconnect(self) -> None: ...


def clean(config: str) -> str:
    lines = [line.rstrip() for line in config.replace("\r\n", "\n").splitlines()]
    return "\n".join(line for line in lines if line and not VOLATILE.match(line)) + "\n"


def _credentials(device: Device) -> tuple[str, str]:
    prefix = device.driver.get("credentials_env", "")
    user, password = os.getenv(f"{prefix}_USERNAME"), os.getenv(f"{prefix}_PASSWORD")
    if not prefix or not user or not password:
        raise DriverError(f"{device.hostname}: set {prefix or '<PREFIX>'}_USERNAME and "
                          f"{prefix or '<PREFIX>'}_PASSWORD (never in the repo)")
    return user, password


def connect(device: Device) -> Connection:
    """Open an SSH session. Tests replace this function with a fake device."""
    user, password = _credentials(device)
    try:
        from netmiko import ConnectHandler
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise DriverError("live devices need netmiko: pip install -e '.[live]'") from exc
    try:
        return ConnectHandler(device_type=DEVICE_TYPES[device.vendor], host=device.driver["host"],
                              port=int(device.driver.get("port", 22)), username=user,
                              password=password, conn_timeout=20)
    except Exception as exc:  # any SSH or auth failure becomes a readable error
        raise DriverError(f"{device.hostname}: cannot connect ({type(exc).__name__}: {exc})") from exc


def fetch_config(device: Device) -> str:
    conn = connect(device)
    try:
        return clean(conn.send_command(SHOW_CONFIG[device.vendor], read_timeout=60))
    finally:
        conn.disconnect()


def push(device: Device, commands: list[str]) -> str:
    """Send configuration commands; raise if the device rejects any of them."""
    conn = connect(device)
    try:
        return conn.send_config_set([c.strip() for c in commands], cmd_verify=True,
                                    error_pattern=ERROR_PATTERN[device.vendor], read_timeout=60)
    except Exception as exc:  # netmiko raises ConfigInvalidException and others
        raise DriverError(f"{device.hostname}: device rejected the change ({exc})") from exc
    finally:
        conn.disconnect()


def probe(device: Device) -> dict:
    conn = connect(device)
    try:
        brief = conn.send_command("show ip interface brief" if device.vendor == Vendor.CISCO_IOS
                                  else "display ip interface brief")
        version = conn.send_command("show version | include Version" if device.vendor ==
                                    Vendor.CISCO_IOS else "display version | include VRP")
    finally:
        conn.disconnect()
    return {"interfaces": brief, "version": version.strip().splitlines()[:2]}
