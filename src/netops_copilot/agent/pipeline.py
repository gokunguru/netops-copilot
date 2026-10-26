"""Agent pipeline: parse -> generate -> gate -> dry-run -> explain. Stubs to fill in."""

from netops_copilot.models import Intent, ProposedChange


def parse_intent(request: str, configs: dict[str, str]) -> Intent:
    raise NotImplementedError


def generate_changes(intent: Intent, errors: list[str] | None = None) -> list[ProposedChange]:
    raise NotImplementedError


def dry_run(changes: list[ProposedChange]) -> list[str]:
    """Apply changes to the Containerlab replica, return failed checks (empty = OK)."""
    raise NotImplementedError


def explain(intent: Intent, changes: list[ProposedChange]) -> str:
    raise NotImplementedError
