"""Command-line entry point: netops-copilot "create VLAN 30 named USERS on site-a and site-b" """

import argparse
import os
import sys
from pathlib import Path

from netops_copilot.agent.pipeline import findings_table, load_inventory, run
from netops_copilot.models import RunResult

DEFAULT_INVENTORY = Path(__file__).resolve().parents[2] / "lab" / "inventory.yml"


def render(result: RunResult) -> str:
    out = [f"Request : {result.request}"]
    if result.intent:
        out.append(f"Intent  : {result.intent.summary}  "
                   f"[{result.intent.change_type.value}, targets={result.intent.targets}]")
    for a in result.attempts:
        status = "OK" if a.ok else "FAILED"
        out.append(f"\nAttempt {a.number}: gate {a.gate.verdict.value}, dry-run "
                   f"{'skipped' if a.gate.violations else ('OK' if not a.dry_run_errors else 'FAILED')}"
                   f" -> {status}")
        for c in a.changes:
            out.append(f"  {c.device} ({c.vendor.value}): " + " | ".join(x.strip() for x in c.commands))
        for e in a.gate.violations + a.dry_run_errors:
            out.append(f"  ! {e}")
    if result.error:
        out.append(f"\nERROR: {result.error}")
        return "\n".join(out)
    if result.is_audit:
        out.append(f"\nACL audit: {'COMPLIANT' if result.compliant else 'NON-COMPLIANT'} "
                   f"({sum(not f.compliant for f in result.findings)} of "
                   f"{len(result.findings)} checks failed)")
        out.append(findings_table(result.findings))
        out.append(f"\nExplanation:\n{result.explanation}")
        return "\n".join(out)
    out.append("\nValidated diff (VLAN table):")
    for host, diff in result.diffs.items():
        out.append(f"[{host}]\n{diff}")
    out.append(f"\nExplanation:\n{result.explanation}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="netops-copilot", description=__doc__)
    p.add_argument("request", help="plain-language change request")
    p.add_argument("--inventory", default=str(DEFAULT_INVENTORY))
    p.add_argument("--mock", action="store_true", help="offline deterministic model, no API call")
    p.add_argument("--mock-faulty", action="store_true",
                   help="mock model that first proposes a destructive change (demo of the retry loop)")
    p.add_argument("--retries", type=int, default=int(os.getenv("MAX_RETRIES", "3")))
    p.add_argument("--yes", action="store_true", help="approve without prompting (lab only)")
    args = p.parse_args(argv)

    if args.mock or args.mock_faulty:
        from netops_copilot.llm.mock import MockLLM
        llm = MockLLM(faulty_first_generation=args.mock_faulty)
    else:
        from netops_copilot.llm.client import MetaClient
        llm = MetaClient()

    result = run(llm, args.request, load_inventory(args.inventory), max_retries=args.retries)
    print(render(result))
    if result.is_audit and not result.error:
        return 0 if result.compliant else 3  # read-only: nothing to approve
    if not result.ready_for_approval:
        return 1

    approved = args.yes or input("\nApprove this change? [y/N] ").strip().lower() == "y"
    if not approved:
        print("Rejected by operator. Nothing was pushed.")
        return 2
    # Push to devices is intentionally not implemented yet: next step is the Containerlab runner.
    print("Approved. (Push not implemented yet: lab runner is the next milestone.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
