"""Command-line entry point: netops-copilot "create VLAN 30 named USERS on site-a and site-b" """

import argparse
import os
import sys
from pathlib import Path

from netops_copilot import changes
from netops_copilot.agent.pipeline import findings_table, load_inventory, run
from netops_copilot.models import RunResult

DEFAULT_INVENTORY = Path(os.getenv("NETOPS_INVENTORY")
                         or Path(__file__).resolve().parents[2] / "lab" / "inventory.yml")


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
    if result.findings:
        out.append(f"\nAudit before fix: {sum(not f.compliant for f in result.findings)} of "
                   f"{len(result.findings)} checks failed")
    out.append("\nValidated diff:")
    for host, diff in result.diffs.items():
        out.append(f"[{host}]\n{diff}")
    out.append(f"\nExplanation:\n{result.explanation}")
    return "\n".join(out)


def print_history(store) -> int:
    entries = store.journal()
    if not entries:
        print("No change applied to the lab yet.")
        return 0
    for e in entries:
        print(f"#{e['seq']:<3} {e['time']}  {e['type']:<8} {e['change']}  by {e['operator']:<12} "
              f"{', '.join(e['devices'])}  \"{e['request']}\"")
    print(f"\nJournal integrity (hash chain): {'OK' if store.verify_journal() else 'BROKEN'}")
    return 0 if store.verify_journal() else 5


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="netops-copilot", description=__doc__)
    p.add_argument("request", nargs="?", help="plain-language change request")
    p.add_argument("--inventory", default=str(DEFAULT_INVENTORY))
    p.add_argument("--mock", action="store_true", help="offline deterministic model, no API call")
    p.add_argument("--mock-faulty", action="store_true",
                   help="mock model that first proposes a destructive change (demo of the retry loop)")
    p.add_argument("--retries", type=int, default=int(os.getenv("MAX_RETRIES", "3")))
    p.add_argument("--yes", action="store_true", help="approve without prompting (lab only)")
    p.add_argument("--history", action="store_true", help="show the change journal")
    p.add_argument("--rollback", metavar="CHANGE_ID", help="roll back an applied change")
    p.add_argument("--reset-lab", action="store_true",
                   help="discard every applied change and the journal (demo reset)")
    args = p.parse_args(argv)
    store = changes.Store()

    if args.history:
        return print_history(store)
    if args.reset_lab:
        store.reset()
        print(f"Lab reset: configs back to the inventory, journal cleared ({store.root}).")
        return 0
    if args.rollback:
        try:
            entry = changes.rollback(args.rollback, args.inventory, store)
        except changes.ChangeError as exc:
            print(f"Rollback refused: {exc}")
            return 4
        print(f"Rolled back {entry['change']} on {', '.join(entry['devices'])} "
              f"(journal #{entry['seq']}).")
        return 0
    if not args.request:
        p.error("a change request is required (or --history, --rollback, --reset-lab)")

    if args.mock or args.mock_faulty:
        from netops_copilot.llm.mock import MockLLM
        llm = MockLLM(faulty_first_generation=args.mock_faulty)
    else:
        from netops_copilot.llm.client import MetaClient
        llm = MetaClient()

    devices = load_inventory(args.inventory, store)
    result = run(llm, args.request, devices, max_retries=args.retries)
    print(render(result))
    if result.is_audit and not result.error:
        return 0 if result.compliant else 3  # read-only: nothing to approve
    if not result.ready_for_approval:
        return 1

    approved = args.yes or input("\nApprove this change? [y/N] ").strip().lower() == "y"
    if not approved:
        print("Rejected by operator. Nothing was applied.")
        return 2
    try:
        entry = changes.commit(result, devices, args.inventory, store)
    except changes.ChangeError as exc:
        print(f"Not applied: {exc}")
        return 4
    folder = store.changes / entry["change"]
    record = store.record(entry["change"])
    print(f"\nApplied to the lab as change {entry['change']} by {entry['operator']} "
          f"(journal #{entry['seq']}).")
    for host, info in record["devices"].items():
        print(f"  rollback {host}: " + " | ".join(c.strip() for c in info["rollback"]))
    print(f"  Ansible: {folder / 'playbook.yml'}  (rollback.yml, inventory.yml alongside)")
    print(f"  Undo:    netops-copilot --rollback {entry['change']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
