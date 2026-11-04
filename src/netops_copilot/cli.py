"""Command-line entry point: netops-copilot "create VLAN 30 named USERS on site-a and site-b" """

import argparse
import os
import sys
from pathlib import Path

from netops_copilot import changes, policy, replay
from netops_copilot.agent.pipeline import findings_table, load_inventory, run
from netops_copilot.models import RunResult

DEFAULT_INVENTORY = Path(os.getenv("NETOPS_INVENTORY")
                         or Path(__file__).resolve().parents[2] / "lab" / "inventory.yml")


def render(result: RunResult) -> str:
    out = []
    if result.reading:
        r = result.reading
        out += [f"Image   : {', '.join(r.images)}  (read by the model, confidence {r.confidence})",
                f"Seen    : {r.seen}"]
    if inv := result.investigation:
        out.append(f"Goal    : {inv.goal}")
        for c in inv.calls:
            args = ", ".join(
                f"{k}=" + " ".join(f"{f.get('label')}:{f.get('expected')}" for f in v)
                if k == "flows" and isinstance(v, list) else f"{k}={v}"
                for k, v in c.arguments.items())
            out.append(f"  tool  {'ok ' if c.ok else 'ERR'} {c.name}({args})")
        if inv.answer:
            out.append(f"Found   : {inv.answer}")
        if result.answered:
            out.append("\nNo change proposed: the agent only looked (read-only tools).")
            return "\n".join(out)
    out.append(f"Request : {result.request}")
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
    if result.policy:
        out.append(f"Policy  : {result.policy} (intent built from the versioned policy)")
    out.append("\nValidated diff:")
    for host, diff in result.diffs.items():
        out.append(f"[{host}]\n{diff}")
    out.append(f"\nExplanation:\n{result.explanation}")
    if rv := result.review:
        out.append(f"\nReview  : {rv.verdict.upper()} by an independent session of {rv.model}, "
                   f"{len(rv.calls)} tool calls. {rv.summary}")
        out += [f"  ! [{c.severity}] {c.device + ': ' if c.device else ''}{c.text}"
                for c in rv.concerns]
    if result.risk:
        out.append(f"\nRisk floor (deterministic): {result.risk.level.upper()}  "
                   f"[{'; '.join(result.risk.reasons)}]")
    return "\n".join(out)


def print_history(store) -> int:
    entries = store.journal()
    if not entries:
        print("No change applied to the lab yet.")
        return 0
    for e in entries:
        print(f"#{e['seq']:<3} {e['time']}  {e['type']:<9} {e['change']}  by {e['operator']:<12} "
              f"{', '.join(e['devices'])}  \"{e['request']}\"")
    print(f"\nJournal integrity (hash chain): {'OK' if store.verify_journal() else 'BROKEN'}")
    return 0 if store.verify_journal() else 5


def probe(inventory: str) -> int:
    from netops_copilot import drivers

    devices = [d for d in load_inventory(inventory, live=False).values() if d.live]
    if not devices:
        print("No live device in this inventory (no `driver` entry).")
        return 0
    for d in devices:
        try:
            info = drivers.probe(d)
        except drivers.DriverError as exc:
            print(exc)
            return 4
        print(f"{d.hostname} ({d.driver['host']}) {' / '.join(info['version'])}")
        print(f"  edge: {', '.join(d.edge)}   protected: {', '.join(d.protected) or '-'}")
        print("  " + info["interfaces"].replace("\n", "\n  "))
    return 0


def _policies(args) -> list:
    return policy.load(args.policies or policy.DEFAULT_DIR)


def check_policies(args, store) -> int:
    from netops_copilot.drivers import DriverError

    try:
        results = policy.check_all(_policies(args), load_inventory(args.inventory, store))
    except policy.PolicyError as exc:
        print(f"Policy error: {exc}")
        return 1
    except DriverError as exc:
        print(f"Cannot read the devices: {exc}")
        return 4
    for r in results:
        status = "COMPLIANT" if r.compliant else f"DRIFT ({len(r.failed)} of {len(r.rows)} failed)"
        print(f"{r.policy.name:<24} {r.policy.kind:<5} {r.policy.severity:<7} {status}")
        for row in r.failed:
            print(f"    {row.device} {row.subject}: expected {row.expected}, actual {row.actual}"
                  + (f" <- {row.detail}" if row.detail else ""))
    drift = [r.policy.name for r in results if not r.compliant]
    if drift:
        print("\nFix: " + "  ".join(f"netops-copilot --enforce {n}" for n in drift))
    if args.report:
        Path(args.report).write_text(policy.report(results, shown_path(args.inventory)) + "\n")
    return 3 if drift else 0


def shown_path(path: str) -> str:
    """Path safe to publish (e.g. in a GitHub issue): relative to the current directory, or
    just the file name. Never an absolute path that would expose a home directory."""
    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return resolved.name


def policy_intent(args, devices):
    found = {p.name: p for p in _policies(args)}
    if args.enforce not in found:
        raise policy.PolicyError(f"unknown policy '{args.enforce}', known: {', '.join(found)}")
    return policy.intent(policy.check(found[args.enforce], devices))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="netops-copilot", description=__doc__)
    p.add_argument("request", nargs="?", help="plain-language change request")
    p.add_argument("--inventory", default=str(DEFAULT_INVENTORY))
    p.add_argument("--agent", action="store_true",
                   help="investigate first with read-only tools: the request can be a question "
                        "or a goal ('make sure VLAN 20 exists everywhere')")
    p.add_argument("--no-review", action="store_true",
                   help="skip the independent reviewer (a second model session that can only "
                        "escalate a change to the human)")
    p.add_argument("--review-provider", choices=["meta", "baseten"], default=None,
                   help="model of the reviewer; default: the other provider if its key is set")
    p.add_argument("--image", action="append", default=[], metavar="PATH",
                   help="photo, screenshot or diagram of the request (repeatable); "
                        "the request text then becomes an optional note")
    p.add_argument("--mock", action="store_true", help="offline deterministic model, no API call")
    p.add_argument("--provider", choices=["meta", "baseten"], default=None,
                   help="where Muse Spark runs: meta (Meta Model API, muse-spark-1.3, default) or "
                        "baseten (open-weights Muse Spark Open); default from $LLM_PROVIDER")
    p.add_argument("--mock-faulty", action="store_true",
                   help="mock model that first proposes a destructive change (demo of the retry loop)")
    p.add_argument("--retries", type=int, default=int(os.getenv("MAX_RETRIES", "3")))
    p.add_argument("--yes", action="store_true", help="approve without prompting (lab only)")
    p.add_argument("--history", action="store_true", help="show the change journal")
    p.add_argument("--rollback", metavar="CHANGE_ID", help="roll back an applied change")
    p.add_argument("--probe", action="store_true",
                   help="connect to the live devices of the inventory and show their interfaces")
    p.add_argument("--check-policies", action="store_true",
                   help="check the inventory against the versioned policies, no model "
                        "(exit code 3 on drift)")
    p.add_argument("--enforce", metavar="POLICY",
                   help="propose the change that brings the devices back into a policy")
    p.add_argument("--policies", default=None, metavar="DIR",
                   help="policy directory (default: policies/ or $NETOPS_POLICIES)")
    p.add_argument("--report", metavar="FILE", help="with --check-policies: write a Markdown report")
    p.add_argument("--record", metavar="FILE",
                   help="save this run (steps, timing, result, outcome) for playback in the "
                        "public demo, e.g. replays/devnet-fix.json")
    p.add_argument("--record-title", metavar="TITLE", help="title shown for the recording")
    p.add_argument("--reset-lab", action="store_true",
                   help="discard every applied change and the journal (demo reset)")
    args = p.parse_args(argv)
    store = changes.Store()

    if args.history:
        return print_history(store)
    if args.probe:
        return probe(args.inventory)
    if args.reset_lab:
        store.reset()
        print(f"Lab reset: configs back to the inventory, journal cleared ({store.root}).")
        return 0
    if args.rollback:
        from netops_copilot.drivers import DriverError
        try:
            entry = changes.rollback(args.rollback, args.inventory, store)
        except changes.ChangeError as exc:
            print(f"Rollback refused: {exc}")
            return 4
        except DriverError as exc:  # seen on the shared DevNet sandbox: SSH refused for a while
            print(f"Rollback not done, nothing was changed: {exc}\nRetry the same command later.")
            return 4
        if entry["type"] == "reconcile":
            print(f"Nothing to roll back: {', '.join(entry['already_reverted'])} already back to "
                  f"the state before {entry['change']} (changed outside NetOps Copilot). "
                  f"Recorded in the journal (#{entry['seq']}).")
            return 0
        print(f"Rolled back {entry['change']} on {', '.join(entry['devices'])} "
              f"(journal #{entry['seq']}).")
        if entry["already_reverted"]:
            print(f"  Already reverted outside the tool: {', '.join(entry['already_reverted'])}.")
        return 0
    if args.check_policies:
        return check_policies(args, store)
    if not args.request and not args.image and not args.enforce:
        p.error("a change request, --image or --enforce is required "
                "(or --history, --rollback, --check-policies, --reset-lab)")
    from netops_copilot import vision

    try:
        images = [vision.load_path(path) for path in args.image]
    except (OSError, vision.ImageError) as exc:
        print(f"Cannot use the image: {exc}")
        return 1

    if args.mock or args.mock_faulty:
        from netops_copilot.llm.mock import MockLLM
        llm = MockLLM(faulty_first_generation=args.mock_faulty)
        review = not args.no_review
    else:
        from netops_copilot.llm.client import MetaClient, reviewer
        try:
            llm = MetaClient(provider=args.provider)
            review = False if args.no_review else reviewer(llm, args.review_provider)
        except RuntimeError as exc:
            print(exc)
            return 1

    from netops_copilot.drivers import DriverError

    try:
        devices = load_inventory(args.inventory, store)
    except DriverError as exc:
        print(f"Cannot read the devices: {exc}")
        return 4
    enforce = None
    if args.enforce:
        try:
            enforce = policy_intent(args, devices)
        except policy.PolicyError as exc:
            print(f"Policy error: {exc}")
            return 1
        if enforce is None:
            print(f"Policy {args.enforce}: nothing to enforce, the devices comply "
                  "(or only VLAN renames remain, which are left to an operator).")
            return 0
    recorder = replay.Recorder() if args.record else None
    on_step = recorder or (lambda step: None)
    if args.enforce:
        result = run(llm, f"Enforce policy {args.enforce}", devices, max_retries=args.retries,
                     intent=enforce, policy=args.enforce, on_step=on_step, review=review)
    else:
        result = run(llm, args.request or "", devices, max_retries=args.retries, images=images,
                     agent=args.agent, on_step=on_step, review=review)
    print(render(result))

    def done(code: int, **outcome) -> int:
        if recorder:
            live = [d for d in devices.values() if d.live]
            target = (", ".join(f"{d.hostname} ({d.driver['host']}) over SSH" for d in live)
                      or "lab simulator: Cisco IOS and Huawei VRP config models")
            path = recorder.save(args.record, title=args.record_title or result.request,
                                 model=(f"{llm.model} ({llm.label})" if hasattr(llm, "label")
                                        else "offline mock model"),
                                 target=target, result=result, outcome=replay.Outcome(**outcome))
            print(f"\nRecorded to {path}")
        return code

    if result.answered:
        return done(0)
    if result.is_audit and not result.error:
        return done(0 if result.compliant else 3)  # read-only: nothing to approve
    if not result.ready_for_approval:
        return done(1)

    try:
        if result.escalated:
            # The reviewer or a deterministic rule escalated: never auto-approved.
            who = ("The independent reviewer" if result.review and result.review.escalated
                   else "A deterministic rule (control plane)")
            print(f"\n{who} ESCALATED this change: a human must decide.")
            approved = input("Approve despite the concerns? Type 'override' to approve: "
                             ).strip().lower() == "override"
        else:
            approved = args.yes or input("\nApprove this change? [y/N] ").strip().lower() == "y"
    except (EOFError, OSError):  # no terminal (piped, CI): never approve implicitly
        approved = False
    if not approved:
        print("Rejected by operator. Nothing was applied."
              + (" (--yes never approves an escalated change.)" if result.escalated and args.yes
                 else ""))
        return done(2, decision="rejected")
    try:
        entry = changes.commit(result, devices, args.inventory, store)
    except changes.ChangeError as exc:
        print(f"Not applied: {exc}")
        return done(4, decision="failed", detail=str(exc))
    folder = store.changes / entry["change"]
    record = store.record(entry["change"])
    where = (f"pushed to {', '.join(entry['live'])} and verified on the running config"
             if entry.get("live") else "applied to the lab")
    print(f"\nChange {entry['change']} {where} by {entry['operator']} (journal #{entry['seq']}).")
    for host, info in record["devices"].items():
        print(f"  rollback {host}: " + " | ".join(c.strip() for c in info["rollback"]))
    print(f"  Ansible: {folder / 'playbook.yml'}  (rollback.yml, inventory.yml alongside)")
    scope = "" if Path(args.inventory) == DEFAULT_INVENTORY else f"--inventory {args.inventory} "
    print(f"  Undo:    netops-copilot {scope}--rollback {entry['change']}")
    return done(0, decision="approved", change=entry["change"], where=where,
                rollback={h: info["rollback"] for h, info in record["devices"].items()})


if __name__ == "__main__":
    sys.exit(main())
