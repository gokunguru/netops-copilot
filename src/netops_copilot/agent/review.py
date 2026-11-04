"""Independent reviewer: a second model session that checks a change before the human does.

It never sees the generator's prompts, retries or reasoning: only the operator's request, the
intent, the commands and the diffs, plus read-only tools on the running and candidate states.
It can approve or escalate, nothing else: it cannot change the change, rerun it or relax the
gate. Whatever goes wrong on its side (API error, invalid verdict, no conclusion) escalates.
"""

import json
from collections.abc import Callable

from pydantic import BaseModel, Field, ValidationError

from netops_copilot.agent import prompts, tools
from netops_copilot.agent.investigate import _args, _summary
from netops_copilot.lab import config_editor
from netops_copilot.llm.client import LLM, extract_json
from netops_copilot.models import Concern, Device, ProposedChange, Review, Step, ToolCall

MAX_CALLS = 10
VERDICT_NUDGE = "Give your verdict now: call the `verdict` tool, not plain text."
STATES = ("running", "candidate")


class _Verdict(BaseModel):
    verdict: str = Field(pattern="^(approve|escalate)$")
    summary: str = Field(default="", max_length=1000)
    concerns: list[Concern] = Field(default_factory=list, max_length=10)


def specs() -> list[dict]:
    """The investigation tools, each with a `state` argument, plus `verdict`."""
    out = []
    for spec in tools.specs():
        fn = json.loads(json.dumps(spec["function"]))
        if fn["name"] == "finish":
            continue
        fn["parameters"]["properties"]["state"] = {
            "type": "string", "enum": list(STATES),
            "description": "running (now, default) or candidate (after the change)"}
        out.append({"type": "function", "function": fn})
    out.append({"type": "function", "function": {
        "name": "verdict",
        "description": "Your review. approve, or escalate with specific concerns for the human.",
        "parameters": {"type": "object", "required": ["verdict", "summary"], "properties": {
            "verdict": {"type": "string", "enum": ["approve", "escalate"]},
            "summary": {"type": "string"},
            "concerns": {"type": "array", "items": {
                "type": "object", "required": ["severity", "text"], "properties": {
                    "severity": {"type": "string", "enum": ["low", "medium", "high"]},
                    "device": {"type": "string"}, "text": {"type": "string"}}}}}}}})
    return out


def candidate(changes: list[ProposedChange], devices: dict[str, Device]) -> dict[str, Device]:
    out = dict(devices)
    for c in changes:
        config = config_editor.apply(c.vendor, devices[c.device].config, c.commands)
        out[c.device] = devices[c.device].model_copy(update={"config": config})
    return out


def json_verdict(llm: LLM, opening: list[dict], calls: list[ToolCall]) -> _Verdict:
    evidence = "\n".join(f"- {c.name}({json.dumps(c.arguments)}) -> {c.output[:1200]}"
                         for c in calls)[:12000] or "(none)"
    reply = llm.chat([*opening, {"role": "user", "content": prompts.review_fallback(evidence)}])
    return _Verdict(**extract_json(reply))


def _decide(v: _Verdict, calls: list[ToolCall], model: str) -> Review:
    # Only escalation is possible: any medium or high concern makes it an escalation, whatever
    # verdict the model wrote next to it.
    serious = any(c.severity != "low" for c in v.concerns)
    verdict = "escalate" if v.verdict == "escalate" or serious else "approve"
    return Review(verdict=verdict, summary=v.summary.strip(), concerns=v.concerns, calls=calls,
                  model=model)


def review(llm: LLM, operator_request: str, intent_json: str, changes: list[ProposedChange],
           diffs: dict[str, str], devices: dict[str, Device],
           on_step: Callable[[Step], None], facts: str = "") -> Review:
    model = (f"{llm.model} ({llm.label})" if hasattr(llm, "label")
             else getattr(llm, "model", "offline mock model"))
    calls: list[ToolCall] = []
    try:
        states = {"running": devices, "candidate": candidate(changes, devices)}
        messages = [{"role": "system", "content": prompts.REVIEW_SYSTEM},
                    {"role": "user", "content": prompts.review_user(
                        operator_request, intent_json,
                        json.dumps([c.model_dump(mode="json") for c in changes]), diffs,
                        facts)}]
        spec = specs()
        nudged = forced = False
        while True:
            # Budget spent, or prose instead of a verdict: offer only `verdict`, and require it.
            if nudged or len(calls) >= MAX_CALLS:
                if forced:
                    break  # the provider ignored the forced verdict: last resort below
                forced = True
                message = llm.complete(messages, spec[-1:], force="verdict")
            else:
                message = llm.complete(messages, spec)
            requested = message.get("tool_calls") or []
            if not requested:
                if nudged:
                    break
                nudged = True
                messages += [{"role": "assistant", "content": message.get("content") or ""},
                             {"role": "user", "content": VERDICT_NUDGE}]
                continue
            messages.append({"role": "assistant", "content": message.get("content") or "",
                             "tool_calls": requested})
            for call in requested:
                name, args = call["function"]["name"], {}
                try:
                    args = _args(call)
                    if name == "verdict":
                        return _decide(_Verdict(**args), calls, model)
                    if len(calls) >= MAX_CALLS:
                        raise tools.ToolError("tool budget exhausted: give your verdict now")
                    state = args.pop("state", "running")
                    if state not in STATES:
                        raise tools.ToolError(f"state must be one of {', '.join(STATES)}")
                    output, ok = tools.call(name, args, states[state]), True
                    args["state"] = state
                except (tools.ToolError, json.JSONDecodeError) as exc:
                    output, ok = f"error: {exc}", False
                except ValidationError as exc:
                    output, ok = f"error: invalid verdict: {exc.errors()[0]['msg']}", False
                calls.append(ToolCall(name=name, arguments=args, ok=ok, output=output))
                shown = ", ".join(f"{k}={v}" for k, v in args.items() if not isinstance(v, list))
                on_step(Step(name="review_tool", ok=ok,
                             detail=f"{name}({shown}) → {_summary(output)}"))
                messages.append({"role": "tool", "tool_call_id": call.get("id", name),
                                 "content": output})
        # Seen on Muse Spark Open (Baseten): tool calls keep coming, even with a forced
        # tool_choice. Last resort that works on any provider: a fresh request without tools,
        # with the evidence gathered so far, answered as JSON and validated by the same schema.
        return _decide(json_verdict(llm, messages[:2], calls), calls, model)
    except Exception as exc:  # noqa: BLE001  fail closed: no review means a human must look
        return Review(verdict="escalate", calls=calls, model=model,
                      summary="The independent review could not complete.",
                      concerns=[Concern(severity="medium",
                                        text=f"reviewer unavailable ({type(exc).__name__}: "
                                             f"{str(exc)[:200]}): review this change yourself")])
