"""Agent loop: the model calls read-only tools until it can answer, within a fixed budget."""

import json
from collections.abc import Callable

from pydantic import ValidationError

from netops_copilot.agent import prompts, tools
from netops_copilot.llm.client import LLM
from netops_copilot.models import Device, Investigation, Step, ToolCall

FINISH_NUDGE = ("Call the `finish` tool now: `answer` with what you found, and `request` with "
                "the change request if the operator asked for a change and one is needed, "
                "otherwise null. Do not answer in plain text.")
NO_REQUEST = {"", "null", "none", "n/a", "na", "no", "no change", "nothing", "-"}


def _summary(text: str) -> str:
    line = " ".join(text.split())
    return line if len(line) <= 160 else line[:157] + "..."


def _args(call: dict) -> dict:
    raw = call["function"].get("arguments") or "{}"
    args = json.loads(raw) if isinstance(raw, str) else raw
    if not isinstance(args, dict):
        raise tools.ToolError("arguments must be a JSON object")
    return args


def investigate(llm: LLM, goal: str, devices: dict[str, Device],
                on_step: Callable[[Step], None], max_calls: int = tools.MAX_CALLS) -> Investigation:
    """Raises ValueError if the model does not conclude within max_calls tool calls."""
    result = Investigation(goal=goal)
    messages = [{"role": "system", "content": prompts.AGENT_SYSTEM},
                {"role": "user", "content": prompts.agent_user(goal)}]
    specs = tools.specs()
    nudged = False
    while True:
        if len(result.calls) >= max_calls + 3:  # ignored the budget warning: stop
            raise ValueError(f"the agent did not conclude within {max_calls} tool calls")
        # Budget spent, or prose instead of a conclusion: offer only `finish`, and require it.
        forced = nudged or len(result.calls) >= max_calls
        message = (llm.complete(messages, [s for s in specs if s["function"]["name"] == "finish"],
                                force="finish") if forced else llm.complete(messages, specs))
        calls = message.get("tool_calls") or []
        if not calls:
            text = (message.get("content") or "").strip()
            if not nudged:
                # Seen on Muse Spark Open: after the tool budget, a prose answer that says a fix
                # is needed but never calls `finish`, so the request is lost. Ask once.
                nudged = True
                messages += [{"role": "assistant", "content": text},
                             {"role": "user", "content": FINISH_NUDGE}]
                continue
            result.answer = text  # still prose: an answer with nothing to change
            if not result.answer:
                raise ValueError("the agent returned neither a tool call nor an answer")
            return result
        messages.append({"role": "assistant", "content": message.get("content") or "",
                         "tool_calls": calls})
        for call in calls:
            name, args = call["function"]["name"], {}
            try:
                args = _args(call)
                if name == "finish":
                    done = tools.Finish(**args)
                    result.answer = done.answer.strip()
                    request = (done.request or "").strip().strip('"\'.')
                    # Models sometimes spell "no request" as a string: never parse that.
                    result.request = None if request.lower() in NO_REQUEST else request
                    return result
                if len(result.calls) >= max_calls:
                    raise tools.ToolError("tool budget exhausted: call finish now with what you have")
                output, ok = tools.call(name, args, devices), True
            except (tools.ToolError, json.JSONDecodeError) as exc:
                output, ok = f"error: {exc}", False
            except ValidationError as exc:  # invalid finish: tell the model, let it retry
                output, ok = f"error: invalid finish: {exc.errors()[0]['msg']}", False
            result.calls.append(ToolCall(name=name, arguments=args, ok=ok, output=output))
            shown = ", ".join(f"{k}=[{len(v)}]" if isinstance(v, list) else f"{k}={v}"
                              for k, v in args.items())
            on_step(Step(name="tool", ok=ok, detail=f"{name}({shown}) → {_summary(output)}"))
            messages.append({"role": "tool", "tool_call_id": call.get("id", name),
                             "content": output})
