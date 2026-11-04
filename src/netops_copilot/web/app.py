"""Web UI and REST API: FastAPI + HTMX, live pipeline progress over Server-Sent Events.

Run it with:  netops-copilot-web --mock   (offline)   or   netops-copilot-web   (Muse Spark)
"""

import argparse
import asyncio
import base64
import binascii
import os
import re
import shutil
import uuid
from collections import OrderedDict
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from html import escape
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.requests import Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from netops_copilot import changes, drivers, policy, replay, vision
from netops_copilot.agent.pipeline import load_inventory, run
from netops_copilot.cli import DEFAULT_INVENTORY
from netops_copilot.models import Device, Intent, RunResult, Step

HERE = Path(__file__).parent
templates = Jinja2Templates(directory=HERE / "templates")

STEP_LABELS = {
    "policy": "Policy guard", "review_tool": "Reviewer looks", "review": "Independent review", "read": "Read image", "tool": "Tool call", "investigate": "Investigation", "parse": "Parse intent", "generate": "Generate config", "gate": "Safety gate",
    "dry_run": "Dry-run", "explain": "Explain", "audit": "ACL audit",
}
EXAMPLES = [
    {"label": "VLAN, multi-vendor", "request": "Create VLAN 30 named users on site-a and site-b",
     "faulty": False},
    {"label": "Retry loop", "request": "Create VLAN 30 named users on site-a", "faulty": True},
    {"label": "ACL audit",
     "request": "Telnet and SMB must be blocked and HTTPS allowed on all edge ACLs",
     "faulty": False},
    {"label": "ACL auto-fix",
     "request": "Fix the edge ACLs: telnet and SMB must be blocked and HTTPS allowed",
     "faulty": True},
    {"label": "Agent: telnet exposure", "agent": True, "faulty": False,
     "request": "Is telnet reachable from outside anywhere? Fix it where it is."},
    {"label": "Agent: VLAN everywhere", "agent": True, "faulty": False,
     "request": "Make sure VLAN 20 VOICE exists on every device"},
    {"label": "Ticket screenshot", "request": "", "sample": "ticket.png", "faulty": False},
    {"label": "Whiteboard photo", "request": "", "sample": "whiteboard.png", "faulty": False},
]
SAMPLES = HERE / "static" / "examples"


@dataclass
class Run:
    id: str
    request: str
    faulty: bool
    devices: dict[str, Device]  # snapshot the run was validated against
    images: list[vision.Image] = field(default_factory=list)
    agent: bool = False
    intent: Intent | None = None  # set when enforcing a versioned policy
    policy: str = ""
    session: str = ""  # demo mode: the visitor who started it
    replay: "replay.Replay | None" = None  # recorded run on a real system, played back
    started: bool = False
    result: RunResult | None = None
    error: str = ""
    decision: str = ""  # "", "approved", "rejected" or "failed"
    change: dict | None = None  # journal entry once applied
    detail: str = ""


MAX_SESSIONS = 200  # demo mode: private labs kept at once
MAX_RUNS = 500
SESSION = re.compile(r"^[0-9a-f]{16}$")


class DemoSession:
    """ASGI middleware (demo mode): one anonymous cookie per visitor, so every visitor gets a
    private lab and only sees their own runs. The cookie holds a random id, nothing else."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        cookies = dict(part.strip().split("=", 1) for header, value in scope["headers"]
                       if header == b"cookie" for part in value.decode().split(";") if "=" in part)
        sid = cookies.get("netops_session", "")
        new = not SESSION.match(sid)
        if new:
            sid = uuid.uuid4().hex[:16]
        scope.setdefault("state", {})["session"] = sid

        async def send_with_cookie(message):
            if new and message["type"] == "http.response.start":
                message.setdefault("headers", []).append((b"set-cookie", (
                    f"netops_session={sid}; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax"
                ).encode()))
            await send(message)

        return await self.app(scope, receive, send_with_cookie)


class RunRequest(BaseModel):
    request: str = ""
    images: list[str] = []  # base64, or data: URLs
    agent: bool = False  # investigate first with read-only tools


def decode_image(text: str, n: int) -> vision.Image:
    try:
        return vision.load(base64.b64decode(text.split(",", 1)[-1], validate=True), f"image-{n}")
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(422, f"image {n}: {exc}") from exc


def sse(event: str, data: str) -> str:
    lines = data.splitlines() or [""]
    return f"event: {event}\n" + "".join(f"data: {line}\n" for line in lines) + "\n"


def create_app(mock: bool | None = None, inventory: str | Path | None = None,
               step_delay: float | None = None, max_retries: int = 3,
               state_dir: str | Path | None = None,
               policies: str | Path | None = None, demo: bool | None = None,
               replays: str | Path | None = None) -> FastAPI:
    # Public demo: offline model only (no API key to burn), one private lab per visitor.
    demo = os.getenv("NETOPS_DEMO") == "1" if demo is None else demo
    mock = True if demo else (os.getenv("NETOPS_MOCK") == "1" if mock is None else mock)
    from netops_copilot.llm.client import settings
    provider = None if mock else os.getenv("LLM_PROVIDER")
    model_label = "" if mock else "{model} · {label}".format(**settings(provider))
    # In mock mode every step is instant: a short pause makes the progress readable on screen.
    step_delay = (0.35 if mock else 0.0) if step_delay is None else step_delay
    inventory = inventory or DEFAULT_INVENTORY
    store = changes.Store(state_dir)
    runs: dict[str, Run] = {}
    policy_dir = policies or policy.DEFAULT_DIR
    recorded = replay.load_all(replays or replay.DEFAULT_DIR)
    sessions: OrderedDict[str, changes.Store] = OrderedDict()

    def store_of(http: Request) -> changes.Store:
        """The lab state of this visitor (demo mode) or the shared one."""
        if not demo:
            return store
        sid = http.state.session
        if sid not in sessions:
            sessions[sid] = changes.Store(store.root / "sessions" / sid)
            while len(sessions) > MAX_SESSIONS:  # forget the least recent visitor
                _, old = sessions.popitem(last=False)
                shutil.rmtree(old.root, ignore_errors=True)
        sessions.move_to_end(sid)
        return sessions[sid]

    def devices(st: changes.Store, live: bool = True) -> dict[str, Device]:
        """Current state: lab configs (with approved changes) and running configs over SSH."""
        return load_inventory(inventory, st, live=live)

    def keep(r: Run) -> None:
        runs[r.id] = r
        while len(runs) > MAX_RUNS:
            runs.pop(next(iter(runs)))

    app = FastAPI(title="NetOps Copilot", version="0.1.0",
                  description="AI agent for validated multi-vendor network changes.")
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    if demo:
        app.add_middleware(DemoSession)

    def make_llm(faulty: bool):
        if mock:
            from netops_copilot.llm.mock import MockLLM
            return MockLLM(faulty_first_generation=faulty)
        from netops_copilot.llm.client import MetaClient
        return MetaClient(provider=provider)

    def review_of(llm):
        """Independent reviewer: the other provider when its key is set, else a new session."""
        if mock:
            return True
        from netops_copilot.llm.client import reviewer
        return reviewer(llm)

    def render(name: str, **ctx) -> str:
        return templates.get_template(name).render(labels=STEP_LABELS, **ctx)

    def get_run(run_id: str, http: Request) -> Run:
        r = runs.get(run_id)
        if r is None or (demo and r.session != http.state.session):
            raise HTTPException(404, "unknown run")
        return r

    # ---------- HTML ----------

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        st = store_of(request)
        return templates.TemplateResponse(request, "index.html", {
            "examples": EXAMPLES, "mock": mock, "demo": demo, "model_label": model_label,
            "devices": devices(st, live=False).values(), "replays": recorded,
            "recorded_live": any("over SSH" in x.target for x in recorded),
            "journal": list(reversed(st.journal()))[:6], "journal_ok": st.verify_journal()})

    @app.post("/runs", response_class=HTMLResponse)
    async def create_run(http: Request, request: str = Form(""), faulty: str = Form(""),
                         sample: str = Form(""), agent: str = Form(""), enforce: str = Form(""),
                         images: list[UploadFile] = File(default=[])):
        request = request.strip()
        try:
            loaded = [vision.load(data, f.filename) for f in images if f.filename
                      and (data := await f.read(vision.MAX_BYTES + 1))]
            if sample:
                if sample not in {ex.get("sample") for ex in EXAMPLES}:
                    raise HTTPException(404, "unknown sample image")
                loaded.append(vision.load_path(SAMPLES / sample))
            vision.check_count(loaded)
        except vision.ImageError as exc:
            return f'<div class="callout callout-fail"><strong>Image refused.</strong> {escape(str(exc))}</div>'
        if not request and not loaded and not enforce:
            raise HTTPException(422, "empty request")
        return await asyncio.to_thread(start_run, request, faulty, loaded, agent == "1", enforce,
                                       store_of(http), getattr(http.state, "session", ""))

    def start_run(request: str, faulty: str, loaded: list[vision.Image], agent: bool,
                  enforce: str, st: changes.Store, session: str) -> str:
        try:
            snapshot = devices(st)
            intent = policy_intent(enforce, snapshot) if enforce else None
        except drivers.DriverError as exc:
            return f'<div class="callout callout-fail"><strong>Cannot read the devices.</strong> {escape(str(exc))}</div>'
        except policy.PolicyError as exc:
            return f'<div class="callout callout-fail"><strong>Policy error.</strong> {escape(str(exc))}</div>'
        if enforce and intent is None:
            return (f'<div class="callout callout-ok"><strong>{escape(enforce)}</strong>: nothing to '
                    'enforce, the devices comply.</div>')
        r = Run(id=uuid.uuid4().hex[:8], request=f"Enforce policy {enforce}" if enforce else request,
                faulty=mock and faulty == "1", devices=snapshot, images=loaded, agent=agent,
                intent=intent, policy=enforce, session=session)
        keep(r)
        return render("run.html", run=r)

    @app.post("/replays/{name}", response_class=HTMLResponse)
    def start_replay(name: str, http: Request):
        found = next((x for x in recorded if x.name == name), None)
        if found is None:
            raise HTTPException(404, "unknown recording")
        shown = found.result.reading.images if found.result.reading else []
        inv = found.result.investigation
        r = Run(id=uuid.uuid4().hex[:8], request=inv.goal if inv else found.request,
                faulty=False, devices={},
                session=getattr(http.state, "session", ""), replay=found,
                agent=found.result.investigation is not None,
                images=[vision.load_path(SAMPLES / n) for n in shown if (SAMPLES / n).is_file()])
        keep(r)
        return render("run.html", run=r)

    @app.get("/runs/{run_id}/events")
    async def events(run_id: str, http: Request):
        r = get_run(run_id, http)

        async def stream() -> AsyncIterator[str]:
            if r.replay:  # recorded on a real system: same steps, original pace (capped)
                last = 0.0
                for step in r.replay.steps:
                    if not r.started:
                        await asyncio.sleep(min(max(step.t - last, 0.0), replay.MAX_PAUSE)
                                            * (1 if step_delay else 0))
                    last = step.t
                    yield sse("step", render("step.html", step=step.as_step()))
                r.started, r.result = True, r.replay.result
                yield sse("result", render("result.html", run=r))
                yield sse("done", "")
                return
            if r.started:  # browser reconnected: replay the final state, never rerun
                while r.result is None and not r.error:
                    await asyncio.sleep(0.2)
                yield sse("result", render("result.html", run=r))
                yield sse("done", "")
                return
            r.started = True
            loop = asyncio.get_running_loop()
            queue: asyncio.Queue[Step] = asyncio.Queue()

            def on_step(step: Step) -> None:
                loop.call_soon_threadsafe(queue.put_nowait, step)

            def work() -> RunResult:
                llm = make_llm(r.faulty)
                return run(llm, r.request, r.devices, max_retries, on_step,
                           images=r.images, agent=r.agent, intent=r.intent,
                           policy=r.policy or None, review=review_of(llm))

            task = asyncio.create_task(asyncio.to_thread(work))
            while not (task.done() and queue.empty()):
                try:
                    step = await asyncio.wait_for(queue.get(), timeout=0.1)
                except TimeoutError:
                    continue
                if step_delay:
                    await asyncio.sleep(step_delay)
                yield sse("step", render("step.html", step=step))
            try:
                r.result = task.result()
            except Exception as exc:  # noqa: BLE001  API down, bad key: show it, never hang
                r.error = f"{type(exc).__name__}: {exc}"
            yield sse("result", render("result.html", run=r))
            yield sse("done", "")

        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.get("/runs/{run_id}/images/{n}")
    def run_image(run_id: str, n: int, http: Request) -> Response:
        images = get_run(run_id, http).images
        if not 0 <= n < len(images):
            raise HTTPException(404)
        return Response(images[n].data, media_type=images[n].mime,
                        headers={"X-Content-Type-Options": "nosniff"})

    @app.post("/runs/{run_id}/{decision}", response_class=HTMLResponse)
    def decide(run_id: str, decision: str, http: Request, ack: str = Form("")):
        r = get_run(run_id, http)
        if decision not in ("approve", "reject"):
            raise HTTPException(404)
        if r.replay:
            raise HTTPException(409, "recorded run: read-only")
        store = store_of(http)
        if not (r.result and r.result.ready_for_approval):
            raise HTTPException(409, "nothing to approve")
        if decision == "approve" and r.result.escalated and ack != "1":
            # Escalated (reviewer or control-plane rule): needs an explicit acknowledgement.
            raise HTTPException(409, "escalated to a human: acknowledge first")
        if not r.decision:
            if decision == "reject":
                r.decision = "rejected"
            else:
                try:
                    r.change = changes.commit(r.result, r.devices, inventory, store,
                                              changes.operator() + " (web)")
                    r.decision = "approved"
                except changes.ChangeError as exc:
                    r.decision, r.detail = "failed", str(exc)
        record = store.record(r.change["change"]) if r.change else None
        # Applied changes move the policy state: the policies panel refreshes itself.
        return HTMLResponse(render("decision.html", run=r, record=record),
                            headers={"HX-Trigger": "refresh-policies"})

    @app.get("/changes/{change_id}/{name}", response_class=PlainTextResponse)
    def artefact(change_id: str, name: str, http: Request):
        try:
            return store_of(http).artefact(change_id, name)
        except changes.ChangeError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.post("/changes/{change_id}/rollback", response_class=HTMLResponse)
    def do_rollback(change_id: str, http: Request):
        try:
            entry = changes.rollback(change_id, inventory, store_of(http),
                                     changes.operator() + " (web)")
        except changes.ChangeError as exc:
            return render("rollback.html", ok=False, message=str(exc))
        return HTMLResponse(render("rollback.html", ok=True, entry=entry),
                            headers={"HX-Trigger": "refresh-policies"})

    @app.post("/lab/reset", response_class=HTMLResponse)
    def reset_lab(http: Request):
        store_of(http).reset()
        return ('<div class="callout callout-ok small">Lab reset: configs back to the inventory, '
                'journal cleared. Reload the page.</div>')

    def policy_results(snapshot: dict[str, Device]) -> list[policy.PolicyResult]:
        return policy.check_all(policy.load(policy_dir), snapshot)

    def policy_intent(name: str, snapshot: dict[str, Device]) -> Intent | None:
        found = [r for r in policy_results(snapshot) if r.policy.name == name]
        if not found:
            raise policy.PolicyError(f"unknown policy '{name}'")
        return policy.intent(found[0])

    @app.get("/policies", response_class=HTMLResponse)
    def policies_panel(http: Request):
        """Loaded after the page: checking live devices opens SSH sessions."""
        try:
            results = policy_results(devices(store_of(http)))
        except (policy.PolicyError, drivers.DriverError) as exc:
            return f'<p class="small fail">{escape(str(exc))}</p>'
        return render("policies.html", results=results)

    # ---------- JSON API ----------

    @app.post("/api/runs", tags=["api"])
    def api_run(body: RunRequest, http: Request) -> dict:
        """Run the full pipeline synchronously and return the result (no approval).

        `images`: optional photos, screenshots or diagrams (base64 or data: URLs), read by the
        model into the request; `request` is then an optional note.
        """
        if len(body.images) > vision.MAX_IMAGES or not (body.request.strip() or body.images):
            raise HTTPException(422, f"a request or 1 to {vision.MAX_IMAGES} images are required")
        images = [decode_image(text, n) for n, text in enumerate(body.images)]
        llm = make_llm(False)
        result = run(llm, body.request.strip(), devices(store_of(http)), max_retries,
                     images=images, agent=body.agent, review=review_of(llm))
        return result.model_dump(mode="json") | {
            "ready_for_approval": result.ready_for_approval,
            "compliant": result.compliant if result.is_audit else None,
            "answered": result.answered,
            "escalated": result.escalated,
        }

    @app.get("/healthz", tags=["ops"])
    def healthz() -> dict:
        """Liveness probe for containers and load balancers."""
        return {"status": "ok", "mock": mock, "demo": demo,
                "devices": len(devices(store, live=False))}

    @app.get("/api/inventory", tags=["api"])
    def api_inventory(http: Request) -> list[dict]:
        return [{"hostname": d.hostname, "vendor": d.vendor.value, "live": d.live}
                for d in devices(store_of(http), live=False).values()]

    @app.get("/api/policies", tags=["api"])
    def api_policies(http: Request) -> dict:
        """Every versioned policy checked against the current state (no model involved)."""
        try:
            results = policy_results(devices(store_of(http)))
        except policy.PolicyError as exc:
            raise HTTPException(500, str(exc)) from exc
        return {"compliant": all(r.compliant for r in results),
                "fingerprint": policy.fingerprint(results),
                "policies": [{"name": r.policy.name, "kind": r.policy.kind,
                              "severity": r.policy.severity, "owner": r.policy.owner,
                              "compliant": r.compliant, "checks": len(r.rows),
                              "failed": [x.model_dump() for x in r.failed]} for r in results]}

    @app.get("/api/changes", tags=["api"])
    def api_changes(http: Request) -> dict:
        """The change journal, oldest first, and whether its hash chain is intact."""
        st = store_of(http)
        return {"entries": st.journal(), "integrity_ok": st.verify_journal()}

    @app.get("/api/replays", tags=["api"])
    def api_replays() -> list[dict]:
        """Runs recorded on the real Muse Spark API and real devices, played back in the UI."""
        return [x.model_dump(mode="json", include={"name", "title", "recorded", "model", "target"})
                for x in recorded]

    return app


def serve() -> None:
    p = argparse.ArgumentParser(prog="netops-copilot-web")
    p.add_argument("--mock", action="store_true", help="offline deterministic model, no API call")
    p.add_argument("--host", default=os.getenv("NETOPS_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.getenv("NETOPS_PORT", "8000")))
    p.add_argument("--inventory", default=str(DEFAULT_INVENTORY))
    args = p.parse_args()
    import uvicorn
    # --mock forces offline mode; otherwise NETOPS_MOCK=1 (e.g. set in the container) decides.
    uvicorn.run(create_app(mock=True if args.mock else None, inventory=args.inventory),
                host=args.host, port=args.port)


if __name__ == "__main__":
    serve()
