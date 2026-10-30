"""Web UI and REST API: FastAPI + HTMX, live pipeline progress over Server-Sent Events.

Run it with:  netops-copilot-web --mock   (offline)   or   netops-copilot-web   (Muse Spark)
"""

import argparse
import asyncio
import os
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from html import escape
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException
from fastapi.requests import Request
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from netops_copilot import changes, drivers
from netops_copilot.agent.pipeline import load_inventory, run
from netops_copilot.cli import DEFAULT_INVENTORY
from netops_copilot.models import Device, RunResult, Step

HERE = Path(__file__).parent
templates = Jinja2Templates(directory=HERE / "templates")

STEP_LABELS = {
    "parse": "Parse intent", "generate": "Generate config", "gate": "Safety gate",
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
]


@dataclass
class Run:
    id: str
    request: str
    faulty: bool
    devices: dict[str, Device]  # snapshot the run was validated against
    started: bool = False
    result: RunResult | None = None
    error: str = ""
    decision: str = ""  # "", "approved", "rejected" or "failed"
    change: dict | None = None  # journal entry once applied
    detail: str = ""


class RunRequest(BaseModel):
    request: str


def sse(event: str, data: str) -> str:
    lines = data.splitlines() or [""]
    return f"event: {event}\n" + "".join(f"data: {line}\n" for line in lines) + "\n"


def create_app(mock: bool | None = None, inventory: str | Path | None = None,
               step_delay: float | None = None, max_retries: int = 3,
               state_dir: str | Path | None = None) -> FastAPI:
    mock = os.getenv("NETOPS_MOCK") == "1" if mock is None else mock
    # In mock mode every step is instant: a short pause makes the progress readable on screen.
    step_delay = (0.35 if mock else 0.0) if step_delay is None else step_delay
    inventory = inventory or DEFAULT_INVENTORY
    store = changes.Store(state_dir)
    runs: dict[str, Run] = {}

    def devices(live: bool = True) -> dict[str, Device]:
        """Current state: lab configs (with approved changes) and running configs over SSH."""
        return load_inventory(inventory, store, live=live)

    app = FastAPI(title="NetOps Copilot", version="0.1.0",
                  description="AI agent for validated multi-vendor network changes.")
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    def make_llm(faulty: bool):
        if mock:
            from netops_copilot.llm.mock import MockLLM
            return MockLLM(faulty_first_generation=faulty)
        from netops_copilot.llm.client import MetaClient
        return MetaClient()

    def render(name: str, **ctx) -> str:
        return templates.get_template(name).render(labels=STEP_LABELS, **ctx)

    def get_run(run_id: str) -> Run:
        if run_id not in runs:
            raise HTTPException(404, "unknown run")
        return runs[run_id]

    # ---------- HTML ----------

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        return templates.TemplateResponse(request, "index.html", {
            "examples": EXAMPLES, "mock": mock, "devices": devices(live=False).values(),
            "journal": list(reversed(store.journal()))[:6],
            "journal_ok": store.verify_journal()})

    @app.post("/runs", response_class=HTMLResponse)
    def create_run(request: str = Form(...), faulty: str = Form("")):
        request = request.strip()
        if not request:
            raise HTTPException(422, "empty request")
        try:
            snapshot = devices()
        except drivers.DriverError as exc:
            return f'<div class="callout callout-fail"><strong>Cannot read the devices.</strong> {escape(str(exc))}</div>'
        r = Run(id=uuid.uuid4().hex[:8], request=request, faulty=mock and faulty == "1",
                devices=snapshot)
        runs[r.id] = r
        return render("run.html", run=r)

    @app.get("/runs/{run_id}/events")
    async def events(run_id: str):
        r = get_run(run_id)

        async def stream() -> AsyncIterator[str]:
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
                return run(make_llm(r.faulty), r.request, r.devices, max_retries, on_step)

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

    @app.post("/runs/{run_id}/{decision}", response_class=HTMLResponse)
    def decide(run_id: str, decision: str):
        r = get_run(run_id)
        if decision not in ("approve", "reject"):
            raise HTTPException(404)
        if not (r.result and r.result.ready_for_approval):
            raise HTTPException(409, "nothing to approve")
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
        return render("decision.html", run=r, record=record)

    @app.get("/changes/{change_id}/{name}", response_class=PlainTextResponse)
    def artefact(change_id: str, name: str):
        try:
            return store.artefact(change_id, name)
        except changes.ChangeError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.post("/changes/{change_id}/rollback", response_class=HTMLResponse)
    def do_rollback(change_id: str):
        try:
            entry = changes.rollback(change_id, inventory, store, changes.operator() + " (web)")
        except changes.ChangeError as exc:
            return render("rollback.html", ok=False, message=str(exc))
        return render("rollback.html", ok=True, entry=entry)

    @app.post("/lab/reset", response_class=HTMLResponse)
    def reset_lab():
        store.reset()
        return ('<div class="callout callout-ok small">Lab reset: configs back to the inventory, '
                'journal cleared. Reload the page.</div>')

    # ---------- JSON API ----------

    @app.post("/api/runs", tags=["api"])
    def api_run(body: RunRequest) -> dict:
        """Run the full pipeline synchronously and return the result (no approval)."""
        result = run(make_llm(False), body.request, devices(), max_retries)
        return result.model_dump(mode="json") | {
            "ready_for_approval": result.ready_for_approval,
            "compliant": result.compliant if result.is_audit else None,
        }

    @app.get("/healthz", tags=["ops"])
    def healthz() -> dict:
        """Liveness probe for containers and load balancers."""
        return {"status": "ok", "mock": mock, "devices": len(devices(live=False))}

    @app.get("/api/inventory", tags=["api"])
    def api_inventory() -> list[dict]:
        return [{"hostname": d.hostname, "vendor": d.vendor.value, "live": d.live}
                for d in devices(live=False).values()]

    @app.get("/api/changes", tags=["api"])
    def api_changes() -> dict:
        """The change journal, oldest first, and whether its hash chain is intact."""
        return {"entries": store.journal(), "integrity_ok": store.verify_journal()}

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
