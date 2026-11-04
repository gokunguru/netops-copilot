"""Public demo on Modal: offline model, a private lab per visitor, recorded real runs.

    pip install modal && modal setup        # once
    modal deploy deploy/modal_app.py        # prints the public URL

Nothing secret is uploaded: .env, the lab state and git data are excluded, and the demo never
calls the Meta API (NETOPS_DEMO forces the offline model).
"""

import os
from pathlib import Path

import modal

ROOT = Path(__file__).resolve().parents[1]

image = (
    modal.Image.debian_slim(python_version="3.12")
    .add_local_dir(ROOT, "/app", copy=True, ignore=[
        ".git", ".github", ".env", ".env.*", ".netops", ".venv", "venv", "**/__pycache__",
        "**/*.egg-info", ".pytest_cache", ".ruff_cache", ".coverage", "tests", "docs", "deploy",
    ])
    .run_commands("pip install --no-cache-dir /app")
    .env({
        "NETOPS_DEMO": "1",
        "NETOPS_INVENTORY": "/app/lab/inventory.yml",
        "NETOPS_POLICIES": "/app/policies",
        "NETOPS_REPLAYS": "/app/replays",
        "NETOPS_STATE_DIR": "/tmp/netops",
        "NETOPS_OPERATOR": "demo-visitor",
    })
)

app = modal.App("netops-copilot-demo")


# One container: runs and live progress (SSE) are kept in memory, so every request of a visitor
# must reach the same process. Concurrency comes from async, not from more containers.
# MIN_CONTAINERS=1 keeps one container warm (no cold start for judges), at the cost of an idle
# CPU container: `MIN_CONTAINERS=1 modal deploy deploy/modal_app.py`, then redeploy without it.
@app.function(image=image, max_containers=1, min_containers=int(os.getenv("MIN_CONTAINERS", "0")),
              scaledown_window=1200, timeout=900)
@modal.concurrent(max_inputs=100)
@modal.asgi_app()
def web():
    from netops_copilot.web.app import create_app

    return create_app()
