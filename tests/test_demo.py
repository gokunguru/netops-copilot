"""Public demo mode (private lab per visitor, offline model) and recorded runs played back."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from netops_copilot import cli, replay
from netops_copilot.web import app as web
from netops_copilot.web.app import create_app

SAMPLES = Path(__file__).resolve().parents[1] / "src" / "netops_copilot" / "web" / "static" / "examples"
VLAN = "Create VLAN 30 named users on site-a"


@pytest.fixture
def recordings(tmp_path, monkeypatch):
    monkeypatch.setenv("NETOPS_STATE_DIR", str(tmp_path / "rec-state"))
    folder = tmp_path / "replays"
    assert cli.main(["--mock", "Telnet must be blocked on all edge ACLs",
                     "--record", str(folder / "audit.json")]) == 3
    assert cli.main(["--mock", "--image", str(SAMPLES / "ticket.png"), "--yes", "--no-review",
                     "--record", str(folder / "ticket.json"), "--record-title", "Ticket"]) == 0
    (folder / "broken.json").write_text("{not json")
    return folder


def demo(tmp_path, recordings=None):
    return create_app(demo=True, step_delay=0, state_dir=tmp_path / "demo",
                      replays=recordings or tmp_path / "none")


def start(c, **data):
    html = c.post("/runs", data=data).text
    return html.split('id="run-', 1)[1].split('"', 1)[0]


# ---------- recording ----------

def test_recording_holds_steps_result_and_outcome(recordings):
    data = json.loads((recordings / "ticket.json").read_text())
    assert data["title"] == "Ticket" and data["model"] == "offline mock model"
    assert data["target"].startswith("lab simulator")
    assert [s["name"] for s in data["steps"]][:2] == ["read", "parse"]
    assert all(b["t"] >= a["t"] for a, b in zip(data["steps"], data["steps"][1:], strict=False))
    assert data["outcome"]["decision"] == "approved" and data["outcome"]["rollback"]
    assert "/home/" not in json.dumps(data) and "/Users/" not in json.dumps(data)


def test_broken_recordings_are_skipped(recordings):
    assert [r.name for r in replay.load_all(recordings)] == ["audit", "ticket"]
    assert replay.load_all(recordings / "missing") == []


def test_recorded_live_target_and_failure(tmp_path, monkeypatch):
    rec = replay.Recorder()
    from netops_copilot.models import RunResult, Step
    rec(Step(name="parse", ok=True))
    path = rec.save(tmp_path / "r.json", title="t", model="muse-spark-1.3",
                    target="cat8k (sandbox) over SSH", result=RunResult(request="r"),
                    outcome=replay.Outcome(decision="failed", detail="device rejected"))
    assert replay.load_all(tmp_path)[0].outcome.detail == "device rejected"
    assert path.exists()


# ---------- demo mode ----------

def test_each_visitor_gets_a_private_lab(tmp_path):
    app = demo(tmp_path)
    alice, bob = TestClient(app), TestClient(app)
    rid = start(alice, request=VLAN)
    alice.get(f"/runs/{rid}/events")
    assert "Applied to the lab" in alice.post(f"/runs/{rid}/approve").text
    assert alice.get("/api/changes").json()["entries"]
    assert bob.get("/api/changes").json()["entries"] == []  # bob's lab is untouched
    assert bob.get(f"/runs/{rid}/events").status_code == 404  # and cannot see alice's run
    assert bob.post(f"/runs/{rid}/approve").status_code == 404
    assert "public demo" in bob.get("/").text
    assert alice.get("/healthz").json()["demo"] is True


def test_demo_forces_the_offline_model(tmp_path, monkeypatch):
    monkeypatch.setenv("META_API_KEY", "would-cost-money")
    c = TestClient(demo(tmp_path))
    body = c.post("/api/runs", json={"request": VLAN}).json()
    assert body["ready_for_approval"]  # MockLLM: no network call was possible


def test_cookie_is_random_and_validated(tmp_path):
    c = TestClient(demo(tmp_path))
    c.get("/")
    sid = c.cookies.get("netops_session")
    assert len(sid) == 16 and int(sid, 16) >= 0
    forged = TestClient(c.app, cookies={"netops_session": "../../etc"})
    reply = forged.get("/")  # forged id: replaced by a fresh one, never used as a path
    assert reply.headers["set-cookie"].startswith("netops_session=")
    assert "etc" not in reply.headers["set-cookie"]
    assert not (tmp_path / "etc").exists()


def test_old_sessions_and_runs_are_dropped(tmp_path, monkeypatch):
    monkeypatch.setattr(web, "MAX_SESSIONS", 2)
    app = demo(tmp_path)
    clients = [TestClient(app) for _ in range(3)]
    for c in clients:
        rid = start(c, request=VLAN)
        c.get(f"/runs/{rid}/events")
        c.post(f"/runs/{rid}/approve")
    assert len(list((tmp_path / "demo" / "sessions").iterdir())) == 2  # oldest lab deleted
    assert clients[0].get("/api/changes").json()["entries"] == []  # comes back fresh
    monkeypatch.setattr(web, "MAX_RUNS", 2)
    ids = [start(clients[0], request=VLAN) for _ in range(3)]
    assert clients[0].get(f"/runs/{ids[0]}/events").status_code == 404
    assert clients[0].get(f"/runs/{ids[2]}/events").status_code == 200


# ---------- playback ----------

def test_recordings_play_back_read_only(tmp_path, recordings):
    c = TestClient(demo(tmp_path, recordings))
    page = c.get("/").text
    assert "Recorded on real systems" in page and "▶ Ticket" in page
    assert "real Cisco router" not in page  # no live-device recording here: never claimed
    html = c.post("/replays/ticket").text
    assert "recorded" in html and "/images/0" in html  # sample image shown again
    rid = html.split('id="run-', 1)[1].split('"', 1)[0]
    events = c.get(f"/runs/{rid}/events").text
    assert "Read image" in events and "Approved by the operator" in events
    assert "read-only playback" in events and "hx-post=\"/runs/" not in events
    assert c.post(f"/runs/{rid}/approve").status_code == 409
    assert "Read image" in c.get(f"/runs/{rid}/events").text  # reconnect: replayed again
    assert c.post("/replays/nope").status_code == 404
    assert [r["name"] for r in c.get("/api/replays").json()] == ["audit", "ticket"]


def test_audit_recording_has_no_outcome(tmp_path, recordings):
    c = TestClient(demo(tmp_path, recordings))
    rid = c.post("/replays/audit").text.split('id="run-', 1)[1].split('"', 1)[0]
    assert "NON-COMPLIANT" in c.get(f"/runs/{rid}/events").text


def test_agent_recording_shows_the_operator_goal(tmp_path, monkeypatch):
    monkeypatch.setenv("NETOPS_STATE_DIR", str(tmp_path / "s"))
    folder = tmp_path / "r"
    cli.main(["--mock", "--agent", "Make sure VLAN 20 VOICE exists on every device", "--yes",
              "--record", str(folder / "agent.json")])
    c = TestClient(demo(tmp_path, folder))
    assert "Make sure VLAN 20 VOICE exists on every device" in c.post("/replays/agent").text
    live = json.loads((folder / "agent.json").read_text()) | {"target": "cat8k (x) over SSH"}
    (folder / "agent.json").write_text(json.dumps(live))
    assert "real Cisco router" in TestClient(demo(tmp_path, folder)).get("/").text
