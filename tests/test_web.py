import re

from fastapi.testclient import TestClient

from netops_copilot.web.app import create_app


def client():
    return TestClient(create_app(mock=True, step_delay=0))


def start(c, request, faulty=""):
    page = c.post("/runs", data={"request": request, "faulty": faulty})
    assert page.status_code == 200
    run_id = re.search(r'sse-connect="/runs/(\w+)/events"', page.text).group(1)
    stream = c.get(f"/runs/{run_id}/events").text
    return run_id, stream


def events(stream):
    return re.findall(r"^event: (\w+)$", stream, re.MULTILINE)


def test_index_lists_examples_and_inventory():
    page = client().get("/")
    assert page.status_code == 200
    assert "Retry loop" in page.text and "site-b" in page.text and "offline mock model" in page.text


def test_vlan_run_streams_steps_then_result_and_can_be_approved():
    c = client()
    run_id, stream = start(c, "Create VLAN 30 named users on site-a and site-b")
    assert events(stream) == ["step"] * 5 + ["result", "done"]
    assert "+vlan 30" in stream and "Approve" in stream
    decision = c.post(f"/runs/{run_id}/approve")
    assert decision.status_code == 200 and "Applied to the lab" in decision.text
    # a decision is final
    assert "Applied to the lab" in c.post(f"/runs/{run_id}/reject").text


def test_retry_loop_visible_in_stream():
    _, stream = start(client(), "Create VLAN 30 named users on site-a", faulty="1")
    assert "step-fail" in stream and "existing VLAN 20 removed" in stream
    assert "attempt 2" in stream


def test_audit_run_shows_findings_and_no_approval():
    c = client()
    run_id, stream = start(c, "Telnet and SMB must be blocked and HTTPS allowed on all edge ACLs")
    assert "NON-COMPLIANT" in stream and "Huawei traffic-filter default permit" in stream
    assert "Approve" not in stream
    assert c.post(f"/runs/{run_id}/approve").status_code == 409


def test_reconnect_replays_result_without_rerunning():
    c = client()
    run_id, _ = start(c, "Create VLAN 30 named users on site-a")
    again = c.get(f"/runs/{run_id}/events").text
    assert events(again) == ["result", "done"]


def test_user_input_is_escaped():
    page = client().post("/runs", data={"request": "<script>alert(1)</script>"})
    assert "<script>alert(1)</script>" not in page.text and "&lt;script&gt;" in page.text


def test_json_api():
    c = client()
    body = c.post("/api/runs", json={"request": "Create VLAN 30 named users on site-a"}).json()
    assert body["ready_for_approval"] is True and body["intent"]["targets"] == ["site-a"]
    assert {d["hostname"] for d in c.get("/api/inventory").json()} == {"site-a", "site-b", "core"}


def test_healthz():
    assert client().get("/healthz").json() == {"status": "ok", "mock": True, "devices": 3}
