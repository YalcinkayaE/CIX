from __future__ import annotations

from fastapi.testclient import TestClient

from src.api.app import create_app

KERNEL_PATH = "/Users/erkanyalcinkaya/projects/axoden-kernel"


def _payload() -> dict:
    return {
        "events": [
            {
                "source_id": "siem-A",
                "event_id": "evt-kernel-1",
                "source_timestamp": "2026-02-06T10:00:00Z",
                "raw_payload": {
                    "message": "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+[]{}|;:,.<>?",
                    "event": {"kind": "alert"},
                },
            }
        ]
    }


def test_kernel_ingest_events_basic(tmp_path, monkeypatch):
    monkeypatch.setenv("AXODEN_KERNEL_PATH", KERNEL_PATH)
    monkeypatch.setenv("CIX_KERNEL_LEDGER_PATH", str(tmp_path / "kernel_ledger.jsonl"))

    client = TestClient(create_app())
    payload = _payload()
    headers = {"Idempotency-Key": "ingest-basic-1"}

    resp = client.post("/v1/ingest/events", json=payload, headers=headers)
    assert resp.status_code == 200
    body = resp.json()

    assert body["registry_commit"]
    assert body["batch_id"]
    assert len(body["admitted"]) + len(body["dropped"]) == 1

    resp2 = client.post("/v1/ingest/events", json=payload, headers=headers)
    assert resp2.status_code == 200
    assert resp2.json() == body


def test_kernel_graph_run(tmp_path, monkeypatch):
    monkeypatch.setenv("AXODEN_KERNEL_PATH", KERNEL_PATH)
    monkeypatch.setenv("CIX_KERNEL_LEDGER_PATH", str(tmp_path / "kernel_ledger.jsonl"))

    import src.pipeline.graph_pipeline as graph_pipeline

    monkeypatch.setattr(
        graph_pipeline,
        "run_graph_pipeline",
        lambda raw_events, output_dir, enable_kernel=False: {
            "reports": [],
            "ledgers": [],
            "graphs_html": [],
            "graphs_png": [],
        },
    )

    client = TestClient(create_app())
    payload = _payload()
    ingest_headers = {"Idempotency-Key": "ingest-graph-1"}

    ingest_resp = client.post("/v1/ingest/events", json=payload, headers=ingest_headers)
    assert ingest_resp.status_code == 200
    ingest_body = ingest_resp.json()
    assert ingest_body["admitted"]

    evidence_ids = [item["evidence_id"] for item in ingest_body["admitted"]]
    run_headers = {"Idempotency-Key": "run-graph-1"}
    run_resp = client.post("/v1/runs/graph", json={"evidence_ids": evidence_ids}, headers=run_headers)
    assert run_resp.status_code == 200
    run_body = run_resp.json()
    assert run_body["run_id"]

    status_resp = client.get(f"/v1/runs/{run_body['run_id']}")
    assert status_resp.status_code == 200

    artifacts_resp = client.get(f"/v1/runs/{run_body['run_id']}/artifacts")
    assert artifacts_resp.status_code == 200
