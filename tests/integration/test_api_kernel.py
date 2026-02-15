from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app


def _kernel_path_or_skip() -> str:
    env_path = os.getenv("AXODEN_KERNEL_PATH")
    if env_path:
        kernel_path = Path(env_path).expanduser().resolve()
    else:
        repo_root = Path(__file__).resolve().parents[2]
        kernel_path = (repo_root.parent / "axoden-kernel").resolve()
    if not kernel_path.exists():
        pytest.skip("AxoDen kernel not found. Set AXODEN_KERNEL_PATH to run kernel integration tests.")
    return str(kernel_path)


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
    monkeypatch.setenv("AXODEN_KERNEL_PATH", _kernel_path_or_skip())
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
    monkeypatch.setenv("AXODEN_KERNEL_PATH", _kernel_path_or_skip())
    monkeypatch.setenv("CIX_KERNEL_LEDGER_PATH", str(tmp_path / "kernel_ledger.jsonl"))

    import src.pipeline.graph_pipeline as graph_pipeline

    monkeypatch.setattr(
        graph_pipeline,
        "run_graph_pipeline",
        lambda raw_events, output_dir, enable_kernel=False: {
            "reports": [f"{output_dir}/Forensic_Assessment_Campaign_1.md"],
            "ledgers": [f"{output_dir}/forensic_ledger_campaign_1.json"],
            "graphs_html": [f"{output_dir}/investigation_graph_campaign_1.html"],
            "graphs_png": [],
            "snapshots_html": [f"{output_dir}/campaign_snapshot_1.html"],
            "temporal_analyses_json": [f"{output_dir}/temporal_analysis_campaign_1.json"],
            "verification_json": [f"{output_dir}/cmi_verification_campaign_1.json"],
            "manifests_json": [f"{output_dir}/reproducibility_manifest.json"],
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
    artifact_types = {item["type"] for item in artifacts_resp.json().get("artifacts", [])}
    assert "temporal_analysis_json" in artifact_types
    assert "verification_json" in artifact_types
    assert "reproducibility_manifest_json" in artifact_types
