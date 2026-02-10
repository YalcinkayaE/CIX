from __future__ import annotations

from fastapi.testclient import TestClient

from src.api.app import create_app


def test_api_ingest_classify_basic(tmp_path, monkeypatch):
    ledger_path = tmp_path / "ledger.jsonl"
    monkeypatch.setenv("CIX_LEDGER_PATH", str(ledger_path))
    client = TestClient(create_app())
    payload = {
        "events": [
            {
                "source_id": "siem-A",
                "event_id": "evt-api-1",
                "source_timestamp": "2026-02-06T10:00:00Z",
                "raw_payload": {"message": "hello", "event": {"kind": "alert"}},
            }
        ]
    }
    resp = client.post("/api/v1/ingest/classify", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert "per_event" in body
    assert body["per_event"][0]["event_id"] == "evt-api-1"
    assert body["per_event"][0]["band"] in {"VACUUM", "LOW_ENTROPY", "MIMIC_SCOPED"}
    assert "batch" in body
    assert "stage1_ms" in body["batch"]


def test_api_ingest_classify_cef(tmp_path, monkeypatch):
    ledger_path = tmp_path / "ledger.jsonl"
    monkeypatch.setenv("CIX_LEDGER_PATH", str(ledger_path))
    client = TestClient(create_app())
    payload = {
        "events": [
            {
                "source_id": "siem-B",
                "event_id": "evt-api-2",
                "source_timestamp": "2026-02-06T10:01:00Z",
                "format": "cef",
                "raw_event": "CEF:0|Acme|ThreatX|1.0|100|Test Event|5|src=10.0.0.1 dst=10.0.0.2 msg=hello",
            }
        ]
    }
    resp = client.post("/api/v1/ingest/classify", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["per_event"][0]["event_id"] == "evt-api-2"
    assert "entropy_raw" in body["per_event"][0]
