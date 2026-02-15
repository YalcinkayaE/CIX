from __future__ import annotations

from datetime import datetime, timezone

import networkx as nx

from src.pipeline.graph_pipeline import (
    _build_ground_truth_draft_payload,
    _candidate_core_event_ids,
    _compute_detection_metrics,
    _render_claim_and_verification_appendix,
)


def test_compute_detection_metrics_precision_recall():
    metrics = _compute_detection_metrics(
        predicted_event_ids=["E1", "E2", "E4"],
        ground_truth_event_ids=["E2", "E3", "E4"],
    )
    assert metrics["true_positive"] == 2
    assert metrics["false_positive"] == 1
    assert metrics["false_negative"] == 1
    assert metrics["precision"] == 0.6667
    assert metrics["recall"] == 0.6667


def test_claim_appendix_includes_evidence_pointers_and_scoring():
    traversal = {
        "seed_alerts": [{"alert": "Alert:E1", "event_id": "E1", "host": "WS5", "process": "wscript.exe", "command": "wscript.exe launcher.vbs"}],
        "rca_patient_zero": {"alert": "Alert:E1", "event_id": "E1", "host": "WS5", "process": "wscript.exe", "command": "wscript.exe launcher.vbs"},
        "rca_connectivity_top": {"alert": "Alert:E2", "event_id": "E2", "host": "WS5", "process": "powershell.exe", "command": "powershell.exe -enc ...", "score": 0.77},
        "rca_top": [],
    }
    verification = {
        "decision": {"claim_label": "INFERRED", "reason": "Insufficient statistical evidence for VERIFIED; keep as INFERRED"},
        "statistics": {"cmi_observed": 0.01, "p_value": 0.2, "ci95_low": 0.0, "ci95_high": 0.1},
    }
    metrics = _compute_detection_metrics(["E1", "E2"], ["E1", "E3"])

    appendix = _render_claim_and_verification_appendix(
        traversal_analysis=traversal,
        verification_analysis=verification,
        manifest_name="reproducibility_manifest.json",
        temporal_artifact_name="temporal_analysis_campaign_1.json",
        verification_artifact_name="cmi_verification_campaign_1.json",
        predicted_core_event_ids=["E1", "E2"],
        detection_metrics=metrics,
        ground_truth_event_ids=["E1", "E3"],
        ground_truth_draft={
            "recommended_event_ids": ["E1", "E2"],
            "stage_candidates": {
                "initial_access_script_execution": {
                    "event_id": "E1",
                    "alert": "Alert:E1",
                    "feature_score": 3,
                }
            },
        },
    )

    assert "## 8. Claim Evidence Pointers" in appendix
    assert "## 10. Quantitative Detection Scoring" in appendix
    assert "## 12. Ground Truth Draft (Analyst Review)" in appendix
    assert "event_id=E1" in appendix
    assert "TP/FP/FN" in appendix


def test_candidate_core_event_ids_prefers_generic_stage_evidence():
    graph = nx.DiGraph()
    graph.add_node("Alert:E1", type="Alert", event_id="E1")
    graph.add_node("Alert:E2", type="Alert", event_id="E2")
    graph.add_node("Alert:E3", type="Alert", event_id="E3")
    graph.add_node("Alert:E4", type="Alert", event_id="E4")
    graph.add_node("Alert:E5", type="Alert", event_id="E5")

    graph.add_node("MITRE:T1059.005", type="MITRE_Technique")
    graph.add_node("MITRE:T1059.001", type="MITRE_Technique")
    graph.add_node("MITRE:T1033", type="MITRE_Technique")
    graph.add_node("MITRE:T1074.001", type="MITRE_Technique")
    graph.add_node("IP:1.2.3.4", type="IP", value="1.2.3.4")

    graph.add_edge("Alert:E1", "MITRE:T1059.005", relationship="INDICATES_TECHNIQUE")
    graph.add_edge("Alert:E2", "MITRE:T1059.001", relationship="INDICATES_TECHNIQUE")
    graph.add_edge("Alert:E3", "MITRE:T1033", relationship="INDICATES_TECHNIQUE")
    graph.add_edge("Alert:E4", "MITRE:T1074.001", relationship="INDICATES_TECHNIQUE")
    graph.add_edge("Alert:E5", "IP:1.2.3.4", relationship="HAS_DEST_IP")

    traversal = {
        "seed_alerts": [{"event_id": "E1"}],
        "rca_patient_zero": {"event_id": "RCA1"},
        "rca_connectivity_top": {"event_id": "RCA2"},
        "rca_top": [{"event_id": "RCA3"}],
    }
    alert_meta = {
        "Alert:E1": {"event_id": "E1", "timestamp_dt": datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)},
        "Alert:E2": {"event_id": "E2", "timestamp_dt": datetime(2026, 1, 1, 10, 1, tzinfo=timezone.utc)},
        "Alert:E3": {"event_id": "E3", "timestamp_dt": datetime(2026, 1, 1, 10, 2, tzinfo=timezone.utc)},
        "Alert:E4": {"event_id": "E4", "timestamp_dt": datetime(2026, 1, 1, 10, 3, tzinfo=timezone.utc)},
        "Alert:E5": {"event_id": "E5", "timestamp_dt": datetime(2026, 1, 1, 10, 4, tzinfo=timezone.utc)},
    }

    predicted = _candidate_core_event_ids(
        traversal_analysis=traversal,
        subgraph=graph,
        alert_meta=alert_meta,
    )

    assert predicted[:5] == ["E1", "E2", "E3", "E4", "E5"]
    assert "RCA1" not in predicted
    assert "RCA2" not in predicted


def test_ground_truth_draft_payload_consolidates_ids_and_env_export():
    payload = _build_ground_truth_draft_payload(
        [
            {"campaign_index": 1, "recommended_event_ids": ["E1", "E2"]},
            {"campaign_index": 2, "recommended_event_ids": ["E2", "E3"]},
        ]
    )

    assert payload["kind"] == "ground_truth_draft"
    assert payload["recommended_event_ids"] == ["E1", "E2", "E3"]
    assert payload["env_export"] == '["E1", "E2", "E3"]'
