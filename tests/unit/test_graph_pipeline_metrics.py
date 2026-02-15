from __future__ import annotations

from src.pipeline.graph_pipeline import (
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
    )

    assert "## 8. Claim Evidence Pointers" in appendix
    assert "## 10. Quantitative Detection Scoring" in appendix
    assert "event_id=E1" in appendix
    assert "TP/FP/FN" in appendix
