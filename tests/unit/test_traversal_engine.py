from __future__ import annotations

import networkx as nx

from src.pipeline.traversal import analyze_campaign_traversal, build_alert_meta


def test_build_alert_meta_parses_timestamp():
    alerts = [
        {
            "eventId": "E1",
            "timestamp": "2026-02-13T10:00:00Z",
            "data": {"hostname": "ws1", "process_image": "wscript.exe"},
        }
    ]
    meta = build_alert_meta(alerts)
    assert "Alert:E1" in meta
    assert meta["Alert:E1"]["timestamp"] == "2026-02-13T10:00:00Z"
    assert meta["Alert:E1"]["timestamp_dt"] is not None


def test_analyze_campaign_traversal_produces_temporal_and_rca_sections():
    g = nx.DiGraph()
    g.add_node("Alert:E1", type="Alert", event_id="E1")
    g.add_node("Alert:E2", type="Alert", event_id="E2")
    g.add_node("Alert:E3", type="Alert", event_id="E3")
    g.add_node("Host:WS5", type="Host", value="WS5")
    g.add_node("IP:8.8.8.8", type="IP", value="8.8.8.8")
    g.add_node("MITRE:T1059.005", type="MITRE_Technique", name="VBScript", tactic="Execution")
    g.add_node("Command:wscript.exe launcher.vbs", type="CommandLine", value="wscript.exe launcher.vbs")

    g.add_edge("Alert:E1", "Host:WS5", relationship="ON_HOST")
    g.add_edge("Alert:E2", "Host:WS5", relationship="ON_HOST")
    g.add_edge("Alert:E2", "IP:8.8.8.8", relationship="HAS_DEST_IP")
    g.add_edge("Alert:E3", "IP:8.8.8.8", relationship="HAS_DEST_IP")
    g.add_edge("Alert:E1", "MITRE:T1059.005", relationship="INDICATES_TECHNIQUE")
    g.add_edge("Alert:E1", "Command:wscript.exe launcher.vbs", relationship="OBSERVED_COMMAND")

    alert_meta = {
        "Alert:E1": {
            "event_id": "E1",
            "timestamp": "2026-02-13T10:00:00Z",
            "timestamp_dt": build_alert_meta([{"eventId": "E1", "timestamp": "2026-02-13T10:00:00Z", "data": {}}])[
                "Alert:E1"
            ]["timestamp_dt"],
            "host": "WS5",
            "user": "pgustavo",
            "process": "wscript.exe",
            "command": "wscript.exe launcher.vbs",
        },
        "Alert:E2": {
            "event_id": "E2",
            "timestamp": "2026-02-13T10:02:00Z",
            "timestamp_dt": build_alert_meta([{"eventId": "E2", "timestamp": "2026-02-13T10:02:00Z", "data": {}}])[
                "Alert:E2"
            ]["timestamp_dt"],
            "host": "WS5",
            "user": "pgustavo",
            "process": "powershell.exe",
            "command": "powershell.exe -enc ...",
        },
        "Alert:E3": {
            "event_id": "E3",
            "timestamp": "2026-02-13T10:04:00Z",
            "timestamp_dt": build_alert_meta([{"eventId": "E3", "timestamp": "2026-02-13T10:04:00Z", "data": {}}])[
                "Alert:E3"
            ]["timestamp_dt"],
            "host": "DC1",
            "user": "system",
            "process": "lsass.exe",
            "command": "",
        },
    }

    analysis = analyze_campaign_traversal(
        subgraph=g,
        alert_meta=alert_meta,
        campaign_index=1,
        tau_blast_seconds=300,
    )

    assert analysis["summary"]["alert_nodes"] == 3
    assert analysis["summary"]["temporal_paths"] >= 1
    assert analysis["seed_alerts"]
    assert analysis["blast_radius"]["rows"]
    assert analysis["rca_top"]
    assert "counterfactuals" in analysis
