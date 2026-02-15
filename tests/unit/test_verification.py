from __future__ import annotations

import networkx as nx

from src.pipeline.verification import discrete_cmi, verify_channel_independence


def test_discrete_cmi_positive_for_dependent_signals():
    x = [0, 0, 1, 1] * 20
    y = [0, 0, 1, 1] * 20
    z = [0] * len(x)
    value = discrete_cmi(x, y, z, alpha=1.0)
    assert value > 0.0


def test_verify_channel_independence_returns_expected_schema():
    g = nx.DiGraph()
    g.add_node("Alert:W1", type="Alert", event_id="W1")
    g.add_node("Alert:D1", type="Alert", event_id="D1")
    g.add_node("Host:WORKSTATION5", type="Host", value="WORKSTATION5")
    g.add_node("Host:MORDORDC", type="Host", value="MORDORDC")
    g.add_node("IP:168.63.129.16", type="IP", value="168.63.129.16")
    g.add_node("MITRE:T1021", type="MITRE_Technique", name="Remote Services", tactic="Lateral Movement")
    g.add_node("Command:wscript.exe launcher.vbs", type="CommandLine", value="wscript.exe launcher.vbs")
    g.add_node("Command:lsass.exe", type="CommandLine", value="lsass.exe")

    g.add_edge("Alert:W1", "Host:WORKSTATION5", relationship="ON_HOST")
    g.add_edge("Alert:W1", "IP:168.63.129.16", relationship="HAS_DEST_IP")
    g.add_edge("Alert:W1", "Command:wscript.exe launcher.vbs", relationship="OBSERVED_COMMAND")
    g.add_edge("Alert:W1", "MITRE:T1021", relationship="INDICATES_TECHNIQUE")

    g.add_edge("Alert:D1", "Host:MORDORDC", relationship="ON_HOST")
    g.add_edge("Alert:D1", "IP:168.63.129.16", relationship="HAS_DEST_IP")
    g.add_edge("Alert:D1", "Command:lsass.exe", relationship="OBSERVED_COMMAND")
    g.add_edge("Alert:D1", "MITRE:T1021", relationship="INDICATES_TECHNIQUE")

    alert_meta = {
        "Alert:W1": {
            "event_id": "W1",
            "timestamp": "2026-02-13T10:00:00Z",
            "timestamp_dt": None,
            "host": "WORKSTATION5",
            "user": "pgustavo",
            "process": "wscript.exe",
            "command": "wscript.exe launcher.vbs",
        },
        "Alert:D1": {
            "event_id": "D1",
            "timestamp": "2026-02-13T10:03:00Z",
            "timestamp_dt": None,
            "host": "MORDORDC",
            "user": "system",
            "process": "lsass.exe",
            "command": "lsass.exe",
        },
    }

    result = verify_channel_independence(
        subgraph=g,
        alert_meta=alert_meta,
        campaign_index=1,
        permutation_count=100,
        bootstrap_count=100,
    )
    assert "statistics" in result
    assert "decision" in result
    assert result["decision"]["claim_label"] in {"INFERRED", "VERIFIED"}
    assert "samples" in result
