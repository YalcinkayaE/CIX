from __future__ import annotations

import networkx as nx

from src.graph import GraphConstructor
from src.models import GraphReadyAlert


def test_whoami_maps_to_t1033_not_t1082():
    graph = nx.DiGraph()
    constructor = GraphConstructor()
    alert = GraphReadyAlert(
        event_id="evt-1",
        file_name="whoami.exe",
        process_image="C:\\Windows\\System32\\whoami.exe",
        command_line="whoami.exe /all",
    )

    constructor.add_to_graph(graph, alert)

    assert "MITRE:T1033" in graph.nodes
    assert graph.has_edge("Alert:evt-1", "MITRE:T1033")
    assert "MITRE:T1082" not in graph.nodes


def test_systeminfo_maps_to_t1082():
    graph = nx.DiGraph()
    constructor = GraphConstructor()
    alert = GraphReadyAlert(
        event_id="evt-2",
        file_name="systeminfo.exe",
        command_line="systeminfo.exe",
    )

    constructor.add_to_graph(graph, alert)

    assert "MITRE:T1082" in graph.nodes
    assert graph.has_edge("Alert:evt-2", "MITRE:T1082")
