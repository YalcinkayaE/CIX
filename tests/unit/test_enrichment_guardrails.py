from __future__ import annotations

import networkx as nx

from src.enrichment import EnrichmentAgent


class _FakeResponse:
    def __init__(self, malicious: int):
        self.status_code = 200
        self._malicious = malicious

    def json(self):
        return {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": self._malicious},
                    "country": "US",
                }
            }
        }


def test_platform_service_ip_is_not_auto_promoted(monkeypatch):
    graph = nx.DiGraph()
    graph.add_node("Alert:E1", type="Alert", event_id="E1")
    graph.add_node("IP:168.63.129.16", type="IP", value="168.63.129.16")
    graph.add_edge("Alert:E1", "IP:168.63.129.16", relationship="HAS_DEST_IP")

    agent = EnrichmentAgent()
    agent.vt_key = "test-key"
    monkeypatch.setattr("src.enrichment.requests.get", lambda *args, **kwargs: _FakeResponse(malicious=7))

    agent._enrich_ip(graph, "IP:168.63.129.16", "168.63.129.16")

    efi_node = "EFI:VT:168.63.129.16"
    assert efi_node in graph.nodes
    edge_data = graph.get_edge_data("IP:168.63.129.16", efi_node)
    assert edge_data["relationship"] == "ENRICHED_BY_VT_IP"
    assert graph.nodes[efi_node]["verdict"] == "LIKELY_PLATFORM_SERVICE"
    assert graph.nodes[efi_node]["requires_corroboration"] is True


def test_non_platform_ip_requires_corroboration_before_confirmed_malicious(monkeypatch):
    graph = nx.DiGraph()
    graph.add_node("IP:8.8.8.8", type="IP", value="8.8.8.8")

    agent = EnrichmentAgent()
    agent.vt_key = "test-key"
    monkeypatch.setattr("src.enrichment.requests.get", lambda *args, **kwargs: _FakeResponse(malicious=5))

    agent._enrich_ip(graph, "IP:8.8.8.8", "8.8.8.8")

    efi_node = "EFI:VT:8.8.8.8"
    assert efi_node in graph.nodes
    edge_data = graph.get_edge_data("IP:8.8.8.8", efi_node)
    assert edge_data["relationship"] == "ENRICHED_BY_VT_IP"
    assert graph.nodes[efi_node]["verdict"] == "UNCONFIRMED_MALICIOUS_IP"
