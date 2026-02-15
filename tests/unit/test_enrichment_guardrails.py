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
    assert edge_data["relationship"] == "PLATFORM_SERVICE_CONTEXT"
    assert graph.nodes[efi_node]["verdict"] == "LIKELY_PLATFORM_SERVICE"
    assert graph.nodes[efi_node]["requires_corroboration"] is True
    assert graph.nodes[efi_node]["primary_c2_candidate"] is False


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
    assert graph.nodes[efi_node]["primary_c2_candidate"] is False


def test_non_platform_ip_with_attack_corroboration_is_promoted(monkeypatch):
    graph = nx.DiGraph()
    graph.add_node("Alert:E1", type="Alert", event_id="E1")
    graph.add_node("IP:8.8.8.8", type="IP", value="8.8.8.8")
    graph.add_node("MITRE:T1059.001", type="MITRE_Technique")
    graph.add_edge("Alert:E1", "IP:8.8.8.8", relationship="HAS_DEST_IP")
    graph.add_edge("Alert:E1", "MITRE:T1059.001", relationship="INDICATES_TECHNIQUE")

    agent = EnrichmentAgent()
    agent.vt_key = "test-key"
    monkeypatch.setattr("src.enrichment.requests.get", lambda *args, **kwargs: _FakeResponse(malicious=9))

    agent._enrich_ip(graph, "IP:8.8.8.8", "8.8.8.8")

    efi_node = "EFI:VT:8.8.8.8"
    edge_data = graph.get_edge_data("IP:8.8.8.8", efi_node)
    assert edge_data["relationship"] == "MALICIOUS_IP_CONFIRMED"
    assert graph.nodes[efi_node]["verdict"] == "CORROBORATED_MALICIOUS_IP"
    assert graph.nodes[efi_node]["primary_c2_candidate"] is True
