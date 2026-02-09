from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import networkx as nx

from src.audit import ForensicLedger
from src.chaser import BraveChaser
from src.enrichment import EnrichmentAgent
from src.graph import GraphConstructor
from src.models import GraphReadyAlert
from src.refiner import IntelligenceRefiner
from src.synthesis import GraphNarrator
from src.visualize import GraphVisualizer
from src.canon_registry import arv_evaluate, arv_phi
from src.ingest.dedup import compute_event_hash
from src.kernel.kernel_gate import KernelGate


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def run_graph_pipeline(
    raw_alerts: List[Dict],
    output_dir: str = "data",
    enable_kernel: bool = True,
    kernel_ledger_path: str = "data/kernel_ledger.jsonl",
) -> Dict[str, List[str]]:
    """
    Execute the CIX graph pipeline and return artifact paths.
    When enable_kernel=True, apply kernel gating + dedup before graph build.
    """
    output_root = Path(output_dir)
    _ensure_dir(output_root)

    admitted_alerts = raw_alerts
    if enable_kernel:
        gate = KernelGate(ledger_path=kernel_ledger_path)
        gated_results = []
        halt_triggered = False
        for raw_alert in raw_alerts:
            result = gate.evaluate(raw_alert)
            if result.action_id == "ARV.HALT":
                gate.append_ledger(result)
                halt_triggered = True
                break
            if result.action_id in {"ARV.ADMIT", "ARV.COMPRESS"}:
                gated_results.append(result)
            else:
                gate.append_ledger(result)
        if halt_triggered:
            return {
                "reports": [],
                "ledgers": [],
                "graphs_html": [],
                "graphs_png": [],
            }

        deduped_results = []
        seen_hashes = set()
        for result in gated_results:
            event_hash = compute_event_hash(result.graph_raw)
            if event_hash in seen_hashes:
                continue
            seen_hashes.add(event_hash)
            deduped_results.append(result)

        admitted_alerts = [r.graph_raw for r in deduped_results]
        for result in deduped_results:
            gate.append_ledger(result)

    # Build world graph
    world_graph = nx.DiGraph()
    constructor = GraphConstructor()
    for raw_alert in admitted_alerts:
        alert_model = GraphReadyAlert.from_raw_data(raw_alert)
        constructor.add_to_graph(world_graph, alert_model)

    # ARV gate 1 (post construction)
    arv_state = {
        "phi_prev": 12,
        "d_plus": 0.0,
        "root_a": "init_A",
        "root_b": "init_B",
    }
    phi_curr = arv_phi(world_graph.nodes)
    decision = arv_evaluate(
        phi_curr,
        arv_state["phi_prev"],
        arv_state["d_plus"],
        arv_state["root_a"],
        arv_state["root_b"],
    )
    if decision.action != "EXECUTE":
        return {
            "reports": [],
            "ledgers": [],
            "graphs_html": [],
            "graphs_png": [],
        }
    arv_state["phi_prev"] = phi_curr
    arv_state["d_plus"] = decision.metrics["d_plus"]

    # Enrichment (EFI) + ARV gate 2
    agent = EnrichmentAgent()
    agent.chase_leads(world_graph)
    phi_curr = arv_phi(world_graph.nodes)
    decision = arv_evaluate(
        phi_curr,
        arv_state["phi_prev"],
        arv_state["d_plus"],
        "agent_v1_out_A",
        "agent_v1_out_B",
    )
    if decision.action != "EXECUTE":
        return {
            "reports": [],
            "ledgers": [],
            "graphs_html": [],
            "graphs_png": [],
        }
    arv_state["phi_prev"] = phi_curr
    arv_state["d_plus"] = decision.metrics["d_plus"]

    # External lead chasing + ARV gate 3
    chaser = BraveChaser()
    refiner = IntelligenceRefiner()
    leads_to_chase = [n for n, d in world_graph.nodes(data=True) if d.get("type") == "SearchLead"]
    for lead_node in leads_to_chase:
        query = world_graph.nodes[lead_node].get("query")
        snippets = chaser.chase_lead(query)
        if snippets:
            intel = refiner.refine_artifacts(query, snippets)
            for artifact in intel.get("artifacts", []):
                val = artifact.get("value")
                a_type = artifact.get("type")
                artifact_node = f"Artifact:{val}"
                if artifact_node not in world_graph:
                    world_graph.add_node(
                        artifact_node,
                        type=a_type,
                        value=val,
                        source=artifact.get("source_url"),
                        confidence=artifact.get("confidence"),
                    )
                    world_graph.add_edge(lead_node, artifact_node, relationship="DISCOVERED_ARTIFACT")

    phi_curr = arv_phi(world_graph.nodes)
    decision = arv_evaluate(
        phi_curr,
        arv_state["phi_prev"],
        arv_state["d_plus"],
        "chaser_out_A",
        "chaser_out_B",
    )
    if decision.action not in {"EXECUTE", "THROTTLE"}:
        return {
            "reports": [],
            "ledgers": [],
            "graphs_html": [],
            "graphs_png": [],
        }

    # Campaign split + reports
    undirected = world_graph.to_undirected()
    components = list(nx.connected_components(undirected))

    narrator = GraphNarrator()
    ledger = ForensicLedger()
    visualizer = GraphVisualizer()

    reports: List[str] = []
    ledgers: List[str] = []
    graphs_html: List[str] = []
    graphs_png: List[str] = []

    for idx, comp_nodes in enumerate(components):
        subgraph = world_graph.subgraph(comp_nodes).copy()
        summary = narrator.summarize(subgraph)
        assessment_report = narrator.generate_assessment_report(subgraph)

        report_path = output_root / f"Forensic_Assessment_Campaign_{idx+1}.md"
        report_path.write_text(assessment_report, encoding="utf-8")
        reports.append(str(report_path))

        triples = []
        for u, v, data in subgraph.edges(data=True):
            triples.append({"source": u, "relationship": data.get("relationship"), "target": v})
        comp_arv = [{"gate": "Campaign_Isolation", "phi": len(comp_nodes)}]

        ledger_name = output_root / f"forensic_ledger_campaign_{idx+1}.json"
        ledger.file_path = str(ledger_name)
        ledger.export(triples, summary, comp_arv)
        ledgers.append(str(ledger_name))

        viz_name = output_root / f"investigation_graph_campaign_{idx+1}.png"
        interactive_name = output_root / f"investigation_graph_campaign_{idx+1}.html"

        visualizer.generate_image(subgraph, output_path=str(viz_name))
        visualizer.generate_interactive_html(subgraph, output_path=str(interactive_name))

        graphs_png.append(str(viz_name))
        graphs_html.append(str(interactive_name))

    return {
        "reports": reports,
        "ledgers": ledgers,
        "graphs_html": graphs_html,
        "graphs_png": graphs_png,
    }
