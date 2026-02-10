from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import networkx as nx

from src.audit import ForensicLedger
from src.chaser import BraveChaser
from src.enrichment import EnrichmentAgent
from src.graph import GraphConstructor
from src.models import GraphReadyAlert
from src.refiner import IntelligenceRefiner
from src.synthesis import GraphNarrator
from src.visualize import GraphVisualizer
from src.canon_registry import ARV_BETA, ARV_PHI_LIMIT, ARV_TAU, arv_evaluate, arv_phi, profile_settings
from src.ingest.dedup import compute_event_hash
from src.kernel.kernel_gate import KernelGate
from src.kernel.stage1 import BAND_LOW, BAND_MIMIC, BAND_VACUUM, classify_batch


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_json(data: Dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash_evidence(evidence: Dict) -> str:
    payload = dict(evidence)
    payload["evidence_id"] = ""
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _append_evidence(ledger_path: Path, evidence: Dict, prev_hash: str) -> str:
    evidence["prev_hash"] = prev_hash
    evidence_id = _hash_evidence(evidence)
    evidence["evidence_id"] = evidence_id
    with ledger_path.open("a", encoding="utf-8") as handle:
        handle.write(_canonical_json(evidence))
        handle.write("\n")
    return evidence_id


def run_graph_pipeline(
    raw_alerts: List[Dict],
    output_dir: str = "data",
    enable_kernel: bool = True,
    kernel_ledger_path: str = "data/kernel_ledger.jsonl",
    arv_phi_limit: int | None = None,
    arv_phi_limit_gate1: int | None = None,
    arv_phi_limit_gate23: int | None = None,
    arv_phi_limit_gate3: int | None = None,
    arv_beta: float | None = None,
    arv_tau: float | None = None,
    profile_id: str | None = None,
    registry_commit: str | None = None,
    lineage_id: str | None = None,
    triage_only: bool = False,
    skip_enrichment: bool = False,
    verbose: bool = False,
) -> Dict[str, List[str]]:
    """
    Execute the CIX graph pipeline and return artifact paths.
    When enable_kernel=True, apply kernel gating + dedup before graph build.
    """
    output_root = Path(output_dir)
    _ensure_dir(output_root)
    arv_ledger_path = output_root / "arv_gate_ledger.jsonl"
    arv_prev_hash = ""

    admitted_alerts = raw_alerts
    triage_counts = {
        "total_ingested": len(raw_alerts),
        "background_low_entropy": 0,
        "background_semantic": 0,
        "red_zone_high_entropy": 0,
        "dedup_removed": 0,
        "active_candidates": 0,
        "findings": 0,
    }
    semantic_background_event_ids = {
        "4624",  # Successful logon
        "4634",  # Logoff
        "4647",  # User-initiated logoff
    }
    semantic_background_category_exact = {
        "logon",
        "logoff",
        "account logon",
    }
    # Profile settings (fallbacks for ARV + evidence metadata)
    profile = profile_settings(profile_id)
    profile_id = profile.get("profile_id") or profile_id
    registry_commit = registry_commit or profile.get("registry_commit")

    # Stage 1 entropic triage (low/high/mimic)
    stage1_events = []
    for raw_alert in raw_alerts:
        raw_payload = (
            raw_alert.get("raw_payload")
            or raw_alert.get("raw_event")
            or raw_alert.get("data", raw_alert)
        )
        data = raw_alert.get("data", {}) if isinstance(raw_alert, dict) else {}
        payload_timestamp = None
        if isinstance(raw_payload, dict):
            payload_timestamp = (
                raw_payload.get("@timestamp")
                or raw_payload.get("EventTime")
                or raw_payload.get("EventReceivedTime")
                or raw_payload.get("UtcTime")
                or raw_payload.get("TimeCreated")
                or raw_payload.get("TimeGenerated")
                or raw_payload.get("Timestamp")
            )
        stage1_events.append(
            {
                "event_id": raw_alert.get("eventId") or raw_alert.get("event_id") or "unknown",
                "raw_payload": raw_payload,
                "source_id": raw_alert.get("source_id") or raw_alert.get("source") or "unknown",
                "source_timestamp": raw_alert.get("timestamp")
                or raw_alert.get("source_timestamp")
                or data.get("event_time")
                or data.get("timestamp")
                or payload_timestamp,
            }
        )
    stage1_result = classify_batch(stage1_events)
    per_event = stage1_result.get("per_event", [])
    mimic_indices = []
    for idx, entry in enumerate(per_event):
        band = entry.get("band")
        if band == BAND_LOW:
            triage_counts["background_low_entropy"] += 1
        elif band == BAND_VACUUM:
            triage_counts["red_zone_high_entropy"] += 1
        elif band == BAND_MIMIC:
            mimic_indices.append(idx)

    # Semantic background filter (low-risk categories)
    semantic_exclude_indices: set[int] = set()
    for idx in mimic_indices:
        raw_alert = raw_alerts[idx]
        raw_event = raw_alert.get("raw_payload") or raw_alert.get("raw_event") or {}
        data = raw_alert.get("data", {}) if isinstance(raw_alert, dict) else {}
        event_id = raw_event.get("EventID") or raw_event.get("eventId") or raw_alert.get("eventId") or ""
        category = (
            raw_event.get("Category")
            or raw_event.get("EventType")
            or data.get("rule_intent")
            or ""
        )
        if str(event_id) in semantic_background_event_ids:
            semantic_exclude_indices.add(idx)
            continue
        category_lc = str(category).lower()
        if category_lc and category_lc in semantic_background_category_exact:
            semantic_exclude_indices.add(idx)

    if semantic_exclude_indices:
        triage_counts["background_semantic"] = len(semantic_exclude_indices)

    filtered_indices = [i for i in mimic_indices if i not in semantic_exclude_indices]
    filtered_alerts = [raw_alerts[i] for i in filtered_indices]

    # Deduplicate after entropic filtering using (EventID, Image)
    deduped_alerts = []
    seen_keys = set()
    for idx in filtered_indices:
        raw_alert = raw_alerts[idx]
        raw_event = raw_alert.get("raw_payload") or raw_alert.get("raw_event") or {}
        data = raw_alert.get("data", {}) if isinstance(raw_alert, dict) else {}
        event_id = raw_event.get("EventID") or raw_event.get("eventId") or raw_alert.get("eventId") or f"event_{idx}"
        process_image = raw_event.get("Image") or raw_event.get("ProcessName") or raw_event.get("New Process Name") or data.get("process_image")
        dedup_key = (event_id, process_image)
        if dedup_key in seen_keys:
            triage_counts["dedup_removed"] += 1
            continue
        seen_keys.add(dedup_key)
        deduped_alerts.append(raw_alert)

    if enable_kernel:
        gate = KernelGate(profile_id=profile_id or "profile.cix", ledger_path=kernel_ledger_path)
        gated_results = []
        for raw_alert in deduped_alerts:
            result = gate.evaluate(raw_alert)
            gate.append_ledger(result)
            if result.action_id in {"ARV.ADMIT", "ARV.COMPRESS"}:
                gated_results.append(result)
        admitted_alerts = [r.graph_raw for r in gated_results]
    else:
        admitted_alerts = deduped_alerts

    # Build world graph
    world_graph = nx.DiGraph()
    constructor = GraphConstructor()
    for raw_alert in admitted_alerts:
        alert_model = GraphReadyAlert.from_raw_data(raw_alert)
        constructor.add_to_graph(world_graph, alert_model)

    triage_counts["active_candidates"] = max(
        0,
        triage_counts["total_ingested"]
        - triage_counts["background_low_entropy"]
        - triage_counts["background_semantic"]
        - triage_counts["red_zone_high_entropy"]
        - triage_counts["dedup_removed"],
    )

    # Findings (unique MITRE techniques)
    mitre_nodes = {
        node
        for node, data in world_graph.nodes(data=True)
        if data.get("type") == "MITRE_Technique"
    }
    triage_counts["findings"] = len(mitre_nodes)

    print("TRIAGE INPUT - TOTAL INGESTED", triage_counts["total_ingested"])
    print(f"BACKGROUND -{triage_counts['background_low_entropy']} (Low entropy)")
    print(f"BACKGROUND -{triage_counts['background_semantic']} (Semantic)")
    print(f"RED ZONE -{triage_counts['red_zone_high_entropy']} (High entropy)")
    print(f"DEDUPED -{triage_counts['dedup_removed']}")
    print(f"ACTIVE TRIAGE CANDIDATES {triage_counts['active_candidates']}")
    print(f"FINDINGS {triage_counts['findings']}")

    triage_summary_path = output_root / "triage_summary.json"
    triage_summary_path.write_text(json.dumps(triage_counts, indent=2), encoding="utf-8")

    if triage_only:
        return {
            "reports": [],
            "ledgers": [],
            "graphs_html": [],
            "graphs_png": [],
            "triage_summary": [str(triage_summary_path)],
        }

    def emit_gate_evidence(
        gate: str,
        decision_obj,
        metrics: Dict[str, Any],
        root_id: str | None = None,
    ) -> None:
        nonlocal arv_prev_hash
        evidence = {
            "evidence_id": "",
            "schema_version": profile.get("schema_version"),
            "domain": "cix",
            "kind": "decision",
            "timestamp": _utc_now(),
            "source": {
                "system": "cix-alerts",
                "sensor": "pipeline",
                "feed_id": "batch",
            },
            "inputs": [],
            "features_summary": {
                "gate": gate,
                "action": decision_obj.action,
                "reason": decision_obj.reason,
                **metrics,
            },
            "profile_id": profile_id,
            "registry_commit": registry_commit,
            "prev_hash": "",
        }
        if lineage_id:
            evidence["lineage_id"] = lineage_id
            evidence["inputs"].append({"ref_type": "lineage", "ref": lineage_id})
        if root_id:
            evidence["root_id"] = root_id
            evidence["inputs"].append({"ref_type": "root", "ref": root_id})
        arv_prev_hash = _append_evidence(arv_ledger_path, evidence, arv_prev_hash)

    # ARV gate 1 (post-triage admission)
    arv_state = {
        "phi_prev": 12,
        "d_plus": 0.0,
        "root_a": "init_A",
        "root_b": "init_B",
    }
    # Use active triage candidates for admission gating (not graph complexity)
    phi_curr = triage_counts["active_candidates"]
    phi_limit_gate1 = profile.get("phi_limit_admission", ARV_PHI_LIMIT)
    phi_limit_gate2 = profile.get("phi_limit_enrichment", ARV_PHI_LIMIT)
    phi_limit_gate3 = profile.get("phi_limit_reporting", ARV_PHI_LIMIT)
    if arv_phi_limit_gate1 is not None:
        phi_limit_gate1 = arv_phi_limit_gate1
    if arv_phi_limit_gate23 is not None:
        phi_limit_gate2 = arv_phi_limit_gate23
    if arv_phi_limit_gate3 is not None:
        phi_limit_gate3 = arv_phi_limit_gate3
    if arv_phi_limit is not None and arv_phi_limit_gate1 is None:
        phi_limit_gate1 = arv_phi_limit
    if arv_phi_limit is not None and arv_phi_limit_gate23 is None:
        phi_limit_gate2 = arv_phi_limit
    if arv_phi_limit is not None and arv_phi_limit_gate3 is None:
        phi_limit_gate3 = arv_phi_limit
    beta = profile.get("arv_beta", ARV_BETA) if arv_beta is None else arv_beta
    tau = profile.get("arv_tau", ARV_TAU) if arv_tau is None else arv_tau
    decision = arv_evaluate(
        phi_curr,
        arv_state["phi_prev"],
        arv_state["d_plus"],
        arv_state["root_a"],
        arv_state["root_b"],
        phi_limit=phi_limit_gate1,
        beta=beta,
        tau=tau,
    )
    emit_gate_evidence(
        "ARV1",
        decision,
        {
            "phi_curr": phi_curr,
            "phi_limit": phi_limit_gate1,
            "beta": beta,
            "tau": tau,
            **decision.metrics,
        },
    )
    if verbose:
        print(f"[ARV1] action={decision.action} reason={decision.reason} metrics={decision.metrics}")
    if decision.action != "EXECUTE":
        return {
            "reports": [],
            "ledgers": [],
            "graphs_html": [],
            "graphs_png": [],
        }
    arv_state["phi_prev"] = phi_curr
    arv_state["d_plus"] = decision.metrics["d_plus"]

    if not skip_enrichment:
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
            phi_limit=phi_limit_gate2,
            beta=beta,
            tau=tau,
        )
        emit_gate_evidence(
            "ARV2",
            decision,
            {
                "phi_curr": phi_curr,
                "phi_limit": phi_limit_gate2,
                "beta": beta,
                "tau": tau,
                **decision.metrics,
            },
        )
        if verbose:
            print(f"[ARV2] action={decision.action} reason={decision.reason} metrics={decision.metrics}")
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
        phi_limit=phi_limit_gate3,
        beta=beta,
        tau=tau,
    )
    root_id = hashlib.sha256("chaser_out_A|chaser_out_B".encode("utf-8")).hexdigest()
    emit_gate_evidence(
        "ARV3",
        decision,
        {
            "phi_curr": phi_curr,
            "phi_limit": phi_limit_gate3,
            "beta": beta,
            "tau": tau,
            **decision.metrics,
        },
        root_id=root_id,
    )
    if verbose:
        print(f"[ARV3] action={decision.action} reason={decision.reason} metrics={decision.metrics}")
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
        assessment_report = narrator.generate_assessment_report(subgraph, triage_summary=triage_counts)

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
