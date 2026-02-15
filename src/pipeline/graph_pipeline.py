from __future__ import annotations

import hashlib
import json
import os
import platform
from collections import Counter
from datetime import datetime, timezone
from html import escape
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
from src.pipeline.traversal import analyze_campaign_traversal, build_alert_meta
from src.pipeline.verification import verify_channel_independence
from src.canon_registry import ARV_BETA, ARV_PHI_LIMIT, ARV_TAU, arv_evaluate, arv_phi, profile_settings
from src.ingest.dedup import compute_event_hash
from src.kernel.kernel_gate import KernelGate
from src.kernel.ledger import Ledger
from src.kernel.stage1 import BAND_LOW, BAND_MIMIC, BAND_VACUUM, classify_batch


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _cleanup_previous_pipeline_artifacts(output_root: Path) -> None:
    # Remove previous run artifacts owned by this pipeline so output counts are deterministic.
    patterns = [
        "Forensic_Assessment_Campaign_*.md",
        "forensic_ledger_campaign_*.json",
        "investigation_graph_campaign_*.html",
        "investigation_graph_campaign_*.png",
        "campaign_snapshot_*.html",
        "temporal_analysis_campaign_*.json",
        "cmi_verification_campaign_*.json",
    ]
    for pattern in patterns:
        for artifact in output_root.glob(pattern):
            if artifact.is_file():
                artifact.unlink()
    for name in (
        "ledger.jsonl",
        "kernel_ledger.jsonl",
        "arv_gate_ledger.jsonl",
        "triage_summary.json",
        "reproducibility_manifest.json",
    ):
        target = output_root / name
        if target.exists() and target.is_file():
            target.unlink()


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


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def _render_claim_and_verification_appendix(
    traversal_analysis: Dict[str, Any],
    verification_analysis: Dict[str, Any],
    manifest_name: str,
) -> str:
    seed_alerts = traversal_analysis.get("seed_alerts", [])
    top_seed = seed_alerts[0] if seed_alerts else {}
    rca_top = traversal_analysis.get("rca_top", [])
    top_rca = rca_top[0] if rca_top else {}
    decision = verification_analysis.get("decision", {})
    stats = verification_analysis.get("statistics", {})
    claim_label = str(decision.get("claim_label") or "INFERRED")

    observed_claim = "Graph contains temporal and topological evidence edges across campaign entities."
    inferred_claim = (
        f"Top RCA candidate is {top_rca.get('alert', 'n/a')} on host {top_rca.get('host', 'n/a')} "
        f"with score {top_rca.get('score', 'n/a')}."
    )
    verification_claim = (
        "Distinct DC channel evidence statistically validated."
        if claim_label == "VERIFIED"
        else "Distinct DC channel evidence not yet statistically sufficient; retain INFERRED status."
    )

    return "\n".join(
        [
            "",
            "## 6. Claim Labels (Observed/Inferred/Verified)",
            f"- [OBSERVED] {observed_claim}",
            f"- [INFERRED] {inferred_claim}",
            f"- [{claim_label}] {verification_claim}",
            "",
            "## 7. Verification Summary (CMI)",
            f"- `CMI_obs`: {stats.get('cmi_observed', 0.0)}",
            f"- `p_value`: {stats.get('p_value', 1.0)}",
            f"- `CI95`: [{stats.get('ci95_low', 0.0)}, {stats.get('ci95_high', 0.0)}]",
            f"- `Decision`: {decision.get('reason', 'n/a')}",
            f"- `Primary Seed`: {top_seed.get('alert', 'n/a')}",
            "",
            "## 8. Reproducibility Envelope",
            f"- Manifest: `{manifest_name}`",
            "- Claim labels are bounded by available evidence and verification outputs in this run.",
        ]
    )


def _severity_label(subgraph: nx.DiGraph) -> str:
    finding_count = sum(1 for _, data in subgraph.nodes(data=True) if data.get("type") == "MITRE_Technique")
    efi_count = sum(1 for _, data in subgraph.nodes(data=True) if data.get("type") == "EFI")
    if finding_count >= 5 or efi_count >= 5:
        return "HIGH"
    if finding_count >= 2 or efi_count >= 2:
        return "MEDIUM"
    return "LOW"


def _render_campaign_snapshot(
    subgraph: nx.DiGraph,
    campaign_index: int,
    triage_counts: Dict[str, int],
    report_path: Path,
    ledger_path: Path,
    graph_html_path: Path,
) -> str:
    node_count = subgraph.number_of_nodes()
    edge_count = subgraph.number_of_edges()
    finding_nodes = sorted(
        [
            (node, data)
            for node, data in subgraph.nodes(data=True)
            if data.get("type") == "MITRE_Technique"
        ],
        key=lambda item: item[0],
    )
    efi_rows = []
    for src, dst, edge_data in subgraph.edges(data=True):
        dst_data = subgraph.nodes.get(dst, {})
        if dst_data.get("type") != "EFI":
            continue
        score = dst_data.get("score")
        if score is None:
            score = dst_data.get("pulses", "-")
        efi_rows.append(
            {
                "source": src,
                "relationship": edge_data.get("relationship", "RELATED"),
                "target": dst,
                "provider": dst_data.get("source", "Unknown"),
                "score": score,
            }
        )
    efi_rows = sorted(efi_rows, key=lambda row: (str(row["provider"]), str(row["target"])))

    asset_types = {"Host", "User", "IP", "Process", "FileName", "SHA256", "MalwareFamily"}
    asset_values = []
    for _, data in subgraph.nodes(data=True):
        ntype = data.get("type")
        if ntype not in asset_types:
            continue
        value = data.get("value")
        if value:
            asset_values.append(str(value))
    asset_values = sorted(set(asset_values))[:16]

    relation_counter = Counter()
    for _, _, edge_data in subgraph.edges(data=True):
        relation_counter[str(edge_data.get("relationship", "RELATED"))] += 1
    relation_rows = sorted(relation_counter.items(), key=lambda item: (-item[1], item[0]))[:12]

    severity = _severity_label(subgraph)
    total_ingested = triage_counts.get("total_ingested", 0)
    findings = triage_counts.get("findings", 0)
    signal_ratio = "n/a" if findings == 0 else f"1:{max(1, int(total_ingested / max(1, findings)))}"

    findings_table = "".join(
        (
            f"<tr><td class='mono'>{escape(node)}</td>"
            f"<td>{escape(str(data.get('name', 'Unknown technique')))}</td>"
            f"<td>{escape(str(data.get('tactic', 'n/a')))}</td></tr>"
        )
        for node, data in finding_nodes
    ) or "<tr><td colspan='3' class='muted'>No MITRE findings in this campaign.</td></tr>"

    efi_table = "".join(
        (
            f"<tr><td class='mono'>{escape(str(row['source']))}</td>"
            f"<td>{escape(str(row['relationship']))}</td>"
            f"<td class='mono'>{escape(str(row['target']))}</td>"
            f"<td>{escape(str(row['provider']))}</td>"
            f"<td>{escape(str(row['score']))}</td></tr>"
        )
        for row in efi_rows
    ) or "<tr><td colspan='5' class='muted'>No EFI nodes generated.</td></tr>"

    relation_table = "".join(
        f"<tr><td class='mono'>{escape(name)}</td><td>{count}</td></tr>"
        for name, count in relation_rows
    ) or "<tr><td colspan='2' class='muted'>No graph relationships.</td></tr>"

    assets_html = "".join(f"<span class='asset-tag'>{escape(value)}</span>" for value in asset_values)
    if not assets_html:
        assets_html = "<span class='muted'>No impacted assets extracted.</span>"

    generated_at = _utc_now()
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CIX Campaign Snapshot</title>
  <style>
    :root {{
      --bg: #f7f3eb; --card: #ffffff; --ink: #0f172a; --muted: #5b6472;
      --border: #e2e8f0; --accent: #1f7a6e; --accent-soft: #d9f1eb;
      --danger: #c84638; --warn: #d07a2b; --shadow: 0 4px 20px rgba(0,0,0,0.05);
    }}
    body {{ margin: 0; background: var(--bg); color: var(--ink); font-family: system-ui, sans-serif; padding: 1.5rem; }}
    .container {{ max-width: 1200px; margin: 0 auto; background: var(--card); border: 1px solid var(--border); border-radius: 16px; overflow: hidden; box-shadow: var(--shadow); }}
    header {{ background: linear-gradient(135deg, #1f7a6e 0%, #155e54 100%); color: white; padding: 2rem; display: flex; justify-content: space-between; align-items: center; gap: 1rem; }}
    h1 {{ margin: 0; font-size: 1.5rem; }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
    .hud {{ display: grid; grid-template-columns: repeat(6, minmax(120px, 1fr)); border-bottom: 1px solid var(--border); background: #faf8f4; }}
    .hud-card {{ padding: 1rem; text-align: center; border-right: 1px solid var(--border); }}
    .hud-card:last-child {{ border-right: none; }}
    .label {{ display: block; font-size: 0.68rem; text-transform: uppercase; color: var(--muted); font-weight: 700; letter-spacing: .03em; margin-bottom: .4rem; }}
    .value {{ font-weight: 800; font-size: 1rem; }}
    .value.sev-high {{ color: var(--danger); }} .value.sev-medium {{ color: var(--warn); }} .value.sev-low {{ color: var(--accent); }}
    section {{ padding: 1.5rem 2rem; border-bottom: 1px solid var(--border); }}
    section:last-child {{ border-bottom: none; }}
    h2 {{ margin-top: 0; color: #155e54; font-size: 1.1rem; }}
    .pipeline {{ display: grid; grid-template-columns: repeat(7, 1fr); gap: .75rem; }}
    .step {{ background: #faf8f4; border: 1px solid var(--border); border-radius: 10px; padding: .8rem; text-align: center; }}
    .count {{ display: block; font-size: 1.25rem; font-weight: 800; }}
    table {{ width: 100%; border-collapse: collapse; border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }}
    th, td {{ text-align: left; padding: .75rem; border-bottom: 1px solid var(--border); vertical-align: top; }}
    th {{ background: #f8fafc; font-size: .72rem; text-transform: uppercase; color: var(--muted); }}
    .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }}
    .asset-list {{ display: flex; gap: .4rem; flex-wrap: wrap; }}
    .asset-tag {{ background: #f1f5f9; border: 1px solid var(--border); border-radius: 8px; padding: .2rem .55rem; font-size: .8rem; }}
    .links a {{ color: #155e54; text-decoration: none; font-weight: 700; }}
    .links a:hover {{ text-decoration: underline; }}
    .muted {{ color: var(--muted); }}
    @media (max-width: 900px) {{
      .hud {{ grid-template-columns: repeat(2, minmax(120px, 1fr)); }}
      .pipeline {{ grid-template-columns: repeat(2, minmax(120px, 1fr)); }}
      .grid {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>Campaign {campaign_index} Snapshot</h1>
        <div class="mono" style="opacity:.9; font-size:.82rem;">Generated {escape(generated_at)}</div>
      </div>
      <div class="mono" style="text-align:right;">AxoDen CIX Snapshot</div>
    </header>

    <div class="hud">
      <div class="hud-card"><span class="label">Severity</span><span class="value sev-{severity.lower()}">{severity}</span></div>
      <div class="hud-card"><span class="label">S/N Ratio</span><span class="value">{signal_ratio}</span></div>
      <div class="hud-card"><span class="label">Findings</span><span class="value">{findings}</span></div>
      <div class="hud-card"><span class="label">EFI Nodes</span><span class="value">{len(efi_rows)}</span></div>
      <div class="hud-card"><span class="label">Graph Nodes</span><span class="value">{node_count}</span></div>
      <div class="hud-card"><span class="label">Graph Edges</span><span class="value">{edge_count}</span></div>
    </div>

    <section>
      <h2>Efficiency Pipeline</h2>
      <div class="pipeline">
        <div class="step"><span class="label">Ingested</span><span class="count">{triage_counts.get("total_ingested", 0)}</span></div>
        <div class="step"><span class="label">Low Entropy</span><span class="count">-{triage_counts.get("background_low_entropy", 0)}</span></div>
        <div class="step"><span class="label">Semantic</span><span class="count">-{triage_counts.get("background_semantic", 0)}</span></div>
        <div class="step"><span class="label">Red Zone</span><span class="count">-{triage_counts.get("red_zone_high_entropy", 0)}</span></div>
        <div class="step"><span class="label">Deduped</span><span class="count">-{triage_counts.get("dedup_removed", 0)}</span></div>
        <div class="step"><span class="label">Active</span><span class="count">{triage_counts.get("active_candidates", 0)}</span></div>
        <div class="step"><span class="label">Findings</span><span class="count">{triage_counts.get("findings", 0)}</span></div>
      </div>
    </section>

    <section>
      <h2>Key MITRE Findings</h2>
      <table>
        <thead><tr><th>Technique ID</th><th>Name</th><th>Tactic</th></tr></thead>
        <tbody>{findings_table}</tbody>
      </table>
    </section>

    <section>
      <h2>EFI Evidence</h2>
      <table>
        <thead><tr><th>Source Node</th><th>Relation</th><th>EFI Node</th><th>Provider</th><th>Score/Pulses</th></tr></thead>
        <tbody>{efi_table}</tbody>
      </table>
    </section>

    <section>
      <h2>Assets & Relationships</h2>
      <div class="grid">
        <div>
          <div class="label">Impacted Assets</div>
          <div class="asset-list">{assets_html}</div>
        </div>
        <div>
          <table>
            <thead><tr><th>Relationship</th><th>Count</th></tr></thead>
            <tbody>{relation_table}</tbody>
          </table>
        </div>
      </div>
    </section>

    <section class="links">
      <h2>Generated Artifacts</h2>
      <p><a href="{escape(report_path.name)}">Forensic Assessment (Markdown)</a></p>
      <p><a href="{escape(ledger_path.name)}">Forensic Ledger (JSON)</a></p>
      <p><a href="{escape(graph_html_path.name)}">Interactive Graph (HTML)</a></p>
    </section>
  </div>
</body>
</html>
"""


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
    max_campaigns: int | None = None,
) -> Dict[str, List[str]]:
    """
    Execute the CIX graph pipeline and return artifact paths.
    When enable_kernel=True, apply kernel gating + dedup before graph build.
    """
    output_root = Path(output_dir)
    _ensure_dir(output_root)
    _cleanup_previous_pipeline_artifacts(output_root)
    stage1_ledger_path = output_root / "ledger.jsonl"
    arv_ledger_path = output_root / "arv_gate_ledger.jsonl"
    arv_prev_hash = ""

    admitted_alerts = raw_alerts
    triage_counts = {
        "total_ingested": len(raw_alerts),
        "background_low_entropy": 0,
        "background_semantic": 0,
        "red_zone_high_entropy": 0,
        "stage1_failed": 0,
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
    stage1_result = classify_batch(stage1_events, ledger=Ledger(str(stage1_ledger_path)))
    per_event = stage1_result.get("per_event", [])
    batch_counts = stage1_result.get("batch", {}) if isinstance(stage1_result, dict) else {}
    triage_counts["stage1_failed"] = int(batch_counts.get("failed_count", 0) or 0)
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
        gate = KernelGate(profile_id=profile_id or "axoden-cix-1-v0.2.0", ledger_path=kernel_ledger_path)
        gated_results = []
        for raw_alert in deduped_alerts:
            result = gate.evaluate(raw_alert)
            gate.append_ledger(result)
            if result.action_id in {"ARV.EXECUTE", "ARV.THROTTLE"}:
                gated_results.append(result)
        admitted_alerts = [r.graph_raw for r in gated_results]
    else:
        admitted_alerts = deduped_alerts

    # Build world graph
    alert_meta = build_alert_meta(admitted_alerts)
    world_graph = nx.DiGraph()
    constructor = GraphConstructor()
    for raw_alert in admitted_alerts:
        alert_model = GraphReadyAlert.from_raw_data(raw_alert)
        constructor.add_to_graph(world_graph, alert_model)

    triage_counts["active_candidates"] = len(deduped_alerts)

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
    print(f"FAILED -{triage_counts['stage1_failed']} (Invalid schema)")
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
            "snapshots_html": [],
            "temporal_analyses_json": [],
            "verification_json": [],
            "manifests_json": [],
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
    if decision.action != "ARV.EXECUTE":
        return {
            "reports": [],
            "ledgers": [],
            "graphs_html": [],
            "graphs_png": [],
            "snapshots_html": [],
            "temporal_analyses_json": [],
            "verification_json": [],
            "manifests_json": [],
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
                "E_evidence": world_graph.number_of_edges(),
                **decision.metrics,
            },
        )
        if verbose:
            print(f"[ARV2] action={decision.action} reason={decision.reason} metrics={decision.metrics}")
        if decision.action != "ARV.EXECUTE":
            return {
                "reports": [],
                "ledgers": [],
                "graphs_html": [],
                "graphs_png": [],
                "snapshots_html": [],
                "temporal_analyses_json": [],
                "verification_json": [],
                "manifests_json": [],
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
            "E_evidence": world_graph.number_of_edges(),
            **decision.metrics,
        },
        root_id=root_id,
    )
    if verbose:
        print(f"[ARV3] action={decision.action} reason={decision.reason} metrics={decision.metrics}")
    if decision.action not in {"ARV.EXECUTE", "ARV.THROTTLE"}:
        return {
            "reports": [],
            "ledgers": [],
            "graphs_html": [],
            "graphs_png": [],
            "snapshots_html": [],
            "temporal_analyses_json": [],
            "verification_json": [],
            "manifests_json": [],
        }

    # Campaign split + reports
    undirected = world_graph.to_undirected()
    components = list(nx.connected_components(undirected))

    def _component_rank(comp_nodes: set[str]) -> tuple[int, int, int, int]:
        sub = world_graph.subgraph(comp_nodes)
        mitre_count = sum(1 for _, data in sub.nodes(data=True) if data.get("type") == "MITRE_Technique")
        alert_count = sum(1 for _, data in sub.nodes(data=True) if data.get("type") == "Alert")
        edge_count = sub.number_of_edges()
        node_count = sub.number_of_nodes()
        return (mitre_count, alert_count, edge_count, node_count)

    # Deterministic ordering: highest-signal campaigns first.
    components.sort(key=_component_rank, reverse=True)
    total_components = len(components)
    if max_campaigns is not None and max_campaigns > 0:
        components = components[:max_campaigns]

    narrator = GraphNarrator()
    ledger = ForensicLedger()
    visualizer = GraphVisualizer()

    reports: List[str] = []
    ledgers: List[str] = []
    graphs_html: List[str] = []
    graphs_png: List[str] = []
    snapshots_html: List[str] = []
    temporal_analyses_json: List[str] = []
    verification_json: List[str] = []
    manifests_json: List[str] = []

    for idx, comp_nodes in enumerate(components):
        subgraph = world_graph.subgraph(comp_nodes).copy()
        summary = narrator.summarize(subgraph)
        assessment_report = narrator.generate_assessment_report(subgraph, triage_summary=triage_counts)

        report_path = output_root / f"Forensic_Assessment_Campaign_{idx+1}.md"

        triples = []
        for u, v, data in subgraph.edges(data=True):
            triples.append({"source": u, "relationship": data.get("relationship"), "target": v})
        comp_arv = [{"gate": "Campaign_Isolation", "phi": len(comp_nodes)}]

        ledger_name = output_root / f"forensic_ledger_campaign_{idx+1}.json"
        ledger.file_path = str(ledger_name)
        ledger.export(triples, summary, comp_arv)
        ledgers.append(str(ledger_name))

        interactive_name = output_root / f"investigation_graph_campaign_{idx+1}.html"
        snapshot_name = output_root / f"campaign_snapshot_{idx+1}.html"

        visualizer.generate_interactive_html(subgraph, output_path=str(interactive_name))
        snapshot_html = _render_campaign_snapshot(
            subgraph=subgraph,
            campaign_index=idx + 1,
            triage_counts=triage_counts,
            report_path=report_path,
            ledger_path=ledger_name,
            graph_html_path=interactive_name,
        )
        snapshot_name.write_text(snapshot_html, encoding="utf-8")

        traversal_analysis = analyze_campaign_traversal(
            subgraph=subgraph,
            alert_meta=alert_meta,
            campaign_index=idx + 1,
        )
        temporal_analysis_name = output_root / f"temporal_analysis_campaign_{idx+1}.json"
        temporal_analysis_name.write_text(
            json.dumps(traversal_analysis, indent=2),
            encoding="utf-8",
        )
        verification_analysis = verify_channel_independence(
            subgraph=subgraph,
            alert_meta=alert_meta,
            campaign_index=idx + 1,
        )
        verification_name = output_root / f"cmi_verification_campaign_{idx+1}.json"
        verification_name.write_text(
            json.dumps(verification_analysis, indent=2),
            encoding="utf-8",
        )
        report_with_claims = assessment_report + _render_claim_and_verification_appendix(
            traversal_analysis=traversal_analysis,
            verification_analysis=verification_analysis,
            manifest_name="reproducibility_manifest.json",
        )
        report_path.write_text(report_with_claims, encoding="utf-8")
        reports.append(str(report_path))

        graphs_html.append(str(interactive_name))
        snapshots_html.append(str(snapshot_name))
        temporal_analyses_json.append(str(temporal_analysis_name))
        verification_json.append(str(verification_name))

    artifact_records: List[Dict[str, Any]] = []
    artifact_collections = {
        "report_md": reports,
        "ledger_json": ledgers,
        "graph_html": graphs_html,
        "snapshot_html": snapshots_html,
        "temporal_analysis_json": temporal_analyses_json,
        "verification_json": verification_json,
        "stage1_ledger_jsonl": [str(stage1_ledger_path)],
        "triage_summary_json": [str(triage_summary_path)],
        "arv_gate_ledger_jsonl": [str(arv_ledger_path)],
    }
    for artifact_type, paths in artifact_collections.items():
        for artifact_path in paths:
            p = Path(artifact_path)
            if not p.exists():
                continue
            artifact_records.append(
                {
                    "type": artifact_type,
                    "path": p.name if p.parent == output_root else str(p),
                    "sha256": _sha256_file(p),
                    "size_bytes": p.stat().st_size,
                }
            )

    dataset_hash = hashlib.sha256(
        json.dumps(raw_alerts, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()
    manifest = {
        "generated_at": _utc_now(),
        "dataset": {
            "event_count": len(raw_alerts),
            "sha256": dataset_hash,
        },
        "profile": {
            "profile_id": profile_id,
            "registry_commit": registry_commit,
        },
        "arv_parameters": {
            "phi_limit_gate1": phi_limit_gate1,
            "phi_limit_gate2": phi_limit_gate2,
            "phi_limit_gate3": phi_limit_gate3,
            "beta": beta,
            "tau": tau,
        },
        "lineage_id": lineage_id,
        "run_context": {
            "invocation_command": os.getenv("CIX_RUN_COMMAND"),
            "cwd": str(Path.cwd()),
            "python_version": platform.python_version(),
            "platform": platform.platform(),
        },
        "artifacts": artifact_records,
        "campaigns": {
            "total_components": total_components,
            "emitted_components": len(components),
            "max_campaigns": max_campaigns,
        },
    }
    manifest_path = output_root / "reproducibility_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    manifests_json.append(str(manifest_path))

    return {
        "reports": reports,
        "ledgers": ledgers,
        "graphs_html": graphs_html,
        "graphs_png": graphs_png,
        "snapshots_html": snapshots_html,
        "temporal_analyses_json": temporal_analyses_json,
        "verification_json": verification_json,
        "manifests_json": manifests_json,
    }
