from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from itertools import combinations
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx


SUSPICIOUS_TOKENS = (
    "powershell",
    "wscript",
    "cscript",
    "encodedcommand",
    " -enc",
    "whoami",
    "rundll32",
    "regsvr32",
)


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def build_alert_meta(admitted_alerts: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    meta: Dict[str, Dict[str, Any]] = {}
    for raw_alert in admitted_alerts:
        event_id = str(raw_alert.get("eventId") or raw_alert.get("event_id") or "unknown")
        data = raw_alert.get("data", {}) if isinstance(raw_alert, dict) else {}
        timestamp = (
            raw_alert.get("timestamp")
            or data.get("event_time")
            or data.get("timestamp")
            or raw_alert.get("source_timestamp")
        )
        meta[f"Alert:{event_id}"] = {
            "event_id": event_id,
            "timestamp": timestamp,
            "timestamp_dt": _parse_timestamp(timestamp),
            "host": data.get("hostname"),
            "user": data.get("user"),
            "process": data.get("process_image"),
            "command": data.get("command_line"),
        }
    return meta


def _alert_sort_key(alert_node: str, alert_meta: Dict[str, Dict[str, Any]]) -> Tuple[int, str]:
    ts = alert_meta.get(alert_node, {}).get("timestamp_dt")
    ts_key = ts.isoformat() if isinstance(ts, datetime) else "9999-12-31T00:00:00+00:00"
    return (0 if isinstance(ts, datetime) else 1, ts_key + "|" + alert_node)


def _alert_score(subgraph: nx.DiGraph, alert_node: str, alert_meta: Dict[str, Dict[str, Any]]) -> Tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []

    techniques = [
        t
        for _, t, d in subgraph.out_edges(alert_node, data=True)
        if d.get("relationship") == "INDICATES_TECHNIQUE"
    ]
    if techniques:
        score += 30
        reasons.append(f"technique mappings ({len(techniques)})")

    network_edges = [
        t
        for _, t, d in subgraph.out_edges(alert_node, data=True)
        if d.get("relationship") in {"HAS_SOURCE_IP", "HAS_DEST_IP"}
    ]
    if network_edges:
        score += 15
        reasons.append("network context")

    hash_nodes = [
        t
        for _, t, d in subgraph.out_edges(alert_node, data=True)
        if d.get("relationship") == "HAS_FILE_HASH"
    ]
    efi_hits = 0
    for hash_node in hash_nodes:
        for _, dst, edge_data in subgraph.out_edges(hash_node, data=True):
            if edge_data.get("relationship") in {"ENRICHED_BY_VT", "ENRICHED_BY_OTX"}:
                efi_hits += 1
    if efi_hits:
        score += 20
        reasons.append(f"external corroboration ({efi_hits})")

    cmd_parts = []
    for _, dst, d in subgraph.out_edges(alert_node, data=True):
        if d.get("relationship") in {"OBSERVED_COMMAND", "OBSERVED_PROCESS"}:
            cmd_parts.append(str(dst))
    local_meta = alert_meta.get(alert_node, {})
    if local_meta.get("command"):
        cmd_parts.append(str(local_meta["command"]))
    if local_meta.get("process"):
        cmd_parts.append(str(local_meta["process"]))
    cmd_blob = " ".join(cmd_parts).lower()
    if any(token in cmd_blob for token in SUSPICIOUS_TOKENS):
        score += 20
        reasons.append("suspicious interpreter/command marker")

    return score, reasons


def _select_seed_alerts(subgraph: nx.DiGraph, alert_meta: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    alert_nodes = [n for n, d in subgraph.nodes(data=True) if d.get("type") == "Alert"]
    scored: List[Dict[str, Any]] = []
    for alert_node in alert_nodes:
        score, reasons = _alert_score(subgraph, alert_node, alert_meta)
        meta = alert_meta.get(alert_node, {})
        scored.append(
            {
                "alert": alert_node,
                "event_id": meta.get("event_id"),
                "timestamp": meta.get("timestamp"),
                "host": meta.get("host"),
                "score": score,
                "reasons": reasons,
            }
        )
    scored.sort(
        key=lambda item: (
            -int(item.get("score", 0)),
            _alert_sort_key(item["alert"], alert_meta),
        )
    )
    if not scored:
        return []
    top_score = int(scored[0].get("score", 0))
    if top_score <= 0:
        return scored[:1]
    return scored[: min(3, len(scored))]


def _build_alert_projection(subgraph: nx.DiGraph, alert_meta: Dict[str, Dict[str, Any]]) -> nx.DiGraph:
    projection = nx.DiGraph()
    alert_nodes = [n for n, d in subgraph.nodes(data=True) if d.get("type") == "Alert"]
    projection.add_nodes_from(alert_nodes)

    for node, data in subgraph.nodes(data=True):
        if data.get("type") == "Alert":
            continue
        connected_alerts: Set[str] = set()
        for pred in subgraph.predecessors(node):
            if subgraph.nodes[pred].get("type") == "Alert":
                connected_alerts.add(pred)
        for succ in subgraph.successors(node):
            if subgraph.nodes[succ].get("type") == "Alert":
                connected_alerts.add(succ)

        if len(connected_alerts) < 2:
            continue

        for left, right in combinations(sorted(connected_alerts), 2):
            left_ts = alert_meta.get(left, {}).get("timestamp_dt")
            right_ts = alert_meta.get(right, {}).get("timestamp_dt")
            if isinstance(left_ts, datetime) and isinstance(right_ts, datetime):
                src, dst = (left, right) if left_ts <= right_ts else (right, left)
            else:
                src, dst = (left, right) if left <= right else (right, left)

            edge = projection.get_edge_data(src, dst, default={})
            via_nodes = set(edge.get("via_nodes", []))
            via_nodes.add(node)
            projection.add_edge(
                src,
                dst,
                relationship="COOBSERVED",
                via_nodes=sorted(via_nodes),
                weight=len(via_nodes),
            )

    return projection


def _path_is_temporal(path: List[str], alert_meta: Dict[str, Dict[str, Any]]) -> bool:
    previous: Optional[datetime] = None
    for node in path:
        current = alert_meta.get(node, {}).get("timestamp_dt")
        if current is None:
            continue
        if previous is not None and current < previous:
            return False
        previous = current
    return True


def _delta_seconds(path: List[str], alert_meta: Dict[str, Dict[str, Any]]) -> Optional[int]:
    if len(path) < 2:
        return 0
    start = alert_meta.get(path[0], {}).get("timestamp_dt")
    end = alert_meta.get(path[-1], {}).get("timestamp_dt")
    if not isinstance(start, datetime) or not isinstance(end, datetime):
        return None
    return int((end - start).total_seconds())


def _collect_temporal_paths(
    projection: nx.DiGraph,
    seed_alerts: List[str],
    alert_meta: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for seed in seed_alerts:
        for target in projection.nodes:
            if target == seed:
                continue
            try:
                path = nx.shortest_path(projection, source=seed, target=target)
            except nx.NetworkXNoPath:
                continue
            if not _path_is_temporal(path, alert_meta):
                continue
            rows.append(
                {
                    "seed_alert": seed,
                    "target_alert": target,
                    "path": path,
                    "hops": max(0, len(path) - 1),
                    "delta_seconds": _delta_seconds(path, alert_meta),
                }
            )
    rows.sort(
        key=lambda item: (
            item.get("delta_seconds") is None,
            item.get("delta_seconds") if item.get("delta_seconds") is not None else 10**12,
            item.get("hops", 0),
        )
    )
    return rows


def _counterfactual_candidates(subgraph: nx.DiGraph) -> List[Tuple[str, str]]:
    candidates: List[Tuple[str, str]] = []
    for node, data in subgraph.nodes(data=True):
        ntype = data.get("type")
        if ntype == "EFI":
            candidates.append((node, "EFI"))
            continue
        if ntype != "IP":
            continue
        value = str(data.get("value") or node.split(":", 1)[-1]).strip()
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_multicast:
            continue
        candidates.append((node, "ExternalIP"))
    candidates.sort(key=lambda item: item[0])
    return candidates


def _reachable_targets(rows: List[Dict[str, Any]]) -> Set[str]:
    return {str(item["target_alert"]) for item in rows}


def analyze_campaign_traversal(
    subgraph: nx.DiGraph,
    alert_meta: Dict[str, Dict[str, Any]],
    campaign_index: int,
    tau_blast_seconds: int = 300,
    max_counterfactuals: int = 10,
) -> Dict[str, Any]:
    projection = _build_alert_projection(subgraph, alert_meta)
    seeds = _select_seed_alerts(subgraph, alert_meta)
    seed_nodes = [str(item["alert"]) for item in seeds]

    temporal_paths = _collect_temporal_paths(projection, seed_nodes, alert_meta)
    baseline_reachable = _reachable_targets(temporal_paths)

    blast_rows: List[Dict[str, Any]] = []
    for seed in seed_nodes:
        seed_rows = [row for row in temporal_paths if row["seed_alert"] == seed]
        total = len({row["target_alert"] for row in seed_rows})
        within = len(
            {
                row["target_alert"]
                for row in seed_rows
                if isinstance(row.get("delta_seconds"), int) and int(row["delta_seconds"]) <= tau_blast_seconds
            }
        )
        blast_rows.append(
            {
                "seed_alert": seed,
                "total_reachable": total,
                "within_threshold": within,
                "tau_seconds": tau_blast_seconds,
            }
        )
    blast_rows.sort(key=lambda item: (-int(item["within_threshold"]), -int(item["total_reachable"]), item["seed_alert"]))

    centrality = nx.betweenness_centrality(projection) if projection.number_of_nodes() > 1 else {}
    supports = {
        node: int(projection.in_degree(node) + projection.out_degree(node))
        for node in projection.nodes
    }
    max_centrality = max(centrality.values(), default=1.0) or 1.0
    max_support = max(supports.values(), default=1) or 1
    ordered_alerts = sorted(projection.nodes, key=lambda node: _alert_sort_key(node, alert_meta))
    precedence = {
        node: (len(ordered_alerts) - idx) / max(1, len(ordered_alerts))
        for idx, node in enumerate(ordered_alerts)
    }

    rca_rows: List[Dict[str, Any]] = []
    for node in projection.nodes:
        cent = float(centrality.get(node, 0.0))
        sup = float(supports.get(node, 0))
        pre = float(precedence.get(node, 0.0))
        score = 0.5 * (cent / max_centrality) + 0.3 * (sup / max_support) + 0.2 * pre
        meta = alert_meta.get(node, {})
        rca_rows.append(
            {
                "alert": node,
                "event_id": meta.get("event_id"),
                "timestamp": meta.get("timestamp"),
                "host": meta.get("host"),
                "betweenness": round(cent, 6),
                "support": int(sup),
                "precedence": round(pre, 6),
                "score": round(score, 6),
            }
        )
    rca_rows.sort(key=lambda item: (-float(item["score"]), str(item["alert"])))

    counterfactuals: List[Dict[str, Any]] = []
    for node, kind in _counterfactual_candidates(subgraph)[:max_counterfactuals]:
        if node not in subgraph:
            continue
        reduced = subgraph.copy()
        reduced.remove_node(node)
        reduced_projection = _build_alert_projection(reduced, alert_meta)
        reduced_paths = _collect_temporal_paths(reduced_projection, seed_nodes, alert_meta)
        reduced_reachable = _reachable_targets(reduced_paths)
        impact = max(0, len(baseline_reachable) - len(reduced_reachable))
        counterfactuals.append(
            {
                "control_node": node,
                "control_kind": kind,
                "baseline_reachable": len(baseline_reachable),
                "post_removal_reachable": len(reduced_reachable),
                "reachability_reduction": impact,
            }
        )
    counterfactuals.sort(
        key=lambda item: (-int(item["reachability_reduction"]), str(item["control_node"]))
    )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "campaign_index": campaign_index,
        "summary": {
            "alert_nodes": len([n for n, d in subgraph.nodes(data=True) if d.get("type") == "Alert"]),
            "projection_edges": projection.number_of_edges(),
            "seed_count": len(seed_nodes),
            "temporal_paths": len(temporal_paths),
            "reachable_alerts": len(baseline_reachable),
            "counterfactual_candidates": len(counterfactuals),
        },
        "seed_alerts": seeds,
        "temporal_paths": temporal_paths[:50],
        "blast_radius": {
            "tau_seconds": tau_blast_seconds,
            "rows": blast_rows,
            "recommendation": "ESCALATE" if any(row["within_threshold"] > 0 for row in blast_rows) else "MONITOR",
        },
        "counterfactuals": counterfactuals[:max_counterfactuals],
        "rca_top": rca_rows[:10],
    }

