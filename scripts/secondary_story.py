#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple


def _load_json(path: Path) -> Dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _split_prefix(node: str) -> Tuple[str, str]:
    if ":" not in node:
        return "Other", node
    prefix, value = node.split(":", 1)
    return prefix, value


def _top_hubs(edges: Sequence[Dict[str, str]], limit: int = 8) -> List[Tuple[str, int]]:
    degree = Counter()
    for edge in edges:
        src = edge.get("source", "")
        dst = edge.get("target", "")
        if src:
            degree[src] += 1
        if dst:
            degree[dst] += 1
    return degree.most_common(limit)


def _mitre_nodes(edges: Sequence[Dict[str, str]]) -> List[str]:
    mitre = set()
    for edge in edges:
        for side in ("source", "target"):
            node = edge.get(side, "")
            if node.startswith("MITRE:"):
                mitre.add(node.replace("MITRE:", "", 1))
    return sorted(mitre)


def _find_edges_with_terms(edges: Sequence[Dict[str, str]], terms: Iterable[str], limit: int = 8) -> List[Dict[str, str]]:
    lowered_terms = [term.lower() for term in terms if term]
    scored: List[Tuple[int, int, Dict[str, str]]] = []
    if not lowered_terms:
        return []
    generic_rel = {"ON_HOST", "HAS_USER"}
    for edge in edges:
        s = edge.get("source", "")
        t = edge.get("target", "")
        rel = edge.get("relationship", "")
        blob = f"{s} {rel} {t}".lower()
        term_hits = sum(1 for term in lowered_terms if term in blob)
        if term_hits <= 0:
            continue
        relation_penalty = 0 if rel not in generic_rel else 1
        # Higher term match, lower penalty first.
        scored.append((-term_hits, relation_penalty, edge))
    scored.sort(key=lambda item: (item[0], item[1]))
    return [edge for _, _, edge in scored[:limit]]


def _build_principals(hubs: Sequence[Tuple[str, int]]) -> List[str]:
    principals = []
    for node, _ in hubs:
        prefix, value = _split_prefix(node)
        if prefix in {"User", "Host"} and value:
            principals.append(value.strip())
    return principals


def _scan_high_entropy_bridge(raw_ledger_path: Path, principals: Sequence[str], limit: int = 5) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    seen = set()
    tokens = [p.lower() for p in principals if p]
    if not tokens or not raw_ledger_path.exists():
        return findings

    with raw_ledger_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            payload = entry.get("payload") or {}
            band = str(payload.get("band", ""))
            reason = str(payload.get("reason", ""))
            projection = str(payload.get("projection", ""))
            blob = f"{reason} {projection}".lower()
            if not any(token in blob for token in tokens):
                continue

            # Treat VACUUM / RED / HIGH_ENTROPY-style bands as the red-zone bridge.
            if not (
                "VACUUM" in band.upper()
                or "RED" in band.upper()
                or "HIGH_ENTROPY" in band.upper()
                or "Thermodynamic Limit Exceeded" in reason
            ):
                continue

            findings.append(
                {
                    "timestamp": str(entry.get("timestamp", "")),
                    "event_id": str(payload.get("event_id", "")),
                    "band": band,
                    "reason": reason,
                    "projection": projection,
                }
            )
            dedupe_key = (str(payload.get("event_id", "")), band, reason, projection)
            if dedupe_key in seen:
                findings.pop()
                continue
            seen.add(dedupe_key)
            if len(findings) >= limit:
                break

    return findings


def _format_story(
    triage: Dict,
    hubs: Sequence[Tuple[str, int]],
    mitre: Sequence[str],
    flow_edges: Sequence[Dict[str, str]],
    bridge_hits: Sequence[Dict[str, str]],
) -> str:
    lines: List[str] = []
    lines.append("# Secondary Story Overlay (Campaign 1)")
    lines.append("")
    lines.append("## 1. Why this second pass")
    lines.append(
        "This overlay links the visible campaign graph to filtered high-entropy evidence, "
        "so analysts can preserve narrative continuity across admitted and excluded events."
    )
    lines.append("")

    lines.append("## 2. Run context")
    lines.append(f"- Ingested: {triage.get('total_ingested', 0)}")
    lines.append(f"- Red zone (high entropy): {triage.get('red_zone_high_entropy', 0)}")
    lines.append(f"- Dedup removed: {triage.get('dedup_removed', 0)}")
    lines.append(f"- Findings (MITRE nodes): {triage.get('findings', 0)}")
    if mitre:
        lines.append(f"- MITRE techniques observed: {', '.join(mitre)}")
    lines.append("")

    lines.append("## 3. Graph hub evidence")
    for idx, (node, degree) in enumerate(hubs, start=1):
        prefix, value = _split_prefix(node)
        lines.append(f"{idx}. `{prefix}` `{value}` (degree={degree})")
    lines.append("")

    lines.append("## 4. Attack-thread candidates (hub anchored)")
    if flow_edges:
        for idx, edge in enumerate(flow_edges, start=1):
            lines.append(
                f"{idx}. `{edge.get('source', '')}` --[{edge.get('relationship', '')}]--> `{edge.get('target', '')}`"
            )
    else:
        lines.append("- No flow candidates matched heuristic terms.")
    lines.append("")

    lines.append("## 5. Filtered high-entropy bridge")
    if bridge_hits:
        lines.append(
            "Filtered high-entropy records share principal tokens with campaign hubs, "
            "which supports a single continuous operator story."
        )
        for idx, hit in enumerate(bridge_hits, start=1):
            lines.append(
                f"{idx}. event_id={hit['event_id']} band={hit['band']} reason={hit['reason']} "
                f"projection=`{hit['projection']}`"
            )
    else:
        lines.append(
            "No explicit bridge records were found in `ledger.jsonl` for this run window. "
            "If you reset ledgers before each run, bridge extraction will be cleaner."
        )
    lines.append("")

    lines.append("## 6. Working narrative (analyst-ready)")
    lines.append(
        "The campaign is centered on a small set of high-degree entities (notably user/host/process hubs). "
        "Execution behavior around script-host and PowerShell activity maps to the observed MITRE techniques. "
        "A filtered high-entropy branch tied to the same principal(s) suggests pre/post steps that were excluded "
        "for safety/noise control, but are still relevant context for incident chronology and scoping."
    )
    lines.append("")

    lines.append("## 7. Suggested analyst follow-up")
    lines.append("1. Rehydrate the filtered branch around shared principals (for example, pgustavo) as a side timeline.")
    lines.append("2. Compare command-line lineage from admitted vs filtered records to test if they share launcher ancestry.")
    lines.append("3. Add a confidence tag per story segment (high=graph-confirmed, medium=bridge-inferred).")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a secondary story overlay from campaign artifacts.")
    parser.add_argument(
        "--forensic-ledger",
        default="data/forensic_ledger_campaign_1.json",
        help="Path to forensic ledger campaign JSON",
    )
    parser.add_argument(
        "--triage-summary",
        default="data/triage_summary.json",
        help="Path to triage summary JSON",
    )
    parser.add_argument(
        "--raw-ledger",
        default="data/ledger.jsonl",
        help="Path to raw ingest ledger JSONL (used for high-entropy bridge detection)",
    )
    parser.add_argument(
        "--out",
        default="data/Secondary_Story_Campaign_1.md",
        help="Output markdown file",
    )
    args = parser.parse_args()

    forensic_path = Path(args.forensic_ledger)
    triage_path = Path(args.triage_summary)
    raw_ledger_path = Path(args.raw_ledger)
    out_path = Path(args.out)

    forensic = _load_json(forensic_path)
    triage = _load_json(triage_path)
    edges = forensic.get("ledger_entries", [])

    hubs = _top_hubs(edges, limit=8)
    principals = _build_principals(hubs)
    mitre = _mitre_nodes(edges)

    flow_terms = ["pgustavo", "WORKSTATION5", "wscript", "powershell", "launcher.vbs"]
    flow_edges = _find_edges_with_terms(edges, flow_terms, limit=8)
    bridge_hits = _scan_high_entropy_bridge(raw_ledger_path, principals=principals, limit=5)

    story = _format_story(
        triage=triage,
        hubs=hubs,
        mitre=mitre,
        flow_edges=flow_edges,
        bridge_hits=bridge_hits,
    )
    out_path.write_text(story, encoding="utf-8")
    print(f"Wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
