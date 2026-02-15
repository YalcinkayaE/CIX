from __future__ import annotations

import math
import random
from datetime import datetime, timezone
from typing import Any, Dict, List, Sequence, Tuple

import networkx as nx


def _quantile(values: List[float], q: float) -> float:
    if not values:
        return 0.0
    if q <= 0:
        return float(values[0])
    if q >= 1:
        return float(values[-1])
    pos = q * (len(values) - 1)
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return float(values[lo])
    frac = pos - lo
    return float(values[lo] * (1 - frac) + values[hi] * frac)


def discrete_cmi(
    x: Sequence[int],
    y: Sequence[int],
    z: Sequence[int],
    alpha: float = 1.0,
) -> float:
    if not (len(x) == len(y) == len(z)):
        raise ValueError("x, y, z must have equal lengths")
    n = len(x)
    if n == 0:
        return 0.0

    xs = sorted(set(int(v) for v in x))
    ys = sorted(set(int(v) for v in y))
    zs = sorted(set(int(v) for v in z))

    k_xyz = max(1, len(xs) * len(ys) * len(zs))
    denom = n + alpha * k_xyz

    p_xyz: Dict[Tuple[int, int, int], float] = {}
    counts_xyz: Dict[Tuple[int, int, int], int] = {}
    for xv, yv, zv in zip(x, y, z):
        key = (int(xv), int(yv), int(zv))
        counts_xyz[key] = counts_xyz.get(key, 0) + 1

    for xv in xs:
        for yv in ys:
            for zv in zs:
                c = counts_xyz.get((xv, yv, zv), 0)
                p_xyz[(xv, yv, zv)] = (c + alpha) / denom

    p_xz: Dict[Tuple[int, int], float] = {}
    p_yz: Dict[Tuple[int, int], float] = {}
    p_z: Dict[int, float] = {}
    for xv in xs:
        for zv in zs:
            p_xz[(xv, zv)] = sum(p_xyz[(xv, yv, zv)] for yv in ys)
    for yv in ys:
        for zv in zs:
            p_yz[(yv, zv)] = sum(p_xyz[(xv, yv, zv)] for xv in xs)
    for zv in zs:
        p_z[zv] = sum(p_xyz[(xv, yv, zv)] for xv in xs for yv in ys)

    cmi = 0.0
    for xv in xs:
        for yv in ys:
            for zv in zs:
                pxyz = p_xyz[(xv, yv, zv)]
                numerator = pxyz * p_z[zv]
                denominator = p_xz[(xv, zv)] * p_yz[(yv, zv)]
                if pxyz <= 0.0 or numerator <= 0.0 or denominator <= 0.0:
                    continue
                cmi += pxyz * math.log2(numerator / denominator)
    return float(max(0.0, cmi))


def _permute_within_strata(y: Sequence[int], z: Sequence[int], rng: random.Random) -> List[int]:
    idx_by_z: Dict[int, List[int]] = {}
    for idx, zv in enumerate(z):
        idx_by_z.setdefault(int(zv), []).append(idx)
    out = list(int(v) for v in y)
    for idxs in idx_by_z.values():
        vals = [out[i] for i in idxs]
        rng.shuffle(vals)
        for i, new_val in zip(idxs, vals):
            out[i] = new_val
    return out


def permutation_test_cmi(
    x: Sequence[int],
    y: Sequence[int],
    z: Sequence[int],
    observed_cmi: float,
    permutations: int = 1000,
    alpha: float = 1.0,
    seed: int = 13,
) -> Dict[str, Any]:
    if len(x) == 0:
        return {"p_value": 1.0, "permutations": 0, "null_mean": 0.0}
    rng = random.Random(seed)
    ge_count = 0
    null_values: List[float] = []
    y_seq = list(int(v) for v in y)
    z_seq = list(int(v) for v in z)
    x_seq = list(int(v) for v in x)
    for _ in range(max(1, permutations)):
        y_perm = _permute_within_strata(y_seq, z_seq, rng)
        cmi_perm = discrete_cmi(x_seq, y_perm, z_seq, alpha=alpha)
        null_values.append(cmi_perm)
        if cmi_perm >= observed_cmi:
            ge_count += 1
    p_value = (1 + ge_count) / (1 + len(null_values))
    return {
        "p_value": float(p_value),
        "permutations": len(null_values),
        "null_mean": float(sum(null_values) / max(1, len(null_values))),
    }


def bootstrap_ci_cmi(
    x: Sequence[int],
    y: Sequence[int],
    z: Sequence[int],
    bootstraps: int = 1000,
    alpha: float = 1.0,
    seed: int = 17,
) -> Dict[str, float]:
    n = len(x)
    if n == 0:
        return {"ci_low": 0.0, "ci_high": 0.0}
    rng = random.Random(seed)
    x_seq = [int(v) for v in x]
    y_seq = [int(v) for v in y]
    z_seq = [int(v) for v in z]
    draws: List[float] = []
    for _ in range(max(1, bootstraps)):
        idxs = [rng.randrange(n) for _ in range(n)]
        xb = [x_seq[i] for i in idxs]
        yb = [y_seq[i] for i in idxs]
        zb = [z_seq[i] for i in idxs]
        draws.append(discrete_cmi(xb, yb, zb, alpha=alpha))
    draws.sort()
    return {
        "ci_low": float(_quantile(draws, 0.025)),
        "ci_high": float(_quantile(draws, 0.975)),
    }


def _is_dc_host(host: Any) -> bool:
    h = str(host or "").lower()
    return ("dc" in h) or ("domain" in h and "controller" in h)


def _has_relationship(subgraph: nx.DiGraph, node: str, rels: set[str]) -> bool:
    for _, _, edge_data in subgraph.out_edges(node, data=True):
        if edge_data.get("relationship") in rels:
            return True
    return False


def _has_lateral_technique(subgraph: nx.DiGraph, node: str) -> bool:
    for _, dst, edge_data in subgraph.out_edges(node, data=True):
        if edge_data.get("relationship") != "INDICATES_TECHNIQUE":
            continue
        if str(dst).startswith("MITRE:T1021"):
            return True
    return False


def _is_suspicious(subgraph: nx.DiGraph, node: str, alert_meta: Dict[str, Dict[str, Any]]) -> bool:
    rel_suspicious = _has_relationship(
        subgraph,
        node,
        {"INDICATES_TECHNIQUE", "HAS_DEST_IP", "HAS_SOURCE_IP", "OBSERVED_COMMAND"},
    )
    text = " ".join(
        [
            str(alert_meta.get(node, {}).get("command") or ""),
            str(alert_meta.get(node, {}).get("process") or ""),
            str(node),
        ]
    ).lower()
    token_suspicious = any(
        token in text for token in ("powershell", "wscript", "cscript", "whoami", " -enc", "encodedcommand")
    )
    return rel_suspicious or token_suspicious


def verify_channel_independence(
    subgraph: nx.DiGraph,
    alert_meta: Dict[str, Dict[str, Any]],
    campaign_index: int,
    permutation_count: int = 1000,
    bootstrap_count: int = 1000,
    alpha_significance: float = 0.05,
) -> Dict[str, Any]:
    alert_nodes = [n for n, d in subgraph.nodes(data=True) if d.get("type") == "Alert"]

    x_ws: List[int] = []
    y_dc: List[int] = []
    z_latent: List[int] = []
    sample_rows: List[Dict[str, Any]] = []

    for node in alert_nodes:
        meta = alert_meta.get(node, {})
        host = meta.get("host")
        dc_host = _is_dc_host(host)
        suspicious = _is_suspicious(subgraph, node, alert_meta)
        has_network = _has_relationship(subgraph, node, {"HAS_DEST_IP", "HAS_SOURCE_IP"})
        lateral = 1 if (has_network or _has_lateral_technique(subgraph, node)) else 0
        ws_signal = 1 if (not dc_host and suspicious) else 0
        dc_signal = 1 if (dc_host and suspicious) else 0

        x_ws.append(ws_signal)
        y_dc.append(dc_signal)
        z_latent.append(lateral)
        sample_rows.append(
            {
                "alert": node,
                "host": host,
                "A_WS": ws_signal,
                "A_DC": dc_signal,
                "L": lateral,
            }
        )

    cmi_obs = discrete_cmi(x_ws, y_dc, z_latent, alpha=1.0)
    perm = permutation_test_cmi(
        x_ws,
        y_dc,
        z_latent,
        observed_cmi=cmi_obs,
        permutations=permutation_count,
        alpha=1.0,
    )
    ci = bootstrap_ci_cmi(
        x_ws,
        y_dc,
        z_latent,
        bootstraps=bootstrap_count,
        alpha=1.0,
    )

    reject_h0 = (
        cmi_obs > 0.0
        and perm["p_value"] < alpha_significance
        and ci["ci_low"] > 0.0
    )
    claim_label = "VERIFIED" if reject_h0 else "INFERRED"

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "campaign_index": campaign_index,
        "hypothesis": {
            "H0": "I(A_DC;L|A_WS)=0",
            "H1": "I(A_DC;L|A_WS)>0",
        },
        "inputs_summary": {
            "alerts": len(alert_nodes),
            "ws_positive": int(sum(x_ws)),
            "dc_positive": int(sum(y_dc)),
            "lateral_positive": int(sum(z_latent)),
        },
        "statistics": {
            "cmi_observed": float(cmi_obs),
            "p_value": float(perm["p_value"]),
            "alpha_significance": float(alpha_significance),
            "ci95_low": float(ci["ci_low"]),
            "ci95_high": float(ci["ci_high"]),
            "permutations": int(perm["permutations"]),
            "bootstraps": int(max(1, bootstrap_count)),
            "null_mean": float(perm["null_mean"]),
        },
        "decision": {
            "reject_h0": bool(reject_h0),
            "claim_label": claim_label,
            "reason": (
                "CMI > 0, null rejected, CI excludes zero"
                if reject_h0
                else "Insufficient statistical evidence for VERIFIED; keep as INFERRED"
            ),
        },
        "samples": sample_rows[:100],
    }
