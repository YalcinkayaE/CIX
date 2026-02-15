#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Dict, List


DEFAULT_SCALE = {
    "Y": 1.0,
    "P": 0.5,
    "U": 0.0,
}


def _load_weights(path: Path) -> Dict[str, float]:
    weights: Dict[str, float] = {}
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        required = {"feature", "weight"}
        if not required.issubset(set(reader.fieldnames or [])):
            missing = required.difference(set(reader.fieldnames or []))
            raise ValueError(f"Weights file missing columns: {sorted(missing)}")
        for row in reader:
            feature = (row.get("feature") or "").strip()
            if not feature:
                continue
            try:
                weight = float(row.get("weight") or 0.0)
            except ValueError as exc:
                raise ValueError(f"Invalid weight for feature '{feature}': {row.get('weight')}") from exc
            weights[feature] = weight
    if not weights:
        raise ValueError("No weights loaded.")
    return weights


def _score_row(row: Dict[str, str], weights: Dict[str, float], scale: Dict[str, float]) -> Dict[str, float]:
    per_feature: Dict[str, float] = {}
    total_raw = 0.0
    for feature, weight in weights.items():
        marker = (row.get(feature) or "U").strip().upper()
        value = scale.get(marker, 0.0)
        feature_score = weight * value
        per_feature[feature] = feature_score
        total_raw += feature_score
    return {
        "total_raw": total_raw,
        **per_feature,
    }


def _rank(rows: List[Dict[str, str]]) -> None:
    rows.sort(key=lambda r: float(r["score_100"]), reverse=True)
    rank = 0
    prev_score = None
    for idx, row in enumerate(rows, start=1):
        score = float(row["score_100"])
        if prev_score is None or score < prev_score:
            rank = idx
            prev_score = score
        row["rank"] = str(rank)


def main() -> None:
    parser = argparse.ArgumentParser(description="Score Y/P/U feature benchmark matrix using weighted features.")
    parser.add_argument(
        "--matrix",
        default="docs/benchmark/feature_benchmark_matrix_v1.csv",
        help="Input feature matrix CSV",
    )
    parser.add_argument(
        "--weights",
        default="docs/benchmark/feature_benchmark_weights_v1.csv",
        help="Feature weights CSV",
    )
    parser.add_argument(
        "--output",
        default="docs/benchmark/feature_benchmark_weighted_score_v1.csv",
        help="Output scored CSV",
    )
    args = parser.parse_args()

    matrix_path = Path(args.matrix)
    weights_path = Path(args.weights)
    output_path = Path(args.output)

    weights = _load_weights(weights_path)
    max_score = sum(weights.values())
    if max_score <= 0:
        raise ValueError("Sum of weights must be > 0.")

    scored_rows: List[Dict[str, str]] = []
    with matrix_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        matrix_fields = set(reader.fieldnames or [])
        missing_features = [feat for feat in weights if feat not in matrix_fields]
        if missing_features:
            raise ValueError(f"Matrix missing required feature columns: {missing_features}")

        for row in reader:
            system = (row.get("system") or "").strip()
            if not system:
                continue
            scored = _score_row(row, weights, DEFAULT_SCALE)
            score_100 = (scored["total_raw"] / max_score) * 100.0
            out_row: Dict[str, str] = {
                "rank": "",
                "system": system,
                "score_raw": f"{scored['total_raw']:.2f}",
                "score_100": f"{score_100:.2f}",
                "confidence": row.get("confidence", ""),
                "notes": row.get("notes", ""),
            }
            for feature in weights:
                out_row[f"{feature}_score"] = f"{scored[feature]:.2f}"
            scored_rows.append(out_row)

    _rank(scored_rows)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = ["rank", "system", "score_raw", "score_100", "confidence"]
    fieldnames.extend([f"{feature}_score" for feature in weights.keys()])
    fieldnames.append("notes")

    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(scored_rows)

    print(f"Wrote scored benchmark to {output_path}")


if __name__ == "__main__":
    main()

