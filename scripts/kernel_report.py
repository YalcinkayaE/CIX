from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List


def _load_records(path: Path) -> List[Dict]:
    records: List[Dict] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize kernel ledger decisions")
    parser.add_argument(
        "--ledger",
        default="data/kernel_ledger.jsonl",
        help="Ledger JSONL path",
    )
    args = parser.parse_args()

    ledger_path = Path(args.ledger)
    if not ledger_path.exists():
        print(f"Ledger not found: {ledger_path}")
        return 2

    records = _load_records(ledger_path)
    action_counts = Counter()
    reason_counts = Counter()
    state_counts = Counter()
    by_alert = defaultdict(list)

    for record in records:
        if record.get("kind") != "decision":
            continue
        decision = record.get("decision", {})
        action = decision.get("action_id")
        reasons = decision.get("reason_codes", [])
        action_counts[action] += 1
        for reason in reasons:
            reason_counts[reason] += 1
        state = record.get("features_summary", {}).get("next_state")
        if state:
            state_counts[state] += 1
        inputs = record.get("inputs", [])
        if inputs:
            by_alert[inputs[0].get("ref")].append(action)

    print("Actions:")
    for action, count in action_counts.most_common():
        print(f"  {action}: {count}")

    print("Reasons:")
    for reason, count in reason_counts.most_common():
        print(f"  {reason}: {count}")

    if state_counts:
        print("States:")
        for state, count in state_counts.most_common():
            print(f"  {state}: {count}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
