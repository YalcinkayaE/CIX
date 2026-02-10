#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def main():
    if len(sys.argv) < 2:
        print("Usage: wrap_jsonl.py <input_jsonl> [output_json]", file=sys.stderr)
        sys.exit(1)
    inp = Path(sys.argv[1])
    if not inp.exists():
        print(f"File not found: {inp}", file=sys.stderr)
        sys.exit(1)
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else inp.with_suffix(".batch.json")

    events = []
    with inp.open("r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"Invalid JSON on line {line_no}: {exc}")

    out.write_text(json.dumps({"events": events}, indent=2))
    print(f"Wrote {len(events)} events to {out}")


if __name__ == "__main__":
    main()
