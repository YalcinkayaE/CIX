#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def pick_first(obj: Dict[str, Any], keys: Iterable[str]) -> Any:
    for k in keys:
        if k in obj and obj[k] not in (None, ""):
            return obj[k]
    return None


def normalize_event(event: Dict[str, Any], default_source_id: str | None) -> Dict[str, Any]:
    source_id = default_source_id or pick_first(
        event,
        [
            "source_id",
            "SourceName",
            "SourceModuleName",
            "ProviderName",
            "Provider",
            "Channel",
            "host",
            "Hostname",
        ],
    )
    if not source_id:
        source_id = "unknown-source"

    # Prefer record-level identifiers to avoid collisions (EventID is a Windows event code).
    event_id = pick_first(event, ["event_id", "eventId", "RecordNumber", "EventRecordID", "EventID", "id"])
    if event_id is None:
        event_id = sha256_hex(canonical_json(event))[:16]

    source_timestamp = pick_first(
        event,
        ["source_timestamp", "EventTime", "@timestamp", "EventReceivedTime", "timestamp", "TimeCreated"],
    )
    if source_timestamp is None:
        source_timestamp = "1970-01-01T00:00:00Z"

    raw_payload_hash = f"sha256:{sha256_hex(canonical_json(event))}"

    return {
        "source_id": str(source_id),
        "event_id": str(event_id),
        "source_timestamp": str(source_timestamp),
        "raw_payload": event,
        "raw_payload_hash": raw_payload_hash,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize JSONL events into Stage-1 ingest format")
    parser.add_argument("input", help="Input JSONL file")
    parser.add_argument("output", help="Output JSON file with {events: [...]} structure")
    parser.add_argument("--source-id", dest="source_id", default=None, help="Override source_id for all events")
    args = parser.parse_args()

    inp = Path(args.input)
    if not inp.exists():
        raise SystemExit(f"File not found: {inp}")

    events = []
    with inp.open("r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"Invalid JSON on line {line_no}: {exc}")
            if not isinstance(obj, dict):
                raise SystemExit(f"Expected JSON object on line {line_no}")
            events.append(normalize_event(obj, args.source_id))

    out = Path(args.output)
    out.write_text(json.dumps({"events": events}, indent=2))
    print(f"Wrote {len(events)} events to {out}")


if __name__ == "__main__":
    main()
