#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <json_file> [url] [mode] [--fresh] [--ledger <path>]" >&2
  echo "Modes: summary (default), bands, vacuum, full" >&2
  echo "Example: $0 samples/cef_event.json" >&2
  exit 1
fi

JSON_FILE="$1"
URL="${2:-http://localhost:8009/api/v1/ingest/classify}"
MODE="${3:-summary}"

shift || true
shift || true
shift || true

FRESH=false
LEDGER_PATH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fresh)
      FRESH=true
      shift
      ;;
    --ledger)
      LEDGER_PATH="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

if [[ ! -f "$JSON_FILE" ]]; then
  echo "File not found: $JSON_FILE" >&2
  exit 1
fi

wrap_jsonl() {
  local input="$1"
  local output="$2"
  python3 - "$input" "$output" <<'PY'
import json
import sys
import hashlib
from pathlib import Path
from typing import Any, Dict, Iterable
inp = Path(sys.argv[1])
out = Path(sys.argv[2])

def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def pick_first(obj: Dict[str, Any], keys: Iterable[str]) -> Any:
    for k in keys:
        if k in obj and obj[k] not in (None, ""):
            return obj[k]
    return None

def normalize_event(event: Dict[str, Any]) -> Dict[str, Any]:
    source_id = pick_first(
        event,
        [
            "source_id",
            "stream",
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

    event_id = pick_first(event, ["event_id", "eventId", "RecordNumber", "EventRecordID", "EventID", "id"])
    if event_id is None:
        event_id = sha256_hex(canonical_json(event))[:16]

    source_timestamp = pick_first(event, ["source_timestamp", "ts", "EventTime", "@timestamp", "EventReceivedTime", "timestamp", "TimeCreated"])
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

items = []
with inp.open("r", encoding="utf-8", errors="ignore") as f:
    for line_no, line in enumerate(f, 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"Invalid JSON on line {line_no}: {exc}")
        if isinstance(obj, dict):
            items.append(normalize_event(obj))

out.write_text(json.dumps({"events": items}, indent=2))
print(f"Wrote {len(items)} events to {out}")
PY
}

normalize_json_array() {
  local input="$1"
  local output="$2"
  python3 - "$input" "$output" <<'PY'
import json
import sys
import hashlib
from pathlib import Path
from typing import Any, Dict, Iterable

inp = Path(sys.argv[1])
out = Path(sys.argv[2])

def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def pick_first(obj: Dict[str, Any], keys: Iterable[str]) -> Any:
    for k in keys:
        if k in obj and obj[k] not in (None, ""):
            return obj[k]
    return None

def normalize_event(event: Dict[str, Any]) -> Dict[str, Any]:
    source_id = pick_first(event, ["source_id", "stream", "SourceName", "SourceModuleName", "ProviderName", "Provider", "Channel", "host", "Hostname"])
    if not source_id:
        source_id = "unknown-source"

    # Prefer record-level identifiers (EventID is a Windows event code)
    event_id = pick_first(event, ["event_id", "eventId", "RecordNumber", "EventRecordID", "EventID", "id"])
    if event_id is None:
        event_id = sha256_hex(canonical_json(event))[:16]

    source_timestamp = pick_first(event, ["source_timestamp", "ts", "EventTime", "@timestamp", "EventReceivedTime", "timestamp", "TimeCreated"])
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

raw = json.loads(inp.read_text())
if not isinstance(raw, list):
    raise SystemExit("Expected a JSON array at top-level")

normalized = [normalize_event(ev) for ev in raw if isinstance(ev, dict)]
out.write_text(json.dumps({"events": normalized}, indent=2))
print(f"Wrote {len(normalized)} events to {out}")
PY
}

# Detect JSONL vs JSON object/array
if python3 - "$JSON_FILE" >/dev/null 2>&1 <<'PY'
import json, sys
from pathlib import Path
p=Path(sys.argv[1])
obj=json.loads(p.read_text())
print(type(obj).__name__)
PY
then
  root_type=$(python3 - "$JSON_FILE" <<'PY'
import json, sys
from pathlib import Path
p=Path(sys.argv[1])
obj=json.loads(p.read_text())
print(type(obj).__name__)
PY
  )
  if [[ "$root_type" == "list" ]]; then
    NORMALIZED_FILE="${JSON_FILE%.*}.normalized.json"
    normalize_json_array "$JSON_FILE" "$NORMALIZED_FILE"
    FINAL_FILE="$NORMALIZED_FILE"
  else
    FINAL_FILE="$JSON_FILE"
  fi
else
  line_count=$(wc -l < "$JSON_FILE" | tr -d ' ')
  if [[ "$line_count" -gt 1 ]]; then
    WRAPPED_FILE="${JSON_FILE%.*}.batch.json"
    wrap_jsonl "$JSON_FILE" "$WRAPPED_FILE"
    FINAL_FILE="$WRAPPED_FILE"
  else
    echo "Invalid JSON in $JSON_FILE" >&2
    exit 1
  fi
fi

if [[ -n "$LEDGER_PATH" ]]; then
  export CIX_LEDGER_PATH="$LEDGER_PATH"
fi

if [[ "$FRESH" == "true" ]]; then
  LEDGER_FILE="${CIX_LEDGER_PATH:-/Users/erkanyalcinkaya/projects/cix-alerts/data/ledger.jsonl}"
  if [[ -f "$LEDGER_FILE" ]]; then
    rm -f "$LEDGER_FILE"
  fi
fi

RESP=$(curl -s "$URL" -H "Content-Type: application/json" -d "@${FINAL_FILE}")

case "$MODE" in
  summary)
    if ! echo "$RESP" | jq -e '.batch | type == "object"' >/dev/null; then
      echo "$RESP" | jq '.'
      echo "ERROR: response missing .batch counters (likely schema/API error)." >&2
      exit 1
    fi
    echo "$RESP" | jq '.batch | {vacuum_count, low_entropy_count, mimic_scoped_count, drop_count, suppress_count, pass_count, processed_count, replayed_count, conflict_count, failed_count, stage1_ms}'
    ;;
  bands)
    if ! echo "$RESP" | jq -e '.per_event | type == "array"' >/dev/null; then
      echo "$RESP" | jq '.'
      echo "ERROR: response missing .per_event list (likely schema/API error)." >&2
      exit 1
    fi
    echo "$RESP" | jq '.per_event | sort_by(.band) | group_by(.band) | map({band: .[0].band, count: length})'
    ;;
  vacuum)
    if ! echo "$RESP" | jq -e '.per_event | type == "array"' >/dev/null; then
      echo "$RESP" | jq '.'
      echo "ERROR: response missing .per_event list (likely schema/API error)." >&2
      exit 1
    fi
    echo "$RESP" | jq '.per_event[] | select(.band=="VACUUM") | {event_id, entropy_raw, reason}'
    ;;
  full)
    echo "$RESP" | jq '.'
    ;;
  *)
    echo "Unknown mode: $MODE" >&2
    exit 1
    ;;
esac
