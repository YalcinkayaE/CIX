from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .hashing import canonical_json, sha256_hex


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Ledger:
    """
    Append-only ledger with hash chaining (JSONL).
    Each entry includes prev_hash and entry_hash for integrity checks.
    """

    def __init__(self, file_path: str = "data/ledger.jsonl") -> None:
        self.file_path = Path(file_path)
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        self.last_hash = ""  # empty for genesis
        self._idempotency_index: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        self._event_hash_index: Dict[Tuple[str, str], str] = {}
        if self.file_path.exists():
            self._load_existing()

    def _load_existing(self) -> None:
        try:
            with self.file_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                    self.last_hash = entry.get("entry_hash", self.last_hash)
                    self._index_entry(entry)
        except FileNotFoundError:
            return

    def _index_entry(self, entry: Dict[str, Any]) -> None:
        if entry.get("type") != "BAND_DECISION":
            return
        payload = entry.get("payload", {})
        source_id = payload.get("source_id")
        event_id = payload.get("event_id")
        raw_payload_hash = payload.get("raw_payload_hash")
        if not (source_id and event_id and raw_payload_hash):
            return
        key = (source_id, event_id, raw_payload_hash)
        self._idempotency_index[key] = {
            "band": payload.get("band"),
            "decision_code": payload.get("decision_code"),
            "http_status": payload.get("http_status"),
            "ledger_entry_id": entry.get("entry_id"),
        }
        self._event_hash_index[(source_id, event_id)] = raw_payload_hash

    def seed_idempotency(self, already_ingested: Optional[Dict[str, Any]]) -> None:
        if not already_ingested:
            return
        source_id = already_ingested.get("source_id")
        event_id = already_ingested.get("event_id")
        raw_payload_hash = already_ingested.get("raw_payload_hash")
        if not (source_id and event_id and raw_payload_hash):
            return
        key = (source_id, event_id, raw_payload_hash)
        self._idempotency_index[key] = {
            "band": already_ingested.get("original_decision", {}).get("band"),
            "decision_code": already_ingested.get("original_decision", {}).get("decision_code"),
            "http_status": already_ingested.get("original_decision", {}).get("http_status"),
            "ledger_entry_id": already_ingested.get("original_ledger_entry_id"),
        }
        self._event_hash_index[(source_id, event_id)] = raw_payload_hash

    def lookup_idempotent(self, source_id: str, event_id: str, raw_payload_hash: str) -> Optional[Dict[str, Any]]:
        return self._idempotency_index.get((source_id, event_id, raw_payload_hash))

    def lookup_event_hash(self, source_id: str, event_id: str) -> Optional[str]:
        return self._event_hash_index.get((source_id, event_id))

    def append(self, entry_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        entry = {
            "entry_id": str(uuid.uuid4()),
            "timestamp": _utc_now(),
            "type": entry_type,
            "payload": payload,
            "prev_hash": self.last_hash,
        }
        entry_hash = sha256_hex(canonical_json(entry))
        entry["entry_hash"] = entry_hash

        with self.file_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        self.last_hash = entry_hash
        self._index_entry(entry)
        return entry
