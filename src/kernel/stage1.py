from __future__ import annotations

import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .hashing import canonical_json, hash_payload, sha256_hex
from .ledger import Ledger
from ..ingest.siem_formats import parse_cef, parse_leef, parse_syslog

BAND_VACUUM = "VACUUM"
BAND_LOW = "LOW_ENTROPY"
BAND_MIMIC = "MIMIC_SCOPED"

STATUS_PROCESSED = "PROCESSED"
STATUS_REPLAYED = "REPLAYED"
STATUS_CONFLICT = "CONFLICT"
STATUS_FAILED = "FAILED"

DECISION_VACUUM = "VACUUM_DROP"
DECISION_LOW = "LOW_ENTROPY_SUPPRESS"
DECISION_MIMIC = "MIMIC_SCOPED_PASS"

HTTP_DROP = 418
HTTP_OK = 200
HTTP_CONFLICT = 409
HTTP_BAD_REQUEST = 400


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    import math

    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def _resolve_thresholds(profile: Optional[Dict[str, Any]]) -> Dict[str, float]:
    profile = profile or {}
    thresholds = (
        profile.get("ingestion_thresholds")
        or profile.get("parameters", {}).get("ingestion_thresholds")
        or {}
    )
    vacuum_max = thresholds.get("vacuum_entropy_max")
    low_max = thresholds.get("low_entropy_max")
    mimic_min = thresholds.get("mimic_scoped_min")
    if vacuum_max is None or low_max is None or mimic_min is None:
        raise ValueError("Missing ingestion thresholds: vacuum_entropy_max, low_entropy_max, mimic_scoped_min")
    return {
        "vacuum_entropy_max": float(vacuum_max),
        "low_entropy_max": float(low_max),
        "mimic_scoped_min": float(mimic_min),
    }


def _parse_if_needed(event: Dict[str, Any]) -> Dict[str, Any]:
    fmt = (event.get("format") or "").lower()
    raw_payload = event.get("raw_payload")
    raw_event = event.get("raw_event")
    if isinstance(raw_payload, str) and fmt in {"cef", "leef", "syslog"}:
        parsed = _parse_by_format(fmt, raw_payload)
        event["raw_payload"] = {"format": fmt, "raw": raw_payload, "parsed": parsed}
        if not event.get("source_timestamp") and parsed.get("timestamp"):
            event["source_timestamp"] = parsed.get("timestamp")
    elif isinstance(raw_event, str) and fmt in {"cef", "leef", "syslog"}:
        parsed = _parse_by_format(fmt, raw_event)
        event["raw_payload"] = {"format": fmt, "raw": raw_event, "parsed": parsed}
        if not event.get("source_timestamp") and parsed.get("timestamp"):
            event["source_timestamp"] = parsed.get("timestamp")
    return event


def _parse_by_format(fmt: str, raw: str) -> Dict[str, Any]:
    if fmt == "leed":
        fmt = "leef"
    if fmt == "cef":
        return parse_cef(raw)
    if fmt == "leef":
        return parse_leef(raw)
    if fmt == "syslog":
        return parse_syslog(raw)
    raise ValueError(f"Unsupported format: {fmt}")


def _compute_features(raw_payload: Any) -> Dict[str, Any]:
    payload_text = canonical_json(raw_payload)
    entropy = _shannon_entropy(payload_text)
    return {
        "payload_length": len(payload_text),
        "entropy": entropy,
    }


def _classify_band(entropy: float, thresholds: Dict[str, float]) -> Tuple[str, str, int]:
    if entropy <= thresholds["vacuum_entropy_max"]:
        return BAND_VACUUM, DECISION_VACUUM, HTTP_DROP
    if entropy <= thresholds["low_entropy_max"]:
        return BAND_LOW, DECISION_LOW, HTTP_OK
    if entropy >= thresholds["mimic_scoped_min"]:
        return BAND_MIMIC, DECISION_MIMIC, HTTP_OK
    return BAND_LOW, DECISION_LOW, HTTP_OK


def classify_batch(
    events: List[Dict[str, Any]],
    profile: Optional[Dict[str, Any]] = None,
    ledger: Optional[Ledger] = None,
    precondition: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    ledger = ledger or Ledger()
    if precondition and isinstance(precondition, dict):
        ledger.seed_idempotency(precondition.get("already_ingested"))

    thresholds = _resolve_thresholds(profile)

    batch_id = str(uuid.uuid4())
    start_time = time.time()

    counters = {
        "vacuum_count": 0,
        "low_entropy_count": 0,
        "mimic_scoped_count": 0,
        "drop_count": 0,
        "suppress_count": 0,
        "pass_count": 0,
        "replayed_count": 0,
        "conflict_count": 0,
        "failed_count": 0,
    }

    per_event = []

    ledger.append(
        "BATCH_RECEIVED",
        {
            "batch_id": batch_id,
            "received_count": len(events),
            "profile_parameters": profile or {},
        },
    )

    for event in events:
        event = _parse_if_needed(dict(event))
        source_id = event.get("source_id")
        event_id = event.get("event_id")
        source_timestamp = event.get("source_timestamp")
        raw_payload = event.get("raw_payload")
        raw_payload_ref = event.get("raw_payload_ref")
        raw_payload_hash = event.get("raw_payload_hash")

        if not source_id or not event_id or not source_timestamp or (raw_payload is None and raw_payload_ref is None):
            counters["failed_count"] += 1
            per_event.append(
                {
                    "event_id": event_id,
                    "status": STATUS_FAILED,
                    "error_code": "INVALID_SCHEMA",
                    "http_status": HTTP_BAD_REQUEST,
                }
            )
            continue

        if not raw_payload_hash:
            raw_payload_hash = hash_payload(raw_payload if raw_payload is not None else raw_payload_ref)

        idempotent = ledger.lookup_idempotent(source_id, event_id, raw_payload_hash)
        if idempotent:
            counters["replayed_count"] += 1
            replay_entry = ledger.append(
                "IDEMPOTENT_REPLAY",
                {
                    "source_id": source_id,
                    "event_id": event_id,
                    "raw_payload_hash": raw_payload_hash,
                    "original_ledger_entry_id": idempotent.get("ledger_entry_id"),
                },
            )
            per_event.append(
                {
                    "event_id": event_id,
                    "status": STATUS_REPLAYED,
                    "band": idempotent.get("band"),
                    "decision_code": idempotent.get("decision_code"),
                    "http_status": idempotent.get("http_status") or HTTP_OK,
                    "ledger": {
                        "replay_entry_decision_code": "IDEMPOTENT_REPLAY",
                        "replay_entry_id": replay_entry.get("entry_id"),
                    },
                }
            )
            continue

        prior_hash = ledger.lookup_event_hash(source_id, event_id)
        if prior_hash and prior_hash != raw_payload_hash:
            counters["conflict_count"] += 1
            conflict_entry = ledger.append(
                "EVENT_ID_CONFLICT",
                {
                    "source_id": source_id,
                    "event_id": event_id,
                    "raw_payload_hash_old": prior_hash,
                    "raw_payload_hash_new": raw_payload_hash,
                },
            )
            per_event.append(
                {
                    "event_id": event_id,
                    "status": STATUS_CONFLICT,
                    "http_status": HTTP_CONFLICT,
                    "ledger": {
                        "conflict_entry_decision_code": "EVENT_ID_CONFLICT",
                        "conflict_entry_id": conflict_entry.get("entry_id"),
                    },
                }
            )
            continue

        features = _compute_features(raw_payload if raw_payload is not None else raw_payload_ref)
        feature_hash = sha256_hex(canonical_json(features))
        band, decision_code, http_status = _classify_band(features["entropy"], thresholds)

        if band == BAND_VACUUM:
            counters["vacuum_count"] += 1
            counters["drop_count"] += 1
        elif band == BAND_LOW:
            counters["low_entropy_count"] += 1
            counters["suppress_count"] += 1
        else:
            counters["mimic_scoped_count"] += 1
            counters["pass_count"] += 1

        decision_payload = {
            "source_id": source_id,
            "event_id": event_id,
            "ingest_timestamp": _utc_now(),
            "raw_payload_hash": raw_payload_hash,
            "band": band,
            "decision_code": decision_code,
            "http_status": http_status,
            "classification_features_id": feature_hash,
        }

        decision_entry = ledger.append("BAND_DECISION", decision_payload)

        evidence_pointers = {
            "source_id": source_id,
            "event_id": event_id,
            "ingest_timestamp": decision_payload["ingest_timestamp"],
            "raw_payload_hash": raw_payload_hash,
            "decision_code": decision_code,
            "classification_features_id": feature_hash,
            "ledger_entry_id": decision_entry.get("entry_id"),
            "prev_hash": decision_entry.get("prev_hash"),
            "entry_hash": decision_entry.get("entry_hash"),
        }

        response_event = {
            "event_id": event_id,
            "status": STATUS_PROCESSED,
            "band": band,
            "decision_code": decision_code,
            "http_status": http_status,
            "evidence_pointers": evidence_pointers,
        }

        if band == BAND_LOW:
            response_event["envelope"] = {
                "must_store_minimal_envelope": True,
                "must_not_include_free_text_summary": True,
            }

        per_event.append(response_event)

    stage1_ms = int((time.time() - start_time) * 1000)
    counters["stage1_ms"] = stage1_ms

    processed_count = sum(1 for e in per_event if e.get("status") == STATUS_PROCESSED)
    replayed_count = counters["replayed_count"]
    conflict_count = counters["conflict_count"]
    failed_count = counters["failed_count"]

    counters["processed_count"] = processed_count
    counters["replayed_count"] = replayed_count
    counters["conflict_count"] = conflict_count
    counters["failed_count"] = failed_count

    ledger.append(
        "BATCH_COMPLETED",
        {
            "batch_id": batch_id,
            "processed_count": processed_count,
            "replayed_count": replayed_count,
            "conflict_count": conflict_count,
            "failed_count": failed_count,
            "counters": counters,
            "elapsed_ms": stage1_ms,
        },
    )

    return {
        "batch_id": batch_id,
        "processed_count": processed_count,
        "replayed_count": replayed_count,
        "conflict_count": conflict_count,
        "failed_count": failed_count,
        "per_event": per_event,
        "batch": counters,
        "profile_parameters": profile or {},
    }
