from __future__ import annotations

import math
import re
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .hashing import canonical_json, hash_payload, sha256_hex
from .ledger import Ledger
from ..ingest.siem_formats import parse_cef, parse_leef, parse_syslog

ENTROPY_FLOOR_DEFAULT = 2.0
ENTROPY_CEILING = 5.2831

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

_IP_RE = re.compile(
    r"\\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\b"
)
_DOMAIN_RE = re.compile(r"\\b(?:[a-zA-Z0-9-]{1,63}\\.)+(?:[a-zA-Z]{2,63})\\b")
_HEX_RE = re.compile(r"\\b[a-fA-F0-9]{16,}\\b")
_NUM_RE = re.compile(r"\\b\\d+\\b")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _template_text(s: str) -> str:
    s = (s or "").lower()
    s = _IP_RE.sub("<ip>", s)
    s = _DOMAIN_RE.sub("<domain>", s)
    s = _HEX_RE.sub("<hex>", s)
    s = _NUM_RE.sub("<num>", s)
    return s


def _bucket_port(port: object) -> str:
    try:
        p = int(str(port))
    except Exception:
        return "port:unknown"
    common = {53, 80, 88, 135, 389, 443, 445, 636, 3389}
    return f"port:{p}" if p in common else "port:other"


def _extract_payload_text(event: Dict[str, Any]) -> str:
    if not isinstance(event, dict):
        return str(event)

    lower_map = {str(k).lower(): v for k, v in event.items()}

    def pick(*keys: str) -> str:
        for key in keys:
            v = lower_map.get(key.lower())
            if v is None:
                continue
            s = str(v).strip()
            if s:
                return s
        return ""

    parts: list[str] = []
    for text_field in (
        pick("command_line", "commandline"),
        pick("image", "process_name", "process"),
        pick("message", "msg"),
        pick("scriptblocktext", "powershell_script", "payload"),
        pick("url", "uri", "request"),
    ):
        if text_field:
            parts.append(text_field)

    return " | ".join(parts) if parts else canonical_json(event)


def _project_event(obj: object) -> str:
    if not isinstance(obj, dict):
        return _template_text(str(obj))

    obj_lc = {str(k).lower(): v for k, v in obj.items()}

    keep_keys = [
        "event_id",
        "eventid",
        "eventcode",
        "provider",
        "source",
        "stream",
        "event_type",
        "action",
        "status",
        "outcome",
        "severity",
        "technique",
        "technique_id",
        "rule_id",
        "process",
        "process_name",
        "image",
        "command_line",
        "commandline",
        "msg",
        "message",
        "user",
        "account",
        "accountname",
        "group",
        "src_ip",
        "dst_ip",
        "ip",
        "client_ip",
        "remote_ip",
        "sourceip",
        "destinationip",
        "sourceaddress",
        "destaddress",
        "src_port",
        "dst_port",
        "port",
        "sourceport",
        "destport",
    ]

    parts: list[str] = []
    for k in keep_keys:
        if k not in obj_lc:
            continue
        v = obj_lc.get(k)
        if v is None:
            continue
        if k in {"msg", "message"}:
            head = str(v).splitlines()[0] if str(v) else ""
            if head:
                parts.append(f"{k}={_template_text(head[:200])}")
            continue
        if k in {
            "src_ip",
            "dst_ip",
            "ip",
            "client_ip",
            "remote_ip",
            "sourceip",
            "destinationip",
            "sourceaddress",
            "destaddress",
        }:
            parts.append(f"{k}=<ip>")
            continue
        if k in {"src_port", "dst_port", "port", "sourceport", "destport"}:
            parts.append(_bucket_port(v))
            continue
        parts.append(f"{k}={_template_text(str(v))}")
    return "|".join(parts) if parts else _template_text(canonical_json(obj))


def _contains_suspicious_markers(text: str) -> bool:
    s = (text or "").lower()
    needles = (
        "mimikatz",
        "lsass",
        "dcsync",
        "domain admins",
        "krbtgt",
        "psexec",
        "wmic",
        "regsvr32",
        "rundll32",
        "certutil",
        "t1003",
        "t1059",
        "t1053",
        "4662",
        "4698",
        "4104",
        "ransom",
        "encrypt",
        "mass rename",
        "prompt injection",
        "ignore all previous",
        "twin-liar",
        "twin liar",
        "flow_anomaly",
        "process_event",
        "unrecognized protocol",
        "tls-z",
        "zero-latency-draft",
    )
    return any(n in s for n in needles)


def _miller_madow_entropy_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = sum(counts.values())
    if n <= 0:
        return 0.0
    d = len(counts)
    probs = [c / n for c in counts.values()]
    h_raw = -sum(p * math.log2(p) for p in probs)
    correction = (d - 1) / (2 * n) if n > 0 else 0.0
    return float(h_raw + correction)


def _resolve_thresholds(profile: Optional[Dict[str, Any]]) -> Dict[str, float]:
    profile = profile or {}
    thresholds = (
        profile.get("ingestion_thresholds")
        or profile.get("parameters", {}).get("ingestion_thresholds")
        or {}
    )
    return {
        "entropy_ceiling": float(
            thresholds.get("entropy_ceiling")
            or thresholds.get("vacuum_entropy_max")
            or ENTROPY_CEILING
        ),
        "entropy_floor": float(
            thresholds.get("entropy_floor")
            or thresholds.get("low_entropy_max")
            or ENTROPY_FLOOR_DEFAULT
        ),
    }


def _parse_if_needed(event: Dict[str, Any]) -> Dict[str, Any]:
    fmt = (event.get("format") or "").lower()
    raw_payload = event.get("raw_payload")
    raw_event = event.get("raw_event")
    if isinstance(raw_payload, str) and fmt in {"cef", "leef", "syslog"}:
        parsed = _parse_by_format(fmt, raw_payload)
        event["parsed_payload"] = parsed
        if not event.get("source_timestamp") and parsed.get("timestamp"):
            event["source_timestamp"] = parsed.get("timestamp")
    elif isinstance(raw_event, str) and fmt in {"cef", "leef", "syslog"}:
        parsed = _parse_by_format(fmt, raw_event)
        event["raw_payload"] = raw_event
        event["parsed_payload"] = parsed
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
    effective_profile = dict(profile or {})
    ingest_params = dict(
        (profile or {}).get("ingestion_thresholds")
        or (profile or {}).get("parameters", {}).get("ingestion_thresholds")
        or {}
    )
    ingest_params["entropy_ceiling"] = thresholds["entropy_ceiling"]
    ingest_params["entropy_floor"] = thresholds["entropy_floor"]
    effective_profile["ingestion_thresholds"] = ingest_params

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
            "profile_parameters": effective_profile,
        },
    )

    prepared_events: List[Dict[str, Any]] = [_parse_if_needed(dict(e)) for e in events]
    n = max(1, len(prepared_events))
    projections: List[str] = []
    for evt in prepared_events:
        payload_for_projection = evt.get("parsed_payload") or evt.get("raw_payload")
        projection_obj: Dict[str, Any] = {}
        if isinstance(payload_for_projection, dict):
            projection_obj.update(payload_for_projection)
        projections.append(_project_event(projection_obj if projection_obj else payload_for_projection))
    freq = Counter(projections)

    for event, proj in zip(prepared_events, projections):
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

        payload_for_analysis = event.get("parsed_payload") or raw_payload

        if payload_for_analysis is None:
            payload_for_analysis = raw_payload_ref

        p = max(1.0 / n, float(freq.get(proj, 1)) / float(n))
        entropy_projected = -math.log2(p)

        payload_text = _extract_payload_text(
            payload_for_analysis if isinstance(payload_for_analysis, dict) else {"payload": payload_for_analysis}
        )
        raw_text = _template_text(payload_text)
        raw_bytes = raw_text.encode("utf-8", errors="ignore")
        entropy_raw = _miller_madow_entropy_bytes(raw_bytes)

        suspicious = _contains_suspicious_markers(payload_text)

        band = BAND_MIMIC
        decision_code = DECISION_MIMIC
        http_status = HTTP_OK
        reason = "Mimic Pattern: Requires triage"
        if entropy_raw > thresholds["entropy_ceiling"]:
            band = BAND_VACUUM
            decision_code = DECISION_VACUUM
            http_status = HTTP_DROP
            reason = "Thermodynamic Limit Exceeded (High Randomness)"
        elif entropy_projected < thresholds["entropy_floor"] and not suspicious:
            band = BAND_LOW
            decision_code = DECISION_LOW
            http_status = HTTP_OK
            reason = "Deterministic Pattern / Background noise"

        features = {
            "entropy_raw": round(float(entropy_raw), 4),
            "entropy_projected": round(float(entropy_projected), 4),
            "entropy_ceiling": thresholds["entropy_ceiling"],
            "entropy_floor": thresholds["entropy_floor"],
            "projection": proj,
            "projection_count": int(freq.get(proj, 1)),
            "reason": reason,
        }
        feature_hash = sha256_hex(canonical_json(features))

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
            "entropy_raw": features["entropy_raw"],
            "entropy_projected": features["entropy_projected"],
            "entropy_ceiling": features["entropy_ceiling"],
            "entropy_floor": features["entropy_floor"],
            "projection": features["projection"],
            "projection_count": features["projection_count"],
            "reason": features["reason"],
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
            "entropy_raw": features["entropy_raw"],
            "entropy_projected": features["entropy_projected"],
            "entropy_ceiling": features["entropy_ceiling"],
            "entropy_floor": features["entropy_floor"],
            "projection": features["projection"],
            "projection_count": features["projection_count"],
            "reason": features["reason"],
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
        "profile_parameters": effective_profile,
    }
