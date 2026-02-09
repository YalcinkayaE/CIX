from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.ingest.siem_formats import parse_cef, parse_leef, parse_syslog
from src.kernel.stage1 import _extract_payload_text, _miller_madow_entropy_bytes, _template_text


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _kernel_root() -> Path:
    env_path = os.getenv("AXODEN_KERNEL_PATH")
    if env_path:
        return Path(env_path).expanduser().resolve()
    return (Path(__file__).resolve().parents[3] / "axoden-kernel").resolve()


def _ensure_kernel_on_path() -> Path:
    root = _kernel_root()
    if not root.exists():
        raise FileNotFoundError(
            f"AxoDen kernel not found at {root}. Set AXODEN_KERNEL_PATH to override."
        )
    sys.path.insert(0, str(root))
    return root


def _content_hash(payload: Any) -> str:
    try:
        dumped = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    except Exception:
        dumped = str(payload)
    return hashlib.sha256(dumped.encode("utf-8")).hexdigest()


def _parse_if_needed(event: Dict[str, Any]) -> Tuple[Dict[str, Any], Any]:
    fmt = (event.get("format") or "").lower()
    raw_payload = event.get("raw_payload")
    raw_event = event.get("raw_event")

    if isinstance(raw_payload, str) and fmt in {"cef", "leef", "syslog"}:
        parsed = _parse_by_format(fmt, raw_payload)
        return event, parsed
    if isinstance(raw_event, str) and fmt in {"cef", "leef", "syslog"}:
        parsed = _parse_by_format(fmt, raw_event)
        return event, parsed
    return event, raw_payload


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


def _normalize_graph_raw(event: Dict[str, Any], payload: Any) -> Dict[str, Any]:
    if "eventId" in event and "data" in event:
        return event
    return {
        "eventId": event.get("event_id") or event.get("eventId") or event.get("id") or "unknown",
        "data": payload if isinstance(payload, dict) else {"payload": payload},
    }


def _compute_entropy(payload: Any) -> float:
    payload_for_analysis = payload
    if not isinstance(payload_for_analysis, dict):
        payload_for_analysis = {"payload": payload_for_analysis}
    payload_text = _extract_payload_text(payload_for_analysis)
    raw_text = _template_text(payload_text)
    raw_bytes = raw_text.encode("utf-8", errors="ignore")
    return float(_miller_madow_entropy_bytes(raw_bytes))


@dataclass
class GateResult:
    raw_alert: Dict[str, Any]
    graph_raw: Dict[str, Any]
    action_id: str
    reason_codes: List[str]
    ingest_evidence: Dict[str, Any]
    decision_evidence: Dict[str, Any]


class KernelGate:
    def __init__(
        self,
        profile_id: str = "profile.cix",
        ledger_path: str = "data/kernel_ledger.jsonl",
        enable_ledger: bool = True,
    ) -> None:
        kernel_root = _ensure_kernel_on_path()
        from sdk import EvidenceLedger, Registry, decide  # type: ignore

        self._Registry = Registry
        self._EvidenceLedger = EvidenceLedger
        self._decide = decide
        self._kernel_root = kernel_root
        self.profile_id = profile_id
        self.registry = Registry.load(kernel_root / "registry")
        self.registry_commit = self.registry.registry_commit()
        self.ledger = EvidenceLedger(Path(ledger_path)) if enable_ledger else None

    def evaluate(self, raw_alert: Dict[str, Any]) -> GateResult:
        event, payload = _parse_if_needed(dict(raw_alert))
        graph_raw = _normalize_graph_raw(event, payload)

        timestamp = (
            raw_alert.get("timestamp")
            or raw_alert.get("source_timestamp")
            or event.get("source_timestamp")
            or _utc_now()
        )
        source_id = raw_alert.get("source_id") or raw_alert.get("source") or "unknown"
        event_id = graph_raw.get("eventId", "unknown")
        entropy = _compute_entropy(payload)

        ingest_evidence = {
            "evidence_id": "",
            "schema_version": "0.2.0",
            "domain": "cix",
            "kind": "ingest_event",
            "timestamp": timestamp,
            "source": {
                "system": "cix-alerts",
                "sensor": source_id,
                "feed_id": raw_alert.get("feed_id", "default"),
            },
            "inputs": [
                {
                    "ref_type": "sha256",
                    "ref": str(event_id),
                    "content_hash": _content_hash(payload),
                }
            ],
            "features_summary": {
                "entropy": entropy,
                "budget_ratio": float(raw_alert.get("budget_ratio", 0.0)),
                "shift": float(raw_alert.get("shift", 0.0)),
                "integrity_fail": bool(raw_alert.get("integrity_fail", False)),
            },
            "profile_id": self.profile_id,
            "registry_commit": self.registry_commit,
            "prev_hash": "",
        }

        decision = self._decide(
            ingest_evidence,
            "VSR.NOMINAL",
            self.registry,
            self.profile_id,
            repeated_abstain_count=0,
            strict=True,
            expected_registry_commit=self.registry_commit,
        )

        decision_payload = {
            "action_id": decision.action_id,
            "reason_codes": decision.reason_codes,
        }
        decision_evidence = {
            "evidence_id": "",
            "schema_version": "0.2.0",
            "domain": "cix",
            "kind": "decision",
            "timestamp": timestamp,
            "source": {
                "system": "cix-alerts",
                "sensor": source_id,
                "feed_id": raw_alert.get("feed_id", "default"),
            },
            "inputs": [],
            "features_summary": {},
            "decision": decision_payload,
            "profile_id": self.profile_id,
            "registry_commit": self.registry_commit,
            "prev_hash": "",
        }

        return GateResult(
            raw_alert=event,
            graph_raw=graph_raw,
            action_id=decision.action_id,
            reason_codes=decision.reason_codes,
            ingest_evidence=ingest_evidence,
            decision_evidence=decision_evidence,
        )

    def append_ledger(self, gate_result: GateResult) -> None:
        if not self.ledger:
            return
        self.ledger.append(gate_result.ingest_evidence)
        self.ledger.append(gate_result.decision_evidence)
