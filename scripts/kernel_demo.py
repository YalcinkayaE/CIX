from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Dict, List


def _kernel_root() -> Path:
    env_path = os.getenv("AXODEN_KERNEL_PATH")
    if env_path:
        return Path(env_path).expanduser().resolve()
    return (Path(__file__).resolve().parents[2] / "axoden-kernel").resolve()


def _ensure_kernel_on_path() -> Path:
    root = _kernel_root()
    if not root.exists():
        raise FileNotFoundError(
            f"AxoDen kernel not found at {root}. Set AXODEN_KERNEL_PATH to override."
        )
    sys.path.insert(0, str(root))
    return root


def _sha256_hex(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _content_hash(alert: Dict) -> str:
    return _sha256_hex(json.dumps(alert, sort_keys=True, separators=(",", ":")))


def _build_ingest_evidence(
    alert: Dict,
    registry_commit: str,
    profile_id: str,
) -> Dict:
    return {
        "evidence_id": "",
        "schema_version": "0.2.0",
        "domain": "cix",
        "kind": "ingest_event",
        "timestamp": alert["timestamp"],
        "source": {
            "system": "cix-alerts-demo",
            "sensor": alert.get("source", "soc"),
            "feed_id": alert.get("feed_id", "demo"),
        },
        "inputs": [
            {
                "ref_type": "sha256",
                "ref": alert.get("alert_id", "unknown"),
                "content_hash": _content_hash(alert),
            }
        ],
        "features_summary": {
            "entropy": alert.get("entropy", 1.0),
            "budget_ratio": alert.get("budget_ratio", 0.1),
            "shift": alert.get("shift", 0.0),
            "integrity_fail": alert.get("integrity_fail", False),
        },
        "profile_id": profile_id,
        "registry_commit": registry_commit,
        "prev_hash": "",
    }


def _build_decision_evidence(
    alert: Dict,
    registry_commit: str,
    profile_id: str,
    decision: Dict,
) -> Dict:
    return {
        "evidence_id": "",
        "schema_version": "0.2.0",
        "domain": "cix",
        "kind": "decision",
        "timestamp": alert["timestamp"],
        "source": {
            "system": "cix-alerts-demo",
            "sensor": alert.get("source", "soc"),
            "feed_id": alert.get("feed_id", "demo"),
        },
        "inputs": [],
        "features_summary": {},
        "decision": decision,
        "profile_id": profile_id,
        "registry_commit": registry_commit,
        "prev_hash": "",
    }


def _build_metric_evidence(
    alert: Dict,
    registry_commit: str,
    profile_id: str,
    metric_id: str,
    value: float,
) -> Dict:
    return {
        "evidence_id": "",
        "schema_version": "0.2.0",
        "domain": "cix",
        "kind": "metric",
        "timestamp": alert["timestamp"],
        "source": {
            "system": "cix-alerts-demo",
            "sensor": alert.get("source", "soc"),
            "feed_id": alert.get("feed_id", "demo"),
        },
        "inputs": [],
        "features_summary": {
            "metric_id": metric_id,
            "value": value,
            "sampling_interval_sec": 60,
        },
        "profile_id": profile_id,
        "registry_commit": registry_commit,
        "prev_hash": "",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="CIX Alerts -> AxoDen Kernel demo")
    parser.add_argument(
        "--input",
        default="samples/cix_kernel_demo_alerts.json",
        help="Path to demo alert JSON list",
    )
    parser.add_argument(
        "--ledger",
        default="data/kernel_ledger.jsonl",
        help="Ledger JSONL output path",
    )
    parser.add_argument("--reset", action="store_true", help="Reset ledger before run")
    parser.add_argument("--profile", default="axoden-cix-1-v0.2.0", help="Registry profile id")
    args = parser.parse_args()

    kernel_root = _ensure_kernel_on_path()

    from sdk import ARVInput, EvidenceLedger, Registry, decide  # type: ignore

    registry = Registry.load(kernel_root / "registry")
    registry_commit = registry.registry_commit()

    ledger_path = Path(args.ledger)
    if args.reset and ledger_path.exists():
        ledger_path.unlink()

    ledger = EvidenceLedger(ledger_path)

    input_path = Path(args.input)
    alerts: List[Dict] = json.loads(input_path.read_text(encoding="utf-8"))

    current_state = "VSR.NOMINAL"

    for alert in alerts:
        ingest = _build_ingest_evidence(alert, registry_commit, args.profile)
        ingest_id = ledger.append(ingest)

        arv_input = ARVInput(
            phi_curr=1,
            phi_prev=1,
            D_plus=0.0,
            dist_2=1.0,
        )
        decision = decide(
            arv_input,
            current_state,
            registry,
            args.profile,
            strict=True,
        )

        decision_payload = {
            "action_id": decision.action_id,
            "reason_code": decision.reason_code,
        }
        decision_evidence = _build_decision_evidence(
            alert, registry_commit, args.profile, decision_payload
        )
        ledger.append(decision_evidence)

        metric_evidence = _build_metric_evidence(
            alert,
            registry_commit,
            args.profile,
            "MQ.M1",
            float(alert.get("budget_ratio", 0.0)),
        )
        ledger.append(metric_evidence)

        current_state = decision.next_state

        print(
            f"alert={alert.get('alert_id')} ingest_id={ingest_id} action={decision.action_id} state={current_state}"
        )

    print(f"Ledger written to {ledger_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
