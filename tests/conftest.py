from __future__ import annotations

import importlib
import inspect
import json
import sys
from pathlib import Path
from typing import Any, Dict

import pytest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from src.kernel.ledger import Ledger

DOCS_DIR = ROOT / "docs"
VECTORS_PATH = DOCS_DIR / "test_vectors.json"


@pytest.fixture(scope="session")
def test_vectors() -> Dict[str, Any]:
    return json.loads(VECTORS_PATH.read_text())


@pytest.fixture(scope="session")
def get_vector(test_vectors):
    def _get(vector_id: str) -> Dict[str, Any]:
        for v in test_vectors.get("vectors", []):
            if v.get("id") == vector_id:
                return v
        pytest.fail(f"Test vector not found: {vector_id}")
    return _get


@pytest.fixture
def temp_ledger(tmp_path):
    return Ledger(str(tmp_path / "ledger.jsonl"))


def load_stage1_module():
    candidates = ["src.kernel.stage1", "src.stage1"]
    for name in candidates:
        try:
            return importlib.import_module(name)
        except ModuleNotFoundError:
            continue
    pytest.fail(
        "Stage 1 module not found. Expected one of: " + ", ".join(candidates)
    )


def get_classify_batch_fn(stage1_module):
    for name in ("classify_batch", "ingest_classify", "stage1_classify_batch"):
        fn = getattr(stage1_module, name, None)
        if fn:
            return fn
    pytest.fail(
        "Stage 1 classify function not found. Expected one of: "
        "classify_batch, ingest_classify, stage1_classify_batch."
    )


def call_classify_batch(fn, events, profile=None, ledger=None, precondition=None):
    sig = inspect.signature(fn)
    kwargs = {}
    for param in sig.parameters:
        if param in ("events", "ingest_events", "batch"):
            kwargs[param] = events
        elif param in ("profile", "profile_parameters", "conformance_profile"):
            kwargs[param] = profile
        elif param in ("ledger", "ledger_sink"):
            kwargs[param] = ledger
        elif param in ("precondition", "already_ingested", "ingest_state"):
            kwargs[param] = precondition
    if kwargs:
        return fn(**kwargs)
    return fn(events)


def normalize_per_event(result: Dict[str, Any]):
    per_event = result.get("per_event") or result.get("per_event_results")
    if per_event is None:
        pytest.fail("Result missing per-event results: expected per_event or per_event_results")
    return per_event


def normalize_batch(result: Dict[str, Any]):
    batch = result.get("batch") or result.get("counters") or result.get("batch_counters")
    if batch is None:
        pytest.fail("Result missing batch counters: expected batch/counters/batch_counters")
    return batch


def find_event(per_event, event_id: str) -> Dict[str, Any]:
    for item in per_event:
        if item.get("event_id") == event_id:
            return item
    pytest.fail(f"Event not found in result: {event_id}")


def has_required_evidence_pointers(event: Dict[str, Any]) -> bool:
    if event.get("required_evidence_pointers_present") is True:
        return True
    evidence = event.get("evidence_pointers") or event.get("evidence") or {}
    required = {
        "source_id",
        "event_id",
        "ingest_timestamp",
        "raw_payload_hash",
        "decision_code",
        "ledger_entry_id",
        "prev_hash",
        "entry_hash",
    }
    keys = set(evidence.keys())
    if not required.issubset(keys):
        return False
    return "classification_features_id" in keys or "feature_hash" in keys
