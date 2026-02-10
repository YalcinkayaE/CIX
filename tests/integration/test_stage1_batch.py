from __future__ import annotations

import pytest

from tests.conftest import (
    call_classify_batch,
    get_classify_batch_fn,
    load_stage1_module,
    normalize_batch,
    normalize_per_event,
)


def test_batch_partial_success_invalid_schema(temp_ledger):
    stage1 = load_stage1_module()
    fn = get_classify_batch_fn(stage1)

    events = [
        {
            "source_id": "siem-A",
            "event_id": "evt-valid-1",
            "source_timestamp": "2026-02-06T10:00:00Z",
            "raw_payload": {"event": {"kind": "alert"}},
        },
        {
            # invalid: missing source_id/event_id
            "source_timestamp": "2026-02-06T10:00:01Z",
            "raw_payload": {"event": {"kind": "alert"}},
        },
    ]

    result = call_classify_batch(fn, events, ledger=temp_ledger)
    per_event = normalize_per_event(result)
    batch = normalize_batch(result)

    statuses = {e.get("status") for e in per_event}
    assert "FAILED" in statuses
    assert "PROCESSED" in statuses or "REPLAYED" in statuses

    assert "failed_count" in batch
    assert batch["failed_count"] >= 1
    assert "processed_count" in batch


def test_batch_counters_include_stage1_ms(temp_ledger):
    stage1 = load_stage1_module()
    fn = get_classify_batch_fn(stage1)

    events = [
        {
            "source_id": "siem-A",
            "event_id": "evt-valid-2",
            "source_timestamp": "2026-02-06T10:02:00Z",
            "raw_payload": {"event": {"kind": "alert"}},
        }
    ]

    result = call_classify_batch(fn, events, ledger=temp_ledger)
    batch = normalize_batch(result)

    assert "stage1_ms" in batch
