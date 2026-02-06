from __future__ import annotations

import pytest

from tests.conftest import (
    call_classify_batch,
    find_event,
    get_classify_batch_fn,
    load_stage1_module,
    normalize_batch,
    normalize_per_event,
    has_required_evidence_pointers,
)


def test_tv01_vacuum_drop(get_vector, profile_thresholds):
    vector = get_vector("tv01_stage1_vacuum_drop_418")
    stage1 = load_stage1_module()
    fn = get_classify_batch_fn(stage1)

    result = call_classify_batch(
        fn,
        vector["input"]["events"],
        profile=profile_thresholds,
        precondition=vector.get("precondition"),
    )
    per_event = normalize_per_event(result)
    batch = normalize_batch(result)

    expected = vector["expected"]["per_event"][0]
    event = find_event(per_event, expected["event_id"])

    assert event.get("status") == expected["status"]
    assert event.get("band") == expected["band"]
    assert event.get("decision_code") == expected["decision_code"]
    assert event.get("http_status") == expected["http_status"]
    assert has_required_evidence_pointers(event)

    assert batch.get("vacuum_count") == vector["expected"]["batch"]["vacuum_count"]
    assert batch.get("drop_count") == vector["expected"]["batch"]["drop_count"]


def test_tv02_low_entropy_envelope(get_vector, profile_thresholds):
    vector = get_vector("tv02_stage1_low_entropy_suppress_envelope")
    stage1 = load_stage1_module()
    fn = get_classify_batch_fn(stage1)

    result = call_classify_batch(
        fn,
        vector["input"]["events"],
        profile=profile_thresholds,
        precondition=vector.get("precondition"),
    )
    per_event = normalize_per_event(result)
    batch = normalize_batch(result)

    expected = vector["expected"]["per_event"][0]
    event = find_event(per_event, expected["event_id"])

    assert event.get("status") == expected["status"]
    assert event.get("band") == expected["band"]
    assert event.get("decision_code") == expected["decision_code"]
    assert event.get("http_status") == expected["http_status"]

    envelope = event.get("envelope")
    assert envelope is not None, "LOW_ENTROPY must include minimal envelope"
    assert envelope.get("must_store_minimal_envelope", True) is True
    assert envelope.get("must_not_include_free_text_summary", True) is True

    assert batch.get("low_entropy_count") == vector["expected"]["batch"]["low_entropy_count"]
    assert batch.get("suppress_count") == vector["expected"]["batch"]["suppress_count"]


def test_tv03_idempotent_replay(get_vector, profile_thresholds):
    vector = get_vector("tv03_idempotency_replay_no_redecision")
    stage1 = load_stage1_module()
    fn = get_classify_batch_fn(stage1)

    result = call_classify_batch(
        fn,
        vector["input"]["events"],
        profile=profile_thresholds,
        precondition=vector.get("precondition"),
    )
    per_event = normalize_per_event(result)
    batch = normalize_batch(result)

    expected = vector["expected"]["per_event"][0]
    event = find_event(per_event, expected["event_id"])

    assert event.get("status") == expected["status"]
    ledger = event.get("ledger") or {}
    assert ledger.get("replay_entry_decision_code") == expected["ledger"]["replay_entry_decision_code"]

    assert batch.get("replayed_count") == vector["expected"]["batch"]["replayed_count"]


def test_tv04_event_id_conflict(get_vector, profile_thresholds):
    vector = get_vector("tv04_event_id_hash_mismatch_conflict_409")
    stage1 = load_stage1_module()
    fn = get_classify_batch_fn(stage1)

    result = call_classify_batch(
        fn,
        vector["input"]["events"],
        profile=profile_thresholds,
        precondition=vector.get("precondition"),
    )
    per_event = normalize_per_event(result)
    batch = normalize_batch(result)

    expected = vector["expected"]["per_event"][0]
    event = find_event(per_event, expected["event_id"])

    assert event.get("status") == expected["status"]
    assert event.get("http_status") == expected["http_status"]
    ledger = event.get("ledger") or {}
    assert ledger.get("conflict_entry_decision_code") == expected["ledger"]["conflict_entry_decision_code"]

    assert batch.get("conflict_count") == vector["expected"]["batch"]["conflict_count"]
