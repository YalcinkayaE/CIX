# Stage 1 Admissibility Blueprint
Version: 0.1
Scope: Backend/API-only implementation for Stage 1 (Admissibility filtering / Semantic Firewall).
Authority: This blueprint is normative for Stage 1 behavior and must align with:
- axoden_soc_kernel_math_contract.md
- axoden_soc_conformance_profile.yaml

## Objective
Provide deterministic, ledger-first admissibility filtering that tri-bands raw ingest events into VACUUM, LOW_ENTROPY, or MIMIC_SCOPED, with explicit idempotency handling, audit-ready evidence pointers, and batch-safe responses.

## Non-goals
- No UI.
- No SIEM or SOAR replacement claims; this is middleware.
- No authoritative LLM outputs; Stage 1 must be fully deterministic and grounded.

## Entry Criteria
- Input is IngestEvent or IngestEvent[].
- Each IngestEvent must include:
  - source_id
  - event_id
  - source_timestamp (RFC3339 or epoch)
  - raw_payload (object) or raw_payload_ref (pointer)
  - raw_payload_hash (sha256) or the fields necessary to compute it

## Exit Criteria
- Every event produces a BandDecision or a conflict decision.
- Every decision is ledgered with required evidence pointers.
- The response includes mandatory counters and per-event status.

## API Surface
- POST /api/v1/ingest/classify executes Stage 1 only.
- POST /assessments includes Stage 1 as the first step, but Stage 1 behavior must remain identical.

## Determinism Requirements
- Identical inputs and parameters must produce identical band decisions, decision codes, and responses.
- Classification feature computation must be deterministic and recorded by feature hash or feature id.
- Canonicalization for hashes must use JCS as defined in the conformance profile.

## Idempotency and Conflict Handling
Idempotency key:
- idempotency_key = (source_id, event_id, raw_payload_hash)

On duplicate key:
- Return original BandDecision without re-decision.
- Write ledger entry with decision_code = IDEMPOTENT_REPLAY.
- Reference the original ledger_entry_id.

On event_id hash mismatch:
- If (source_id, event_id) matches but raw_payload_hash differs, return HTTP 409 (FORK/CONFLICT).
- Write ledger entry with decision_code = EVENT_ID_CONFLICT and store both hashes.

## Classification and Outcomes
Band mapping is normative:
- VACUUM -> HTTP 418 (DROP), decision_code = VACUUM_DROP
- LOW_ENTROPY -> HTTP 200, decision_code = LOW_ENTROPY_SUPPRESS
- MIMIC_SCOPED -> HTTP 200, decision_code = MIMIC_SCOPED_PASS

Terminology constraint:
- Use "pre-triage containment" or "pre-analysis containment" in all narrative descriptions.
- Do not use "pre-execution prevention".

## LOW_ENTROPY Handling (SUPPRESS/COMPRESS)
LOW_ENTROPY events must not proceed to Stage 2. Store a minimal envelope only.

Minimal envelope fields:
- source_id
- event_id
- ingest_timestamp
- raw_payload_hash
- band = LOW_ENTROPY
- decision_code = LOW_ENTROPY_SUPPRESS
- classification_features_id or feature_hash
- feature_summary_ref
- raw_payload_ref (optional, subject to retention policy)

Optional deterministic compression payload:
- field_presence_bitmap
- normalized_entities
- numeric_field_stats

No free-form summaries are permitted.

## Evidence Pointers (Minimum Required)
Every decision must include:
- source_id
- event_id
- ingest_timestamp (server-side)
- raw_payload_hash (sha256)
- classification_features_id or feature_hash
- decision_code
- ledger_entry_id, prev_hash, entry_hash

## Batch Atomicity
Partial success is allowed but must be explicit and ledgered.

Batch response must include:
- batch_id
- processed_count
- replayed_count
- conflict_count
- failed_count
- per_event_results with status in {PROCESSED, REPLAYED, CONFLICT, FAILED}
- counters (see Metrics)

Failure behavior:
- Invalid schema -> mark event FAILED with error_code = INVALID_SCHEMA and continue.
- Ledger unavailable -> fail batch with HTTP 503 and record failure reason if possible.

## Metrics (Required Counters)
Each batch response and terminal ledger entry must include:
- vacuum_count
- low_entropy_count
- mimic_scoped_count
- drop_count
- suppress_count
- pass_count
- replayed_count
- conflict_count
- failed_count
- stage1_ms

## Ledger Entries (Minimum)
- BATCH_RECEIVED
- Per-event decision entry for each event
- IDEMPOTENT_REPLAY for duplicates
- EVENT_ID_CONFLICT for hash mismatch
- BATCH_COMPLETED with counters and elapsed time

## Storage and Retention
- Raw payload retention follows conformance profile settings.
- LOW_ENTROPY stores minimal envelope only; no graph edges or enrichment.

## Acceptance Tests
The following vectors must pass as written:
- docs/test_vectors.json

## Implementation Notes
- Use a pure function for band classification and store its inputs in the feature summary.
- Ensure the idempotency check is ledger-backed to avoid non-deterministic replay.
- Always record the profile parameters used for classification per batch response and ledger entry.
