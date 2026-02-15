---
name: api-only-service-design
description: Design API-only backend services for CIX Alerts/AxoDen pipelines, including endpoints, data models, job semantics, queues, deployment constraints, observability, and test plans. Use when asked to define, review, or enforce API service specs for ingestion, filtering, deduplication, triage, assessment, recommendation, or ledger/audit stages.
---

# Api-Only Service Design

## Overview
Use this skill to produce deterministic, audit-ready API-only service designs for the CIX Alerts pipeline. Enforce explicit schemas, evidence linkage, and replay semantics across every stage.

## Quick Start
1. Read the project references below when the service touches Stage 1 admissibility, ARV/EFI/VSR gates, or ledger behavior.
2. Collect required inputs (sources, SLOs, tenancy, deployment constraints).
3. Fill the skeleton sections in order, keeping every rule explicit and machine-auditable.
4. Produce the required artifacts list (OpenAPI, JSON Schemas, state machines, runbooks, test plan).
5. Validate the design against the Hard Rules section.

## Project References (Read When Relevant)
- `/Users/erkanyalcinkaya/projects/cix-alerts/docs/stage1_admissibility_blueprint.md`
- `/Users/erkanyalcinkaya/projects/cix-alerts/docs/AxoDen_Canonical_Blueprint.md`
- `/Users/erkanyalcinkaya/projects/cix-alerts/docs/axoden_soc_conformance_profile.yaml`
- `/Users/erkanyalcinkaya/projects/cix-alerts/docs/axoden_soc_kernel_math_contract.md`

## Required Inputs
- Service goal and scope boundary (which stage(s) of the pipeline).
- Threat sources and accepted formats (STIX/TAXII/syslog/custom).
- Tenancy model and data isolation expectations.
- Latency/SLO targets and throughput expectations.
- Deployment constraints (Docker, queues, storage, secrets, regions).
- External dependencies (threat intel APIs, graph store, ledger store).

## Core Checklist And Skeleton (Use This Structure)

### 1) Scope And Non-Goals
- State the purpose in one paragraph.
- Explicitly list non-goals.
- Enforce: no UI flows, no vague endpoints, no hidden state transitions.

### 2) Canonical Domain Model (Make Explicit)
Define stable entities and their lifecycle at minimum:
- IngestEvent: raw input item (alerts/logs/IOCs).
- EvidenceObject (EO): normalized, traceable, hash-addressed evidence unit.
- ThermoFilterDecision: accept/reject plus scores, metrics, reasons.
- DedupCluster: cluster id, members, similarity keys used.
- TriageCase: agent work unit (EO set plus context snapshot).
- Assessment: structured findings (risk, confidence, control mapping).
- Recommendation: actions (contain/eradicate/monitor) plus prerequisites.
- Run/Job: async processing unit.
- LedgerEntry: append-only audit record linked to EO/Run.

For each entity, define:
- ID scheme (ULID/UUIDv7) plus content hash (sha256 canonical JSON) where appropriate.
- Immutability rules (EO immutable; recommendations versioned).
- State machine (PENDING -> RUNNING -> SUCCEEDED|FAILED|CANCELLED).

### 3) API Contract Conventions (Hard Requirements)
Idempotency
- Require for ingestion and job creation.
- Standard header: `Idempotency-Key`.
- Replay semantics: same key plus same payload yields same result; same key plus different payload yields HTTP 409.

Versioning
- Use URL or header versioning: `/v1/...`.
- Breaking changes only in new major version.

Error Model
- Single structured error format with:
- code (stable enum)
- message
- details (field-level)
- trace_id

Pagination, Filtering, Sorting
- Cursor-based pagination.
- Explicit query params.
- No ad-hoc search strings unless scoped and documented.

Time
- RFC3339 timestamps, UTC only.
- Declare TTL/retention policies.

### 4) Pipeline Semantics As First-Class Gates
For each stage, declare:
- Inputs and preconditions.
- Outputs.
- Deterministic fields.
- Non-deterministic fields (only where unavoidable).
- Evidence links (EO ids, ledger ids).
- Failure modes and retry policy.
- Metrics (latency, reject-rate, dedupe-rate, agent disagreement).

Recommended gates:
1. Ingestion Gate: normalize, validate schema, compute EO hash, attach source metadata.
2. Thermodynamic/Entropy Gate: compute filter metrics and produce ThermoFilterDecision.
3. Deduplication Gate: deterministic clustering keys plus explainability.
4. Triage Gate: orchestration rules, independence constraints, disagreement handling.
5. Assessment Gate: structured assessment outputs (no free-text-only).
6. Recommendation Gate: action templates with prerequisites, blast-radius, rollback.

Each gate must emit a machine-readable decision object that is auditable.

### 5) Endpoint Set (API-Only, Jobs-First)
Default to async for expensive operations.

Core endpoints:
- `POST /v1/ingest/events` -> returns ingest_event_id, eo_id, decision (if immediate).
- `POST /v1/runs` -> create end-to-end or stage-specific run.
- `GET /v1/runs/{run_id}` -> status plus links to artifacts.
- `GET /v1/runs/{run_id}/artifacts` -> list outputs by type.
- `POST /v1/dedup/clusters` (optional admin).
- `GET /v1/evidence/{eo_id}` -> canonical EO plus provenance and content hash.
- `GET /v1/ledger/entries?ref_type=&ref_id=` -> append-only audit trail.
- `POST /v1/cases` -> create triage case (if needed).
- `GET /v1/recommendations/{id}` -> recommendation plus version and evidence links.

Optional:
- `POST /v1/webhooks` for callbacks (signed delivery, retries).
- `GET /v1/runs/{id}/events` for SSE/WebSocket progress.

For each endpoint, require:
- request schema
- response schema
- authz rules
- idempotency rules
- rate limits
- example payloads

### 6) Async Execution And Queue Semantics
- Define queues: ingest, filter, dedupe, triage, assess, recommend.
- Backpressure: reject/429 vs accept+delay.
- Retries: per-stage retry policy plus poison queue.
- Timeouts: per-stage and overall run TTL.
- Deterministic replay: re-run a stage against the same EO snapshot.

### 7) Security, Tenancy, Trust Boundaries
- AuthN: service-to-service tokens (JWT/OAuth2) or mTLS.
- AuthZ: tenant scoping on every query; strict RBAC.
- Data isolation: per-tenant encryption keys where applicable.
- PII handling: redaction or field-level encryption for logs.
- Supply chain: dependency pinning plus SBOM.
- Abuse prevention: payload size limits, signature validation for inbound feeds.
- Accepted formats: list and define normalization rules; preserve original forensics.

### 8) Observability And Evidence-Grade Auditability
- Correlation IDs: return `trace_id` on every response.
- Structured logs: stable schema.
- Metrics: stage latency distributions, decision rates, queue depth, error rate.
- Ledger: append-only entries with hash chaining when required.
- Linkage: ledger_entry -> run_id -> eo_id -> decision_id.
- Explainability payloads:
- dedupe explanation (keys, similarity evidence)
- agent voting or disagreement summary
- recommendation justification pointers

### 9) Quality Gates: Validation, Testing, Definition Of Done
Require deliverables for every service design:
- OpenAPI spec (must match implementation).
- JSON Schema for all objects.
- Property-based tests for idempotency and invariants.
- Replay tests for deterministic outputs.
- Load tests with throughput and p95/p99 targets.
- Failure injection: queue outage, partial agent failure, degraded store.
- Security tests: authz bypass, signature failures, tenant leakage.

### 10) Compatibility With Existing Repos
Force explicit integration points:
- Threat ingestion connectors (location and outputs).
- Thermodynamic filtering library contracts.
- Dedup strategy plug-ins.
- Agent orchestration interface (I/O, timeouts, evidence constraints).
- Alert log assessment module contract.
- Recommendation policy packs (versioned rules/templates).

### 11) Required Output Artifacts
- `openapi.yaml`
- `schemas/*.json`
- `state_machines.md`
- `runbooks.md`
- `test_plan.md`

### 12) Optional High-Leverage Additions
- Minimal viable service profile vs production hardened profile.
- Threat model worksheet (STRIDE-style, concrete).
- Data retention matrix (raw ingest vs EO vs ledger vs recommendations).
- Policy pack versioning (signed recommendation bundles).

## CIX Alerts Stage 1 Admissibility Constraints (If Applicable)
When the service touches Stage 1 admissibility, enforce:
- Deterministic tri-band decisions: VACUUM, LOW_ENTROPY, MIMIC_SCOPED.
- Idempotency key: (source_id, event_id, raw_payload_hash).
- Duplicate key replay returns original decision and emits IDEMPOTENT_REPLAY.
- Event id hash mismatch returns HTTP 409 and emits EVENT_ID_CONFLICT.
- Canonicalization uses JCS per conformance profile.
- LOW_ENTROPY persists minimal envelope only; no free-form summaries.
- Ledger entries required: BATCH_RECEIVED, per-event decision, IDEMPOTENT_REPLAY, EVENT_ID_CONFLICT, BATCH_COMPLETED.
- Batch response counters: vacuum_count, low_entropy_count, mimic_scoped_count, drop_count, suppress_count, pass_count, replayed_count, conflict_count, failed_count, stage1_ms.
- Terminology constraint: use "pre-triage containment" or "pre-analysis containment" only.

## Procedure
1. Define entities and invariants (EO, Run, Decision, Recommendation).
2. Define stage gates and decision objects.
3. Specify endpoints with schemas and idempotency.
4. Specify queues/jobs with retries and timeouts.
5. Specify authn/authz and tenancy isolation.
6. Specify audit/ledger and metrics.
7. Produce OpenAPI, JSON Schemas, and the test checklist.

## Hard Rules
- No untyped endpoints.
- Every transformation emits a decision object.
- Every output links to evidence (EO plus ledger).
- Determinism and replay semantics are declared per field and per stage.
