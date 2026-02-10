# axoden_soc_kernel_math_contract.md
Version: 0.2
Scope: Backend/API-only implementation contract for the SOC Kernel pipeline (Stages 1–4).
Authority: This document is normative for implementation. Legacy code is advisory only.

## 0) Out-of-scope / exclusions (hard scope boundary)
The following are explicitly OUT OF SCOPE for this build and must not be implemented unless separately authorized:
- AxoDen-Q / quantum extensions and any quantum entropy budgets
- C4 “agent swarm” / multi-agent orchestration as a primary triage mechanism
- Any UI, dashboards, or interactive visualization
- SIEM replacement features (indexing/search as a primary store of record)
- Autonomous response execution without approval gates (SOAR execution can be integrated later as handoff)

## 1) Definitions
### Objects
- **IngestEvent**: Input event from SIEM/telemetry sources.
- **BandDecision**: Stage 1 classification result.
- **CandidateSet**: Stage 2 distilled set of candidates for adjudication.
- **FindingCandidate**: Stage 3 graph-backed proposed finding (not yet certified).
- **CertifiedFinding**: Stage 4 certified finding that passes deterministic certification checks.
- **LedgerEntry**: Append-only hash-chained record for auditability and integrity.

### Pipeline stages (authoritative)
1. **Stage 1 — Admissibility filtering** (Semantic Firewall / tri-band)
2. **Stage 2 — Distillation** (Deduplication + entity normalization)
3. **Stage 3 — Graph forensics adjudication** → outputs **FindingCandidates**
4. **Stage 4 — Certification + Ledger + Exports** → outputs **CertifiedFindings**

---

## 2) Minimal math contract (ER IDs only; implementation must reference these)
This build implements ONLY the following math blocks from the canonical framework:

### ER-TRI-BAND (Stage 1)
- Tri-band classifier producing `VACUUM`, `LOW_ENTROPY`, `MIMIC_SCOPED`.
- VACUUM → **HTTP 418 (DROP)**
- LOW_ENTROPY → SUPPRESS/COMPRESS envelope
- MIMIC_SCOPED → PASS to Stage 2

### ER-LEAK-THRESH (Hunter mode only; optional)
- Hunting leakage threshold: **0.038 bits**.
- If hunter mode is not implemented, omit ER-LEAK-THRESH entirely.

### ER-ARV-PRECEDENCE (Stage 4)
- ARV decision precedence: HALT / ROLLBACK / THROTTLE / EXECUTE (or equivalent deterministic outcomes).
- `phi`, `D_plus`, and `dist_2` must be computed as implemented in the canonical Engine Room block for ARV.

### ER-JCS-HASH (Ledger integrity)
- JSON Canonicalization Scheme (JCS) for deterministic canonical serialization before hashing.
- Hash chain fields required on every ledger entry.

---

## 3) Global invariants (apply to all stages)
### 3.1 Determinism
Given identical inputs and profile parameters:
- Stage decisions MUST be identical.
- Any non-deterministic steps must be isolated so they cannot affect certification unless grounded by evidence pointers.

### 3.2 Ledger-first
No outcome is valid unless recorded in the ledger.
If ledger storage is unavailable:
- Return **HTTP 503** and do not process.

### 3.3 Evidence pointers (minimum required per decision)
Every decision must include:
- source_id
- event_id
- ingest_timestamp (server-side)
- raw_payload_hash (sha256)
- classification_features_id OR feature_hash
- decision_code
- ledger_entry_id + prev_hash + entry_hash

### 3.4 Profile parameter recording (required)
Every batch/assessment MUST record the full parameter profile used for decisions:
- profile_name, profile_version
- phi_limit, beta, tau
- ingestion thresholds (tri-band thresholds)
- any enrichment limits (if Stage 3 enrichment is enabled)

These must be:
- returned in the API response, and
- written to the ledger in BATCH_RECEIVED / ASSESSMENT_RECEIVED.

---

## 4) Idempotency and conflict handling
### 4.1 Idempotency key
idempotency_key = (source_id, event_id, raw_payload_hash)

### 4.2 Duplicate submission behavior
If idempotency_key already exists:
- Return original BandDecision (no re-decision).
- Write ledger entry decision_code = IDEMPOTENT_REPLAY referencing original ledger_entry_id.

### 4.3 Event ID conflict behavior
If (source_id, event_id) exists with different raw_payload_hash:
- Return **HTTP 409 (FORK/CONFLICT)**.
- Write ledger entry decision_code = EVENT_ID_CONFLICT including both hashes.

---

## 5) Batch atomicity
Partial success is allowed but must be explicit.
- Invalid schema → event FAILED with INVALID_SCHEMA; other events continue.
- Ledger unavailable → fail entire request with HTTP 503.

---

## 6) Stage 1 — Admissibility filtering (Semantic Firewall)
Implementation blueprint: docs/stage1_admissibility_blueprint.md
### Entry
IngestEvent(s) with:
- source_id, event_id, source_timestamp
- raw_payload or raw_payload_ref
- raw_payload_hash (or computable)

### Entropy computation (normative)
- Raw entropy uses Miller–Madow over UTF-8 bytes of the extracted payload text.
- Projected surprisal uses Π(event) with p = max(1/n, count(Π(event))/n) and -log2(p).
- Default thresholds: entropy_ceiling = 5.2831, entropy_floor = 2.0.

### Computation (normative outcomes)
- VACUUM → **HTTP 418 (DROP)** decision_code = VACUUM_DROP
- LOW_ENTROPY → SUPPRESS decision_code = LOW_ENTROPY_SUPPRESS (envelope stored)
- MIMIC_SCOPED → PASS decision_code = MIMIC_SCOPED_PASS

### LOW_ENTROPY SUPPRESS/COMPRESS (concrete)
Store deterministic envelope:
- source_id, event_id, ingest_timestamp, raw_payload_hash
- band, decision_code
- feature_summary_ref
- raw_payload_ref (optional)
No free-text summaries.

### Exit
BandDecision per event + ledger entry.

---

## 7) Stage 2 — Distillation (Dedup + entity normalization)
### Entry
Only MIMIC_SCOPED events.

### Computation
- Deterministic entity normalization
- Deterministic dedup keys
- Deterministic grouping/collision policy (GROUP)

### Exit
CandidateSet + ledger entries DISTILLATION_STARTED / COMPLETED.

---

## 8) Stage 3 — Graph forensics adjudication → FindingCandidates
### Entry
CandidateSet.

### Computation
Graph construction / correlation / clustering / bounded enrichment (optional).
Enrichment must be provenance-recorded and bounded by profile limits.

### Output (FindingCandidate requirements)
FindingCandidate[] where each candidate includes:
- finding_id, cluster_id/campaign_id
- entities[]
- claims[]:
  - claim_type ∈ {HYPOTHESIS, OBSERVATION, CONCLUSION}
  - short structured text
  - evidence_refs[] (≥1 per claim) referencing event_ids and/or graph_edge_ids
  - confidence (0..1) or ordinal level
- enrichment_provenance[] (if used)
- graph_refs[] (edge IDs or snapshot ID)

Stage 3 outputs FindingCandidate[] only and MUST NOT emit CertifiedFindings.
Stage 4 is the sole certification authority.

### Exit
- FindingCandidate[] (0..N)
- Ledger entry ADJUDICATION_COMPLETED with counts and references.

---

## 9) Stage 4 — Certification + Ledger + Exports → CertifiedFindings
### Entry
FindingCandidate[] from Stage 3.

### Certification checks (deterministic)
Must reject any FindingCandidate if:
- evidence_refs are unresolvable
- required evidence pointers (Section 3.3) are missing
- policy thresholds fail (min evidence, window constraints, etc.)

Outcomes:
- CERTIFIED → create CertifiedFinding
- REJECTED → HTTP 403 (REJECT)
- NEEDS_MORE_EVIDENCE → HTTP 200 with outcome flag
- FORK → HTTP 409 (FORK/CONFLICT) if independence/diversity constraints enabled and violated

Stage 4 is the only stage allowed to emit CertifiedFinding[].

### Output (CertifiedFinding)
CertifiedFinding[] with:
- finding_id
- certified_timestamp
- severity
- certified_claims[] (claims that passed checks)
- evidence_refs[]
- ledger_entry_id
- export_bundle_id (assessment JSON at minimum)

### Exit
- CertifiedFinding[] (0..N)
- ExportBundle (assessment JSON)
- Ledger entries for certification outcomes + ASSESSMENT_COMPLETED.

---

## 10) Metrics and counters (required)
All processing endpoints MUST output and ledger:
- counts per band and decision
- replay/conflict/failed counts
- stage latencies
- funnel counts (assessment)
