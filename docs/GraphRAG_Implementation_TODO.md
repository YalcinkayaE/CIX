# GraphRAG Implementation TODO

## Objective

Turn the v2 GraphRAG docs into executable capabilities in the CIX pipeline.

## Phase 1: Temporal Traversal Engine (completed)

- [x] Define campaign-level traversal analysis output schema
- [x] Build alert metadata extraction for timestamps and host/process context
- [x] Implement alert projection graph for causal/temporal traversal
- [x] Implement seed selection from suspicious alert signals
- [x] Implement temporal path extraction with monotonic timestamp checks
- [x] Implement blast-radius calculation (`delta_t`, within-threshold impact)
- [x] Implement counterfactual traversal (`G' = G - c`) impact scoring
- [x] Implement RCA ranking (`betweenness + support + precedence`)
- [x] Emit per-campaign `temporal_analysis_campaign_<n>.json`
- [x] Expose temporal analysis artifact in API run artifacts

## Phase 2: Claim Labeling in Reports

- [x] Add `OBSERVED/INFERRED/VERIFIED` tags to generated report sections
- [x] Auto-generate claim-label summary from available evidence/tests
- [x] Prevent `VERIFIED` label unless statistical criteria are present

## Phase 3: Statistical Verification (CMI)

- [x] Implement CMI estimator module for `(A_DC, L | A_WS)`
- [x] Implement permutation test harness (null rejection)
- [x] Implement bootstrap CI estimation
- [x] Emit verification JSON artifact with decision rationale
- [x] Wire verification output into report generation

## Phase 4: Reproducibility Envelope

- [x] Generate run manifest with dataset hash, profile, registry commit, ARV params
- [x] Add per-artifact checksum manifest
- [x] Include exact command and environment snapshot
- [x] Add report section linking manifest and checksums

## Validation

- [x] Unit tests for traversal engine primitives
- [x] Integration test for new temporal analysis artifact wiring
- [x] Sample-data smoke run asserting temporal analysis artifacts are present
