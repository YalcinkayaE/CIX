# CIX-Alerts Positioning Pack (v0.6.0 Alignment)

Date: 2026-02-15  
Product: CIX-Alerts (AxoDen-aligned middleware)

## 0) Alignment Baseline

This pack is aligned to:

1. `/Users/erkanyalcinkaya/projects/cix-alerts/docs/GraphRAG_Stakeholder_OnePager_v2.md`
2. `/Users/erkanyalcinkaya/projects/cix-alerts/docs/GraphRAG_Certifiable_Forensic_AI_v2.md`
3. `/Users/erkanyalcinkaya/projects/cix-alerts/docs/benchmark/AxoDen_Middleware_Benchmark_v1.md`
4. `/Users/erkanyalcinkaya/projects/axoden-kernel/docs/core-info/GTM_Tech_Readiness_Assessment_v060.md`
5. `/Users/erkanyalcinkaya/projects/axoden-kernel/docs/core-info/AxoDen_GTM_Key_Messages_v060.md`
6. `/Users/erkanyalcinkaya/projects/axoden-kernel/docs/core-info/Framework_Differentiators_v060.md`

Positioning-safe implementation scope for CIX: `D25-D30`.

## 1) Category and Positioning Core

### Category (recommended)

`Certifiable Forensic Middleware` for SOC workflows.

### Positioning statement (master)

For SOC and incident-response teams that cannot rely on black-box AI summaries, CIX-Alerts is certifiable forensic middleware that converts noisy SIEM or SOAR streams into time-ordered causal evidence, with statistical verification and replay-grade reproducibility for defensible decisions.

### Why this category works

1. It avoids competing as a SIEM replacement.
2. It separates CIX from generic AI copilot summarizers.
3. It anchors differentiation in auditability and certifiability, not only speed.

## 2) One-Liner Stack

### Primary one-liner

`CIX-Alerts turns noisy alerts into time-ordered causal evidence, with statistical proof of root cause and remediation impact.`

### Executive variant

`From alert noise to provable incident truth.`

### SOC leadership variant

`Deterministic forensic middleware for faster triage, clearer patient-zero ranking, and audit-ready reporting.`

### Compliance or assurance variant

`Replayable, evidence-linked incident outputs with explicit observed, inferred, and statistically verified claim boundaries.`

### Technical variant

`Powered by AxoDen Kernel: entropy-bounded ingress, temporal graph traversal, counterfactual reachability analysis, topological integrity controls, and cryptographic evidence ledgers.`

## 3) Messaging Pillars

### Pillar 1: Time-Ordered Causality, Not Correlation

Message: CIX reconstructs attack lineage as a timeline of causal evidence rather than a bag of related alerts.

Proof anchors:
1. Temporal path extraction and RCA ranking (`D29`).
2. Patient-zero candidate ranking with temporal precedence.
3. Campaign-level traversal artifacts.

### Pillar 2: Statistical Claim Discipline

Message: High-impact claims are not narrative guesses; they are labeled and gated. The AI can draft the report, but the math signs off on verified claims.

Proof anchors:
1. Claim classes: `OBSERVED`, `INFERRED`, `VERIFIED`.
2. `VERIFIED` gated by CMI, permutation testing, and bootstrap CI (`D28`).
3. Verification JSON emitted per campaign.

### Pillar 3: Replay-Grade Auditability

Message: Every run can be replayed and externally assessed.

Proof anchors:
1. Three-ledger chain of custody (`D26`).
2. Reproducibility envelope with hashes, profile, parameters, artifacts (`D27`).
3. Deterministic output packaging for assessors and post-incident review.

### Pillar 4: Practical SOC Throughput

Message: Reduce analyst load before expensive graph reasoning.

Proof anchors:
1. Entropy tri-band admissibility (`VACUUM`, `LOW_ENTROPY`, `MIMIC_SCOPED`) (`D25`).
2. Deterministic replay and conflict handling at ingest.
3. Stage-1 noise suppression before deeper analysis.

### Pillar 5: Remediation Impact, Not Just Detection

Message: CIX does not stop at "what happened"; it estimates what changes if you remove or block a pivot.

Proof anchors:
1. Counterfactual traversal outputs with reachability deltas (`D29`).
2. Blast-radius implications linked to graph structure and event order.
3. Response options grounded in evidence paths rather than narrative-only advice.
4. Provable-remediation records can support lower legal and cyber-insurance liability by providing a defensible audit of eradication.

## 4) Persona Messaging Matrix

### CISO

1. Core pain: AI-assisted SOC outputs are hard to defend to board or regulators.
2. Message: CIX produces certifiable evidence trails, not opaque summaries.
3. Proof to show: reproducibility manifest + claim-label governance + ledger chain.

### SOC Manager

1. Core pain: analyst time is consumed by noisy, weakly connected alerts.
2. Message: CIX compresses alert surface and prioritizes causal pivots.
3. Proof to show: tri-band counts, temporal pathing, patient-zero ranking.

### Incident Response Lead

1. Core pain: root cause and blast radius are slow to validate under pressure.
2. Message: CIX provides time-ordered traversal and counterfactual impact checks to produce defensible eradication evidence.
3. Proof to show: traversal JSON, counterfactual outputs, RCA section.
4. Economic translation: stronger eradication evidence can improve insurer and legal posture during claim review.

### GRC or Assurance Lead

1. Core pain: inconsistent evidence package quality after incidents.
2. Message: CIX standardizes auditable outputs and replay envelopes per run.
3. Proof to show: manifest completeness and deterministic artifact bundle.

### MSSP Operator

1. Core pain: margin pressure from manual triage and inconsistent case quality.
2. Message: CIX standardizes investigations and reduces manual stitching effort.
3. Proof to show: middleware bundle artifacts and repeatable scoring rubric.

## 5) Competitive Framing

Use these contrasts in calls and decks:

1. Versus SIEM-only workflows: SIEMs collect and alert; CIX reconstructs causal timelines and verification-backed findings.
2. Versus AI copilot summarizers: Copilots summarize text; CIX enforces claim discipline with evidence and stats gates.
3. Versus SOAR-only orchestration: SOAR executes playbooks; CIX strengthens decision quality before and during execution.
4. Versus graph database alone: Graph storage is infrastructure; CIX adds deterministic admissibility, traversal policy, verification, and report artifacts.
5. Versus vector-only RAG: vector search identifies semantic similarity; CIX identifies causal adjacency and temporal precedence. You cannot traverse a timeline in a vector space.

## 5.1 Adversarial Insurance Angle

Message: The reproducibility envelope acts as adversarial insurance.

Use in GTM:
1. If an attacker, auditor, insurer, or vendor disputes a conclusion, provide the reproducibility envelope instead of a narrative argument.
2. Third parties can replay the same inputs and parameters to evaluate the same logic path.
3. This supports non-repudiable forensics and reduces dispute-driven uncertainty in post-incident recovery.

## 6) Objection Handling

### "We already have a graph."

Response: A graph data store is necessary but not sufficient. CIX adds temporal and counterfactual traversal policy, claim-label governance, and reproducibility envelopes.

### "Our LLM already summarizes incidents."

Response: Summary quality is not assurance. CIX separates observed, inferred, and verified claims and gates verified claims with explicit statistical tests.

### "This sounds heavy for operations."

Response: The first control is a lightweight tri-band ingress that reduces noise. CIX is middleware that complements existing SIEM and SOAR investments.

### "Can this be audited later?"

Response: Each run emits replay-linked artifacts and manifest metadata designed for independent reassessment.

## 7) Buyer-Facing Proof Kit

For every demo or pilot, show this sequence:

1. Ingest and tri-band reduction counts.
2. Campaign graph with time-ordered path.
3. RCA section with ranked patient-zero candidates.
4. Counterfactual "remove pivot" impact result.
5. Verification section (CMI, p-value, CI).
6. Reproducibility envelope and artifact checksums.

## 8) Website and Deck Copy

### Homepage hero

`Certifiable forensic middleware for SOC teams.`

### Homepage subhead

`CIX-Alerts converts noisy alerts into time-ordered causal evidence, with statistical verification and replay-grade audit trails.`

### Messaging stack (compressed)

Headline: `From alert noise to provable incident truth.`  
Subhead: `CIX-Alerts reconstructs causal attack timelines and verifies findings with statistical and reproducibility controls.`  
Technical layer: `Powered by AxoDen Kernel for entropy-bounded safety, utilizing temporal graph traversal, counterfactual reachability analysis, topological integrity controls, and cryptographic evidence ledgers.`

### Core CTA

`Run a reproducible incident proof-of-value.`

### Deck opener

`Most AI SOC tools optimize for summary speed. CIX optimizes for defensible incident truth.`

## 9) Message Guardrails

Use:

1. "Implemented in CIX middleware layer" for D25-D30 features.
2. "Kernel-aligned" rather than "kernel-native" unless specifically true.
3. "Statistically verified" only when CMI plus permutation and CI criteria are met.

Avoid:

1. "Proves causality" as an absolute statement.
2. "Fully autonomous SOC replacement."
3. Claims that imply replacing SIEM or SOAR.

## 10) Talk Track (60 seconds)

CIX-Alerts is certifiable forensic middleware that sits between SIEM or SOAR telemetry and analyst decisions. It reduces noise at ingress, reconstructs incidents as time-ordered causal evidence, and ranks likely root-cause pivots with counterfactual impact checks. Unlike generic AI summarizers, CIX labels claims as observed, inferred, or statistically verified, where verified claims are gated by explicit CMI, permutation, and confidence-interval checks. Every run is packaged with topological integrity and replay-grade evidence metadata. The result is faster triage with outputs that security, compliance, and leadership can defend.

## 11) ICP Prioritization

Prioritize:

1. Mid-to-large SOC teams with high alert volume and strict post-incident reporting needs.
2. Regulated organizations needing replayable and auditable AI-assisted operations.
3. MSSPs seeking standardized forensic quality across clients.

De-prioritize (initially):

1. Teams seeking a pure SIEM replacement.
2. Buyers optimizing only for lowest-cost alert summarization.
