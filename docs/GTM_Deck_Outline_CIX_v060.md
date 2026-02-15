# CIX-Alerts GTM Narrative Deck Outline (10 Slides)

Date: 2026-02-15  
Version: v0.6.0 alignment  
Audience: Investor + CISO + SOC leadership

## Slide 1: Title and Thesis

### On-slide

Title: `From Alert Noise to Provable Incident Truth`  
Subtitle: `CIX-Alerts: Certifiable Forensic Middleware for SOC teams`

### Speaker notes

1. Open with category clarity: CIX is not a SIEM replacement and not another AI summarizer.
2. Position CIX as trust infrastructure between SIEM or SOAR telemetry and analyst decisions.
3. Set the thesis: time-ordered causal evidence plus statistical proof and remediation impact.

## Slide 2: The SOC Problem in One Frame

### On-slide

Headline: `Current SOC pipelines optimize for alert volume, not defensible conclusions`

Three pain points:
1. High alert volume with weak causal linkage.
2. AI summaries can be fast but hard to defend.
3. Post-incident disputes (legal, insurer, vendor) expose evidence gaps.

### Speaker notes

1. Explain that summary speed does not equal incident truth.
2. Emphasize board-level concern: hallucinated or unsupported claims in incident reports.
3. Transition to CIX moat: reduce noise before AI reasoning starts.

## Slide 3: The Signal-to-Noise Moat

### On-slide

Headline: `95.3% of events invalidated before AI-facing reasoning`

Proof point (Mordor baseline):
1. Ingested: `2067`
2. Invalidated before deep reasoning: `1969`
3. Active candidates: `98`
4. Reduction: `95.3%` (`1969 / 2067`)

### Speaker notes

1. Stress that CIX did not summarize all 2067 events.
2. It filtered invalid/noise events first, then reasoned on the smaller active set.
3. This is an operational moat and a compute moat.

## Slide 4: Category Definition

### On-slide

Headline: `Certifiable Forensic Middleware`

Primary one-liner:
`CIX-Alerts turns noisy alerts into time-ordered causal evidence, with statistical proof of root cause and remediation impact.`

### Speaker notes

1. Define the category explicitly: forensic middleware.
2. Mention why this is defensible: evidentiary outputs, verification gates, replayability.
3. Tie directly to buyer outcomes: faster triage and lower decision risk.

## Slide 5: Why We Win (Competitive Fences)

### On-slide

Headline: `Causal Adjacency vs Semantic Similarity`

Contrasts:
1. Versus SIEM-only: collect and alert vs reconstruct and verify.
2. Versus AI summarizers: fluent text vs evidence-gated claims.
3. Versus graph DB alone: storage vs traversal policy + verification + artifacts.
4. Versus vector-only RAG: semantic similarity vs causal adjacency and temporal precedence.

### Speaker notes

1. Use the line: you cannot traverse a timeline in a vector space.
2. Explain that CIX prioritizes causally adjacent events, not merely similar descriptions.
3. Anchor this slide as the core technical fence in the market.

## Slide 6: Trust Infrastructure (D25-D30)

### On-slide

Headline: `Implementation-backed trust stack`

Layered controls:
1. Entropy tri-band admissibility (`D25`).
2. Three-ledger chain of custody (`D26`).
3. Reproducibility envelope (`D27`).
4. Claim-label governance with stats gates (`D28`).
5. Temporal and counterfactual traversal (`D29`).
6. Analyst artifact bundle (`D30`).

### Speaker notes

1. Emphasize these are implemented middleware differentiators, not future concepts.
2. Map each layer to risk reduction: fewer false paths, stronger traceability, higher defensibility.
3. Frame CIX as SOC trust infrastructure, not only workflow automation.

## Slide 7: Hallucination-Checking by Design

### On-slide

Headline: `Statistical Proof Gates (Mathematical Hallucination-Checking)`

Claim discipline:
1. `OBSERVED`: direct artifact evidence.
2. `INFERRED`: structural reasoning.
3. `VERIFIED`: statistical criteria satisfied.

Verification gates:
1. CMI check.
2. Permutation null rejection.
3. Confidence interval criteria.

### Speaker notes

1. Use executive translation: AI drafts the report, math signs off on verified claims.
2. Clarify this is about lowering unsupported-claim risk.
3. Tie to governance and external reporting defensibility.

## Slide 8: Remediation Impact and Economic Value

### On-slide

Headline: `From detection to provable remediation`

Business impact:
1. Counterfactual traversal estimates impact of removing a pivot.
2. Supports defensible eradication evidence.
3. Can improve legal and cyber-insurance posture during claim review.

### Speaker notes

1. This is the Verify/Sustain/Recover advantage.
2. Translate technical output into budget language: risk mitigation, not only ops efficiency.
3. Link to incident response and compliance stakeholders jointly.

## Slide 9: Adversarial Insurance and Non-Repudiable Forensics

### On-slide

Headline: `When disputed, replay beats argument`

Message:
1. Reproducibility envelope acts as adversarial insurance.
2. Third parties can replay the same logic path.
3. Outcome: non-repudiable forensic posture.

### Speaker notes

1. Frame this for attacker disputes, insurer disputes, auditor scrutiny, and vendor disagreement.
2. Stress deterministic replay over narrative debate.
3. Position as a strategic trust differentiator.

## Slide 10: Adoption Motion and Ask

### On-slide

Headline: `90-Day Proof of Causal Value`

Pilot structure:
1. Run fixed datasets through current SOC pipeline and CIX.
2. Measure reduction, evidence quality, and replay outcomes.
3. Deliver artifact bundle and decision-risk comparison.

Success criteria:
1. Signal reduction before deep reasoning.
2. Verified claim quality and traceability.
3. Reproducible outputs suitable for external review.

CTA:
`Run a reproducible incident proof-of-value.`

### Speaker notes

1. Close with controlled adoption, not platform rip-and-replace.
2. Explain that pilot success is measurable and auditable.
3. End with a clear next step: scoped proof-of-value engagement.

## Optional Appendix Slides

1. Objection handling (`We already have a graph`, `We already use LLM summaries`).
2. Technical artifact examples (report, ledger, traversal JSON, verification JSON, manifest).
3. Benchmark scoring rubric and hard-fail gates.
