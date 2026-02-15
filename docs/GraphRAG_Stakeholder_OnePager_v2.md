# CyberIntelX.io One-Pager

## Certifiable Forensic Middleware with Entropy-Bounded GraphRAG

**Version:** v2  \
**Date:** February 13, 2026  \
**Scope:** External and executive briefing

---

## The Problem

Traditional SIEM pipelines produce large volumes of alerts and rely on manual analyst correlation. This delays containment and increases risk during active campaigns.

---

## The Shift

CyberIntelX.io applies an entropy-bounded GraphRAG workflow:

1. **Filter uncertainty at ingress** (before expensive analysis).
2. **Build a forensic graph** from events, entities, and evidence links.
3. **Prioritize causal pivots** using temporal and topological signals.
4. **Gate decisions with verification policy** (VSR and ARV constraints).

Result: investigation moves from alert-by-alert review to structured, auditable forensic reasoning.

## Positioning One-Liner

`CIX-Alerts turns noisy alerts into time-ordered causal evidence, with statistical proof of root cause and remediation impact.`

---

## What We Observed (Mordor Sample Baseline)

Dataset: `empire_launcher_vbs_2020-09-04160940.batch.json`

- Ingested: `2067` events
- Semantic background removed: `4`
- Red-zone removed: `1`
- Deduplicated: `1964`
- Active candidates: `98`

This represents a high compression of investigative surface area before graph reasoning.

### The Signal-to-Noise Moat

CIX-Alerts did not summarize all `2067` events. It invalidated `1969` events (`4` semantic background + `1` red-zone + `1964` deduplicated) before the AI-facing reasoning stage, leaving `98` active candidates.

---

## Business Value

- **Faster triage:** fewer candidates reach analyst focus.
- **Higher confidence decisions:** graph context reduces isolated-alert ambiguity.
- **Causal evidence for action:** findings are evidence-linked and timeline-consistent, not just narrative summaries.
- **Remediation impact clarity:** counterfactual traversal estimates what changes when specific pivots are removed or blocked.
- **Auditability:** evidence, relations, and decisions are artifact-backed and reproducible.
- **Operational readiness:** supports automated playbooks (isolation, containment, and RCA).

---

## Why GraphRAG Is Better Than Linear Correlation

- **Temporal certitude:** event order is explicit in graph evidence.
- **Topological risk scoring:** bridge nodes and pivots are measurable.
- **Counterfactual analysis:** teams can test remediation impact before execution.
- **Statistical proof gates (Mathematical Hallucination-Checking):** key claims are verified with CMI, permutation testing, and confidence intervals.

---

## Governance and Certifiability

Every conclusion is labeled as one of:

- **Observed** (directly measured in artifacts)
- **Inferred** (reasoned from structure)
- **Verified** (statistically tested)

This claim discipline is the foundation for ASIL-M style assurance and defensible external reporting.

Technical layer:
- Powered by AxoDen Kernel for entropy-bounded safety.
- Temporal graph traversal for incident lineage.
- Counterfactual reachability analysis for remediation impact.
- Topological integrity and cryptographic evidence ledgers for replay-grade assurance.

---

## Immediate Adoption Path

1. Standardize run metadata (dataset hash, profile ID, ARV parameters, commit IDs).
2. Publish one reproducibility bundle per investigation.
3. Add statistical verification checks for high-impact claims.
4. Tie graph-derived thresholds to containment automations.

---

## Outcome

CyberIntelX.io positions SOC operations to shift from noisy alert handling to certifiable, evidence-grounded autonomous forensics and provable incident truth.
