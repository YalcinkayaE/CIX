# AxoDen Middleware Benchmark Spec and Scoring Rubric (v1)

Last updated: 2026-02-15
Owner: CIX Alerts / AxoDen team
Purpose: Measure where AxoDen stands against AI-SOC middleware competitors using repeatable, evidence-based criteria.

## 1. Benchmark Goal

Compare middleware systems that sit between SIEM or SOAR platforms and analysts on four core outcomes:

1. Detect and prioritize meaningful security signal.
2. Produce forensic outputs with evidence grounding.
3. Control hallucination risk in analyst-facing narratives.
4. Preserve reproducibility and auditability across runs.

## 2. Scope and Non-Goals

In scope:

1. Middleware behavior after log ingestion (triage, graph reasoning, report artifacts, audit trail).
2. End-to-end outputs that an analyst consumes.
3. Repeatability under fixed inputs.

Out of scope:

1. Replacing SIEM or SOAR products.
2. Vendor pricing negotiation.
3. Detection engineering quality of upstream rules.

## 3. Candidate System Set

Use this benchmark against any candidate in the AI SOC middleware segment (for example, Dropzone, Qevlar, Radiant, Prophet, Torq-like agentic overlays) plus AxoDen baseline.

## 4. Dataset Suite

Run at least three datasets:

| Dataset ID | Source | Event Count | Ground Truth Requirement |
|---|---|---:|---|
| `MORDOR_C1_2067` | `samples/empire_launcher_vbs_2020-09-04160940.batch.json` | 2067 | Curated critical-event set and causal chain |
| `CIX_DEMO_SMALL` | `samples/campaign_demo.json` | 4 | Full event-level truth |
| `CUSTOM_ENTERPRISE` | Internal corpus | N/A | Analyst-validated findings and timeline |

Ground-truth package per dataset must include:

1. Critical events list (event IDs or deterministic fingerprints).
2. Canonical causal chain(s).
3. Expected root cause actor or host.
4. Known malicious pivots (IP, hash, user, host).

## 5. Fairness Protocol

For each system and dataset:

1. Freeze input file and runtime config.
2. Freeze prompts and analyst questions.
3. Disable manual intervention during run.
4. Execute 3 repeated runs (same config).
5. Save all produced artifacts and logs.

Rules:

1. If a metric is not supported by the system output, score zero for that metric.
2. If a claim cannot be traced to evidence, count it as unsupported.
3. If output is non-deterministic, score replay stability from observed variance.

## 6. Required Output Contract

A "complete" run should produce:

1. Analyst narrative report.
2. Machine-readable evidence ledger or equivalent trace log.
3. Graph artifact (interactive or equivalent explorable output).
4. Reproducibility manifest: dataset hash, model/profile version, runtime parameters.
5. Verification section for key claims (or explicit "inferred only").

## 7. Scoring Rubric (100 Points)

### A. Forensic Accuracy and Signal Quality (25)

| Metric | Points | Scoring Rule |
|---|---:|---|
| A1. Critical event recall | 10 | `10 * recall` where recall is fraction of ground-truth critical events recovered |
| A2. Causal chain correctness | 8 | 8 for fully correct ordering and links, 4 partial, 0 incorrect |
| A3. False-positive burden | 7 | 7 if analyst confirms low/no noise; 3 moderate noise; 0 high noise |

### B. Evidence Grounding and Hallucination Control (20)

| Metric | Points | Scoring Rule |
|---|---:|---|
| B1. Unsupported claim rate | 8 | 8 if <=2%, 4 if >2% and <=5%, 0 if >5% |
| B2. Claim label correctness | 6 | 6 if observed/inferred/verified labels are consistently applied and correct |
| B3. Evidence citation completeness | 6 | 6 if each key claim links to concrete artifact evidence; partial downscore |

### C. Reproducibility and Auditability (20)

| Metric | Points | Scoring Rule |
|---|---:|---|
| C1. Manifest completeness | 6 | Requires dataset hash, config/profile, runtime params, artifact list |
| C2. Ledger integrity | 7 | 7 if tamper-evident chain or equivalent verifiable audit linkage exists |
| C3. Replay stability | 7 | 7 if repeated runs are materially identical; partial for bounded variance |

### D. Temporal and Counterfactual Analysis (15)

| Metric | Points | Scoring Rule |
|---|---:|---|
| D1. Temporal consistency | 5 | 5 if timeline order is internally consistent and evidence-backed |
| D2. Blast-radius utility | 5 | 5 if propagation or impact analysis is explicit and usable |
| D3. Counterfactual utility | 5 | 5 if "remove/block pivot" analysis is explicit and coherent |

### E. Operational Feasibility (10)

| Metric | Points | Scoring Rule |
|---|---:|---|
| E1. Time to first analyst artifact | 4 | 4 if within target SLA, 2 if near target, 0 if outside target |
| E2. End-to-end runtime | 3 | 3 if within agreed execution budget |
| E3. Storage amplification | 3 | 3 if artifact+ledger size is proportionate to input; penalize severe inflation |

### F. Integration and Analyst UX (10)

| Metric | Points | Scoring Rule |
|---|---:|---|
| F1. SIEM or SOAR compatibility | 4 | 4 if cleanly ingests existing export formats |
| F2. Analyst usability of outputs | 3 | 3 if report+graph+ledger are immediately usable |
| F3. Export and API interoperability | 3 | 3 if outputs can be consumed downstream without manual conversion |

Final score:

`Total = A + B + C + D + E + F` (max 100)

## 8. Hard Fail Gates

Any run is flagged "not production-ready" if one or more conditions occur:

1. Unsupported claim rate > 5%.
2. No reproducibility manifest or equivalent run envelope.
3. No evidence traceability for top findings.
4. Output cannot be replayed or audited.

## 9. Interpretation Bands

| Total Score | Interpretation |
|---|---|
| 85-100 | Strong production candidate and clear differentiation |
| 70-84 | Competitive but needs targeted hardening |
| 50-69 | Limited readiness; significant risk gaps remain |
| <50 | Not acceptable for high-assurance SOC use |

## 10. Execution Workflow

1. Prepare dataset + ground-truth bundle.
2. Run each system 3 times per dataset.
3. Fill `benchmark_results_template.csv`.
4. Compute per-metric and total scores.
5. Publish one comparison report with evidence links.

## 11. AxoDen Baseline Targets (Initial)

These are initial targets, not guaranteed outcomes:

1. Critical event recall >= 0.90 on benchmarked datasets.
2. Unsupported claim rate <= 2%.
3. Manifest completeness = 100%.
4. Replay stability variance <= 5%.
5. Full analyst artifact bundle present for each emitted campaign.

## 12. Output Files for This Benchmark

1. `docs/benchmark/AxoDen_Middleware_Benchmark_v1.md` (this spec)
2. `docs/benchmark/benchmark_results_template.csv` (run capture sheet)

