# Technical Appendix (v2)

## Entropy-Bounded GraphRAG Verification Protocol

**Date:** February 13, 2026  \
**Purpose:** Internal engineering, validation, and certification support (ASIL-M aligned)

---

## 1. Scope and Claim Types

All findings must be tagged:

- `OBSERVED`: direct artifact evidence (ledger, graph node/edge, timestamp, hash)
- `INFERRED`: model- or graph-derived interpretation
- `VERIFIED`: statistical test passed with defined threshold and confidence

No `VERIFIED` label is permitted without explicit test outputs.

---

## 2. Core Data Objects

Let:

- `G = (V, E)` be the forensic graph.
- `A_WS` be workstation alert channel observations.
- `A_DC` be domain controller alert channel observations.
- `L` be lateral movement latent state (or proxy label).
- `T(v)` be event timestamp for node `v`.

---

## 3. Entropy-Bounded Triage Metrics

### 3.1 Raw entropy estimator

For byte distribution `p_i` over payload text:

`H_raw = -sum_i p_i * log2(p_i) + ((d - 1) / (2n))`

Where:

- `d`: number of observed byte symbols
- `n`: payload byte count
- second term is Miller-Madow correction

### 3.2 Projected entropy

Given projection bucket probability `p`:

`H_proj = -log2(p)`

### 3.3 Funnel KPIs

- Reduction ratio:
  `R = 1 - (active_candidates / total_ingested)`
- Dedup ratio:
  `D = dedup_removed / total_ingested`
- Stage-1 failure ratio:
  `F = stage1_failed / total_ingested`

---

## 4. Verification Test for Distinct DC Signal

### 4.1 Hypotheses

- `H0`: `I(A_DC ; L | A_WS) = 0` (echo / no incremental information)
- `H1`: `I(A_DC ; L | A_WS) > 0` (distinct channel evidence)

### 4.2 Conditional mutual information (CMI)

For discrete variables:

`I(X;Y|Z) = sum_{x,y,z} p(x,y,z) * log( p(x,y|z) / (p(x|z)*p(y|z)) )`

Use:

- frequency estimator with Laplace smoothing (`alpha = 1`) or
- kNN estimator for mixed continuous/discrete features

### 4.3 Null-model significance test

1. Compute observed `CMI_obs`.
2. Permute `A_DC` within each stratum of `A_WS` (preserve marginal structure).
3. Recompute `CMI_perm` for `N` permutations (recommended `N >= 1000`).
4. `p_value = (1 + count(CMI_perm >= CMI_obs)) / (N + 1)`.

Reject `H0` if `p_value < alpha` (default `alpha = 0.05`).

### 4.4 Confidence interval

Bootstrap `(A_WS, A_DC, L)` tuples with replacement (`B >= 1000`) and compute:

- `CI95 = [q2.5(CMI_boot), q97.5(CMI_boot)]`

Accept strong evidence only if lower bound `> 0`.

### 4.5 Decision rule for claim label

- `VERIFIED` if:
  - `CMI_obs > 0`
  - `p_value < alpha`
  - `CI95_low > 0`
  - sensor dependency review has no unresolved shared-cause blocker
- Else label as `INFERRED`.

---

## 5. Graph Analytics for Response Decisions

### 5.1 Temporal blast radius

For paired indicators:

`delta_t = T(A_DC) - T(A_WS)`

If `delta_t < tau_blast` (example: `5m`), escalate containment policy.

### 5.2 Counterfactual traversal

Given candidate control edge/node `c`:

1. Create graph copy `G' = G - c`.
2. Compute affected set:
   `Delta = Reachable_G(seeds) - Reachable_G'(seeds)`.
3. Use `|Delta|` and critical-node overlap as remediation impact score.

### 5.3 RCA ranking

For candidate upstream nodes `u`:

`score(u) = w1 * betweenness(u) + w2 * causal_support(u) + w3 * temporal_precedence(u)`

Output top-k with evidence paths and uncertainty.

---

## 6. Reproducibility Envelope (Mandatory)

Include all fields in every published assessment:

- Dataset name and SHA-256
- Kernel version and service commit hashes
- Profile ID and registry commit
- ARV parameters (`phi_limit`, `beta`, `tau`)
- Runtime flags used
- Artifact manifest and checksums

No certification-grade conclusion is valid without this envelope.

---

## 7. Execution Protocol (Project-Level)

### 7.1 Baseline run

```bash
python3 main.py samples/empire_launcher_vbs_2020-09-04160940.batch.json --verbose
```

### 7.2 Policy-tuned diagnostic run

```bash
python3 main.py samples/empire_launcher_vbs_2020-09-04160940.batch.json \
  --verbose \
  --arv-beta 10 \
  --phi-limit-arv2 5000 \
  --phi-limit-arv3 5000
```

Note: tuned runs are for sensitivity analysis and should be labeled accordingly.

---

## 8. Standard Report Template

Use the following structure for internal and external reports.

```markdown
# Incident Assessment: <CASE_ID>

## Reproducibility Envelope
- Dataset: <name>
- Dataset SHA-256: <hash>
- Kernel Version: <version>
- Profile ID: <profile_id>
- Registry Commit: <hash>
- ARV Params: <phi/beta/tau>
- Command: <exact command>

## Triage Funnel
- Ingested: <n>
- Background Removed: <n>
- Red-Zone Removed: <n>
- Deduplicated: <n>
- Active Candidates: <n>

## Key Graph Findings
1. <finding> [OBSERVED/INFERRED/VERIFIED]
2. <finding> [OBSERVED/INFERRED/VERIFIED]

## Verification Tests (if applicable)
- Test: CMI(A_DC;L|A_WS)
- CMI_obs: <value>
- p-value: <value>
- CI95: [<low>, <high>]
- Decision: <reject/fail to reject H0>
- Claim Label: <VERIFIED or INFERRED>

## Recommended Actions
1. <action>
2. <action>
3. <action>

## Artifacts
- Report: <path>
- Ledger: <path>
- Graph HTML: <path>
- Snapshot HTML: <path>
```

---

## 9. Review Checklist

- [ ] All claims tagged (`OBSERVED/INFERRED/VERIFIED`)
- [ ] No theorem/proof language without measured validation output
- [ ] Reproducibility envelope complete
- [ ] Statistical assumptions documented
- [ ] Artifact links and hashes included

