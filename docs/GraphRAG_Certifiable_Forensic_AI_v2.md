# WHITE PAPER (V2): Certifiable Forensic AI

## Entropy-Bounded GraphRAG for Autonomous SIEM

**Author:** Erkan Yalcinkaya  
**Kernel Line:** AxoDen v0.4.x  
**Date:** February 13, 2026

---

## 1. Executive Context: From Detection to Verifiable Forensics

### The shift
Traditional SIEM workflows are optimized for alert generation, then depend on manual analyst correlation. GraphRAG changes this operating model by treating events, entities, and evidence links as a single investigation graph.

### Why it matters
- Linear alert streams are high volume and weakly connected.
- Forensic decisions require causal structure, temporal ordering, and corroboration quality.
- Entropy-bounded triage reduces noise before graph expansion, preserving analyst and compute budgets.

### Triage funnel (latest reproducible baseline)
On the Mordor sample `empire_launcher_vbs_2020-09-04160940.batch.json`:
- Ingested events: `2067`
- Low-entropy filtered: `0`
- Semantic background filtered: `4`
- Red-zone filtered: `1`
- Stage-1 schema failures: `0`
- Deduplicated: `1964`
- Active candidates: `98`

This is the stable baseline. Reporting output depends on ARV policy thresholds at runtime.

---

## 2. Claim Discipline: What Is Observed vs Inferred vs Verified

To support ASIL-M style assurance, every statement must be labeled:

- **Observed:** Directly present in ledger/graph (nodes, edges, timestamps, process names, hashes).
- **Inferred:** Reasoned from observed structure (pivot host, likely path, blast radius estimate).
- **Verified (Statistical):** Supported by explicit tests (for example, conditional mutual information with confidence bounds and null-model rejection).

This prevents over-claiming and makes external communication auditable.

---

## 3. GraphRAG Value in Practice

### 3.1 Temporal certitude
Graph edges plus event timestamps provide ordered attack narratives instead of isolated alerts.

### 3.2 Topological risk scoring
Bridge and centrality metrics identify operationally critical pivots (for example, a workstation bridging user activity to external infrastructure).

### 3.3 Evidence-grounded enrichment
External intelligence (for example, VT/OTX) is attached as graph evidence, not free-text speculation.

---

## 4. Verification Framework for Lateral Movement

### Question
Is a Domain Controller alert a distinct confirmation signal, or only a correlated echo of workstation compromise?

### Hypotheses
- `H0 (Echo): I(A_DC ; L | A_WS) = 0`
- `H1 (Distinct signal): I(A_DC ; L | A_WS) > 0`

Where:
- `A_WS` = workstation alert channel
- `A_DC` = domain controller alert channel
- `L` = latent lateral movement state

### Required evidence for acceptance of H1
1. Estimated `I(A_DC ; L | A_WS) > 0`
2. Null-model/permutation test rejects `H0` at configured alpha
3. Confidence interval excludes zero
4. Sensor-dependency review shows no trivial shared-cause artifact explaining both channels

### Important caution
Disjoint process names alone do **not** prove conditional independence. They are supporting features, not proof.

---

## 5. Mordor Case Template (Operational)

Use this template in incident reports:

1. **Inception:** initial user/process trigger
2. **Execution/Obfuscation:** script/interpreter chain
3. **Artifact evidence:** file/hash/process lineage
4. **Network transition:** outbound or lateral edge
5. **Corroboration:** enrichment nodes and confidence

Each step must include:
- Node IDs
- Edge type
- Timestamp (UTC)
- Source evidence reference

---

## 6. Recommended VSR Enhancements

### 6.1 Temporal blast radius policy
- Compute `delta_t` between upstream compromise indicators and DC-side indicators.
- If `delta_t < threshold` (for example 5 minutes), trigger pre-approved circuit-breaker controls.

### 6.2 Counterfactual traversal
- Remove candidate control node/edge (for example malicious IP edge) in a copied graph.
- Measure downstream reachability reduction.
- Use result as remediation effectiveness evidence.

### 6.3 Automated RCA pathing
- Reverse traverse from high-severity leaf nodes.
- Rank upstream candidates by betweenness and causal support count.
- Emit ranked patient-zero candidates with confidence labels.

---

## 7. Reproducibility Envelope (Required in Every Report)

- Dataset name and SHA-256
- Kernel/service versions
- Profile ID and registry commit
- ARV parameters (`phi limits`, `beta`, `tau`)
- Exact run command
- Artifact manifest (report, graph html, ledger json, snapshot html)

Without this envelope, conclusions are non-certifiable.

---

## 8. Conclusion

The defensible value of GraphRAG is not that it "proves everything," but that it converts SOC reasoning into a testable and auditable workflow:
- entropy-bounded ingress,
- structured causal graph reconstruction,
- explicit statistical verification gates,
- reproducible artifacts.

That is the practical foundation for certifiable autonomous forensics.
