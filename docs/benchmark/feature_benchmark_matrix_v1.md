# AI SOC Middleware Feature Benchmark Matrix (v1)

Last updated: 2026-02-15  
Scope: Publicly documented capabilities only (official vendor pages/docs where possible).  
Purpose: Fast feature-level comparison to complement the quantitative scoring rubric.

## Legend

- `Y`: Explicitly documented in public source(s)
- `P`: Partially documented or marketing-claim level (insufficient implementation detail)
- `U`: Not publicly documented (or not found in reviewed sources)

## Feature Matrix (Populated)

| System | SIEM/SOAR Integration | Autonomous Triage/Investigation | Evidence/Explainability to Analyst | Human-in-the-loop Approval/Control | "No Training on Customer Data" Claim | Hallucination/Grounding Control Claim | Reproducibility Artifacts (manifest/checksums) | Tamper-evident Ledger / Chain Hash | Statistical Claim Verification Gate | Temporal/Counterfactual Graph Analytics | Confidence |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **AxoDen CIX (this repo)** | Y | Y | Y | P | U | Y | Y | Y | Y | Y | High |
| **Dropzone AI** | Y | Y | Y | P | Y | P | U | U | U | U | Medium |
| **Qevlar AI** | Y | Y | Y | P | Y | Y | U | U | U | U | Medium |
| **Prophet Security** | Y | Y | Y | P | Y | P | P | U | U | U | Medium |
| **Radiant Security** | Y | Y | Y | Y | U | P | U | U | U | U | Medium |
| **D3 Morpheus** | Y | Y | Y | Y | U | P | U | U | U | U | Medium |
| **Torq HyperSOC** | Y | Y | P | Y | U | U | U | P | U | U | Medium-Low |
| **ReliaQuest GreyMatter** | Y | P | P | P | U | U | U | U | U | U | Low-Medium |

## Notes on AxoDen CIX Row

Backed by implemented artifacts in this repository:

1. Multi-ledger chain: stage-1 + kernel + ARV + campaign forensic outputs.
2. Reproducibility manifest with run metadata and artifact checksums.
3. Claim-label discipline (`OBSERVED`/`INFERRED`/`VERIFIED`) with statistical gate (CMI/permutation/bootstrap).
4. Temporal/counterfactual traversal and RCA ranking artifacts.

## Evidence Map (Sources Used)

### AxoDen CIX

1. `/Users/erkanyalcinkaya/projects/cix-alerts/src/pipeline/graph_pipeline.py`
2. `/Users/erkanyalcinkaya/projects/cix-alerts/src/pipeline/verification.py`
3. `/Users/erkanyalcinkaya/projects/cix-alerts/src/pipeline/traversal.py`
4. `/Users/erkanyalcinkaya/projects/cix-alerts/docs/GraphRAG_Technical_Appendix_v2.md`

### Dropzone AI

1. https://www.dropzone.ai/product
2. https://www.dropzone.ai/integrations
3. https://docs.dropzone.ai/integrations
4. https://www.dropzone.ai/ai-soc-analyst

### Qevlar AI

1. https://www.qevlar.com/
2. https://www.qevlar.com/faq
3. https://www.qevlar.com/integrations
4. https://www.qevlar.com/product

### Prophet Security

1. https://www.prophetsecurity.ai/
2. https://www.prophetsecurity.ai/integrations
3. https://www.prophetsecurity.ai/why-prophet-security
4. https://www.prophetsecurity.ai/use-cases/endpoint

### Radiant Security

1. https://radiantsecurity.ai/platform-redesign/
2. https://radiantsecurity.ai/integrations/
3. https://help.radiantsecurity.ai/features/security-operations-insights

### D3 Morpheus

1. https://d3security.com/morpheus/
2. https://d3security.com/the-ai-soc/
3. https://d3security.com/

### Torq HyperSOC

1. https://torq.io/ai-soc-automation/
2. https://torq.io/blog/torq-hypersoc-faq/

### ReliaQuest GreyMatter

1. https://reliaquest.com/integrations/

## Use Guidance

1. Treat this as a living pre-sales and product strategy artifact.
2. Upgrade `P`/`U` to `Y` only when you have concrete documentation or hands-on PoC evidence.
3. Pair this file with `/Users/erkanyalcinkaya/projects/cix-alerts/docs/benchmark/AxoDen_Middleware_Benchmark_v1.md` for quantitative ranking.
