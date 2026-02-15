# CIX Alerts Release Notes - v0.6.1

Release date: 2026-02-15  
Tag: `v0.6.1`  
Alignment: patch release on top of `v0.6.0`.

## 1) Default Output Folder Is Now Unique Per Run

- `main.py` now defaults to writing artifacts under:
  - `reports/report_<UTC timestamp>_<microseconds>`
- This prevents accidental overwrite between runs and makes run-by-run comparison easier.
- `--output-dir` still overrides this behavior when an explicit path is provided.

## 2) Forensic Reporting Coherence Improvements

- Incident anchor selection now prefers initial-access stage evidence when available.
- Report incident header normalization aligns `Incident ID` with selected campaign anchor.
- Temporal patient-zero ranking now prefers the top temporal seed where available.
- Platform-service IP handling remains contextual (`PLATFORM_SERVICE_CONTEXT`) instead of default primary malicious C2.

## 3) Ground Truth Draft Workflow Expanded

- First-pass output now includes `ground_truth_draft.json`.
- Forensic report includes a dedicated analyst review section:
  - `## 12. Ground Truth Draft (Analyst Review)`
  - draft event IDs
  - copy-ready env export value
  - stage-level draft candidate rationale

## 4) Scoring Presentation Tightening (No GT Provided)

- When `CIX_GROUND_TRUTH_EVENT_IDS` is not set:
  - `TP/FP/FN` now shows not-evaluable guidance.
  - `Precision` and `Recall` render as `n/a`.
- This avoids misleading interpretation of placeholder values in first-pass runs.

## 5) Validation

- Unit and regression suite pass at release cut:
  - `29 passed`
