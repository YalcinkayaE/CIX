# CIX Alerts Context Recovery

Purpose: Reload the minimum project context at the start of a new session before making changes.

## 1. Startup Read Order

1. `AGENTS.md`
2. `README.md`
3. `docs/AxoDen_Canonical_Blueprint.md`
4. `docs/api/README.md`
5. Latest release note in `docs/releases/`

## 2. Operational Baseline

1. This repo is aligned to AxoDen Kernel `v0.6.0`.
2. Default profile is `axoden-cix-1-v0.2.0`.
3. ARV decision semantics use `reason_code` (single string).
4. Reporting artifacts are campaign-scoped and include traversal and verification JSON outputs.

## 3. Run Baseline

1. Create or activate virtualenv: `python3 -m venv .venv && source .venv/bin/activate`
2. Install deps: `pip install -r requirements.txt`
3. Run tests: `./.venv/bin/pytest -q`
4. Use explicit output directory for deterministic runs:
   `./.venv/bin/python main.py <input> --output-dir <dir>`

## 4. Known Guardrails

1. Do not trust file counts in shared `data/` unless run-specific output directory is used.
2. For large sample runs, ARV gates can halt reporting unless profile or flags permit execution.
3. Keep release tag synchronized with kernel version for traceability.

## 5. Benchmark Artifacts

1. Quantitative rubric:
   `docs/benchmark/AxoDen_Middleware_Benchmark_v1.md`
2. Feature matrix:
   `docs/benchmark/feature_benchmark_matrix_v1.md`
3. Weighted scoring script:
   `scripts/score_feature_benchmark.py`
4. Latest scored output:
   `docs/benchmark/feature_benchmark_weighted_score_v1.csv`

## 6. Session-End Checklist

1. Re-run tests if code changed.
2. Confirm generated artifacts and paths in release notes or run log.
3. Commit only intended files.
4. Push commit and aligned version tag.

