# CIX Alerts Release Notes - v0.6.0

Release date: 2026-02-15  
Tag: `v0.6.0`  
Commit: `c0cce72`  
Alignment: version synced with `axoden-kernel` `v0.6.0` for cross-repo traceability.

## 1) Benchmark Pack Added

Added a full benchmark specification and execution structure for AI SOC middleware comparison:

1. `docs/benchmark/AxoDen_Middleware_Benchmark_v1.md`
2. `docs/benchmark/benchmark_results_template.csv`
3. `docs/benchmark/benchmark_run_log_2026-02-15.md`

Coverage includes:

1. Fairness protocol
2. Weighted scoring categories (100-point rubric)
3. Hard fail gates
4. Interpretation bands
5. Baseline targets

## 2) Feature Matrix and Weighted Scoring

Added a populated feature benchmark and automated scoring flow:

1. `docs/benchmark/feature_benchmark_matrix_v1.md`
2. `docs/benchmark/feature_benchmark_matrix_v1.csv`
3. `docs/benchmark/feature_benchmark_weights_v1.csv`
4. `docs/benchmark/feature_benchmark_weighted_score_v1.csv`
5. `scripts/score_feature_benchmark.py`

This enables repeatable `Y/P/U` feature scoring and ranking from a single command.

## 3) Ledger and Output Determinism Updates

Improved run determinism and output scoping:

1. Added run-scoped output control via `--output-dir` in `main.py`.
2. Ensured kernel ledger defaults to `<output-dir>/kernel_ledger.jsonl` unless explicitly overridden.
3. Fixed event extraction in `src/models.py` to support normalized and raw payload shapes used in kernel-integrated flows.
4. Updated pipeline behavior in `src/pipeline/graph_pipeline.py` to:
   - use output-directory scoped stage-1 ledger,
   - clean prior pipeline-owned artifacts in the selected output directory,
   - include stage-1 ledger in artifact manifest tracking.

Impact:

1. Eliminates uncontrolled cross-run ledger growth in shared directories.
2. Makes output file counts deterministic per run configuration.
3. Improves traceability for reproducibility and audit workflows.

## 4) GTM and Differentiator Alignment Across Repos

Aligned strategy and messaging across `cix-alerts` and `axoden-kernel`:

1. Added CIX middleware differentiators (`D25-D30`) to:
   - `/Users/erkanyalcinkaya/projects/axoden-kernel/docs/core-info/Framework_Differentiators_v060.md`
2. Updated GTM messaging to explicitly position CIX as SIEM/SOAR-to-analyst middleware:
   - `/Users/erkanyalcinkaya/projects/axoden-kernel/docs/core-info/AxoDen_GTM_Key_Messages_v060.md`
3. Kernel docs alignment commit:
   - `axoden-kernel` commit `4c354e5`

---

Validation snapshot:

1. `./.venv/bin/pytest -q` -> `18 passed, 1 warning`
2. `v0.6.0` tag pushed for CIX release alignment.

