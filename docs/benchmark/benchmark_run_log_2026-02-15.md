# Benchmark Run Log - 2026-02-15

## Context

- Benchmark spec: `docs/benchmark/AxoDen_Middleware_Benchmark_v1.md`
- Feature matrix: `docs/benchmark/feature_benchmark_matrix_v1.csv`
- Weights: `docs/benchmark/feature_benchmark_weights_v1.csv`
- Scoring script: `scripts/score_feature_benchmark.py`

## Execution

Command:

```bash
python3 scripts/score_feature_benchmark.py \
  --matrix docs/benchmark/feature_benchmark_matrix_v1.csv \
  --weights docs/benchmark/feature_benchmark_weights_v1.csv \
  --output docs/benchmark/feature_benchmark_weighted_score_v1.csv
```

Output:

- `docs/benchmark/feature_benchmark_weighted_score_v1.csv`

## Summary Ranking (Feature-Weighted)

1. AxoDen CIX - 93.50
2. Qevlar AI - 50.50
2. Prophet Security - 50.50
4. Radiant Security - 44.00
4. D3 Morpheus - 44.00
6. Dropzone AI - 43.50
7. Torq HyperSOC - 37.00
8. ReliaQuest GreyMatter - 22.50

## Notes

1. This is a feature-evidence benchmark, not an end-to-end operational PoC benchmark.
2. `Y/P/U` inputs should be revised as stronger public docs or hands-on validation becomes available.
3. Use together with the quantitative scoring rubric for production-readiness decisions.

