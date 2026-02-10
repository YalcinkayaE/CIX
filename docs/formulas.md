# Formulas and When to Use Them

This file captures the formulas implemented in this repo and the intended usage points. Items marked "pending port" are sourced from `projects/axoden-sfa` and are not yet implemented here.

## Stage 1 (Implemented)

**Thresholds (Stage‑1 Tri‑Band)**
- Noise floor: `2.0` bits (LOW_ENTROPY threshold).
- Vacuum ceiling: `5.2831` bits (VACUUM/red zone threshold).
- Implemented in: `src/kernel/stage1.py`.

**Entropy Estimator (Miller–Madow)**
```
H_MM = -∑_i p_i log2(p_i) + (d - 1) / (2n)
```
- `d` is support size (unique symbols), `n` is sample count.
- Implemented in: `src/kernel/stage1.py` (raw entropy over payload bytes).
- Source (axoden‑sfa): `src/shared/entropy/entropy_estimator.py`.

**Stage‑1 Tri‑Band (Surprisal for Noise)**
```
surprisal = -log2(p)
p = max(1/n, count(projection) / n)
```
- Use for per‑event projected surprisal (noise filtering).
- Implemented in: `src/kernel/stage1.py`.

**Stage‑1 VACUUM (Raw Entropy)**
- Use Miller–Madow entropy over raw payload bytes to detect high randomness.
- VACUUM if `H_raw > ENTROPY_CEILING`.
- Implemented in: `src/kernel/stage1.py`.

## Pending Port (Sourced from axoden‑sfa)

**Conditional Entropy**
```
H(X|Y) = Σ_y p(y) H(X|Y = y)
```
- Used for EBDP per‑stage budgets and EFI conditional leakage.
- Source (axoden‑sfa): `src/shared/entropy/entropy_estimator.py`.

**Mutual Information**
```
I(X;Y) = H(X) - H(X|Y)
```
- Repo computes MI both directions (X→Y and Y→X) and averages for robustness.
- Source (axoden‑sfa): `src/shared/entropy/entropy_estimator.py`.

**EBDP Per‑Stage Budget**
```
H(X_k | X_{k-1}) ≤ H_k^max
```
- Monitor each pipeline stage’s conditional entropy against its budget.
- Source (axoden‑sfa): `src/shared/entropy/ebdp_monitor.py`.

**EBDP Global Budget (Compositional Bound)**
```
H_total = Σ_k H_k
H_total ≤ Global_Budget
```
- GlobalEntropyMonitor accumulates stage entropies and hard‑blocks on budget exceed.
- Source (axoden‑sfa): `src/shared/entropy/ebdp_monitor.py`.

**EFI Leakage (Hallucination Control)**
```
I(X_k; M_k | X_{k-1}) = H(X_k|X_{k-1}) - H(X_k|X_{k-1}, M_k)
I(X_k; M_k | X_{k-1}) ≤ ε
```
- `M_k` is model state (prompt, params, metadata).
- Source (axoden‑sfa): `src/shared/entropy/efi_monitor.py`.

**EFI Surplus Entropy (Fabrication Detection)**
```
E^+_k = max(0, I(X'_k; M_k) - I(X'_k; X_{k-1}))
```
- Fabrication if `E^+_k > surplus_threshold`.
- Source (axoden‑sfa): `src/shared/entropy/efi_monitor.py`.

**EFI Certified Surplus (Finite‑Sample Margin)**
```
certified_surplus = surplus + margin
```
- `margin` from McDiarmid bound (see next formula).
- Source (axoden‑sfa): `src/shared/entropy/efi_monitor.py` and `src/shared/entropy/entropy_estimator.py`.

**Finite‑Sample Certification Margin (McDiarmid)**
```
sensitivity = (ln(n) + 2) / n
margin = sqrt((sensitivity^2 * ln(2 / confidence)) / 2)
```
- Used to report conservative, certified estimates.
- Source (axoden‑sfa): `src/shared/entropy/entropy_estimator.py`.

**Text‑Guard Proxy Surplus (Narrative/Free‑Form Output)**
```
proxy = 0.25 * (count of novel IOCs) + 0.05 * max(0, H_out - H_in)
```
- Source (axoden‑sfa): `src/shared/safety/efi_text_guard.py`.

**CFS Independence (Behavioral)**
```
independence = 1 - max(0, cosine_similarity(vec_a, vec_b))
```
- Vectors are surplus‑entropy time series per agent.
- Source (axoden‑sfa): `src/shared/entropy/cfs_monitor.py`.
