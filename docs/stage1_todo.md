# Stage 1 TODO (Blueprint-Derived)
Updated: 2026-02-06

## Tasks
- [x] Entropy formulas + constants (Miller–Madow, noise floor 2.0, vacuum ceiling 5.2831)
- [x] Payload text extraction + projection (templating, projection, suspicious markers)
- [x] Tri-band logic (VACUUM / LOW_ENTROPY / MIMIC_SCOPED)
- [x] CEF/LEEF/Syslog parsing
- [x] Idempotency + conflict handling
- [x] LOW_ENTROPY envelope handling
- [x] Ledger hash chaining + evidence pointers
- [x] Batch counters + terminal ledger entries
- [x] Tests (unit + integration scaffolding)
- [x] API wrapper for POST /api/v1/ingest/classify

## Notes
- Tests are present but not run yet.
- Stage 1 now uses canonical thresholds from formulas.md unless overridden by request profile.
- TODO: Review storage growth for `kernel_ledger.jsonl` and `ledger.jsonl` (logs approaching source file size); decide retention/rotation or sampling strategy.
