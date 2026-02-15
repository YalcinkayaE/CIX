# CIX Alerts Kernel Demo

This demo wires CIX alerts to the AxoDen Kernel (registry + evidence + decision + ledger), producing a deterministic evidence ledger and replay verification.

## Prerequisites
- AxoDen Kernel repo at `/Users/erkanyalcinkaya/projects/axoden-kernel` or set `AXODEN_KERNEL_PATH`
- Python deps in this repo (add `pyyaml`)

## Compatibility Notes
- Targets AxoDen Kernel v0.6.0 integration in this repo.
- Uses profile `axoden-cix-1-v0.2.0` by default.
- Decisions are stored with `action_id` + `reason_code` (singular).

## Run Demo
```bash
export AXODEN_KERNEL_PATH=/Users/erkanyalcinkaya/projects/axoden-kernel
python3 scripts/kernel_demo.py --reset
```

Expected output: decisions with actions and a ledger at `data/kernel_ledger.jsonl`.

## Replay Verification
```bash
export AXODEN_KERNEL_PATH=/Users/erkanyalcinkaya/projects/axoden-kernel
python3 scripts/kernel_replay.py --ledger data/kernel_ledger.jsonl
```

## Notes
- Demo alerts live in `samples/cix_kernel_demo_alerts.json`.
- Evidence objects are immutable after hashing; decisions are emitted as new evidence records.
