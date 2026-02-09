from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def _kernel_root() -> Path:
    env_path = os.getenv("AXODEN_KERNEL_PATH")
    if env_path:
        return Path(env_path).expanduser().resolve()
    return (Path(__file__).resolve().parents[2] / "axoden-kernel").resolve()


def _ensure_kernel_on_path() -> Path:
    root = _kernel_root()
    if not root.exists():
        raise FileNotFoundError(
            f"AxoDen kernel not found at {root}. Set AXODEN_KERNEL_PATH to override."
        )
    sys.path.insert(0, str(root))
    return root


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify kernel ledger determinism")
    parser.add_argument(
        "--ledger",
        default="data/kernel_ledger.jsonl",
        help="Ledger JSONL path",
    )
    args = parser.parse_args()

    _ensure_kernel_on_path()
    from sdk import EvidenceLedger  # type: ignore

    ledger = EvidenceLedger(Path(args.ledger))
    errors = ledger.verify_chain()
    if errors:
        for err in errors:
            print(f"ERROR: {err}")
        return 1

    print("Ledger verified: hashes and chain are deterministic.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
